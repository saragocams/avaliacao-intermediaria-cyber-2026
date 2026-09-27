// Indicadores de sequestro de navegador (hijacking) e "hooks" DENTRO da página.
// Roda como content script em document_start, ANTES de qualquer script da página.
//
// 1) Integridade de objetos globais
//    Guardamos a referência original de funções críticas (fetch, XMLHttpRequest, WebSocket...)
//    e, depois do carregamento, verificamos se algum script as substituiu. Substituir essas
//    funções permite interceptar tudo o que a página envia/recebe - é o que um "hook" faz
//    (ex.: framework BeEF após um XSS) e também o que bibliotecas de monitoramento fazem.
//    Mesma ideia da página "js-leaks" do DuckDuckGo.
//
// 2) Novas variáveis globais com nomes suspeitos (beef, hook, keylogger...)
//
// 3) Captura de teclado por script de terceira parte
//    Scripts de 3ª parte que registram listeners de teclado/input (keystroke logging),
//    mesmo teste que o Blacklight (The Markup) faz.
//
// (WebSocket, EventSource e polling são detectados no background, pelo tráfego de rede.)
//
// 4) CSP via <meta http-equiv> (o cabeçalho HTTP é analisado no background)

(function () {
  const page = window.wrappedJSObject;
  if (!page) return;

  function callerScript() {
    try {
      const urls = (new Error().stack || "").match(/https?:\/\/[^\s)@]+?(?=:\d+:\d+)/g) || [];
      return urls.find((u) => !u.startsWith("moz-extension:")) || null;
    } catch (e) { return null; }
  }

  function send(kind, data) {
    browser.runtime.sendMessage({ type: "hijack", kind, frame: location.href, data });
  }

  // ---------- 1) Fotografia das funções críticas (antes da página rodar) ----------

  const CRITICAL = [
    ["window.fetch", () => page, "fetch"],
    ["XMLHttpRequest.prototype.open", () => page.XMLHttpRequest && page.XMLHttpRequest.prototype, "open"],
    ["XMLHttpRequest.prototype.send", () => page.XMLHttpRequest && page.XMLHttpRequest.prototype, "send"],
    ["window.WebSocket", () => page, "WebSocket"],
    ["window.EventSource", () => page, "EventSource"],
    ["navigator.sendBeacon", () => page.Navigator && page.Navigator.prototype, "sendBeacon"],
    ["EventTarget.prototype.addEventListener", () => page.EventTarget && page.EventTarget.prototype, "addEventListener"],
    ["document.write", () => page.Document && page.Document.prototype, "write"],
    ["window.open", () => page, "open"],
    ["window.eval", () => page, "eval"],
    ["Function.prototype.toString", () => page.Function && page.Function.prototype, "toString"],
    ["JSON.stringify", () => page.JSON, "stringify"],
    ["HTMLFormElement.prototype.submit", () => page.HTMLFormElement && page.HTMLFormElement.prototype, "submit"],
    ["history.pushState", () => page.History && page.History.prototype, "pushState"]
  ];

  const baseline = new Map();
  for (const [name, getObj, prop] of CRITICAL) {
    try {
      const obj = getObj();
      if (obj) baseline.set(name, obj[prop]);
    } catch (e) { /* ignora */ }
  }
  let baselineGlobals;
  try { baselineGlobals = new Set(Object.getOwnPropertyNames(page)); } catch (e) { baselineGlobals = new Set(); }

  const SUSPICIOUS_GLOBAL = /beef|hook|keylog|inject|payload|botnet|cryptonight|coinhive|miner/i;

  function checkIntegrity() {
    const changed = [];
    for (const [name, getObj, prop] of CRITICAL) {
      try {
        const obj = getObj();
        if (!obj || !baseline.has(name)) continue;
        const now = obj[prop];
        if (now !== baseline.get(name)) {
          let src = "";
          try { src = Function.prototype.toString.call(now).slice(0, 120); } catch (e) { src = "(ilegível)"; }
          changed.push({ name, source: src });
        }
      } catch (e) { /* ignora */ }
    }

    let added = [];
    try { added = Object.getOwnPropertyNames(page).filter((k) => !baselineGlobals.has(k)); } catch (e) { /* ignora */ }
    const suspicious = added.filter((k) => SUSPICIOUS_GLOBAL.test(k));

    send("integrity", { changed, addedCount: added.length, suspicious, sampleAdded: added.slice(0, 15) });
  }

  if (window === window.top) {
    window.addEventListener("load", () => {
      setTimeout(checkIntegrity, 1500);
      setTimeout(checkIntegrity, 8000); // scripts carregados tarde
    });
  }

  // ---------- 3) Captura de teclado por script de 3ª parte ----------

  const KEY_EVENTS = new Set(["keydown", "keyup", "keypress", "input", "beforeinput"]);
  const seenKeyScripts = new Set();
  try {
    const etProto = page.EventTarget.prototype;
    const originalAdd = etProto.addEventListener;
    etProto.addEventListener = exportFunction(function (type, ...rest) {
      try {
        if (KEY_EVENTS.has(String(type))) {
          const script = callerScript();
          if (script && !seenKeyScripts.has(script + type)) {
            seenKeyScripts.add(script + type);
            let target = "outro";
            if (this === window) target = "window";
            else if (this === document) target = "document";
            else if (this && this.tagName) target = String(this.tagName).toLowerCase();
            send("key-listener", { event: String(type), target, script });
          }
        }
      } catch (e) { /* nunca quebrar a página */ }
      return Reflect.apply(originalAdd, this, [type, ...rest]);
    }, page);
    // A nossa própria troca não deve ser acusada como alteração de terceiros
    baseline.set("EventTarget.prototype.addEventListener", etProto.addEventListener);
  } catch (e) {
    console.warn("[Privacy Guard] não foi possível monitorar addEventListener:", e);
  }

  // ---------- 4) CSP via <meta> ----------

  if (window === window.top) {
    document.addEventListener("DOMContentLoaded", () => {
      const meta = document.querySelector('meta[http-equiv="Content-Security-Policy" i]');
      if (meta) send("csp-meta", { policy: (meta.getAttribute("content") || "").slice(0, 300) });
    });
  }
})();
