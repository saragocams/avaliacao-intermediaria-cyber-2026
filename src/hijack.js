// Indicadores de hijacking / hook analisados no BACKGROUND (tráfego de rede e cabeçalhos).
// Carregado depois do background.js.
//
// - Canal persistente com domínio de 3ª parte: WebSocket, EventSource (Server-Sent Events)
//   ou "polling" (a mesma URL sendo chamada em intervalos regulares). É o canal de comando
//   usado por um navegador "fisgado" (ex.: BeEF faz polling/WebSocket para o servidor do atacante).
// - Assinaturas conhecidas do BeEF (hook.js, cookie/parâmetro BEEFHOOK).
// - Ausência ou fraqueza de Content-Security-Policy no documento principal (sem CSP,
//   um XSS consegue carregar script de qualquer origem - porta de entrada do hook).
// - Serviços de gravação de sessão (session replay), que registram cliques e digitação.
// - Mensagens do content script (hijack-page.js): objetos globais alterados e captura de teclado.

const SESSION_REPLAY = new Set([
  "hotjar.com", "hotjar.io", "fullstory.com", "clarity.ms", "mouseflow.com", "smartlook.com",
  "smartlook.cloud", "logrocket.com", "lr-ingest.io", "lr-in.com", "inspectlet.com",
  "luckyorange.com", "luckyorange.net", "quantummetric.com", "contentsquare.net",
  "decibelinsight.net", "sessioncam.com", "yandex.ru", "glassboxdigital.io", "heap.io", "heapanalytics.com"
]);

const POLL_MIN = 5;          // pelo menos 5 requisições à mesma URL
const POLL_MAX_CV = 0.35;    // intervalos regulares (coeficiente de variação baixo)
const polls = new Map();     // tabId -> Map(chave -> [timestamps])

function hj(rep) {
  if (!rep.hijack) {
    rep.hijack = {
      csp: null,             // { present, source, weak:[...] }
      channels: [],          // WebSocket / EventSource / polling
      beef: [],              // assinaturas do BeEF
      integrity: null,       // { changed:[], addedCount, suspicious:[] }
      keyListeners: [],      // captura de teclado
      sessionReplay: []      // domínios de gravação de sessão
    };
  }
  return rep.hijack;
}

function pushOnce(list, item, key) {
  if (!list.some((x) => x._k === key)) list.push({ ...item, _k: key });
}

// ---------- CSP do documento principal ----------

function analyzeCsp(policy) {
  const weak = [];
  const p = policy.toLowerCase();
  const scriptSrc = (/(?:^|;)\s*script-src([^;]*)/.exec(p) || /(?:^|;)\s*default-src([^;]*)/.exec(p) || [])[1];
  if (scriptSrc === undefined) weak.push("sem script-src/default-src");
  else {
    if (/'unsafe-inline'/.test(scriptSrc) && !/'nonce-|'sha(256|384|512)-|'strict-dynamic'/.test(scriptSrc)) weak.push("'unsafe-inline'");
    if (/'unsafe-eval'/.test(scriptSrc)) weak.push("'unsafe-eval'");
    if (/(^|\s)(\*|https?:|data:)(\s|$)/.test(scriptSrc)) weak.push("curinga (*, https:, data:)");
  }
  return weak;
}

browser.webRequest.onHeadersReceived.addListener(
  (d) => {
    if (d.tabId < 0) return;
    const rep = getReport(d.tabId);
    if (!rep) return;
    const headers = d.responseHeaders || [];

    if (d.type === "main_frame") {
      const csp = headers.filter((h) => h.name.toLowerCase() === "content-security-policy").map((h) => h.value).join("; ");
      const reportOnly = headers.some((h) => h.name.toLowerCase() === "content-security-policy-report-only");
      hj(rep).csp = csp
        ? { present: true, source: "cabeçalho HTTP", weak: analyzeCsp(csp) }
        : { present: false, source: reportOnly ? "só Report-Only (não bloqueia)" : "ausente", weak: [] };
    }

    // Assinatura BeEF: cookie BEEFHOOK
    for (const h of headers) {
      if (h.name.toLowerCase() === "set-cookie" && /BEEFHOOK=/i.test(h.value || "")) {
        pushOnce(hj(rep).beef, { host: hostnameOf(d.url), evidence: "Set-Cookie BEEFHOOK" }, "cookie" + d.url);
      }
    }
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

// ---------- Canais persistentes e assinaturas ----------

browser.webRequest.onBeforeRequest.addListener(
  (d) => {
    if (d.tabId < 0 || d.type === "main_frame") return;
    const rep = getReport(d.tabId);
    if (!rep) return;
    const host = hostnameOf(d.url);
    const third = isThirdParty(host, rep.host);
    const h = hj(rep);

    // BeEF: o script de hook se chama hook.js por padrão
    let path = "";
    try { path = new URL(d.url).pathname; } catch (e) { /* ignora */ }
    if (/\/hook\.js$/i.test(path) || /[?&]BEEFHOOK=/i.test(d.url)) {
      pushOnce(h.beef, { host, evidence: d.url.slice(0, 150) }, "url" + host + path);
    }

    // Gravação de sessão
    const base = baseDomain(host);
    if (SESSION_REPLAY.has(base)) pushOnce(h.sessionReplay, { domain: base }, base);

    // WebSocket
    if (d.type === "websocket") {
      pushOnce(h.channels, { kind: "WebSocket", host, thirdParty: third, url: d.url.slice(0, 150) }, "ws" + host);
      return;
    }

    // Polling: mesma URL (host + caminho) em intervalos regulares
    if (!third || !["xmlhttprequest", "image", "script", "beacon", "ping", "other"].includes(d.type)) return;
    const key = host + path;
    const perTab = polls.get(d.tabId) || new Map();
    polls.set(d.tabId, perTab);
    const ts = perTab.get(key) || [];
    ts.push(Date.now());
    if (ts.length > 20) ts.shift();
    perTab.set(key, ts);

    if (ts.length >= POLL_MIN) {
      const recent = ts.slice(-POLL_MIN);
      const gaps = recent.slice(1).map((t, i) => t - recent[i]);
      const mean = gaps.reduce((a, b) => a + b, 0) / gaps.length;
      const sd = Math.sqrt(gaps.reduce((a, g) => a + (g - mean) ** 2, 0) / gaps.length);
      if (mean >= 500 && mean <= 60000 && sd / mean <= POLL_MAX_CV) {
        pushOnce(h.channels, {
          kind: "Polling", host, thirdParty: true, url: (host + path).slice(0, 150),
          intervalSec: +(mean / 1000).toFixed(1), requests: ts.length
        }, "poll" + key);
      }
    }
  },
  { urls: ["<all_urls>"] }
);

// EventSource (Server-Sent Events): identificado pelo cabeçalho Accept
browser.webRequest.onBeforeSendHeaders.addListener(
  (d) => {
    if (d.tabId < 0) return;
    const accept = (d.requestHeaders || []).find((h) => h.name.toLowerCase() === "accept");
    if (!accept || !/text\/event-stream/i.test(accept.value || "")) return;
    const rep = getReport(d.tabId);
    if (!rep) return;
    const host = hostnameOf(d.url);
    pushOnce(hj(rep).channels, { kind: "EventSource (SSE)", host, thirdParty: isThirdParty(host, rep.host), url: d.url.slice(0, 150) }, "sse" + host);
  },
  { urls: ["<all_urls>"] },
  ["requestHeaders"]
);

// ---------- Mensagens do hijack-page.js ----------

browser.runtime.onMessage.addListener((msg, sender) => {
  if (msg.type !== "hijack") return;
  const rep = sender.tab && getReport(sender.tab.id);
  if (!rep) return;
  const h = hj(rep);

  if (msg.kind === "integrity") h.integrity = msg.data;
  else if (msg.kind === "csp-meta" && (!h.csp || !h.csp.present)) {
    h.csp = { present: true, source: "<meta>", weak: analyzeCsp(msg.data.policy) };
  } else if (msg.kind === "key-listener") {
    const host = hostnameOf(msg.data.script);
    const third = isThirdParty(host, rep.host);
    if (third) pushOnce(h.keyListeners, { ...msg.data, host }, msg.data.script + msg.data.event);
  }
});

browser.tabs.onRemoved.addListener((tabId) => polls.delete(tabId));
browser.webNavigation.onCommitted.addListener((d) => { if (d.frameId === 0) polls.delete(d.tabId); });
