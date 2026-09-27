const $ = (id) => document.getElementById(id);

// Monta elementos sem innerHTML: nomes de domínio/cookie vêm de sites não confiáveis,
// então tudo entra como texto (evita XSS dentro do próprio popup).
function h(tag, className, ...children) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  for (const c of children) el.append(c instanceof Node ? c : String(c));
  return el;
}

async function render() {
  const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  const rep = await browser.runtime.sendMessage({ type: "get-report", tabId: tab.id });

  if (!rep) {
    $("site").textContent = "Recarregue a página para iniciar a análise.";
    return;
  }

  $("site").textContent = rep.host;

  // Terceira parte
  $("tp-count").textContent = rep.thirdParty.length;
  $("req-summary").textContent =
    `${rep.totalRequests} requisições · ${rep.firstPartyRequests} de 1ª parte · ` +
    `${rep.totalRequests - rep.firstPartyRequests} de 3ª parte`;
  $("tp-list").replaceChildren(...rep.thirdParty.map((t) =>
    h("li", "", h("b", "", t.domain), h("span", "tag", `${t.count} req`),
      h("div", "muted", t.hosts.join(", ")))));

  // Cookies
  const c = rep.cookies;
  const count = (party, kind) => c.filter((x) => x.party === party && x.kind === kind).length;
  const cs = rep.cookieSummary;
  $("ck-count").textContent = cs.total;
  $("ck-summary").textContent =
    `${cs.total} únicos · ${cs.writes} gravações · ${cs.viaJs} via JavaScript` +
    (cs.firstPartyByThirdPartyScript ? ` · ${cs.firstPartyByThirdPartyScript} de 1ª parte criados por script de 3ª` : "");
  $("ck-1s").textContent = count("first", "session");
  $("ck-3s").textContent = count("third", "session");
  $("ck-1p").textContent = count("first", "persistent");
  $("ck-3p").textContent = count("third", "persistent");
  $("ck-list").replaceChildren(...c.map((x) =>
    h("li", "", x.name,
      h("span", "tag", x.party === "third" ? "3ª" : "1ª"),
      h("span", "tag", x.kind === "session" ? "sessão" : "persistente"),
      h("span", "tag", x.sources.join("+")),
      x.timesSet > 1 ? h("span", "tag", `${x.timesSet}×`) : "",
      h("span", "muted", " " + x.domain),
      x.script ? h("div", "muted", "script: " + x.script) : "")));

  // Storage
  const s = rep.storage || {};
  const fmt = (o) => o ? `${o.count} chaves · ${(o.bytes / 1024).toFixed(1)} KB` : "–";
  $("st-ls").textContent = fmt(s.localStorage);
  $("st-ss").textContent = fmt(s.sessionStorage);
  $("st-idb").textContent = s.indexedDB ? `${s.indexedDB.count} bancos` : "–";

  // Fingerprinting
  const fp = rep.fingerprint || [];
  const strong = fp.filter((f) => f.verdict === "fingerprint");
  $("fp-count").textContent = fp.length;
  $("fp-count").style.background = strong.length ? "#d33" : "";
  if (fp.length) {
    $("fp-summary").textContent =
      `${strong.length} fingerprint · ${fp.length - strong.length} suspeito(s)`;
  }
  $("fp-list").replaceChildren(...fp.map((f) =>
    h("li", "", h("b", "", f.api),
      h("span", "tag", f.verdict),
      f.thirdParty ? h("span", "tag", "3ª parte") : "",
      f.details && f.details.width ? h("span", "muted", ` ${f.details.width}×${f.details.height}px`) : "",
      f.details && f.details.distinctChars ? h("span", "muted", ` · ${f.details.distinctChars} caracteres`) : "",
      f.details && f.details.parameter ? h("span", "muted", " " + f.details.parameter) : "",
      h("div", "muted", "script: " + f.script))));

  // Rastreamento entre sites: bounce tracking, cookie sync, parâmetros de rastreamento
  const bounces = rep.bounces || [], sync = rep.cookieSync || [], params = rep.decoratedParams || [];
  const total = bounces.length + sync.length + params.length;
  $("xs-count").textContent = total;
  $("xs-count").style.background = bounces.length || sync.length ? "#d33" : "";
  if (total) {
    $("xs-summary").textContent =
      `${bounces.length} bounce(s) · ${sync.length} ID(s) sincronizado(s) entre ${new Set(sync.map((e) => e.from + e.to)).size} par(es) de domínios · ${params.length} URL(s) com parâmetro de rastreamento`;
  }
  $("xs-bounce").replaceChildren(...bounces.map((b) =>
    h("div", "small", h("b", "", "Bounce: "), b.chain.join(" → "),
      h("div", "muted", "intermediário(s): " + b.bouncers.map((x) =>
        `${x.domain} (${x.how}${x.setCookies ? `, ${x.setCookies} cookie(s)` : ""})`).join(", ")))));
  // Agrupa as sincronizações por par origem → destino (evita dezenas de linhas repetidas)
  const pairs = {};
  for (const e of sync) (pairs[`${e.from} → ${e.to}`] ||= []).push(e);
  $("xs-sync").replaceChildren(...Object.entries(pairs)
    .sort((a, b) => b[1].length - a[1].length)
    .map(([pair, evs]) => h("li", "", h("b", "", pair),
      h("span", "tag", `${evs.length} ID(s)`),
      h("div", "muted", evs.slice(0, 3).map((e) => `${e.cookie} → "${e.param}" (${e.id})`).join(" · ") +
        (evs.length > 3 ? ` · +${evs.length - 3}` : "")))));
  $("xs-params").replaceChildren(...params.slice(0, 10).map((p) =>
    h("li", "", h("b", "", p.params.join(", ")),
      p.thirdParty ? h("span", "tag", "3ª parte") : h("span", "tag", "navegação"),
      h("div", "muted", p.url))));
}

render();
