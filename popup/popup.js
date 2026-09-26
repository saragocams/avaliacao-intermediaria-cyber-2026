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
}

render();
