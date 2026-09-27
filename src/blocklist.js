// Lista de bloqueio personalizada.
// O usuário adiciona domínios pelo popup; ficam salvos em browser.storage.local ("blocklist").
// Qualquer sub-recurso (script, imagem, XHR, iframe, WebSocket...) cujo host seja o domínio
// bloqueado ou um subdomínio dele é cancelado ANTES de sair do navegador (webRequestBlocking).
// A navegação principal (digitar o endereço) não é bloqueada, para não "quebrar" o navegador.

let blocklist = new Set();

function normalizeDomain(d) {
  return String(d || "").trim().toLowerCase()
    .replace(/^[a-z]+:\/\//, "").replace(/\/.*$/, "").replace(/^\*\./, "").replace(/^\.+/, "");
}

function isBlocked(host) {
  if (!host) return null;
  for (const d of blocklist) {
    if (host === d || host.endsWith("." + d)) return d;
  }
  return null;
}

browser.storage.local.get("blocklist").then((r) => {
  blocklist = new Set((r.blocklist || []).map(normalizeDomain).filter(Boolean));
});

browser.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.blocklist) {
    blocklist = new Set((changes.blocklist.newValue || []).map(normalizeDomain).filter(Boolean));
  }
});

browser.webRequest.onBeforeRequest.addListener(
  (d) => {
    if (d.type === "main_frame" || !blocklist.size) return;
    const host = hostnameOf(d.url);
    const rule = isBlocked(host);
    if (!rule) return;

    const rep = d.tabId >= 0 ? getReport(d.tabId) : null;
    if (rep) {
      rep.blocked = rep.blocked || {};
      rep.blocked[rule] = (rep.blocked[rule] || 0) + 1;
      const entry = rep.thirdParty[baseDomain(host)];
      if (entry) entry.blocked++;
    }
    return { cancel: true };
  },
  { urls: ["<all_urls>"] },
  ["blocking"]
);
