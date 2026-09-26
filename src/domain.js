// Utilitários de domínio.
// "Primeira parte" = mesmo domínio registrável (eTLD+1) da aba.
// Ex.: www.g1.globo.com e s.glbimg.com -> globo.com vs glbimg.com (terceira parte).
// Usamos uma lista reduzida de sufixos públicos de 2 níveis (versão "lite" da Public Suffix List).

const MULTI_LEVEL_SUFFIXES = new Set([
  "com.br", "net.br", "org.br", "gov.br", "edu.br", "art.br", "blog.br",
  "co.uk", "org.uk", "ac.uk", "gov.uk",
  "com.au", "net.au", "co.jp", "co.nz", "co.in", "com.ar", "com.mx", "com.pt",
  "github.io", "gitlab.io", "blogspot.com", "herokuapp.com", "netlify.app",
  "vercel.app", "pages.dev", "web.app", "firebaseapp.com", "azurewebsites.net"
]);

function hostnameOf(url) {
  try { return new URL(url).hostname.toLowerCase(); } catch (e) { return ""; }
}

function isIp(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":");
}

// Domínio registrável (eTLD+1) aproximado.
function baseDomain(host) {
  host = (host || "").replace(/^\.+/, "").toLowerCase();
  if (!host || isIp(host)) return host;
  const parts = host.split(".");
  if (parts.length <= 2) return host;
  const last2 = parts.slice(-2).join(".");
  if (MULTI_LEVEL_SUFFIXES.has(last2)) return parts.slice(-3).join(".");
  return last2;
}

function isThirdParty(requestHost, topHost) {
  if (!requestHost || !topHost) return false;
  return baseDomain(requestHost) !== baseDomain(topHost);
}
