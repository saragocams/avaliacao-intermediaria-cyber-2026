// Rastreamento entre sites: bounce tracking, cookie sync e decoração de links.
// Carregado DEPOIS do background.js (usa getReport, hostnameOf, baseDomain, isThirdParty).
//
// 1) BOUNCE TRACKING
//    Navegação que passa por um domínio intermediário antes do destino:
//       origem -> bouncer.com (302 ou JS/meta refresh) -> destino
//    O "bouncer" vira 1ª parte por um instante e consegue gravar/ler o próprio cookie.
//    Detectamos redirecionamentos de servidor (webRequest.onBeforeRedirect) e de cliente
//    (webNavigation com transitionQualifier "client_redirect").
//
// 2) COOKIE SYNC (sincronização de identificadores)
//    Um valor de cookie do domínio A (ex.: uid=8f3a...) aparece na URL de uma requisição
//    para o domínio B. Assim A e B associam os seus IDs do mesmo usuário.
//    Coletamos valores com cara de ID dos cabeçalhos Cookie/Set-Cookie e de document.cookie,
//    e procuramos esses valores nos parâmetros das URLs enviadas a OUTROS domínios.
//    Referência: Acar et al., "The Web Never Forgets", ACM CCS 2014.
//
// 3) DECORAÇÃO DE LINKS (query parameters)
//    Parâmetros de rastreamento conhecidos na URL (gclid, fbclid, ...) carregam um ID de clique
//    de um site para outro, contornando o bloqueio de cookies de terceira parte.

const TRACKING_PARAMS = new Set([
  "gclid", "gbraid", "wbraid", "dclid", "gclsrc", "_gl", "fbclid", "msclkid", "yclid",
  "twclid", "ttclid", "igshid", "li_fat_id", "mc_eid", "mkt_tok", "_hsenc", "_hsmi",
  "oly_enc_id", "oly_anon_id", "vero_id", "rb_clickid", "s_cid", "epik", "irclickid",
  "scclid", "srsltid", "_openstat", "ga_source", "__s", "wickedid", "ef_id", "zanpid"
]);

const BOUNCE_MAX_MS = 10000; // página que "vive" menos que isso e redireciona = bounce

// ---------- Estado ----------

const redirectsInFlight = new Map(); // tabId -> [{ url, host, status, setCookies }]
const lastPage = new Map();          // tabId -> { url, host, committedAt, chain }
const idOwners = new Map();          // valor do ID -> { owner, cookie }
const MAX_IDS = 5000;

function ensureTrackingFields(rep) {
  if (!rep.bounces) rep.bounces = [];
  if (!rep.cookieSync) rep.cookieSync = [];
  if (!rep.decoratedParams) rep.decoratedParams = [];
  return rep;
}

// ---------- Identificadores ----------

// Um valor "parece um ID" se for longo, com pelo menos um dígito e alguma variedade.
function looksLikeId(v) {
  if (!v || v.length < 8 || v.length > 200) return false;
  if (!/\d/.test(v) || !/^[A-Za-z0-9._\-~%+=:|]+$/.test(v)) return false;
  if (/^\d{10,13}$/.test(v)) return false;                 // timestamp
  if (/^(true|false|null|undefined)$/i.test(v)) return false;
  return new Set(v).size >= 5;
}

// Um cookie pode ter o ID "embutido": _ga = GA1.1.123456789.1690000000 -> 123456789
function idCandidates(value) {
  let v = value;
  try { v = decodeURIComponent(value); } catch (e) { /* mantém */ }
  const out = new Set();
  if (looksLikeId(v)) out.add(v);
  for (const part of v.split(/[.|:&=]/)) if (looksLikeId(part)) out.add(part);
  return [...out];
}

function rememberCookieIds(cookieDomain, name, value) {
  const owner = baseDomain(cookieDomain);
  for (const id of idCandidates(value)) {
    if (idOwners.size >= MAX_IDS) idOwners.delete(idOwners.keys().next().value);
    if (!idOwners.has(id)) idOwners.set(id, { owner, cookie: name });
  }
}

// Procura IDs conhecidos de OUTRO domínio nos parâmetros/caminho da URL.
function findSyncedIds(url) {
  let u;
  try { u = new URL(url); } catch (e) { return []; }
  const dest = baseDomain(u.hostname);
  const values = [];
  for (const [k, v] of u.searchParams) values.push([k, v]);
  for (const seg of u.pathname.split("/")) if (seg) values.push(["(caminho)", seg]);

  const found = [];
  for (const [param, raw] of values) {
    for (const cand of idCandidates(raw)) {
      const info = idOwners.get(cand);
      if (info && info.owner !== dest) {
        found.push({ from: info.owner, cookie: info.cookie, to: dest, param,
                     id: cand.length > 12 ? cand.slice(0, 6) + "…" + cand.slice(-4) : cand });
      }
    }
  }
  return found;
}

function recordSync(rep, events, via) {
  ensureTrackingFields(rep);
  for (const e of events) {
    const key = `${e.from}>${e.to}>${e.param}`;
    if (rep.cookieSync.some((x) => x.key === key)) continue;
    rep.cookieSync.push({ ...e, via, key });
  }
}

function decoratedParamsOf(url) {
  try {
    return [...new URL(url).searchParams.keys()].filter((k) => TRACKING_PARAMS.has(k.toLowerCase()));
  } catch (e) { return []; }
}

// ---------- Cabeçalhos: coleta de IDs e detecção de sync ----------

browser.webRequest.onBeforeSendHeaders.addListener(
  (d) => {
    // 1º procura IDs de outros domínios nesta URL...
    if (d.tabId >= 0) {
      const rep = getReport(d.tabId);
      const events = findSyncedIds(d.url);
      if (rep && events.length) recordSync(rep, events, d.type === "main_frame" ? "navegação" : "requisição");
    }
    // ...depois guarda os cookies que o navegador está enviando a este domínio.
    const host = hostnameOf(d.url);
    for (const h of d.requestHeaders || []) {
      if (h.name.toLowerCase() !== "cookie" || !h.value) continue;
      for (const pair of h.value.split(";")) {
        const i = pair.indexOf("=");
        if (i > 0) rememberCookieIds(host, pair.slice(0, i).trim(), pair.slice(i + 1).trim());
      }
    }
  },
  { urls: ["<all_urls>"] },
  ["requestHeaders"]
);

browser.webRequest.onHeadersReceived.addListener(
  (d) => {
    const host = hostnameOf(d.url);
    for (const h of d.responseHeaders || []) {
      if (h.name.toLowerCase() !== "set-cookie" || !h.value) continue;
      for (const line of h.value.split("\n")) {
        const first = line.split(";")[0];
        const i = first.indexOf("=");
        if (i <= 0) continue;
        const dm = /;\s*domain=([^;]+)/i.exec(line);
        rememberCookieIds(dm ? dm[1].replace(/^\./, "") : host, first.slice(0, i).trim(), first.slice(i + 1).trim());
      }
    }
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

// Cookies criados via JS também alimentam a base de IDs
browser.runtime.onMessage.addListener((msg) => {
  if (msg.type !== "js-cookie") return;
  const first = String(msg.raw).split(";")[0];
  const i = first.indexOf("=");
  const dm = /;\s*domain=([^;]+)/i.exec(msg.raw);
  if (i > 0) rememberCookieIds(dm ? dm[1].replace(/^\./, "") : hostnameOf(msg.pageUrl),
                               first.slice(0, i).trim(), first.slice(i + 1).trim());
});

// ---------- Redirecionamentos ----------

browser.webRequest.onBeforeRedirect.addListener(
  (d) => {
    if (d.tabId < 0) return;
    const setCookies = (d.responseHeaders || [])
      .filter((h) => h.name.toLowerCase() === "set-cookie" && h.value)
      .reduce((n, h) => n + h.value.split("\n").filter(Boolean).length, 0);

    if (d.type === "main_frame") {
      const list = redirectsInFlight.get(d.tabId) || [];
      list.push({ url: d.url, host: hostnameOf(d.url), status: d.statusCode, setCookies });
      redirectsInFlight.set(d.tabId, list);
      return;
    }

    // Redirecionamento de sub-recurso entre domínios diferentes carregando um ID:
    // padrão clássico de cookie sync por "pixel" (ad1.com/px -> 302 -> ad2.com/sync?uid=...)
    const from = baseDomain(hostnameOf(d.url)), to = baseDomain(hostnameOf(d.redirectUrl));
    if (from !== to) {
      const rep = getReport(d.tabId);
      const events = findSyncedIds(d.redirectUrl);
      if (rep && events.length) recordSync(rep, events, `redirect ${from} → ${to}`);
    }
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

browser.webNavigation.onCommitted.addListener((d) => {
  if (d.frameId !== 0) return;
  const tabId = d.tabId;
  const now = Date.now();
  const serverHops = (redirectsInFlight.get(tabId) || [])
    .map((h) => ({ host: h.host, how: `HTTP ${h.status}`, setCookies: h.setCookies }));
  redirectsInFlight.delete(tabId);

  // A página anterior foi só uma "ponte" se ela mesma redirecionou via JS/meta refresh
  // poucos segundos depois de carregar.
  const prev = lastPage.get(tabId);
  const q = d.transitionQualifiers || [];
  const clientBounce = prev && q.includes("client_redirect") && (now - prev.committedAt) < BOUNCE_MAX_MS;

  let origin, intermediates;
  if (clientBounce) {
    origin = prev.origin;
    const prevCookies = prev.rep ? Object.keys(prev.rep.cookies).length : 0;
    intermediates = [...prev.intermediates, { host: prev.host, how: "JS/meta refresh", setCookies: prevCookies }, ...serverHops];
  } else {
    origin = { host: prev ? prev.host : "(início)" };
    intermediates = serverHops;
  }
  const destHost = hostnameOf(d.url);

  // "Bouncer" = intermediário que não é nem da origem nem do destino
  const bouncers = intermediates.filter((h) =>
    baseDomain(h.host) !== baseDomain(origin.host) && baseDomain(h.host) !== baseDomain(destHost));

  const rep = getReport(tabId);
  if (rep) {
    ensureTrackingFields(rep);
    if (bouncers.length) {
      rep.bounces.push({
        chain: [origin.host, ...intermediates.map((h) => h.host), destHost],
        bouncers: bouncers.map((b) => ({ domain: baseDomain(b.host), how: b.how, setCookies: b.setCookies }))
      });
    }
    const params = decoratedParamsOf(d.url);
    if (params.length) rep.decoratedParams.push({ url: d.url.slice(0, 200), params });
  }

  lastPage.set(tabId, { host: destHost, committedAt: now, origin, intermediates, rep });
});

// Também checa decoração de links em requisições a terceiros (ex.: pixel com gclid)
browser.webRequest.onBeforeRequest.addListener(
  (d) => {
    if (d.tabId < 0 || d.type === "main_frame") return;
    const rep = getReport(d.tabId);
    if (!rep || !isThirdParty(hostnameOf(d.url), rep.host)) return;
    const params = decoratedParamsOf(d.url);
    if (!params.length) return;
    ensureTrackingFields(rep);
    if (rep.decoratedParams.length < 30) rep.decoratedParams.push({ url: d.url.slice(0, 200), params, thirdParty: true });
  },
  { urls: ["<all_urls>"] }
);

browser.tabs.onRemoved.addListener((tabId) => {
  redirectsInFlight.delete(tabId);
  lastPage.delete(tabId);
});
