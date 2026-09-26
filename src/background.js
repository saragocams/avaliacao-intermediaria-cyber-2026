// Background (persistente): observa o tráfego de rede de cada aba e mantém um relatório por aba.
// Fontes de dados:
//   - webRequest.onBeforeRequest   -> conexões (1ª x 3ª parte)
//   - webRequest.onHeadersReceived -> cabeçalhos Set-Cookie (cookies injetados via HTTP)
//   - runtime.onMessage            -> dados vindos do content script (storage HTML5, etc.)

const reports = new Map(); // tabId -> relatório

function newReport(tabId, url) {
  const host = hostnameOf(url);
  return {
    tabId,
    url,
    host,
    base: baseDomain(host),
    startedAt: Date.now(),
    totalRequests: 0,
    firstPartyRequests: 0,
    thirdParty: {},      // dominioBase -> { hosts:Set, count, types:{}, blocked }
    cookies: [],         // { name, domain, party, kind, source, fromHost }
    storage: { localStorage: null, sessionStorage: null, indexedDB: null }
  };
}

function getReport(tabId) {
  return reports.get(tabId);
}

// ---------- Conexões ----------

browser.webRequest.onBeforeRequest.addListener(
  (details) => {
    const { tabId, type, url } = details;
    if (tabId < 0) return; // requisições que não pertencem a uma aba

    // Navegação principal = página nova -> zera o relatório
    if (type === "main_frame") {
      reports.set(tabId, newReport(tabId, url));
      updateBadge(tabId);
      return;
    }

    const rep = getReport(tabId);
    if (!rep) return;

    const reqHost = hostnameOf(url);
    rep.totalRequests++;

    if (!isThirdParty(reqHost, rep.host)) {
      rep.firstPartyRequests++;
      return;
    }

    const base = baseDomain(reqHost);
    const entry = rep.thirdParty[base] ||
      (rep.thirdParty[base] = { hosts: new Set(), count: 0, types: {}, blocked: 0 });
    entry.hosts.add(reqHost);
    entry.count++;
    entry.types[type] = (entry.types[type] || 0) + 1;

    updateBadge(tabId);
  },
  { urls: ["<all_urls>"] }
);

// ---------- Cookies via HTTP (Set-Cookie) ----------

// Faz o parse de um cabeçalho Set-Cookie.
// Sessão x persistente: persistente se tiver Expires ou Max-Age (> 0).
function parseSetCookie(raw, requestHost) {
  const parts = raw.split(";").map((p) => p.trim());
  const [nameValue, ...attrs] = parts;
  const eq = nameValue.indexOf("=");
  const name = eq >= 0 ? nameValue.slice(0, eq) : nameValue;

  const cookie = { name, domain: requestHost, persistent: false, expires: null,
                   secure: false, httpOnly: false, sameSite: null };

  for (const a of attrs) {
    const [k, ...rest] = a.split("=");
    const key = k.toLowerCase();
    const val = rest.join("=");
    if (key === "domain" && val) cookie.domain = val.replace(/^\./, "").toLowerCase();
    else if (key === "expires") {
      const t = Date.parse(val);
      if (!isNaN(t)) { cookie.persistent = t > Date.now(); cookie.expires = t; }
    } else if (key === "max-age") {
      const s = parseInt(val, 10);
      if (!isNaN(s)) { cookie.persistent = s > 0; cookie.expires = Date.now() + s * 1000; }
    } else if (key === "secure") cookie.secure = true;
    else if (key === "httponly") cookie.httpOnly = true;
    else if (key === "samesite") cookie.sameSite = val;
  }
  return cookie;
}

browser.webRequest.onHeadersReceived.addListener(
  (details) => {
    const { tabId, url, type, responseHeaders } = details;
    if (tabId < 0 || !responseHeaders) return;

    const rep = getReport(tabId);
    if (!rep) return;

    const reqHost = hostnameOf(url);
    for (const h of responseHeaders) {
      if (h.name.toLowerCase() !== "set-cookie" || !h.value) continue;
      // O Firefox pode juntar vários Set-Cookie num único valor separado por \n
      for (const line of h.value.split("\n")) {
        if (!line.trim()) continue;
        const c = parseSetCookie(line, reqHost);
        rep.cookies.push({
          name: c.name,
          domain: c.domain,
          party: isThirdParty(c.domain, rep.host) ? "third" : "first",
          kind: c.persistent ? "persistent" : "session",
          expires: c.expires,
          httpOnly: c.httpOnly,
          secure: c.secure,
          sameSite: c.sameSite,
          source: "http",
          fromHost: reqHost,
          requestType: type
        });
      }
    }
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

// ---------- Mensagens (content script e popup) ----------

browser.runtime.onMessage.addListener((msg, sender) => {
  const tabId = msg.tabId ?? sender.tab?.id;

  if (msg.type === "storage-snapshot") {
    const rep = getReport(tabId);
    if (rep) rep.storage = msg.data;
    return;
  }

  if (msg.type === "get-report") {
    return Promise.resolve(serializeReport(getReport(tabId)));
  }
});

// Converte Sets em arrays para enviar ao popup
function serializeReport(rep) {
  if (!rep) return null;
  const thirdParty = Object.entries(rep.thirdParty)
    .map(([domain, e]) => ({ domain, hosts: [...e.hosts], count: e.count, types: e.types, blocked: e.blocked }))
    .sort((a, b) => b.count - a.count);

  const c = rep.cookies;
  const cookieSummary = {
    total: c.length,
    firstParty: c.filter((x) => x.party === "first").length,
    thirdParty: c.filter((x) => x.party === "third").length,
    session: c.filter((x) => x.kind === "session").length,
    persistent: c.filter((x) => x.kind === "persistent").length
  };

  return { ...rep, thirdParty, cookieSummary };
}

// ---------- Badge ----------

function updateBadge(tabId) {
  const rep = getReport(tabId);
  const n = rep ? Object.keys(rep.thirdParty).length : 0;
  browser.browserAction.setBadgeText({ tabId, text: n ? String(n) : "" });
  browser.browserAction.setBadgeBackgroundColor({ tabId, color: n > 10 ? "#d33" : "#e8a200" });
}

browser.tabs.onRemoved.addListener((tabId) => reports.delete(tabId));
