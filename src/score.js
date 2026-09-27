// Pontuação de risco à privacidade (0 a 10), inspirada no CVSS (Aula 5):
// "o score não é arbitrário: sai de um vetor de métricas".
//
// Cada critério recebe uma nota de 0 a 10; a nota final é a média ponderada.
// Quanto MAIOR, PIOR para a privacidade. Faixas iguais às do CVSS:
//   0 Nenhum · 0.1–3.9 Baixo · 4.0–6.9 Médio · 7.0–8.9 Alto · 9.0–10 Crítico
//
// Critério (sigla)                          Peso  Justificativa
// TP  Domínios de terceira parte             25%  Cada terceiro recebe IP, User-Agent e a URL visitada (Referer):
//                                                 é a base de todo o rastreamento. Escala log (satura em 50).
// CK  Cookies persistentes de 3ª parte        20%  Identificam o usuário entre visitas e entre sites. Inclui cookies
//     + cookies de 1ª criados por script de 3ª    de 1ª parte gravados por scripts de terceiros (ex.: _ga).
// FP  Fingerprinting (canvas/WebGL)           20%  Identifica o dispositivo SEM cookie: o usuário não consegue apagar
//                                                 nem bloquear pelas configurações normais. Pesa tanto quanto cookies
//                                                 apesar de ser menos frequente, porque é mais difícil de evitar.
// XS  Rastreamento entre sites               15%  Bounce tracking e cookie sync existem para contornar bloqueios de
//                                                 cookies de 3ª parte e unir perfis de empresas diferentes.
// HJ  Indicadores de hijacking / hook         15%  Scripts que interceptam funções, teclado ou mantêm canal aberto com
//                                                 terceiros têm acesso ao que o usuário digita/faz. Assinatura BeEF = 10.
// ST  Armazenamento HTML5                     5%  Pode guardar IDs como um cookie, mas também é muito usado para
//                                                 funcionalidade legítima (preferências, cache). Peso baixo.

const SCORE_WEIGHTS = { TP: 0.25, CK: 0.20, FP: 0.20, XS: 0.15, HJ: 0.15, ST: 0.05 };

// Escala logarítmica: 0 -> 0, "sat" -> 10. Poucos itens já pesam; muitos itens saturam.
function logScale(n, sat) {
  if (!n || n <= 0) return 0;
  return Math.min(10, (10 * Math.log(1 + n)) / Math.log(1 + sat));
}

function band(score) {
  if (score === 0) return "Nenhum";
  if (score < 4) return "Baixo";
  if (score < 7) return "Médio";
  if (score < 9) return "Alto";
  return "Crítico";
}

// Recebe o relatório já serializado (o mesmo que o popup recebe)
function computeScore(r) {
  const parts = {};
  const why = {};

  // TP
  const nTp = r.thirdParty.length;
  parts.TP = logScale(nTp, 50);
  why.TP = `${nTp} domínio(s) de 3ª parte`;

  // CK
  const cs = r.cookieSummary || {};
  const third3p = (r.cookies || []).filter((c) => c.party === "third" && c.kind === "persistent").length;
  const fpBy3p = cs.firstPartyByThirdPartyScript || 0;
  parts.CK = logScale(third3p + fpBy3p, 40);
  why.CK = `${third3p} persistente(s) de 3ª parte + ${fpBy3p} de 1ª parte criados por script de 3ª`;

  // FP
  const fp = r.fingerprint || [];
  const strong = fp.filter((f) => f.verdict === "fingerprint");
  if (strong.some((f) => f.thirdParty)) parts.FP = 10;
  else if (strong.length) parts.FP = 8;
  else if (fp.length) parts.FP = 4;
  else parts.FP = 0;
  why.FP = strong.length ? `${strong.length} técnica(s) de fingerprint` : fp.length ? `${fp.length} leitura(s) suspeita(s)` : "nenhum";

  // XS
  const bounces = (r.bounces || []).length;
  const pairs = new Set((r.cookieSync || []).map((e) => e.from + ">" + e.to)).size;
  const params = (r.decoratedParams || []).length;
  parts.XS = Math.min(10, Math.max(bounces ? 10 : 0, pairs * 2.5, params ? 3 : 0));
  why.XS = `${bounces} bounce(s), ${pairs} par(es) de sync, ${params} URL(s) com parâmetro de rastreamento`;

  // HJ
  const h = r.hijack || {};
  let hj = 0;
  const hjWhy = [];
  if ((h.beef || []).length) { hj = 10; hjWhy.push("assinatura BeEF"); }
  const ch3 = (h.channels || []).filter((c) => c.thirdParty).length;
  if (ch3) { hj += 4; hjWhy.push(`${ch3} canal(is) persistente(s) com 3ª parte`); }
  const keys = (h.keyListeners || []).length, replay = (h.sessionReplay || []).length;
  if (keys || replay) { hj += 4; hjWhy.push("captura de teclado/gravação de sessão"); }
  const changed = h.integrity ? h.integrity.changed.length : 0;
  if (changed) { hj += Math.min(3, changed); hjWhy.push(`${changed} objeto(s) global(is) alterado(s)`); }
  if (h.integrity && h.integrity.suspicious.length) { hj += 1; hjWhy.push("globais com nome suspeito"); }
  if (h.csp && !h.csp.present) { hj += 2; hjWhy.push("sem CSP"); }
  else if (h.csp && h.csp.weak.length) { hj += 1; hjWhy.push("CSP fraca"); }
  parts.HJ = Math.min(10, hj);
  why.HJ = hjWhy.join(", ") || "nenhum indicador";

  // ST
  const s = r.storage || {};
  const nKeys = ((s.localStorage && s.localStorage.count) || 0) + ((s.sessionStorage && s.sessionStorage.count) || 0);
  const nIdb = (s.indexedDB && s.indexedDB.count) || 0;
  parts.ST = Math.min(10, logScale(nKeys, 50) + nIdb);
  why.ST = `${nKeys} chave(s) em Web Storage, ${nIdb} banco(s) IndexedDB`;

  let total = 0;
  for (const k of Object.keys(SCORE_WEIGHTS)) total += SCORE_WEIGHTS[k] * parts[k];
  total = Math.round(total * 10) / 10;

  // Vetor no estilo CVSS: PG:1.0/TP:7.8/CK:6.2/...
  const vector = "PG:1.0/" + Object.keys(SCORE_WEIGHTS).map((k) => `${k}:${parts[k].toFixed(1)}`).join("/");

  return {
    score: total,
    band: band(total),
    vector,
    parts: Object.keys(SCORE_WEIGHTS).map((k) => ({
      key: k, weight: SCORE_WEIGHTS[k], value: Math.round(parts[k] * 10) / 10, why: why[k]
    }))
  };
}
