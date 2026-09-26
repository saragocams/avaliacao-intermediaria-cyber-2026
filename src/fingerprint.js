// Detecção de fingerprinting via Canvas e WebGL.
//
// Como funciona o canvas fingerprint: o script desenha um texto/forma num <canvas> invisível
// e lê os pixels (toDataURL / getImageData). Como GPU, driver, fontes e antialiasing variam
// entre máquinas, o resultado vira um "hash" quase único do dispositivo, sem precisar de cookie.
//
// Heurística (adaptada de Englehardt & Narayanan, "Online Tracking: A 1-million-site
// Measurement and Analysis", ACM CCS 2016):
//   1. o canvas tem pelo menos 16x16 px;
//   2. foi escrito texto com >= 10 caracteres distintos OU com >= 2 cores;
//   3. a imagem foi extraída (toDataURL, toBlob ou getImageData cobrindo >= 16x16 px).
// Se 1+2+3 -> "fingerprint". Se só houve extração sem texto -> "suspeito".
//
// WebGL: ler UNMASKED_VENDOR/RENDERER_WEBGL revela o modelo exato da GPU -> "fingerprint".

(function () {
  const page = window.wrappedJSObject;
  if (!page) return;

  const canvasInfo = new WeakMap(); // canvas -> { chars:Set, colors:Set }
  const reported = new Set();       // evita mandar o mesmo evento várias vezes

  function callerScript() {
    try {
      const urls = (new Error().stack || "").match(/https?:\/\/[^\s)@]+?(?=:\d+:\d+)/g) || [];
      return urls.find((u) => !u.startsWith("moz-extension:")) || location.href;
    } catch (e) { return location.href; }
  }

  function report(api, verdict, details) {
    const script = callerScript();
    const key = `${api}|${verdict}|${script}`;
    if (reported.has(key)) return;
    reported.add(key);
    browser.runtime.sendMessage({
      type: "fingerprint", api, verdict, script, frame: location.href, details
    });
  }

  function info(canvas) {
    let i = canvasInfo.get(canvas);
    if (!i) canvasInfo.set(canvas, (i = { chars: new Set(), colors: new Set() }));
    return i;
  }

  // Substitui um método do protótipo da página por uma versão nossa que observa a chamada
  // e depois chama a função original.
  function hook(proto, name, before) {
    const original = proto[name];
    if (typeof original !== "function") return;
    proto[name] = exportFunction(function (...args) {
      try { before(this, args); } catch (e) { /* nunca quebrar a página */ }
      return Reflect.apply(original, this, args);
    }, page);
  }

  function analyzeExtraction(canvas, api, w, h) {
    const i = canvasInfo.get(canvas);
    const bigEnough = w >= 16 && h >= 16;
    const hasText = i && (i.chars.size >= 10 || i.colors.size >= 2);
    const details = {
      width: w, height: h,
      distinctChars: i ? i.chars.size : 0,
      colors: i ? i.colors.size : 0
    };
    if (bigEnough && hasText) report(api, "fingerprint", details);
    else if (bigEnough) report(api, "suspeito", details);
  }

  // --- Canvas 2D: registra o que foi desenhado ---
  const ctx2d = page.CanvasRenderingContext2D && page.CanvasRenderingContext2D.prototype;
  if (ctx2d) {
    for (const m of ["fillText", "strokeText"]) {
      hook(ctx2d, m, (ctx, args) => {
        const i = info(ctx.canvas);
        for (const ch of String(args[0])) i.chars.add(ch);
        i.colors.add(String(m === "fillText" ? ctx.fillStyle : ctx.strokeStyle));
      });
    }
    hook(ctx2d, "getImageData", (ctx, args) => {
      analyzeExtraction(ctx.canvas, "getImageData", Number(args[2]) || 0, Number(args[3]) || 0);
    });
  }

  // --- Canvas: extração da imagem ---
  const canvasProto = page.HTMLCanvasElement && page.HTMLCanvasElement.prototype;
  if (canvasProto) {
    for (const m of ["toDataURL", "toBlob"]) {
      hook(canvasProto, m, (canvas) => analyzeExtraction(canvas, m, canvas.width, canvas.height));
    }
  }

  // --- WebGL: leitura do modelo da GPU ---
  const UNMASKED_VENDOR = 0x9245, UNMASKED_RENDERER = 0x9246;
  for (const cls of ["WebGLRenderingContext", "WebGL2RenderingContext"]) {
    const proto = page[cls] && page[cls].prototype;
    if (!proto) continue;
    hook(proto, "getParameter", (gl, args) => {
      const p = Number(args[0]);
      if (p === UNMASKED_VENDOR || p === UNMASKED_RENDERER) {
        report("webgl.getParameter", "fingerprint", { parameter: p === UNMASKED_VENDOR ? "UNMASKED_VENDOR" : "UNMASKED_RENDERER" });
      }
    });
    hook(proto, "readPixels", (gl) => {
      report("webgl.readPixels", "suspeito", { width: gl.drawingBufferWidth, height: gl.drawingBufferHeight });
    });
  }
})();
