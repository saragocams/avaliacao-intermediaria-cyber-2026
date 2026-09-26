// Content script: roda dentro da página (contexto isolado do Firefox, com "Xray vision").
// Parte 1: fotografa o armazenamento HTML5 da origem da página.

(function () {
  const page = window.wrappedJSObject || window; // objetos "reais" da página

  function readWebStorage(store) {
    try {
      const keys = [];
      let bytes = 0;
      for (let i = 0; i < store.length; i++) {
        const k = store.key(i);
        const v = store.getItem(k) || "";
        keys.push(k);
        bytes += (k.length + v.length) * 2; // UTF-16
      }
      return { count: keys.length, bytes, keys: keys.slice(0, 50) };
    } catch (e) {
      return { count: 0, bytes: 0, keys: [], error: String(e) }; // ex.: storage bloqueado
    }
  }

  async function readIndexedDB() {
    try {
      const idb = page.indexedDB;
      if (!idb || typeof idb.databases !== "function") return { count: 0, names: [] };
      const dbs = await idb.databases();
      const names = Array.from(dbs).map((d) => d.name);
      return { count: names.length, names };
    } catch (e) {
      return { count: 0, names: [], error: String(e) };
    }
  }

  async function snapshot() {
    const data = {
      origin: location.origin,
      localStorage: readWebStorage(window.localStorage),
      sessionStorage: readWebStorage(window.sessionStorage),
      indexedDB: await readIndexedDB(),
      takenAt: Date.now()
    };
    browser.runtime.sendMessage({ type: "storage-snapshot", data });
  }

  // Scripts de rastreamento costumam gravar depois do load, então tiramos várias fotos.
  window.addEventListener("load", () => {
    snapshot();
    setTimeout(snapshot, 3000);
    setTimeout(snapshot, 8000);
  });
})();
