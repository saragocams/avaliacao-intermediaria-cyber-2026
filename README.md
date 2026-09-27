# Privacy Guard — extensão Firefox

Extensão para detectar rastreadores e violações de privacidade no cliente web
(Avaliação Intermediária de Cibersegurança — Insper).

## Como instalar (modo temporário)

1. Abra o Firefox e acesse `about:debugging#/runtime/this-firefox`
2. Clique em **Carregar extensão temporária…**
3. Selecione o arquivo `manifest.json` desta pasta
4. Abra (ou recarregue) um site e clique no ícone do Privacy Guard na barra

> A extensão temporária some ao fechar o Firefox; é só carregar de novo.
> Para ver logs/erros: botão **Inspecionar** na mesma página do about:debugging.

## Estrutura

```
manifest.json        declaração da extensão (Manifest V2, background persistente)
src/domain.js        cálculo de domínio registrável (eTLD+1) e 1ª x 3ª parte
src/background.js    monitora requisições e cabeçalhos Set-Cookie por aba
src/tracking.js      bounce tracking, cookie sync e parâmetros de rastreamento (gclid, fbclid…)
src/hijack.js        indicadores de hijacking no tráfego (WebSocket, polling, CSP, BeEF)
src/hijack-page.js   integridade de objetos globais e captura de teclado dentro da página
src/score.js         pontuação de risco (critérios, pesos e justificativa no próprio arquivo)
src/blocklist.js     lista de bloqueio personalizada (cancela requisições via webRequestBlocking)
src/fingerprint.js   ganchos em Canvas/WebGL para detectar fingerprinting
src/content.js       roda na página: lê localStorage, sessionStorage, IndexedDB
popup/               interface com o relatório da aba atual
evidencias/          HARs e prints usados no relatório
```

## Funcionalidades

- [x] Conexões a domínios de terceira parte
- [x] Cookies injetados via HTTP (1ª/3ª parte, sessão/persistente)
- [x] Armazenamento HTML5 (localStorage, sessionStorage, IndexedDB)
- [x] Cookies via `document.cookie` (e remoção de duplicados)
- [x] Canvas fingerprint (e leitura de GPU via WebGL)
- [x] Cookie sync / bounce tracking / parâmetros de rastreamento na URL
- [x] Hijacking / hook (objetos globais alterados, WebSocket/SSE/polling de 3ª parte, captura de teclado, gravação de sessão, BeEF, CSP)
- [x] Pontuação de risco à privacidade (0–10, vetor de métricas no estilo CVSS)
- [x] Lista de bloqueio personalizada (popup, salva em storage.local)
- [x] Exportação do relatório da página em JSON
