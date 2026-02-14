(() => {
  const FOOTER_DISCLAIMER_SUBSTRING = "node RPC is never exposed publicly";
  const FOOTER_MIT_SUBSTRING = "MIT-licensed implementation";

  const VORTEX_OLD_TITLE = "Transaction Vortex";
  const VORTEX_PREV_TITLE = "Qrypt Nebula";
  const VORTEX_NEW_TITLE = "Qrypt Flow";
  const VORTEX_BLOCKSTRIP_ID = "qry-vortex-blockstrip";
  const VORTEX_STATUS_PILL_ID = "qry-vortex-status-pill";
  const STYLE_ID = "qry-ui-patch-style";
  const NAVBAR_ID = "qry-branded-nav";
  const FOOTER_ID = "qry-branded-footer";
  const VORTEX_CANVAS_STATUS_LABELS = new Set(["LIVE", "CONNECTING", "OFFLINE"]);

  // Qryptcoin Q logo — 96px PNG from resources/images/Q only.png, white background removed, base64-encoded
  const QRY_LOGO_URI = "data:image/png;base64,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";

  function explorerBaseUrl() {
    const host = window.location.hostname;
    const protocol = window.location.protocol;

    if (host === "localhost" || host === "127.0.0.1") {
      return `${protocol}//${host}:8081`;
    }

    if (host.startsWith("mempool.")) {
      return `${protocol}//explorer.${host.slice("mempool.".length)}`;
    }

    if (host.endsWith(".qryptcoin.org")) {
      return `${protocol}//explorer.qryptcoin.org`;
    }

    return `${protocol}//${host}:8081`;
  }

  function mempoolBaseUrl() {
    const host = window.location.hostname;
    const protocol = window.location.protocol;

    if (host === "localhost" || host === "127.0.0.1") {
      return `${protocol}//${host}:8080`;
    }

    if (host.startsWith("explorer.")) {
      return `${protocol}//mempool.${host.slice("explorer.".length)}`;
    }

    if (host.endsWith(".qryptcoin.org")) {
      return `${protocol}//mempool.qryptcoin.org`;
    }

    return `${protocol}//${host}:8080`;
  }

  function isExplorerSite() {
    return window.location.hostname.startsWith("explorer.");
  }

  function crossSiteUrl() {
    return isExplorerSite() ? mempoolBaseUrl() : explorerBaseUrl();
  }

  function crossSiteLabel() {
    return isExplorerSite() ? "Mempool" : "Explorer";
  }

  const MEMPOOL_TEXT_REPLACEMENTS = [
    ["QryptCoin Explorer", "QryptCoin Mempool"],
    ["Mempool & Blockchain", "Live Mempool"],
    [VORTEX_OLD_TITLE, VORTEX_NEW_TITLE],
    [VORTEX_PREV_TITLE, VORTEX_NEW_TITLE],
    ["Live feed", ""],
  ];

  const SHARED_TEXT_REPLACEMENTS = [
    [
      "Explorer is read-only; node RPC is never exposed publicly.",
      "",
    ],
    ["MIT-licensed implementation.", ""],
    [
      "Enable the explorer indexer for full input/output linking and address attribution.",
      "For full input/output linking and address attribution, open this TX in Explorer.",
    ],
  ];

  function getTextReplacements() {
    return isExplorerSite()
      ? SHARED_TEXT_REPLACEMENTS
      : MEMPOOL_TEXT_REPLACEMENTS.concat(SHARED_TEXT_REPLACEMENTS);
  }

  const SEARCH_PLACEHOLDER = "Search TXID (blocks/addresses open Explorer)";

  function shouldRedirectSearch(value) {
    const v = String(value || "").trim();
    if (!v) return null;

    if (/^[0-9]+$/.test(v)) return { kind: "block", path: `/block/${v}` };
    // TXIDs are also 64-hex, so only treat 64-hex as a *block* hash when it
    // looks like one (QryptCoin PoW blocks commonly start with leading zeros).
    if (/^[0-9a-fA-F]{64}$/.test(v) && /^0{4,}/.test(v)) {
      return { kind: "block", path: `/block/${v.toLowerCase()}` };
    }
    if (/^qry1[0-9a-z]+$/i.test(v)) return { kind: "address", path: `/address/${v}` };

    return null;
  }

  function patchSearchBox() {
    const inputs = Array.from(document.querySelectorAll("input"));
    for (const input of inputs) {
      const placeholder = input.getAttribute("placeholder") || "";
      if (!placeholder.toLowerCase().includes("search")) continue;

      if (input.getAttribute("placeholder") !== SEARCH_PLACEHOLDER) {
        input.setAttribute("placeholder", SEARCH_PLACEHOLDER);
      }

      if (input.dataset.qrySearchPatched === "1") continue;
      input.dataset.qrySearchPatched = "1";

      input.addEventListener(
        "keydown",
        (ev) => {
          if (ev.key !== "Enter") return;

          const redirect = shouldRedirectSearch(input.value);
          if (!redirect) return;

          ev.preventDefault();
          ev.stopPropagation();
          window.location.assign(`${explorerBaseUrl()}${redirect.path}`);
        },
        true,
      );

      const form = input.closest("form");
      if (form && form.dataset.qrySearchPatched !== "1") {
        form.dataset.qrySearchPatched = "1";
        form.addEventListener(
          "submit",
          (ev) => {
            const redirect = shouldRedirectSearch(input.value);
            if (!redirect) return;

            ev.preventDefault();
            ev.stopPropagation();
            window.location.assign(`${explorerBaseUrl()}${redirect.path}`);
          },
          true,
        );
      }
    }
  }

  function lowestCommonAncestor(a, b) {
    const seen = new Set();
    let cur = a;
    while (cur) {
      seen.add(cur);
      cur = cur.parentElement;
    }

    cur = b;
    while (cur) {
      if (seen.has(cur)) return cur;
      cur = cur.parentElement;
    }

    return null;
  }

  function removeFooterNoise(disclaimerEl, mitEl) {
    const anchor = disclaimerEl && mitEl ? lowestCommonAncestor(disclaimerEl, mitEl) : disclaimerEl || mitEl;
    if (!anchor || !anchor.isConnected) return;

    const candidate =
      anchor.closest("footer") ||
      anchor.closest('[role="contentinfo"]') ||
      anchor;

    if (!candidate || !candidate.isConnected) return;
    if (candidate === document.body || candidate === document.documentElement) return;
    if (candidate.id === "root") return;

    const rect = candidate.getBoundingClientRect?.();
    if (rect && rect.height > 240 && candidate.tagName?.toLowerCase() !== "footer") {
      if (disclaimerEl) disclaimerEl.style.display = "none";
      if (mitEl) mitEl.style.display = "none";
      return;
    }

    candidate.remove();
  }

  function ensureStyleTag() {
    if (document.getElementById(STYLE_ID)) return;

    const el = document.createElement("style");
    el.id = STYLE_ID;
    el.textContent = `
      /* ═══ COLOR SYSTEM ═══ */
      :root {
        --qry-primary: #00E5FF;
        --qry-primary-dim: rgba(0, 229, 255, 0.15);
        --qry-primary-glow: rgba(0, 229, 255, 0.35);
        --qry-secondary: #3B6FD4;
        --qry-bg-deep: #0A0F1C;
        --qry-bg-surface: #0F172A;
        --qry-bg-card: rgba(15, 23, 42, 0.75);
        --qry-bg-card-hover: rgba(20, 30, 55, 0.85);
        --qry-border: rgba(0, 229, 255, 0.08);
        --qry-border-hover: rgba(0, 229, 255, 0.25);
        --qry-text-primary: #E2E8F0;
        --qry-text-secondary: #94A3B8;
        --qry-text-muted: #64748B;
        --qry-success: #34D399;
        --qry-warning: #FBBF24;
        --qry-danger: #FB7185;
        --qry-font-sans: ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
        --qry-font-mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
      }

      /* ═══ GLOBAL OVERRIDES ═══ */
      body, app-root, .bg-grid, #root > div {
        background: linear-gradient(180deg, var(--qry-bg-deep) 0%, var(--qry-bg-surface) 100%) !important;
        min-height: 100vh;
      }

      html { scroll-behavior: smooth; }

      ::selection {
        background: rgba(0, 229, 255, 0.25);
        color: #fff;
      }

      *::-webkit-scrollbar { width: 6px; height: 6px; }
      *::-webkit-scrollbar-track { background: transparent; }
      *::-webkit-scrollbar-thumb { background: rgba(0, 229, 255, 0.18); border-radius: 3px; }
      *::-webkit-scrollbar-thumb:hover { background: rgba(0, 229, 255, 0.32); }

      a { transition: color 0.2s ease, opacity 0.2s ease; }

      router-outlet + *, #root > div {
        animation: qryFadeIn 0.3s ease-out;
      }

      @keyframes qryFadeIn {
        from { opacity: 0; transform: translateY(4px); }
        to { opacity: 1; transform: translateY(0); }
      }

      /* ═══ BRANDED NAVBAR ═══ */
      header, .topbar {
        background: rgba(10, 15, 28, 0.92) !important;
        backdrop-filter: blur(20px) !important;
        -webkit-backdrop-filter: blur(20px) !important;
        border-bottom: 1px solid rgba(0, 229, 255, 0.12) !important;
      }

      #${NAVBAR_ID} {
        display: inline-flex;
        align-items: center;
        gap: 10px;
        text-decoration: none !important;
        margin-right: 16px;
        white-space: nowrap;
      }

      .qry-nav-logo {
        display: inline-flex;
        align-items: center;
        flex-shrink: 0;
      }

      .qry-nav-logo img {
        width: 28px;
        height: 28px;
        filter: drop-shadow(0 0 8px rgba(38, 198, 218, 0.3));
        transition: filter 0.2s ease;
      }

      #${NAVBAR_ID}:hover .qry-nav-logo img {
        filter: drop-shadow(0 0 14px rgba(38, 198, 218, 0.5));
      }

      .qry-nav-brand-text {
        font-family: var(--qry-font-sans);
        font-size: 14px;
        font-weight: 800;
        letter-spacing: 0.14em;
        background: linear-gradient(135deg, var(--qry-primary), var(--qry-secondary));
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
      }

      .qry-nav-cross-link {
        display: inline-flex;
        align-items: center;
        font-family: var(--qry-font-sans);
        font-size: 12px;
        font-weight: 600;
        color: var(--qry-text-secondary) !important;
        -webkit-text-fill-color: var(--qry-text-secondary);
        text-decoration: none !important;
        padding: 5px 14px;
        border-radius: 8px;
        border: 1px solid var(--qry-border);
        background: transparent;
        transition: all 0.2s ease;
        white-space: nowrap;
        margin-left: 8px;
      }

      .qry-nav-cross-link:hover {
        color: var(--qry-primary) !important;
        -webkit-text-fill-color: var(--qry-primary);
        border-color: var(--qry-border-hover) !important;
        background: var(--qry-primary-dim) !important;
      }

      /* ═══ DASHBOARD CARDS ═══ */
      .qry-card {
        background: var(--qry-bg-card) !important;
        backdrop-filter: blur(12px);
        -webkit-backdrop-filter: blur(12px);
        border: 1px solid var(--qry-border) !important;
        border-radius: 16px !important;
        background-image: linear-gradient(90deg, var(--qry-primary), var(--qry-secondary)) !important;
        background-size: 100% 2px !important;
        background-repeat: no-repeat !important;
        background-position: top center !important;
        transition: all 0.25s ease;
        position: relative;
      }

      .qry-card:hover {
        background-color: var(--qry-bg-card-hover) !important;
        border-color: var(--qry-border-hover) !important;
        transform: translateY(-2px);
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3), 0 0 0 1px rgba(0, 229, 255, 0.06);
      }

      .qry-card .font-display,
      .qry-card [class*="font-display"] {
        font-weight: 700 !important;
        font-size: 1.3em !important;
        text-shadow: 0 0 24px rgba(0, 229, 255, 0.12);
      }

      .qry-card .text-xs.text-slate-400,
      .qry-card [class*="text-slate-400"] {
        text-transform: uppercase !important;
        letter-spacing: 0.06em !important;
        font-size: 10px !important;
        color: var(--qry-text-muted) !important;
      }

      /* ═══ EXPLORER-SPECIFIC (div.panel, div.topbar, div.page) ═══ */
      .topbar {
        position: sticky;
        top: 0;
        z-index: 50;
        padding: 12px 16px;
      }

      .panel {
        background: var(--qry-bg-card) !important;
        border: 1px solid var(--qry-border) !important;
        border-radius: 16px !important;
        padding: 16px !important;
        transition: all 0.2s ease;
      }

      .panel:hover {
        border-color: var(--qry-border-hover) !important;
      }

      .pageTitle {
        font-size: 1.25rem !important;
        font-weight: 700 !important;
        color: var(--qry-text-primary) !important;
      }

      .pageSub {
        color: var(--qry-text-secondary) !important;
        font-size: 0.875rem !important;
      }

      .page {
        max-width: 72rem;
        margin: 0 auto;
        padding: 1.5rem 1rem;
      }

      div.container {
        max-width: 72rem;
        margin: 0 auto;
      }

      .mono {
        font-family: var(--qry-font-mono) !important;
      }

      /* ═══ TABLES ═══ */
      table {
        border-collapse: separate !important;
        border-spacing: 0 !important;
        width: 100%;
      }

      thead th, thead td {
        text-transform: uppercase !important;
        letter-spacing: 0.05em !important;
        font-size: 11px !important;
        color: var(--qry-text-muted) !important;
        border-bottom: 1px solid var(--qry-border) !important;
        padding: 10px 12px !important;
      }

      tbody tr {
        transition: background 0.15s ease;
        position: relative;
      }

      tbody tr:nth-child(even) {
        background: rgba(15, 23, 42, 0.25);
      }

      tbody tr:hover {
        background: rgba(0, 229, 255, 0.04) !important;
      }

      tbody tr:hover td:first-child {
        box-shadow: inset 3px 0 0 var(--qry-primary);
      }

      tbody td {
        padding: 10px 12px !important;
        border-bottom: 1px solid rgba(0, 229, 255, 0.04) !important;
        vertical-align: middle;
      }

      /* Monospace for hashes & addresses */
      td a[href*="/tx/"],
      td a[href*="/address/"],
      td a[href*="/block/"],
      .qry-mono {
        font-family: var(--qry-font-mono) !important;
        font-size: 0.88em;
      }

      /* Block height links */
      td a[href*="/block/"] {
        color: var(--qry-primary) !important;
        text-decoration: none;
        transition: all 0.2s ease;
      }

      td a[href*="/block/"]:hover {
        text-decoration: underline;
        text-underline-offset: 3px;
      }

      /* ═══ BLOCK / TX DETAIL PAGES ═══ */
      .qry-detail-header {
        font-size: 1.1em;
        font-family: var(--qry-font-mono);
        word-break: break-all;
        color: var(--qry-text-primary);
        padding: 12px 0;
      }

      .qry-badge-confirmed {
        display: inline-flex;
        align-items: center;
        gap: 5px;
        padding: 3px 10px;
        border-radius: 9999px;
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 0.04em;
        background: linear-gradient(135deg, rgba(52, 211, 153, 0.18), rgba(52, 211, 153, 0.08));
        color: var(--qry-success);
        border: 1px solid rgba(52, 211, 153, 0.2);
      }

      .qry-badge-pending {
        display: inline-flex;
        align-items: center;
        gap: 5px;
        padding: 3px 10px;
        border-radius: 9999px;
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 0.04em;
        background: linear-gradient(135deg, rgba(251, 191, 36, 0.18), rgba(251, 191, 36, 0.08));
        color: var(--qry-warning);
        border: 1px solid rgba(251, 191, 36, 0.2);
      }

      /* Code blocks for scripts */
      pre, code, .text-code {
        background: rgba(10, 15, 28, 0.6) !important;
        border: 1px solid var(--qry-border);
        border-radius: 8px;
        font-family: var(--qry-font-mono) !important;
        font-size: 0.85em;
      }

      /* ═══ SEARCH BOX ═══ */
      input[type="text"],
      input[placeholder*="Search"],
      input[placeholder*="search"] {
        background: rgba(15, 23, 42, 0.65) !important;
        backdrop-filter: blur(8px);
        -webkit-backdrop-filter: blur(8px);
        border: 1px solid var(--qry-border) !important;
        border-radius: 12px !important;
        color: var(--qry-text-primary) !important;
        padding: 10px 16px !important;
        font-size: 14px !important;
        transition: all 0.25s ease;
        outline: none !important;
      }

      input[type="text"]:focus,
      input[placeholder*="Search"]:focus,
      input[placeholder*="search"]:focus {
        border-color: var(--qry-primary) !important;
        box-shadow: 0 0 0 3px rgba(0, 229, 255, 0.12), 0 0 20px rgba(0, 229, 255, 0.06) !important;
        background: rgba(15, 23, 42, 0.85) !important;
      }

      input::placeholder {
        color: var(--qry-text-muted) !important;
        transition: opacity 0.2s ease;
      }

      input:focus::placeholder {
        opacity: 0.5;
      }

      /* ═══ VORTEX VISUALIZATION ═══ */
      .qry-vortex-canvas {
        height: 360px !important;
      }

      @media (min-width: 768px) {
        .qry-vortex-canvas {
          height: 460px !important;
        }
      }

      @media (min-width: 1024px) {
        .qry-vortex-canvas {
          height: 560px !important;
        }
      }

      /* Deeper gradient overlay behind vortex canvas */
      .qry-vortex-canvas::before {
        content: "";
        position: absolute;
        inset: 0;
        background: radial-gradient(ellipse at 50% 40%, rgba(0, 229, 255, 0.06) 0%, transparent 65%),
                    radial-gradient(ellipse at 30% 80%, rgba(59, 111, 212, 0.05) 0%, transparent 50%);
        pointer-events: none;
        z-index: 1;
      }

      /* Qrypt Flow title gradient text */
      .qry-flow-title {
        background: linear-gradient(135deg, var(--qry-primary), var(--qry-secondary)) !important;
        -webkit-background-clip: text !important;
        -webkit-text-fill-color: transparent !important;
        background-clip: text !important;
        font-weight: 800 !important;
      }

      #${VORTEX_BLOCKSTRIP_ID} {
        position: absolute;
        left: 16px;
        right: 16px;
        bottom: 14px;
        display: flex;
        gap: 10px;
        align-items: stretch;
        pointer-events: none;
        z-index: 30;
      }

      .qry-vortex-block {
        flex: 1 1 0;
        min-width: 78px;
        padding: 10px 12px;
        border-radius: 14px;
        border: 1px solid rgba(255, 255, 255, 0.10);
        background: rgba(0, 0, 0, 0.22);
        backdrop-filter: blur(10px);
        box-shadow: 0 14px 30px rgba(0, 0, 0, 0.45), inset 0 1px 0 rgba(255, 255, 255, 0.05);
        position: relative;
        overflow: hidden;
        transform: translateZ(0);
        transition: transform 0.2s ease, box-shadow 0.2s ease;
      }

      .qry-vortex-block > * {
        position: relative;
        z-index: 1;
      }

      .qry-vortex-block::before {
        content: "";
        position: absolute;
        inset: 0;
        width: calc(var(--qry-fill, 0) * 100%);
        background: linear-gradient(90deg, rgba(0, 229, 255, 0.10), rgba(0, 229, 255, 0.22));
        opacity: 0.9;
        pointer-events: none;
        z-index: 0;
      }

      .qry-vortex-block::after {
        content: "";
        position: absolute;
        inset: -35% -60%;
        background: radial-gradient(circle at 30% 50%, rgba(0, 229, 255, 0.20), transparent 60%);
        transform: translateX(-35%);
        animation: qryBlockSheen 3.2s ease-in-out infinite;
        opacity: 0.35;
        pointer-events: none;
        z-index: 0;
      }

      .qry-vortex-block-top {
        display: flex;
        justify-content: space-between;
        gap: 10px;
        align-items: baseline;
      }

      .qry-vortex-block-label {
        font-family: var(--qry-font-sans);
        font-size: 11px;
        font-weight: 800;
        letter-spacing: 0.02em;
        color: rgba(224, 242, 254, 0.92);
        text-transform: uppercase;
      }

      .qry-vortex-block-meta {
        font-family: var(--qry-font-sans);
        font-size: 11px;
        color: rgba(148, 163, 184, 0.92);
        white-space: nowrap;
      }

      .qry-vortex-block-fee {
        margin-top: 6px;
        font-family: var(--qry-font-sans);
        font-size: 10px;
        color: rgba(148, 163, 184, 0.8);
      }

      #${VORTEX_STATUS_PILL_ID} {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 7px 12px;
        border-radius: 9999px;
        border: 1px solid rgba(255, 255, 255, 0.10);
        background: rgba(0, 0, 0, 0.18);
        backdrop-filter: blur(10px);
        box-shadow: 0 10px 22px rgba(0, 0, 0, 0.45);
        user-select: none;
        pointer-events: none;
      }

      #${VORTEX_STATUS_PILL_ID} .dot {
        width: 8px;
        height: 8px;
        border-radius: 9999px;
        background: rgba(148, 163, 184, 0.9);
        position: relative;
      }

      #${VORTEX_STATUS_PILL_ID}.live .dot {
        background: rgba(0, 229, 255, 0.95);
        box-shadow: 0 0 16px rgba(0, 229, 255, 0.55);
      }

      #${VORTEX_STATUS_PILL_ID}.live .dot::after {
        content: "";
        position: absolute;
        inset: -6px;
        border-radius: 9999px;
        border: 1px solid rgba(0, 229, 255, 0.35);
        animation: qryPulse 1.4s ease-out infinite;
      }

      #${VORTEX_STATUS_PILL_ID}.connecting .dot {
        background: rgba(148, 163, 184, 0.95);
        box-shadow: 0 0 14px rgba(148, 163, 184, 0.35);
      }

      #${VORTEX_STATUS_PILL_ID}.offline .dot {
        background: rgba(251, 113, 133, 0.95);
        box-shadow: 0 0 14px rgba(251, 113, 133, 0.35);
      }

      #${VORTEX_STATUS_PILL_ID} .label {
        font-family: var(--qry-font-sans);
        font-size: 11px;
        font-weight: 800;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: rgba(226, 232, 240, 0.9);
      }

      #${VORTEX_STATUS_PILL_ID}.live .label {
        color: rgba(224, 242, 254, 0.95);
      }

      /* ═══ BRANDED FOOTER ═══ */
      #${FOOTER_ID} {
        background: rgba(10, 15, 28, 0.85);
        backdrop-filter: blur(12px);
        -webkit-backdrop-filter: blur(12px);
        border-top: 1px solid var(--qry-border);
        padding: 16px 24px;
        margin-top: 40px;
      }

      .qry-footer-inner {
        display: flex;
        align-items: center;
        justify-content: space-between;
        max-width: 1280px;
        margin: 0 auto;
        gap: 16px;
        flex-wrap: wrap;
      }

      .qry-footer-brand {
        font-family: var(--qry-font-sans);
        font-size: 12px;
        font-weight: 700;
        letter-spacing: 0.08em;
        background: linear-gradient(135deg, var(--qry-primary), var(--qry-secondary));
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
      }

      .qry-footer-center {
        display: flex;
        gap: 16px;
        align-items: center;
      }

      .qry-footer-link {
        font-family: var(--qry-font-sans);
        font-size: 12px;
        color: var(--qry-text-muted) !important;
        -webkit-text-fill-color: var(--qry-text-muted);
        text-decoration: none !important;
        transition: color 0.2s ease;
      }

      .qry-footer-link:hover {
        color: var(--qry-primary) !important;
        -webkit-text-fill-color: var(--qry-primary);
      }

      .qry-footer-right {
        display: flex;
        align-items: center;
        gap: 6px;
      }

      .qry-footer-status-dot {
        width: 7px;
        height: 7px;
        border-radius: 50%;
        background: var(--qry-text-muted);
        transition: background 0.3s ease, box-shadow 0.3s ease;
      }

      .qry-footer-status-dot.live {
        background: var(--qry-success);
        box-shadow: 0 0 8px rgba(52, 211, 153, 0.5);
      }

      .qry-footer-status-dot.connecting {
        background: var(--qry-text-secondary);
        box-shadow: 0 0 8px rgba(148, 163, 184, 0.3);
      }

      .qry-footer-status-dot.offline {
        background: var(--qry-danger);
        box-shadow: 0 0 8px rgba(251, 113, 133, 0.4);
      }

      .qry-footer-status-text {
        font-family: var(--qry-font-sans);
        font-size: 11px;
        color: var(--qry-text-muted);
      }

      /* ═══ LOADING & TRANSITIONS ═══ */
      @keyframes qryShimmer {
        0% { background-position: -200% 0; }
        100% { background-position: 200% 0; }
      }

      .qry-shimmer {
        background: linear-gradient(90deg, transparent 25%, rgba(0, 229, 255, 0.04) 50%, transparent 75%);
        background-size: 200% 100%;
        animation: qryShimmer 1.8s ease-in-out infinite;
      }

      /* Value update pulse */
      @keyframes qryValuePulse {
        0% { opacity: 1; }
        50% { opacity: 0.6; }
        100% { opacity: 1; }
      }

      /* ═══ MICRO-INTERACTIONS ═══ */
      /* Button hover */
      button, [role="button"], .btn {
        transition: all 0.2s ease;
      }

      button:hover, [role="button"]:hover, .btn:hover {
        transform: scale(1.02);
      }

      /* Link underline slide-in */
      .qry-link-animated {
        position: relative;
        text-decoration: none !important;
      }

      .qry-link-animated::after {
        content: "";
        position: absolute;
        bottom: -1px;
        left: 0;
        width: 0;
        height: 1px;
        background: var(--qry-primary);
        transition: width 0.25s ease;
      }

      .qry-link-animated:hover::after {
        width: 100%;
      }

      /* ═══ KEYFRAME ANIMATIONS ═══ */
      @keyframes qryPulse {
        0% { transform: scale(0.6); opacity: 0.0; }
        15% { opacity: 0.55; }
        100% { transform: scale(1.2); opacity: 0.0; }
      }

      @keyframes qryBlockSheen {
        0% { transform: translateX(-35%); opacity: 0.10; }
        45% { opacity: 0.35; }
        50% { transform: translateX(35%); opacity: 0.30; }
        90% { opacity: 0.10; }
        100% { transform: translateX(-35%); opacity: 0.10; }
      }

      /* ═══ MOBILE RESPONSIVENESS ═══ */
      @media (max-width: 768px) {
        .qry-nav-brand-text {
          font-size: 12px;
          letter-spacing: 0.10em;
        }

        .qry-nav-logo img {
          width: 24px;
          height: 24px;
        }

        #${NAVBAR_ID} {
          gap: 6px;
        }

        .qry-nav-cross-link {
          padding: 4px 10px;
          font-size: 11px;
        }

        .qry-card {
          border-radius: 12px !important;
        }

        .qry-card .font-display,
        .qry-card [class*="font-display"] {
          font-size: 1.1em !important;
        }

        input[type="text"],
        input[placeholder*="Search"],
        input[placeholder*="search"] {
          width: 100% !important;
          font-size: 16px !important;
          border-radius: 10px !important;
        }

        #${FOOTER_ID} {
          padding: 12px 16px;
        }

        .qry-footer-inner {
          flex-direction: column;
          align-items: center;
          text-align: center;
          gap: 8px;
        }

        /* Performance: reduce blur on touch devices */
        .qry-card,
        .qry-nav-cross-link {
          backdrop-filter: none !important;
          -webkit-backdrop-filter: none !important;
        }

        /* Touch-friendly tap targets */
        tbody td { padding: 12px !important; }
        button, [role="button"], .btn, a { min-height: 44px; min-width: 44px; }

        /* Stack vortex blocks on small screens */
        #${VORTEX_BLOCKSTRIP_ID} {
          flex-wrap: wrap;
          gap: 6px;
        }

        .qry-vortex-block {
          min-width: 60px;
          padding: 8px 10px;
          border-radius: 10px;
        }

        /* Table horizontal scroll */
        table {
          display: block;
          overflow-x: auto;
          -webkit-overflow-scrolling: touch;
        }
      }

      @media (max-width: 480px) {
        /* Hide brand text on very small screens, show logo only */
        .qry-nav-brand-text {
          display: none;
        }

        #${NAVBAR_ID} {
          margin-right: 8px;
        }

        .qry-nav-logo img {
          width: 22px;
          height: 22px;
        }

        .qry-nav-cross-link {
          padding: 3px 8px;
          font-size: 10px;
        }
      }

      /* ═══ REDUCED MOTION ═══ */
      @media (prefers-reduced-motion: reduce) {
        *, *::before, *::after {
          animation-duration: 0.01ms !important;
          animation-iteration-count: 1 !important;
          transition-duration: 0.01ms !important;
        }

        router-outlet + *, #root > div { animation: none; }
        .qry-card:hover { transform: none; }
        button:hover, [role="button"]:hover { transform: none; }
      }
    `.trim();

    (document.head || document.documentElement).appendChild(el);
  }

  function stripCanvasStatusBadge(container) {
    if (!container) return false;
    const containerRect = container.getBoundingClientRect?.();
    if (!containerRect) return false;

    const nodes = Array.from(container.querySelectorAll("div,span"));
    for (const node of nodes) {
      if (!node || !node.isConnected) continue;
      if (node.id === VORTEX_STATUS_PILL_ID || node.closest(`#${VORTEX_STATUS_PILL_ID}`)) continue;

      const raw = (node.textContent || "").trim();
      if (!raw) continue;
      const label = raw.toUpperCase();
      if (!VORTEX_CANVAS_STATUS_LABELS.has(label)) continue;

      let candidate = node;
      while (candidate.parentElement && candidate.parentElement !== container) {
        const parentText = (candidate.parentElement.textContent || "").trim().toUpperCase();
        if (parentText !== label) break;
        candidate = candidate.parentElement;
      }

      const rect = candidate.getBoundingClientRect?.();
      if (rect) {
        if (rect.top > containerRect.top + 180) continue;
        if (rect.left > containerRect.left + 180) continue;
      }

      candidate.remove();
      return true;
    }

    return false;
  }

  function findVortexCanvasContainer() {
    const canvases = Array.from(document.querySelectorAll("canvas"));
    for (const canvas of canvases) {
      const parent = canvas.parentElement;
      if (!parent) continue;

      const cls = typeof parent.className === "string" ? parent.className : "";
      if (!cls.includes("bg-gradient-to-b")) continue;
      if (!cls.includes("overflow-hidden")) continue;
      if (!parent.querySelector("div")) continue;

      return parent;
    }

    return null;
  }

  function getOrCreateStatusPill() {
    let pill = document.getElementById(VORTEX_STATUS_PILL_ID);
    if (pill) return pill;

    pill = document.createElement("span");
    pill.id = VORTEX_STATUS_PILL_ID;
    pill.className = "connecting";
    const dot = document.createElement("span");
    dot.className = "dot";
    const lbl = document.createElement("span");
    lbl.className = "label";
    lbl.textContent = "LIVE";
    pill.appendChild(dot);
    pill.appendChild(lbl);
    return pill;
  }

  function patchVortexHeaderStatus() {
    const candidates = Array.from(document.querySelectorAll("div.text-xs.text-slate-500"));
    const statusEl = candidates.find((n) => {
      const t = (n.textContent || "").trim();
      return t === "Live feed" || t === "Connecting." || t === "Offline";
    });
    if (!statusEl) return null;

    if (statusEl.dataset.qryVortexStatusPatched === "1") return statusEl;
    statusEl.dataset.qryVortexStatusPatched = "1";

    statusEl.textContent = "";
    statusEl.style.display = "flex";
    statusEl.style.alignItems = "center";
    statusEl.style.justifyContent = "flex-end";
    statusEl.style.gap = "8px";

    const pill = getOrCreateStatusPill();
    statusEl.appendChild(pill);
    return statusEl;
  }

  function setVortexStatus(state) {
    const pill = getOrCreateStatusPill();
    pill.classList.remove("live", "connecting", "offline");
    pill.classList.add(state);
    const label = pill.querySelector(".label");
    if (label) {
      const labels = { live: "LIVE", connecting: "CONNECTING", offline: "OFFLINE" };
      label.textContent = labels[state] || "LIVE";
    }
    updateFooterConnectionStatus(state);
  }

  function ensureVortexEnhancements() {
    ensureStyleTag();

    patchVortexHeaderStatus();

    const container = findVortexCanvasContainer();
    if (!container) return null;

    if (!container.classList.contains("qry-vortex-canvas")) {
      container.classList.add("qry-vortex-canvas");
    }

    stripCanvasStatusBadge(container);

    let blockstrip = document.getElementById(VORTEX_BLOCKSTRIP_ID);
    if (!blockstrip) {
      blockstrip = document.createElement("div");
      blockstrip.id = VORTEX_BLOCKSTRIP_ID;
      container.appendChild(blockstrip);
    }

    return { container, blockstrip };
  }

  function formatBytes(bytes) {
    const n = typeof bytes === "number" ? bytes : Number(bytes);
    if (!Number.isFinite(n) || n <= 0) return "0 B";

    const units = ["B", "KB", "MB", "GB", "TB"];
    let val = n;
    let unit = 0;
    while (val >= 1000 && unit < units.length - 1) {
      val /= 1000;
      unit++;
    }

    const precision = unit === 0 ? 0 : val >= 100 ? 0 : val >= 10 ? 1 : 1;
    return `${val.toFixed(precision)} ${units[unit]}`;
  }

  function formatDuration(seconds) {
    const s = typeof seconds === "number" ? seconds : Number(seconds);
    if (!Number.isFinite(s) || s < 0) return "-";

    const total = Math.round(s);
    const days = Math.floor(total / 86400);
    if (days > 0) return `${days}d`;
    const hours = Math.floor((total % 86400) / 3600);
    if (hours > 0) return `${hours}h`;
    const mins = Math.floor((total % 3600) / 60);
    return `${Math.max(0, mins)}m`;
  }

  function formatFeerate(miksPerVb) {
    if (miksPerVb === null || miksPerVb === void 0) return "-";
    const v = typeof miksPerVb === "number" ? miksPerVb : Number(miksPerVb);
    if (!Number.isFinite(v)) return "-";
    return `${v.toFixed(2)} miks/vB`;
  }

  function formatInt(value) {
    const n = typeof value === "number" ? value : Number(value);
    if (!Number.isFinite(n)) return "0";
    return new Intl.NumberFormat(void 0, { maximumFractionDigits: 0 }).format(n);
  }

  function updateMetricCard(label, { value, sub }) {
    const nodes = Array.from(document.querySelectorAll("div.text-xs.text-slate-400"));
    const labelEl = nodes.find((n) => (n.textContent || "").trim() === label);
    if (!labelEl) return false;

    const card = labelEl.parentElement;
    if (!card) return false;

    const valueEl = card.querySelector("div.mt-1.font-display");
    if (valueEl && typeof value === "string") valueEl.textContent = value;

    const subEl = card.querySelector("div.mt-0\\.5.text-xs.text-slate-500");
    if (subEl) {
      if (typeof sub === "string") {
        subEl.textContent = sub;
        subEl.style.display = "";
      } else {
        subEl.style.display = "none";
      }
    }

    return true;
  }

  function renderVortexBlocks({ projectedBlocks, blockMaxBytes }) {
    const enh = ensureVortexEnhancements();
    if (!enh) return;

    const { blockstrip } = enh;

    if (!Array.isArray(projectedBlocks) || projectedBlocks.length === 0) {
      blockstrip.replaceChildren();
      return;
    }

    const blocks = projectedBlocks.slice(0, 6);
    const frag = document.createDocumentFragment();

    for (const b of blocks) {
      const idx = typeof b?.index === "number" ? b.index : 0;
      const label = idx === 0 ? "Next" : `+${idx + 1}`;
      const txCount = typeof b?.tx_count === "number" ? b.tx_count : 0;
      const used = typeof b?.total_bytes === "number" ? b.total_bytes : 0;
      const max = typeof blockMaxBytes === "number" && blockMaxBytes > 0 ? blockMaxBytes : 0;
      const pct = max > 0 ? Math.max(0, Math.min(1, used / max)) : 0;

      const minFr = b?.min_feerate_miks_per_vb ?? null;
      const maxFr = b?.max_feerate_miks_per_vb ?? null;
      const feeText =
        minFr === null && maxFr === null
          ? "Fee range: -"
          : minFr === null
            ? `Fee range: ≤ ${formatFeerate(maxFr)}`
            : maxFr === null
              ? `Fee range: ≥ ${formatFeerate(minFr)}`
              : `Fee range: ${formatFeerate(minFr)} – ${formatFeerate(maxFr)}`;

      const el = document.createElement("div");
      el.className = "qry-vortex-block";
      el.style.setProperty("--qry-fill", pct.toFixed(4));
      const topDiv = document.createElement("div");
      topDiv.className = "qry-vortex-block-top";
      const labelEl = document.createElement("div");
      labelEl.className = "qry-vortex-block-label";
      labelEl.textContent = label;
      const metaEl = document.createElement("div");
      metaEl.className = "qry-vortex-block-meta";
      metaEl.textContent = `${formatInt(txCount)} tx \u2022 ${formatBytes(used)}`;
      topDiv.appendChild(labelEl);
      topDiv.appendChild(metaEl);
      const feeEl = document.createElement("div");
      feeEl.className = "qry-vortex-block-fee";
      feeEl.textContent = feeText;
      el.appendChild(topDiv);
      el.appendChild(feeEl);

      frag.appendChild(el);
    }

    blockstrip.replaceChildren(frag);
  }

  async function fetchJsonNoCache(path) {
    const url = new URL(path, window.location.origin);
    url.searchParams.set("_ts", String(Date.now()));
    const res = await fetch(url.toString(), { cache: "no-store", credentials: "same-origin" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  }

  async function refreshChainSummary() {
    try {
      const summary = await fetchJsonNoCache("/api/chain/summary");
      const da = summary?.difficulty_adjustment;
      if (!da) return;

      const blocks = typeof da.blocks_remaining === "number" ? da.blocks_remaining : null;
      const secs = typeof da.estimated_seconds_remaining === "number" ? da.estimated_seconds_remaining : null;

      updateMetricCard("Difficulty window", {
        value: blocks === null ? "-" : `${blocks} blocks`,
        sub: secs === null ? void 0 : `~${formatDuration(secs)} to retarget`,
      });
    } catch {
      // ignore (offline / API down)
    }
  }

  function refreshMempoolMetrics(info) {
    if (!info) return;

    const size = typeof info.size === "number" ? info.size : null;
    const bytes = typeof info.bytes === "number" ? info.bytes : null;
    const limit = typeof info.limit_bytes === "number" ? info.limit_bytes : null;
    const floor = typeof info.mempoolminfee === "number" ? info.mempoolminfee : null;

    if (size !== null) {
      updateMetricCard("Mempool tx", { value: formatInt(size), sub: "Unconfirmed transactions" });
    }

    if (bytes !== null && limit !== null) {
      const pct = limit > 0 ? Math.round((bytes / limit) * 100) : null;
      updateMetricCard("Mempool usage", {
        value: pct === null ? formatBytes(bytes) : `${pct}%`,
        sub: limit > 0 ? `${formatBytes(bytes)} / ${formatBytes(limit)}` : "No configured limit",
      });
    }

    if (floor !== null) {
      updateMetricCard("Min relay feerate", { value: formatFeerate(floor), sub: "Mempool floor" });
    }
  }

  function startLiveUpdates() {
    if (window.__qryLiveMempoolStarted) return;
    window.__qryLiveMempoolStarted = true;

    let lastDataAt = 0;
    const markDataReceived = () => {
      lastDataAt = Date.now();
      setVortexStatus("live");
    };

    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${proto}//${window.location.host}/api/mempool/stream`;

    let ws;
    let backoffMs = 500;

    const connect = () => {
      setVortexStatus("connecting");
      try {
        ws = new WebSocket(wsUrl);
      } catch {
        ws = null;
      }

      if (!ws) {
        setTimeout(connect, Math.min(30_000, backoffMs));
        backoffMs = Math.min(30_000, backoffMs * 2);
        return;
      }

      ws.addEventListener("message", (ev) => {
        try {
          const msg = JSON.parse(String(ev.data || ""));
          const data = msg?.data;
          if (!data) return;

          if (data.info) refreshMempoolMetrics(data.info);
          if (data.projected_blocks) {
            renderVortexBlocks({
              projectedBlocks: data.projected_blocks,
              blockMaxBytes: data.block_max_bytes ?? null,
            });
          }
          markDataReceived();
        } catch {
          // ignore
        }
      });

      ws.addEventListener("open", () => {
        setVortexStatus("live");
      });

      ws.addEventListener("close", () => {
        setVortexStatus("offline");
        setTimeout(connect, Math.min(30_000, backoffMs));
        backoffMs = Math.min(30_000, backoffMs * 2);
      });

      ws.addEventListener("error", () => {
        try {
          ws?.close();
        } catch {
          // ignore
        }
      });
    };

    connect();

    const refreshMempoolFallback = async () => {
      try {
        const [info, fees] = await Promise.all([
          fetchJsonNoCache("/api/mempool/summary"),
          fetchJsonNoCache("/api/mempool/fees"),
        ]);
        if (info) refreshMempoolMetrics(info);
        if (fees?.projected_blocks) {
          renderVortexBlocks({
            projectedBlocks: fees.projected_blocks,
            blockMaxBytes: fees.block_max_bytes ?? null,
          });
        }
        markDataReceived();
      } catch {
        // ignore
      }
    };

    void refreshMempoolFallback();
    setInterval(() => {
      if (ws && ws.readyState === WebSocket.OPEN) return;
      void refreshMempoolFallback();
    }, 7_500);

    setInterval(() => {
      const now = Date.now();
      if (!lastDataAt) return;
      if (now - lastDataAt > 25_000) setVortexStatus("offline");
    }, 2_500);

    // Difficulty changes only on new blocks; keep it fresh without spamming.
    void refreshChainSummary();
    setInterval(() => void refreshChainSummary(), 20_000);
  }

  function startExplorerLiveStatus() {
    if (window.__qryExplorerStatusStarted) return;
    window.__qryExplorerStatusStarted = true;

    const poll = async () => {
      try {
        await fetchJsonNoCache("/api/stats");
        updateFooterConnectionStatus("live");
      } catch {
        updateFooterConnectionStatus("offline");
      }
    };

    void poll();
    setInterval(() => void poll(), 15_000);
  }

  function injectBrandedNavbar() {
    if (document.getElementById(NAVBAR_ID)) return;

    // Real sites use <header> (mempool) or .topbar (explorer), not <nav>
    const headerEl = document.querySelector("header") || document.querySelector(".topbar");
    if (!headerEl) return;

    // Find the first link or .brand element in the header
    const logoLink = headerEl.querySelector("a") || headerEl.querySelector(".brand");
    if (!logoLink) return;

    // Hide the entire original branding (logo + text like "QryptCoin Mempool / Live mempool")
    logoLink.style.display = "none";

    // Build brand container: Q logo + "QRYPTCOIN" text
    const brandContainer = document.createElement("a");
    brandContainer.id = NAVBAR_ID;
    brandContainer.href = "/";

    const logoSpan = document.createElement("span");
    logoSpan.className = "qry-nav-logo";
    const logoImg = document.createElement("img");
    logoImg.src = QRY_LOGO_URI;
    logoImg.alt = "Qryptcoin";
    logoImg.draggable = false;
    logoSpan.appendChild(logoImg);

    const textSpan = document.createElement("span");
    textSpan.className = "qry-nav-brand-text";
    textSpan.textContent = "QRYPTCOIN";

    brandContainer.appendChild(logoSpan);
    brandContainer.appendChild(textSpan);

    // Insert where the old logo link was
    if (logoLink.nextSibling) {
      logoLink.parentElement.insertBefore(brandContainer, logoLink.nextSibling);
    } else {
      logoLink.parentElement.appendChild(brandContainer);
    }

    // Add cross-site navigation link to the header's inner container
    const innerContainer = headerEl.querySelector("div") || headerEl;
    if (!headerEl.querySelector(".qry-nav-cross-link")) {
      const link = document.createElement("a");
      link.className = "qry-nav-cross-link";
      link.href = crossSiteUrl();
      link.textContent = crossSiteLabel();
      link.style.marginLeft = "auto";
      innerContainer.appendChild(link);
    }
  }

  function updateFooterConnectionStatus(state) {
    const footer = document.getElementById(FOOTER_ID);
    if (!footer) return;

    const dot = footer.querySelector(".qry-footer-status-dot");
    const text = footer.querySelector(".qry-footer-status-text");

    if (dot) {
      dot.className = "qry-footer-status-dot";
      const validStates = ["live", "connecting", "offline"];
      if (validStates.includes(state)) dot.classList.add(state);
    }
    if (text) {
      const labels = { live: "Connected", connecting: "Connecting", offline: "Offline" };
      text.textContent = labels[state] || "Offline";
    }
  }

  function injectBrandedFooter() {
    if (document.getElementById(FOOTER_ID)) return;
    if (!document.body) return;

    const footer = document.createElement("footer");
    footer.id = FOOTER_ID;

    const inner = document.createElement("div");
    inner.className = "qry-footer-inner";

    // Left: brand name
    const left = document.createElement("div");
    left.className = "qry-footer-left";
    const brandSpan = document.createElement("span");
    brandSpan.className = "qry-footer-brand";
    brandSpan.textContent = "QRYPTCOIN NETWORK";
    left.appendChild(brandSpan);

    // Center: cross-site link + GitHub
    const center = document.createElement("div");
    center.className = "qry-footer-center";

    const webLink = document.createElement("a");
    webLink.className = "qry-footer-link";
    webLink.href = "https://qryptcoin.org";
    webLink.target = "_blank";
    webLink.rel = "noopener noreferrer";
    webLink.textContent = "Website";
    center.appendChild(webLink);

    const crossLink = document.createElement("a");
    crossLink.className = "qry-footer-link";
    crossLink.href = crossSiteUrl();
    crossLink.textContent = crossSiteLabel();
    center.appendChild(crossLink);

    const tgLink = document.createElement("a");
    tgLink.className = "qry-footer-link";
    tgLink.href = "https://t.me/QryptcoinOfficial";
    tgLink.target = "_blank";
    tgLink.rel = "noopener noreferrer";
    tgLink.textContent = "Telegram";
    center.appendChild(tgLink);

    const ghLink = document.createElement("a");
    ghLink.className = "qry-footer-link";
    ghLink.href = "https://github.com/QryptCoin-Technologies-L-L-C/Qryptcoin";
    ghLink.target = "_blank";
    ghLink.rel = "noopener noreferrer";
    ghLink.textContent = "GitHub";
    center.appendChild(ghLink);

    // Right: connection status
    const right = document.createElement("div");
    right.className = "qry-footer-right";

    const dot = document.createElement("span");
    dot.className = "qry-footer-status-dot";

    const statusText = document.createElement("span");
    statusText.className = "qry-footer-status-text";
    statusText.textContent = "Connecting";

    right.appendChild(dot);
    right.appendChild(statusText);

    inner.appendChild(left);
    inner.appendChild(center);
    inner.appendChild(right);
    footer.appendChild(inner);

    const root = document.getElementById("root") || document.body;
    root.appendChild(footer);
  }

  function ensureFooterAtBottom() {
    const footer = document.getElementById(FOOTER_ID);
    if (!footer) return;
    const root = document.getElementById("root") || document.body;
    // If the footer isn't the last element in its container, move it there
    if (footer.parentElement !== root || footer.nextElementSibling) {
      root.appendChild(footer);
    }
  }

  function enhanceVortexTitle() {
    if (document.querySelector(".qry-flow-title")) return;

    const walker = document.createTreeWalker(
      document.body || document.documentElement,
      NodeFilter.SHOW_TEXT,
      {
        acceptNode(node) {
          if (!node.nodeValue || !node.nodeValue.includes(VORTEX_NEW_TITLE)) return NodeFilter.FILTER_REJECT;
          const tag = node.parentElement?.tagName?.toLowerCase();
          if (tag === "script" || tag === "style") return NodeFilter.FILTER_REJECT;
          return NodeFilter.FILTER_ACCEPT;
        },
      },
    );

    const node = walker.nextNode();
    if (node && node.parentElement) {
      node.parentElement.classList.add("qry-flow-title");
    }
  }

  function tagMetricCards() {
    // Mempool site: cards are siblings of text-xs labels inside grid containers
    const labels = document.querySelectorAll("div.text-xs.text-slate-400, [class*='text-xs'][class*='text-slate-400']");
    for (const label of labels) {
      const card = label.parentElement;
      if (card && !card.classList.contains("qry-card")) {
        card.classList.add("qry-card");
      }
    }
    // Mempool: also tag the Tailwind stat cards directly
    document.querySelectorAll("[class*='rounded-xl'][class*='border'][class*='bg-black']").forEach(el => {
      if (!el.classList.contains("qry-card")) el.classList.add("qry-card");
    });
    // Explorer: tag .panel elements as cards
    document.querySelectorAll(".panel").forEach(el => {
      if (!el.classList.contains("qry-card")) el.classList.add("qry-card");
    });
  }

  function patchTextNodes() {
    const walker = document.createTreeWalker(
      document.body || document.documentElement,
      NodeFilter.SHOW_TEXT,
      {
        acceptNode(node) {
          const parent = node.parentElement;
          if (!parent) return NodeFilter.FILTER_REJECT;
          const tag = parent.tagName.toLowerCase();
          if (tag === "script" || tag === "style" || tag === "noscript") return NodeFilter.FILTER_REJECT;
          if (!node.nodeValue || !node.nodeValue.trim()) return NodeFilter.FILTER_REJECT;
          return NodeFilter.FILTER_ACCEPT;
        },
      },
    );

    let disclaimerEl = null;
    let mitEl = null;

    let node;
    while ((node = walker.nextNode())) {
      const original = node.nodeValue;
      if (!original) continue;

      if (!disclaimerEl && original.includes(FOOTER_DISCLAIMER_SUBSTRING)) {
        disclaimerEl = node.parentElement;
      }
      if (!mitEl && original.includes(FOOTER_MIT_SUBSTRING)) {
        mitEl = node.parentElement;
      }

      for (const [from, to] of getTextReplacements()) {
        if (original.includes(from)) {
          node.nodeValue = original.replaceAll(from, to);
          break;
        }
      }
    }

    if (disclaimerEl || mitEl) {
      removeFooterNoise(disclaimerEl, mitEl);
    }
  }

  function patch() {
    ensureStyleTag();
    patchSearchBox();
    patchTextNodes();
    injectBrandedNavbar();
    injectBrandedFooter();
    ensureFooterAtBottom();
    tagMetricCards();

    if (isExplorerSite()) {
      startExplorerLiveStatus();
    } else {
      ensureVortexEnhancements();
      enhanceVortexTitle();
      startLiveUpdates();
    }
  }

  let scheduled = false;
  let lastPatchAt = 0;
  function schedulePatch() {
    if (scheduled) return;
    scheduled = true;
    requestAnimationFrame(() => {
      scheduled = false;
      const now = Date.now();
      if (now - lastPatchAt < 200) return;
      lastPatchAt = now;
      patch();
    });
  }

  const observer = new MutationObserver(() => schedulePatch());
  observer.observe(document.documentElement, { childList: true, subtree: true });

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => schedulePatch(), { once: true });
  } else {
    schedulePatch();
  }
  // Fee display patch - compute fee from fee_miks
  function patchFeeDisplay() {
    // Find elements that show "0.00000000" fee when fee_miks exists
    const feeLabels = Array.from(document.querySelectorAll("td, dd, span, div"));
    for (const el of feeLabels) {
      const text = el.textContent?.trim() || "";
      // Look for "Fee" label followed by "0.00000000"
      if (text === "0.00000000" || text === "0") {
        const prev = el.previousElementSibling;
        const parent = el.parentElement;
        const labelText = prev?.textContent?.toLowerCase() || parent?.textContent?.toLowerCase() || "";
        if (labelText.includes("fee") && !labelText.includes("feerate")) {
          // Check if page has fee_miks data
          const scripts = Array.from(document.querySelectorAll("script"));
          for (const s of scripts) {
            const match = s.textContent?.match(/"fee_miks"\s*:\s*(\d+)/);
            if (match) {
              const feeMiks = parseInt(match[1], 10);
              if (feeMiks > 0) {
                const feeQry = (feeMiks / 100000000).toFixed(8);
                el.textContent = feeQry;
              }
              break;
            }
          }
        }
      }
    }
  }

  // Intercept fetch to add fee field from fee_miks
  const originalFetch = window.fetch;
  window.fetch = async function(...args) {
    const response = await originalFetch.apply(this, args);
    const url = typeof args[0] === "string" ? args[0] : args[0]?.url || "";
    
    if (url.includes("/api/tx/")) {
      const clone = response.clone();
      try {
        const data = await clone.json();
        if (data && typeof data.fee_miks === "number" && data.fee === null) {
          data.fee = (data.fee_miks / 100000000).toFixed(8);
          return new Response(JSON.stringify(data), {
            status: response.status,
            statusText: response.statusText,
            headers: response.headers
          });
        }
      } catch {}
    }
    return response;
  };
})();
