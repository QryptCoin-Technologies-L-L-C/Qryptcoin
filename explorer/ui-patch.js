(() => {
  const FOOTER_DISCLAIMER_SUBSTRING = "node RPC is never exposed publicly";
  const FOOTER_MIT_SUBSTRING = "MIT-licensed implementation";

  const VORTEX_OLD_TITLE = "Transaction Vortex";
  const VORTEX_PREV_TITLE = "Qrypt Nebula";
  const VORTEX_NEW_TITLE = "Qrypt Flow";
  const VORTEX_BLOCKSTRIP_ID = "qry-vortex-blockstrip";
  const VORTEX_STATUS_PILL_ID = "qry-vortex-status-pill";
  const STYLE_ID = "qry-ui-patch-style";
  const VORTEX_CANVAS_STATUS_LABELS = new Set(["LIVE", "CONNECTING", "OFFLINE"]);

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

  const TEXT_REPLACEMENTS = [
    ["QryptCoin Explorer", "QryptCoin Mempool"],
    ["Mempool & Blockchain", "Live Mempool"],
    [VORTEX_OLD_TITLE, VORTEX_NEW_TITLE],
    [VORTEX_PREV_TITLE, VORTEX_NEW_TITLE],
    ["Live feed", ""],
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
        border-radius: 9999px;
        border: 1px solid rgba(255, 255, 255, 0.10);
        background: rgba(0, 0, 0, 0.22);
        backdrop-filter: blur(10px);
        box-shadow: 0 14px 30px rgba(0, 0, 0, 0.45);
        position: relative;
        overflow: hidden;
        transform: translateZ(0);
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
        font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
        font-size: 11px;
        font-weight: 800;
        letter-spacing: 0.02em;
        color: rgba(224, 242, 254, 0.92);
        text-transform: uppercase;
      }

      .qry-vortex-block-meta {
        font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
        font-size: 11px;
        color: rgba(148, 163, 184, 0.92);
        white-space: nowrap;
      }

      .qry-vortex-block-fee {
        margin-top: 6px;
        font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
        font-size: 10px;
        color: rgba(148, 163, 184, 0.8);
      }

      #${VORTEX_STATUS_PILL_ID} {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 6px 10px;
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
        font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
        font-size: 11px;
        font-weight: 800;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: rgba(226, 232, 240, 0.9);
      }

      #${VORTEX_STATUS_PILL_ID}.live .label {
        color: rgba(224, 242, 254, 0.95);
      }

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

      @media (prefers-reduced-motion: reduce) {
        .qry-vortex-block::after {
          animation: none;
        }

        #${VORTEX_STATUS_PILL_ID}.live .dot::after {
          animation: none;
        }
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
    pill.innerHTML = `<span class="dot"></span><span class="label">LIVE</span>`;
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
    if (label) label.textContent = "LIVE";
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
      el.innerHTML = `
        <div class="qry-vortex-block-top">
          <div class="qry-vortex-block-label"></div>
          <div class="qry-vortex-block-meta"></div>
        </div>
        <div class="qry-vortex-block-fee"></div>
      `.trim();

      const labelEl = el.querySelector(".qry-vortex-block-label");
      if (labelEl) labelEl.textContent = label;

      const metaEl = el.querySelector(".qry-vortex-block-meta");
      if (metaEl) metaEl.textContent = `${formatInt(txCount)} tx • ${formatBytes(used)}`;

      const feeEl = el.querySelector(".qry-vortex-block-fee");
      if (feeEl) feeEl.textContent = feeText;

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

      for (const [from, to] of TEXT_REPLACEMENTS) {
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
    ensureVortexEnhancements();
    patchSearchBox();
    patchTextNodes();
    startLiveUpdates();
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
        if (labelText.includes("fee") && \!labelText.includes("feerate")) {
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
