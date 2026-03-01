(() => {
  if (document.getElementById("frenzy-telewatch-fab")) return;

  function cleanRoomCode(raw = "") {
    return String(raw).toUpperCase().replace(/[^A-Z0-9_-]/g, "").slice(0, 24);
  }

  function detectSuggestedCode() {
    const path = String(location.pathname || "").split("/").filter(Boolean).slice(-1)[0] || "";
    const base = cleanRoomCode(path);
    if (!base || base.length < 4) {
      const host = cleanRoomCode(location.hostname.replace(/\./g, ""));
      return `WATCH-${host.slice(0, 6) || "PARTY"}`;
    }
    return `WATCH-${base.slice(0, 8)}`;
  }

  function codeFromUrl(urlText = "") {
    try {
      const u = new URL(urlText, location.href);
      const parts = u.pathname.split("/").filter(Boolean);
      const tail = parts.slice(-1)[0] || parts.slice(-2).join("") || u.hostname;
      const base = cleanRoomCode(tail);
      if (!base || base.length < 4) return detectSuggestedCode();
      return `WATCH-${base.slice(0, 8)}`;
    } catch {
      return detectSuggestedCode();
    }
  }

  function isLikelyWatchLink(a) {
    if (!a || !a.href) return false;
    const href = String(a.href || "").toLowerCase();
    const text = String(a.textContent || "").toLowerCase().trim();
    if (!href.startsWith("http")) return false;
    if (href.includes("/telewatch/")) return false;
    if (href.includes("/watch/") || href.includes("/title/") || href.includes("/video/")) return true;
    if (href.includes("netflix.com/title/") || href.includes("youtube.com/watch") || href.includes("primevideo.com/detail") || href.includes("disneyplus.com/video")) return true;
    if (text.includes("watch") || text.includes("play") || text.includes("trailer")) return true;
    return false;
  }

  async function send(type, payload = {}) {
    return chrome.runtime.sendMessage({ type, ...payload });
  }

  const fab = document.createElement("button");
  fab.id = "frenzy-telewatch-fab";
  fab.type = "button";
  fab.textContent = "Start Watch Party";

  const panel = document.createElement("div");
  panel.id = "frenzy-telewatch-panel";
  panel.className = "hidden";
  panel.innerHTML = `
    <div class="title">FlickFuse</div>
    <input id="frenzy-room-code" maxlength="24" placeholder="WATCH-AB12CD34" />
    <div class="row">
      <button id="frenzy-start" class="primary">Start Party</button>
      <button id="frenzy-join">Join Party</button>
    </div>
    <div class="row">
      <button id="frenzy-copy">Copy Invite</button>
      <button id="frenzy-open">Open FlickFuse</button>
    </div>
    <div id="frenzy-status" class="muted">Use your current page as the party source.</div>
  `;

  document.documentElement.appendChild(fab);
  document.documentElement.appendChild(panel);

  const input = panel.querySelector("#frenzy-room-code");
  const status = panel.querySelector("#frenzy-status");
  input.value = detectSuggestedCode();

  function setStatus(text) {
    status.textContent = text;
  }

  function roomCode() {
    input.value = cleanRoomCode(input.value);
    return input.value;
  }

  async function startPartyForUrl(sourceUrl, explicitCode = "") {
    const code = cleanRoomCode(explicitCode || codeFromUrl(sourceUrl));
    const res = await send("telewatch:start_party", {
      roomCode: code,
      sourceUrl
    });
    if (res && res.ok) {
      setStatus(`Started ${res.roomCode}`);
      return res;
    }
    setStatus(`Failed: ${res && res.error ? res.error : "unknown"}`);
    return res;
  }

  fab.addEventListener("click", () => {
    panel.classList.toggle("hidden");
  });

  panel.querySelector("#frenzy-start").addEventListener("click", async () => {
    await startPartyForUrl(location.href, roomCode());
  });

  panel.querySelector("#frenzy-join").addEventListener("click", async () => {
    const res = await send("telewatch:join_party", {
      roomCode: roomCode()
    });
    if (res && res.ok) {
      setStatus(`Joining ${res.roomCode}`);
    } else {
      setStatus(`Failed: ${res && res.error ? res.error : "unknown"}`);
    }
  });

  panel.querySelector("#frenzy-open").addEventListener("click", async () => {
    await startPartyForUrl("", roomCode());
    setStatus("Opened FlickFuse.");
  });

  panel.querySelector("#frenzy-copy").addEventListener("click", async () => {
    const code = roomCode();
    if (!code) {
      setStatus("Enter a room code first.");
      return;
    }
    const url = `https://frenzynets.com/telewatch/?room=${encodeURIComponent(code)}&source=extension`;
    try {
      await navigator.clipboard.writeText(url);
      setStatus("Invite copied.");
    } catch {
      setStatus(url);
    }
  });

  function injectPartyButtons() {
    const links = document.querySelectorAll("a[href]");
    for (const a of links) {
      if (!isLikelyWatchLink(a)) continue;
      if (a.dataset.flickfusePartyInjected === "1") continue;
      a.dataset.flickfusePartyInjected = "1";

      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "frenzy-link-party";
      btn.textContent = "Start Party";
      btn.title = "Start FlickFuse party for this title";
      btn.addEventListener("click", async (ev) => {
        ev.preventDefault();
        ev.stopPropagation();
        const target = a.href || location.href;
        input.value = codeFromUrl(target);
        await startPartyForUrl(target, input.value);
      });

      const wrap = document.createElement("span");
      wrap.className = "frenzy-link-party-wrap";
      wrap.appendChild(btn);
      if (a.parentElement) a.insertAdjacentElement("afterend", wrap);
    }
  }

  injectPartyButtons();
  const mo = new MutationObserver(() => injectPartyButtons());
  mo.observe(document.documentElement, { childList: true, subtree: true });
})();
