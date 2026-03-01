(() => {
  if (document.getElementById("frenzy-telewatch-rail")) return;

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
    if (href.includes("/flickfuse/")) return false;
    if (href.includes("/watch/") || href.includes("/title/") || href.includes("/video/")) return true;
    if (href.includes("netflix.com/title/") || href.includes("youtube.com/watch") || href.includes("primevideo.com/detail") || href.includes("disneyplus.com/video")) return true;
    if (text.includes("watch") || text.includes("play") || text.includes("trailer")) return true;
    return false;
  }

  async function send(type, payload = {}) {
    return chrome.runtime.sendMessage({ type, ...payload });
  }

  const rail = document.createElement("aside");
  rail.id = "frenzy-telewatch-rail";
  rail.className = "ff-open";
  rail.innerHTML = `
    <div class="ff-edge">
      <button id="ff-toggle" type="button" title="Toggle FlickFuse rail">FF</button>
    </div>
    <div class="ff-shell">
      <header class="ff-top">
        <div class="ff-brand"><span class="ff-dot"></span>FF</div>
        <button id="ff-upgrade" class="ff-upgrade" type="button">Upgrade</button>
        <div class="ff-icons">
          <button id="ff-users" type="button" title="Members">1</button>
          <button id="ff-share" type="button" title="Share">+</button>
          <button id="ff-close" type="button" title="Close">x</button>
        </div>
      </header>
      <section class="ff-ann">
        <h3>Announcements</h3>
        <div class="ff-ann-card">Premium members get ad shield, voice priority, and AI bot access.</div>
      </section>
      <section class="ff-feed-wrap">
        <div id="ff-feed" class="ff-feed"></div>
      </section>
      <div class="ff-reactions">
        <button type="button">😍</button>
        <button type="button">😮</button>
        <button type="button">😭</button>
        <button type="button">😂</button>
        <button type="button">🔥</button>
      </div>
      <form id="ff-compose" class="ff-compose">
        <input id="ff-msg" maxlength="180" placeholder="Type a message..." />
        <button id="ff-send" type="submit">Send</button>
      </form>
      <div class="ff-row">
        <button id="ff-mic" type="button">Mic</button>
        <button id="ff-cam" type="button">Cam</button>
      </div>
      <input id="frenzy-room-code" maxlength="24" placeholder="WATCH-AB12CD34" />
      <div class="ff-row">
        <button id="frenzy-start" class="primary" type="button">Set a party</button>
        <button id="frenzy-join" type="button">Join</button>
      </div>
      <div class="ff-row">
        <button id="frenzy-copy" type="button">Copy invite</button>
        <button id="frenzy-open" type="button">Open app</button>
      </div>
      <div id="frenzy-status" class="ff-muted">Use this page as your synced source.</div>
    </div>
  `;

  document.documentElement.appendChild(rail);

  const input = rail.querySelector("#frenzy-room-code");
  const status = rail.querySelector("#frenzy-status");
  const feed = rail.querySelector("#ff-feed");
  const compose = rail.querySelector("#ff-compose");
  const msgInput = rail.querySelector("#ff-msg");

  function addFeedLine(message, type = "system") {
    const line = document.createElement("div");
    line.className = `ff-line ${type}`;
    line.textContent = message;
    feed.appendChild(line);
    feed.scrollTop = feed.scrollHeight;
  }

  addFeedLine("created the party.", "system");
  addFeedLine("started playing the video at 00:00", "system");
  input.value = detectSuggestedCode();

  function setStatus(text) {
    status.textContent = text;
    addFeedLine(text, "system");
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

  rail.querySelector("#ff-toggle").addEventListener("click", () => {
    rail.classList.toggle("ff-open");
  });

  rail.querySelector("#ff-close").addEventListener("click", () => {
    rail.classList.remove("ff-open");
  });

  rail.querySelector("#ff-share").addEventListener("click", async () => {
    const code = roomCode();
    const url = `https://frenzynets.com/FlickFuse/?room=${encodeURIComponent(code)}&source=extension`;
    try {
      await navigator.clipboard.writeText(url);
      setStatus("Invite copied.");
    } catch {
      setStatus(url);
    }
  });

  compose.addEventListener("submit", (ev) => {
    ev.preventDefault();
    const text = String(msgInput.value || "").trim();
    if (!text) return;
    addFeedLine(text, "user");
    msgInput.value = "";
  });

  rail.querySelector("#frenzy-start").addEventListener("click", async () => {
    await startPartyForUrl(location.href, roomCode());
  });

  rail.querySelector("#frenzy-join").addEventListener("click", async () => {
    const res = await send("telewatch:join_party", {
      roomCode: roomCode()
    });
    if (res && res.ok) {
      setStatus(`Joining ${res.roomCode}`);
    } else {
      setStatus(`Failed: ${res && res.error ? res.error : "unknown"}`);
    }
  });

  rail.querySelector("#frenzy-open").addEventListener("click", async () => {
    await startPartyForUrl("", roomCode());
    setStatus("Opened FlickFuse.");
  });

  rail.querySelector("#frenzy-copy").addEventListener("click", async () => {
    const code = roomCode();
    if (!code) {
      setStatus("Enter a room code first.");
      return;
    }
    const url = `https://frenzynets.com/FlickFuse/?room=${encodeURIComponent(code)}&source=extension`;
    try {
      await navigator.clipboard.writeText(url);
      setStatus("Invite copied.");
    } catch {
      setStatus(url);
    }
  });

  for (const id of ["ff-mic", "ff-cam", "ff-upgrade"]) {
    const button = rail.querySelector(`#${id}`);
    if (!button) continue;
    button.addEventListener("click", () => {
      if (id === "ff-upgrade") {
        window.open("https://frenzynets.com/FlickFuse/#plans", "_blank", "noopener");
        return;
      }
      button.classList.toggle("active");
      const label = id === "ff-mic" ? "Mic" : "Cam";
      setStatus(`${label} ${button.classList.contains("active") ? "on" : "off"}.`);
    });
  }

  function injectPartyButtons() {
    const links = document.querySelectorAll("a[href]");
    for (const a of links) {
      if (!isLikelyWatchLink(a)) continue;
      if (a.dataset.flickfusePartyInjected === "1") continue;
      a.dataset.flickfusePartyInjected = "1";

      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "frenzy-link-party";
      btn.textContent = "Set a party";
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
