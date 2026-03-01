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

  fab.addEventListener("click", () => {
    panel.classList.toggle("hidden");
  });

  panel.querySelector("#frenzy-start").addEventListener("click", async () => {
    const res = await send("telewatch:start_party", {
      roomCode: roomCode(),
      sourceUrl: location.href
    });
    if (res && res.ok) {
      setStatus(`Started ${res.roomCode}`);
    } else {
      setStatus(`Failed: ${res && res.error ? res.error : "unknown"}`);
    }
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
    await send("telewatch:start_party", { roomCode: roomCode(), sourceUrl: "" });
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
})();
