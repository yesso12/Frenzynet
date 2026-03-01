function cleanRoomCode(raw = "") {
  return String(raw).toUpperCase().replace(/[^A-Z0-9_-]/g, "").slice(0, 24);
}

function setStatus(text, isErr = false) {
  const el = document.getElementById("status");
  el.textContent = text || "";
  el.classList.toggle("err", Boolean(isErr));
}

async function getActiveTab() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  return tabs && tabs[0] ? tabs[0] : null;
}

async function startParty() {
  const roomInput = document.getElementById("roomCode");
  const roomCode = cleanRoomCode(roomInput.value);
  roomInput.value = roomCode;
  const tab = await getActiveTab();
  const sourceUrl = tab && tab.url ? tab.url : "";
  return chrome.runtime.sendMessage({ type: "telewatch:start_party", roomCode, sourceUrl });
}

async function joinParty() {
  const roomInput = document.getElementById("roomCode");
  const roomCode = cleanRoomCode(roomInput.value);
  roomInput.value = roomCode;
  return chrome.runtime.sendMessage({ type: "telewatch:join_party", roomCode });
}

async function openFlickFuse() {
  await chrome.tabs.create({ url: "https://frenzynets.com/telewatch/?source=extension" });
  return { ok: true };
}

async function copyInvite() {
  const roomCode = cleanRoomCode(document.getElementById("roomCode").value);
  if (!roomCode) throw new Error("Enter a room code first.");
  const url = `https://frenzynets.com/telewatch/?room=${encodeURIComponent(roomCode)}&source=extension`;
  await navigator.clipboard.writeText(url);
  return url;
}

async function refreshLast() {
  const data = await chrome.runtime.sendMessage({ type: "telewatch:get_last" });
  const last = document.getElementById("lastRoom");
  if (data && data.lastRoomCode) {
    last.textContent = `Last room: ${data.lastRoomCode}`;
  }
}

async function refreshAdblockState() {
  const data = await chrome.runtime.sendMessage({ type: "adblock:get_state" });
  const stateEl = document.getElementById("adblockState");
  const toggleBtn = document.getElementById("adblockToggleBtn");
  if (!data || !data.ok) {
    stateEl.textContent = "Ad Shield: unavailable";
    toggleBtn.textContent = "Enable Ad Shield";
    return;
  }
  stateEl.textContent = `Ad Shield: ${data.enabled ? "enabled" : "disabled"} (${Number(data.ruleCount || 0)} rules)`;
  toggleBtn.textContent = data.enabled ? "Disable Ad Shield" : "Enable Ad Shield";
}

async function toggleAdblock() {
  const data = await chrome.runtime.sendMessage({ type: "adblock:get_state" });
  const next = !(data && data.ok && data.enabled);
  const setRes = await chrome.runtime.sendMessage({ type: "adblock:set_enabled", enabled: next });
  if (!setRes || !setRes.ok) {
    throw new Error(setRes && setRes.error ? setRes.error : "adblock_toggle_failed");
  }
  await refreshAdblockState();
}

async function boot() {
  const roomInput = document.getElementById("roomCode");
  roomInput.addEventListener("input", () => {
    roomInput.value = cleanRoomCode(roomInput.value);
  });

  document.getElementById("startBtn").addEventListener("click", async () => {
    try {
      const res = await startParty();
      if (!res || !res.ok) throw new Error(res && res.error ? res.error : "failed");
      setStatus(`Started room ${res.roomCode}`);
      await refreshLast();
      window.close();
    } catch (err) {
      setStatus(String(err && err.message ? err.message : err), true);
    }
  });

  document.getElementById("joinBtn").addEventListener("click", async () => {
    try {
      const res = await joinParty();
      if (!res || !res.ok) throw new Error(res && res.error ? res.error : "failed");
      setStatus(`Joining room ${res.roomCode}`);
      await refreshLast();
      window.close();
    } catch (err) {
      setStatus(String(err && err.message ? err.message : err), true);
    }
  });

  document.getElementById("openBtn").addEventListener("click", async () => {
    await openFlickFuse();
    setStatus("Opened FlickFuse.");
    window.close();
  });

  document.getElementById("copyBtn").addEventListener("click", async () => {
    try {
      const url = await copyInvite();
      setStatus("Invite copied.");
      console.debug(url);
    } catch (err) {
      setStatus(String(err && err.message ? err.message : err), true);
    }
  });

  document.getElementById("adblockToggleBtn").addEventListener("click", async () => {
    try {
      await toggleAdblock();
      setStatus("Ad Shield updated.");
    } catch (err) {
      setStatus(String(err && err.message ? err.message : err), true);
    }
  });

  document.getElementById("adblockRefreshBtn").addEventListener("click", async () => {
    await refreshAdblockState();
    setStatus("Ad Shield status refreshed.");
  });

  await refreshLast();
  await refreshAdblockState();
}

boot();
