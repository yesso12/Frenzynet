const TELEWATCH_BASE = "https://frenzynets.com/FlickFuse/";
const ADBLOCK_RULESET_ID = "adblock_rules";

async function applyAdblockState(enabled) {
  await chrome.declarativeNetRequest.updateEnabledRulesets({
    enableRulesetIds: enabled ? [ADBLOCK_RULESET_ID] : [],
    disableRulesetIds: enabled ? [] : [ADBLOCK_RULESET_ID]
  });
}

async function ensureAdblockInitialized() {
  const data = await chrome.storage.local.get(["adblockEnabled"]);
  const enabled = Boolean(data && data.adblockEnabled);
  await applyAdblockState(enabled);
}

function cleanRoomCode(raw = "") {
  return String(raw).toUpperCase().replace(/[^A-Z0-9_-]/g, "").slice(0, 24);
}

function randomRoomCode() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let out = "";
  for (let i = 0; i < 8; i += 1) {
    out += alphabet[Math.floor(Math.random() * alphabet.length)];
  }
  return `WATCH-${out}`;
}

async function openTelewatchRoom(roomCode, sourceUrl = "") {
  const code = cleanRoomCode(roomCode) || randomRoomCode();
  const params = new URLSearchParams({
    room: code,
    source: "extension"
  });
  if (sourceUrl) params.set("media", sourceUrl);
  const url = `${TELEWATCH_BASE}?${params.toString()}`;
  await chrome.storage.local.set({ lastRoomCode: code, lastMediaUrl: sourceUrl || "", lastOpenAt: Date.now() });
  await chrome.tabs.create({ url });
  return { ok: true, roomCode: code, url };
}

chrome.runtime.onInstalled.addListener(async () => {
  const data = await chrome.storage.local.get(["adblockEnabled"]);
  if (typeof data.adblockEnabled !== "boolean") {
    await chrome.storage.local.set({ adblockEnabled: false });
  }
  await ensureAdblockInitialized();
});

chrome.runtime.onStartup.addListener(async () => {
  await ensureAdblockInitialized();
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      if (!msg || typeof msg !== "object") return;
      if (msg.type === "adblock:get_state") {
        const data = await chrome.storage.local.get(["adblockEnabled"]);
        const enabled = Boolean(data && data.adblockEnabled);
        sendResponse({ ok: true, enabled, ruleCount: 100 });
        return;
      }
      if (msg.type === "adblock:set_enabled") {
        const enabled = Boolean(msg.enabled);
        await chrome.storage.local.set({ adblockEnabled: enabled, adblockUpdatedAt: Date.now() });
        await applyAdblockState(enabled);
        sendResponse({ ok: true, enabled });
        return;
      }
      if (msg.type === "telewatch:start_party") {
        const roomCode = cleanRoomCode(msg.roomCode || "") || randomRoomCode();
        const sourceUrl = String(msg.sourceUrl || sender?.tab?.url || "").slice(0, 1500);
        const result = await openTelewatchRoom(roomCode, sourceUrl);
        sendResponse(result);
        return;
      }
      if (msg.type === "telewatch:join_party") {
        const roomCode = cleanRoomCode(msg.roomCode || "");
        if (!roomCode) {
          sendResponse({ ok: false, error: "room_required" });
          return;
        }
        const result = await openTelewatchRoom(roomCode, "");
        sendResponse(result);
        return;
      }
      if (msg.type === "telewatch:get_last") {
        const data = await chrome.storage.local.get(["lastRoomCode", "lastMediaUrl", "lastOpenAt"]);
        sendResponse({ ok: true, ...data });
        return;
      }
    } catch (err) {
      sendResponse({ ok: false, error: String(err && err.message ? err.message : err) });
    }
  })();
  return true;
});
