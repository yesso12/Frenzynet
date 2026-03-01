# FlickFuse Browser Extension

Manifest V3 extension that gives Frenzy an extension-style watch-party workflow similar to Teleparty's UX model:
- Start party from current streaming tab
- Join party by room code
- Copy shareable invite
- Floating in-page launcher on supported streaming sites

## Install (Chrome/Edge/Brave)

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select this folder: `browser-extension/frenzy-telewatch-extension`

## Supported sites (overlay launcher)

- netflix.com
- youtube.com
- disneyplus.com
- hulu.com
- primevideo.com

## Core flow

- Click extension icon -> `Start Party`
- Extension opens: `https://frenzynets.com/FlickFuse/?room=...&source=extension&media=...`
- Share copied invite URL with friends

## Notes

- This extension launches and coordinates your FlickFuse room URLs.
- Playback/media transport logic remains in the FlickFuse web app.
