# FlickFuse Store Review Checklist (Chrome First)

Last updated: 2026-03-01

## 1) Package and sanity check
- Build package: `bash scripts/package-extension.sh`
- Use upload file: `site/frenzynet-updates/flickfuse-extension-chromium-latest.zip`
- Confirm `manifest.json` is present at zip root.
- Confirm extension name/version are correct.

## 2) Required listing fields (Chrome)
- Name: `FlickFuse Party`
- Short description: from `chrome-web-store-listing.md`
- Full description: from `chrome-web-store-listing.md`
- Category: `Social & Communication`
- Website URL: `https://frenzynets.com/FlickFuse/`
- Support URL: `https://frenzynets.com/frenzynet-updates/`
- Privacy policy URL: `https://frenzynets.com/legal/`

## 3) Image specs you need before submit
- App icon: 128x128 PNG (required)
- Small tile icon: 16x16 PNG (recommended)
- Marquee promo tile: 1400x560 PNG (recommended)
- Screenshots: at least 1, up to 5+
- Screenshot size: 1280x800 or 640x400 PNG/JPG

## 4) Screenshot shot list (take these exact screens)
- Screenshot 1: In-page right rail open on a streaming page
- Screenshot 2: "Set a party" button + room code + invite copy
- Screenshot 3: Chat/reactions visible in rail
- Screenshot 4: Mic/cam toggle controls visible
- Screenshot 5: Extension popup showing Start/Join + Ad Shield

## 5) Policy answers that must match code
- Data sale: `No`
- Personal/sensitive data sale: `No`
- Credentials handling: extension does not collect account passwords
- Storage use: local extension settings only (room code + toggles)
- Remote code: do not claim remote code execution
- Host permissions: explain they are for watch-page UI injection and party controls

## 6) Common rejection triggers to avoid
- Description claims not implemented features
- Missing or broken privacy policy URL
- Missing functional screenshots
- Mentioning "works on everything" without limits
- Misleading ad-blocking claims beyond declared ruleset behavior

## 7) Final pre-submit test in clean browser profile
- Install unpacked extension
- Open Netflix/YouTube/Hulu page
- Confirm rail appears and toggles open/close
- Confirm Start/Join opens `https://frenzynets.com/FlickFuse/`
- Confirm Copy Invite works
- Confirm no console errors on extension pages

## 8) After approval
- Replace website store search links with direct listing URL
- Announce install URL in Discord and site hero CTA
- Keep versioned release notes updated
