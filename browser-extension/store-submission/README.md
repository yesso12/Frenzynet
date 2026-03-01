# FlickFuse Store Submission Pack

This folder contains pre-written listing metadata for extension stores.

## Included
- `chrome-web-store-listing.md`
- `firefox-addon-listing.md`
- `edge-addon-listing.md`
- `privacy-policy.md`
- `support-and-contact.md`
- `release-notes.md`

## Publish flow
1. Build fresh extension zips:
   - `bash scripts/package-extension.sh`
2. Build a submission artifact zip:
   - `bash scripts/build-store-submission.sh`
3. Upload package to each store dashboard.
4. Paste listing text from matching markdown file.
5. Add screenshots (1280x800 or larger) from live extension UI.

## Notes
- Store search visibility is delayed until review and indexing complete.
- Manual ZIP installers remain available at `/frenzynet-updates/`.
