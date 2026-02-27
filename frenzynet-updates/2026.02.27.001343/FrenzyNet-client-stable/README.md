# FrenzyNet (Windows UI with login)

This app now uses the VPS control API as the source of truth.

## Runtime behavior
- Login goes to `https://frenzynets.com/api/frenzynet/api/auth/login`
- Allowed profile list is fetched from API after login
- Configs are downloaded live from API on connect/export
- In-app update is manual from the dashboard `Update` button by default
- `FrenzyNet-Launcher.exe` can be used to watchdog/restart `FrenzyNet.exe` on crash/hidden-start failures

## Build Windows EXE
```bash
cd /opt/wireguard/VpnLauncher
./build-win-x64.sh
```

`build-win-x64.sh` now also refreshes `dist/` automatically (including `FrenzyNet-Launcher.exe`).

## Publish update package + manifest (for auto-update)
```bash
sudo /opt/wireguard/VpnLauncher/publish-update.sh
```
Optional version override:
```bash
sudo /opt/wireguard/VpnLauncher/publish-update.sh 2026.02.24.170000
```

## Authenticode signing (reduce SmartScreen warnings)
1. Place your code-signing `.pfx` on the VPS.
2. Run:
```bash
sudo /opt/wireguard/VpnLauncher/configure-codesign.sh /path/to/cert.pfx 'YOUR_PFX_PASSWORD' 'Your Publisher Name'
```
This stores signing env vars in `/etc/frenzynet-control-api.env` and publishes a signed stable build.
