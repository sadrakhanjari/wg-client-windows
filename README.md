# wg-client-windows

Pure-Python WireGuard client for Windows with a dark CustomTkinter UI.

Implements the WireGuard protocol (Noise_IK handshake, ChaCha20-Poly1305 data
plane, replay protection) directly in Python and drives the TUN interface
through `wintun.dll` — no dependency on the official WireGuard GUI.

## Features
- Standalone — no dependency on the official WireGuard application
- Dark mode UI
- Add / edit / delete tunnels (`.conf` import)
- Live stats: ping, uptime, RX/TX speed, totals, endpoint
- Auto-reconnect when download speed drops below a configurable threshold
- Split routing (include / exclude rules) and system tray
- DNS changer on the main page: live status of which resolver is set, one-click
  Set / Unset, and a built-in **DNS test** (ICMP latency + packet loss + real
  DNS-query round-trip) that ranks servers best-first
- 90+ curated resolvers out of the box, including Iranian anti-sanction /
  gaming DNS (Shecan, 403, RadarGame, Electro, Begzar, Shelter, …)
- On-screen overlay (HUD) showing live speed/ping in a screen corner

## Requirements
- Windows 10/11
- Python 3.12
- `customtkinter`, `cryptography`, `pystray`, `Pillow`
- `wintun.dll` (bundled in `vendor/`)

## Run
```
run.bat
```
(triggers UAC for admin privileges — required to create the Wintun adapter)

## Build a standalone executable
```
build.bat
```
Produces `dist\LocalWireGuard\LocalWireGuard.exe`. Optionally compile
`installer.iss` with Inno Setup to produce a setup wizard.

## Tests
Each file under `tests/` is a standalone runner:
```
python tests\test_wgproto.py
```
