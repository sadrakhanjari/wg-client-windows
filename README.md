# wg-client-windows

Pure-Python WireGuard client for Windows with a dark CustomTkinter UI.

## Status
**Work in progress.** Phase 0 (PoC wrapping the official `wireguard.exe`) is functional. Phase 1+ (pure-Python protocol implementation using Wintun) is in progress.

See `CLAUDE.md` for the full plan and current phase.

## Features (planned)
- Standalone — no dependency on the official WireGuard GUI
- Dark mode UI
- Add / edit / delete tunnels
- Live stats: ping, uptime, RX/TX speed, totals, endpoint
- Auto-reconnect when download speed drops below a configurable threshold

## Requirements
- Windows 10/11
- Python 3.12
- `customtkinter`, `cryptography`
- `wintun.dll` (Phase 3+)

## Run
```
run.bat
```
(triggers UAC for admin privileges)
