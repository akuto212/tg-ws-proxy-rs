# tg-ws-proxy-rs

MTProto proxy for Telegram that works through WebSocket transport. Written in Rust.

Based on [tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy) by Flowseal.

## How it works

Telegram clients connect to the proxy via the MTProto protocol. The proxy encrypts traffic and forwards it to Telegram servers over WebSocket connections. This allows the proxy to work in networks where direct connections to Telegram are blocked, but WebSocket traffic is allowed.

Key features:
- **WebSocket tunneling** -- MTProto traffic is wrapped in WebSocket frames and sent through standard HTTPS (port 443)
- **Connection pooling** -- pre-established WebSocket connections to Telegram DCs reduce latency
- **System tray** -- runs in the background with a tray icon (Windows/Linux/macOS), shows connection stats, copy link, autostart toggle

## Installation

### Download binary

Go to [Releases](../../releases) and download the binary for your platform.

### Build from source

Requirements: [Rust](https://rustup.rs/) 1.75+

```bash
git clone https://github.com/akuto/tg-ws-proxy-rs.git
cd tg-ws-proxy-rs
cargo build --release
```

The binary will be at `target/release/proxy-app` (or `proxy-app.exe` on Windows).

## Usage

### GUI mode (default)

Just run the binary. It will start in the system tray with a generated secret. Right-click the tray icon to:
- Open the proxy link in Telegram
- Copy the `tg://` link to clipboard
- Toggle autostart (Windows)
- Toggle error logging
- View connection stats

### CLI mode

```bash
proxy-app --no-tray
```

### Options

```
  -p, --port <PORT>          Listen port [default: 1443]
      --host <HOST>          Listen address [default: 127.0.0.1]
      --secret <SECRET>      32 hex character secret (auto-generated if not set)
      --dc-ip <DC:IP>        DC redirect, e.g. 2:149.154.167.220
      --no-tray              Run in console mode without system tray
      --pool-size <N>        WebSocket connection pool size [default: 4]
      --buf-kb <KB>          Buffer size in KB [default: 64]
  -v, --verbose              Enable debug logging (console mode)
      --setup                Open proxy link in Telegram and exit
```

### Examples

Run on all interfaces with custom port:
```bash
proxy-app --no-tray --host 0.0.0.0 --port 8443
```

Use a specific secret:
```bash
proxy-app --no-tray --secret 0123456789abcdef0123456789abcdef
```

### Configuration

On first run, a `config.json` is saved next to the binary. It stores the secret and settings so they persist between restarts.

## Platform notes

| Platform | Tray icon | Autostart | Notes |
|----------|-----------|-----------|-------|
| Windows  | Yes       | Yes (registry) | Runs as a window app in release mode |
| Linux    | Yes       | No        | Requires a system tray implementation (e.g. KDE, GNOME with extension) |
| macOS    | Yes       | No        | Works with the default menu bar |

On all platforms, `--no-tray` mode works without any GUI dependencies.

## License

[MIT](LICENSE)
