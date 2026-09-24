# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## Overview

PyQt5 tray applet that answers one question: *is the internet actually reachable right now?*
It polls several targets, shows an aggregate status in the tray icon (with a latency sparkline
drawn into it), and offers a window with a live latency chart.
Single file, [pinger.py](pinger.py) — no build system, no tests, no package metadata.
[pinger_icmp_old.py](pinger_icmp_old.py) is the original 37-line ICMP version, kept only for reference.

## Running

```bash
python3 pinger.py
```

`--window` also opens the chart window at startup (it opens automatically when no system tray is available).
Depends on system PyQt5 (`python3-pyqt5`, `/usr/lib/python3/dist-packages/PyQt5`), not pip/venv.
Requires QtNetwork; QtChart is **not** installed, so the chart is hand-drawn with `QPainter`.

Headless smoke test (no display needed):

```bash
QT_QPA_PLATFORM=offscreen python3 -c "import pinger" && python3 pinger.py --window
```

Under `offscreen`, `QWidget.grab().save(path)` is the way to eyeball layout changes without a session.

## Why not ICMP

The original version pinged `8.8.8.8` and was silently useless behind the Happ proxy.
Happ (like sing-box/xray) creates `tun0` and installs `ip rule` entries (priorities 9000–9010) that push
everything into routing table 2022. Its userspace TCP/IP stack **answers ICMP echo locally** without
forwarding, so `ping` reports a steady ~0.1 ms while the internet is completely down.
Verify with `ip route get 8.8.8.8` — if it resolves via `tun0`, ICMP measures nothing.

Any replacement check must therefore make a real TCP/TLS round trip **and validate the payload**,
since DNS hijacking and captive portals both produce a successful connection with wrong content.

## Architecture

Four layers, all in one file, wired by Qt signals — no threads anywhere:

- `Target` — one endpoint plus a bounded `deque` of `(timestamp, ms|None, state, detail)` samples.
  All statistics (average, loss %) are derived from that window; there are no lifetime counters.
- `Monitor(QObject)` — owns a single `QNetworkAccessManager`, a repeating `QTimer`, and the aggregate
  verdict. Emits `updated` after every sample; verdict transitions only stamp `state_since`.
- `ChartWidget` / `MainWindow` — presentation; repaint on `updated`.
- `TrayApp` — tray icon, menu; owns the window and monitor. Deliberately has no popup notifications:
  status is communicated by the icon alone.

Probing is fully asynchronous via Qt's event loop (`QNetworkAccessManager.get`, `QTcpSocket.connectToHost`),
so blocking calls like `subprocess`, `requests`, or `socket` must not be introduced — they would freeze the UI.

### Per-sample states vs. aggregate states

Both live in `STATE_COLORS`, which is why that dict has more keys than `STATE_TEXT`:

- Per-target: `ok` (expected status *and* expected body substring), `bad` (connected, wrong content —
  captive portal, DNS hijack, unexpected redirect), `fail` (timeout, refused, DNS failure).
- Aggregate (`Monitor._recompute`): `ok` / `degraded` / `portal` / `down` / `unknown` / `paused`.

Three settings exist specifically to preserve `bad` detection; changing them re-breaks proxy detection:
`ManualRedirectPolicy` (so a captive portal's 302 surfaces as an unexpected status rather than being
followed), `setCache(None)` + `AlwaysNetwork` (so a cached 204 can't fake liveness), and the
`expect_body` substring check.

## Configuration

`~/.config/pinger/config.json` (respects `XDG_CONFIG_HOME`), written with defaults on first run.
Default poll interval is 15 s; `timeout_ms` must stay below `interval_ms`, or a hung probe is skipped by the
`inflight` guard and leaves a gap in the history instead of recording a failure. `MainWindow` picks its
starting chart range from the interval (smallest range holding ~40 samples), so changing the interval does
not leave the chart with a handful of points.
Unknown keys fall back to `DEFAULT_CONFIG` via a shallow `update`, so nested target specs are all-or-nothing.
Point `XDG_CONFIG_HOME` at a scratch directory to test alternate targets without touching the real config.

Targets are either HTTP (`url`, `expect_status`, `expect_body`) or TCP (`"type": "tcp"`, `host`, `port`) —
the TCP kind is for checking a router or a specific service, and distinguishes "LAN alive, internet dead".

Defaults use captive-portal detection endpoints (`generate_204`, `cdn-cgi/trace`, `success.txt`) because they
are tiny, unauthenticated, and have a precisely known response — which is what makes body validation possible.
Any replacement target needs the same property.

## Conventions

Comments, docstrings, and all user-facing strings are in Russian; keep new ones that way.
