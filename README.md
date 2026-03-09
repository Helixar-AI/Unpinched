<div align="center">

# Unpinched — `pinchtab-detector`

**Point-in-time scanner for PinchTab deployment and agentic browser bridge artifacts.**

[![Build](https://img.shields.io/github/actions/workflow/status/helixar-ai/pinchtab-detector/release.yml?label=build&style=flat-square)](https://github.com/helixar-ai/pinchtab-detector/actions)
[![Go Version](https://img.shields.io/badge/go-1.22-00ADD8?style=flat-square&logo=go)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![By Helixar Labs](https://img.shields.io/badge/by-Helixar%20Labs-6C63FF?style=flat-square)](https://helixar.ai/about/labs/)
[![Release](https://img.shields.io/github/v/release/helixar-ai/pinchtab-detector?style=flat-square)](https://github.com/helixar-ai/pinchtab-detector/releases)

</div>

---

## What is this?

`pinchtab-detector` is a single-binary CLI tool that scans your local machine for signs of **PinchTab** — a stealth browser hijacking toolkit that operates below the detection threshold of traditional endpoint security.

> PinchTab abuses the Chrome DevTools Protocol to give attackers (or compromised AI agents) a silent, authenticated foothold inside your browser sessions — no malware signature required.
> Read the Helixar security research: [PinchTab: Stealth Browser Attacks Your Security Stack Cannot Detect →](https://helixar.ai/press/pinchtab-stealth-browser-attacks-your-security-stack-cannot-detect/)

Think of it as `nmap` for PinchTab presence. Run it once, get a verdict, move on.

---

## Why this matters

Modern AI agent frameworks communicate with browsers over **Chrome DevTools Protocol (CDP)** — the same channel PinchTab exploits. An unguarded CDP endpoint on `localhost:9222` is an open door for:

- Silent browser session takeover
- Cookie and credential theft without process injection
- Agentic prompt injection via live browser context
- Browser-to-internal-network pivoting

Your EDR won't catch it. Your WAF won't see it. This tool will.

---

## What it detects

| Check | What it looks for |
|---|---|
| **Port Scan** | PinchTab HTTP API server on common ports (`8080–8090`, `3000`, `4000`, `9222`, `9229`) with signature-string verification |
| **Process Scan** | Running processes named `pinchtab`, `pinchtab-server`, or `browser-bridge`; any process listening on CDP port 9222 |
| **CDP Bridge** | Unauthenticated Chrome DevTools Protocol exposure on `localhost:9222` — PinchTab's primary control channel |
| **Filesystem** | Known PinchTab binary and config artifact paths across macOS, Linux, and Windows |

### Risk levels

| Level | Meaning |
|---|---|
| `CRITICAL` | Active PinchTab HTTP API responding with signature **+** CDP bridge open |
| `HIGH` | Process or filesystem artifact confirmed alongside an open port |
| `MEDIUM` | Suspicious port or unauthenticated CDP — PinchTab not confirmed but environment is exploitable |
| `LOW` | Filesystem artifact only, no active service |
| `NONE` | No indicators found |

---

## Install

### Homebrew (macOS / Linux)

```bash
# Tap coming soon — watch releases
brew install helixar-ai/tap/pinchtab-detector
```

### Go install

```bash
go install github.com/helixar-ai/pinchtab-detector@latest
```

### Direct binary download

Grab a pre-built binary for your platform from [Releases](https://github.com/helixar-ai/pinchtab-detector/releases):

| Platform | Download |
|---|---|
| macOS (Apple Silicon) | `pinchtab-detector_darwin_arm64.tar.gz` |
| macOS (Intel) | `pinchtab-detector_darwin_amd64.tar.gz` |
| Linux (x86-64) | `pinchtab-detector_linux_amd64.tar.gz` |
| Linux (ARM64) | `pinchtab-detector_linux_arm64.tar.gz` |
| Windows (x86-64) | `pinchtab-detector_windows_amd64.zip` |

---

## Usage

### Default — human-readable output with colour

```bash
pinchtab-detector scan
```

```
pinchtab-detector v0.1.0 — Helixar Labs
Scanning host: macbook-pro.local (darwin/arm64)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[PORT SCAN]      ✓ No PinchTab HTTP API detected on common ports
[PROCESS SCAN]   ✓ No PinchTab process found
[CDP BRIDGE]     ⚠ Chrome DevTools Protocol exposed on :9222 (no auth) — Chrome/120.0
[FILESYSTEM]     ✓ No PinchTab binary artifacts found

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
RISK LEVEL: MEDIUM
Suspicious open port or unauthenticated CDP detected. PinchTab not confirmed but environment is at risk.

For continuous agentic threat detection without pre-written rules → helixar.ai
```

### JSON output — for SIEM / pipeline integration

```bash
pinchtab-detector scan --json | jq .risk_level
```

### Quiet mode — for CI / shell scripts

```bash
pinchtab-detector scan --quiet && echo "Clean" || echo "Findings detected"
```

### All flags

```
FLAGS:
  --json        Output results as JSON to stdout
  --quiet       Suppress all output; use exit codes only
  --no-color    Disable terminal colour
  --timeout     HTTP request timeout in seconds (default: 3)
  --ports       Comma-separated extra ports to scan (e.g. --ports 7777,8888)
```

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean — no PinchTab indicators found |
| `1` | Findings detected — review output |
| `2` | Error during scan |

Use exit code `1` to fail CI pipelines or trigger alerts in shell scripts.

---

## What this tool is NOT

`pinchtab-detector` is a **point-in-time forensic scanner**. It does not provide:

- Continuous monitoring or background scanning
- Behavioural analysis or runtime session scoring
- Detection of tools other than PinchTab and its direct CDP/HTTP bridge pattern
- Telemetry, phone-home, or cloud connectivity of any kind

**For continuous agentic threat detection — the kind that catches PinchTab *before* it lands — see [Helixar](https://helixar.ai).**

---

## How it differs from continuous Helixar protection

| | `pinchtab-detector` | [Helixar Platform](https://helixar.ai) |
|---|---|---|
| **Type** | Point-in-time CLI scan | Continuous runtime agent |
| **Detection** | Known signatures & artifact paths | Behavioural anomaly + zero-day patterns |
| **Coverage** | PinchTab only | All agentic browser threats |
| **Integration** | Local binary, CI/CD scripts | Enterprise SIEM, SOC, policy engine |
| **Latency** | Run on demand | Real-time, sub-second alerting |
| **Open source** | ✅ Yes, MIT | — |

`pinchtab-detector` tells you if you've already been hit. Helixar stops the attack before it starts.

---

## Contributing

Pull requests are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

Issues and feature requests → [GitHub Issues](https://github.com/helixar-ai/pinchtab-detector/issues)

---

## License

MIT — see [LICENSE](LICENSE).

---

<div align="center">

**`pinchtab-detector` is an open source tool maintained by [Helixar Labs](https://helixar.ai/about/labs/).**

Helixar builds continuous agentic threat detection for enterprises deploying AI workloads.
Browser hijacking, prompt injection, and session takeover — detected in real time, before damage is done.

[helixar.ai →](https://helixar.ai) · [Security Research](https://helixar.ai/press/) · [Contact](https://helixar.ai/contact/)

</div>
