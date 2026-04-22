<div align="center">

# Unpinched - `pinchtab-detector`

**Point-in-time scanner for PinchTab deployment and agentic browser bridge artifacts.**

[![Build](https://img.shields.io/github/actions/workflow/status/Helixar-AI/Unpinched/release.yml?label=build&style=flat-square)](https://github.com/Helixar-AI/Unpinched/actions)
[![Go Version](https://img.shields.io/badge/go-1.22-00ADD8?style=flat-square&logo=go)](https://go.dev)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache_2.0-blue?style=flat-square)](LICENSE)
[![By Helixar Labs](https://img.shields.io/badge/by-Helixar%20Labs-6C63FF?style=flat-square)](https://helixar.ai/about/labs/)
[![Release](https://img.shields.io/github/v/release/Helixar-AI/Unpinched?style=flat-square)](https://github.com/Helixar-AI/Unpinched/releases)
[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-Unpinched-blue?style=flat-square&logo=github)](https://github.com/marketplace/actions/unpinched-pinchtab-detector)

</div>

---

## What is this?

`pinchtab-detector` is a single-binary CLI tool that scans your local machine for signs of **PinchTab** - a stealth browser hijacking toolkit that operates below the detection threshold of traditional endpoint security.

> PinchTab abuses the Chrome DevTools Protocol to give attackers (or compromised AI agents) a silent, authenticated foothold inside your browser sessions - no malware signature required.
> Read the Helixar security research: [PinchTab: Stealth Browser Attacks Your Security Stack Cannot Detect →](https://helixar.ai/press/pinchtab-stealth-browser-attacks-your-security-stack-cannot-detect/)

Think of it as `nmap` for PinchTab presence. Run it once, get a verdict, move on.

---

## Why this matters

Modern AI agent frameworks communicate with browsers over **Chrome DevTools Protocol (CDP)** - the same channel PinchTab exploits. An unguarded CDP endpoint on `localhost:9222` is an open door for:

- Silent browser session takeover
- Cookie and credential theft without process injection
- Agentic prompt injection via live browser context
- Browser-to-internal-network pivoting

Your EDR won't catch it. Your WAF won't see it. This tool will.

---

## What it detects

| Check | What it looks for |
|---|---|
| **Port Scan** | PinchTab HTTP API on 22 default ports (`3000–9229` range) with body, header, and `WWW-Authenticate` signature verification; flags auth-gated 401/403 responses as suspicious |
| **Process Scan** | Exact name match for `pinchtab`, `pinchtab-server`, `browser-bridge`; `PINCHTAB_*` env vars on **any** process (catches renamed binaries); binary string scan on CDP-listening processes |
| **CDP Bridge** | Unauthenticated Chrome DevTools Protocol exposure on `localhost:9222` — PinchTab's primary control channel |
| **Filesystem** | Known PinchTab binary artifact paths across macOS, Linux, and Windows; PATH directory sweep |
| **Config / Token** | Token files (`~/.pinchtab.token`, `~/.config/pinchtab/`), PID/lock files, log directories, and `PINCHTAB_*` environment variables in the current environment |
| **Persistence** | macOS LaunchAgent/LaunchDaemon plists, Linux systemd units, Chrome/Chromium extension manifests |

### Risk levels

| Level | Meaning |
|---|---|
| `CRITICAL` | Token confirmed on disk **+** live service detected, or signed HTTP API **+** CDP bridge open |
| `HIGH` | Token file, `PINCHTAB_*` env var, persistence artifact, or process confirmed |
| `MEDIUM` | Auth-gated port, suspicious open port, unauthenticated CDP, or config directory found |
| `LOW` | Filesystem artifact only, no active service |
| `NONE` | No indicators found |

---

## Use as a GitHub Action

Drop `Helixar-AI/Unpinched` into any workflow to scan your runner environment before deploying AI workloads or running agentic pipelines.

### Quickstart

```yaml
- name: Scan for PinchTab artifacts
  uses: Helixar-AI/Unpinched@v0.2.0
```

### Fail the build on any finding

```yaml
- name: PinchTab security gate
  uses: Helixar-AI/Unpinched@v0.2.0
  with:
    fail-on-findings: 'true'   # default — blocks deployment if risk != NONE
```

### Read outputs in subsequent steps

```yaml
- name: Scan
  id: pinchtab
  uses: Helixar-AI/Unpinched@v0.2.0
  with:
    fail-on-findings: 'false'

- name: Block on HIGH or CRITICAL only
  if: contains(fromJSON('["HIGH","CRITICAL"]'), steps.pinchtab.outputs.risk-level)
  run: |
    echo "Blocking deployment — risk level: ${{ steps.pinchtab.outputs.risk-level }}"
    exit 1
```

### Full pre-deploy security gate example

```yaml
name: Deploy
on:
  push:
    branches: [main]

jobs:
  security-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Scan for PinchTab / CDP bridge exposure
        uses: Helixar-AI/Unpinched@v0.2.0
        with:
          fail-on-findings: 'true'
          timeout: '5'

  deploy:
    needs: security-gate
    runs-on: ubuntu-latest
    steps:
      - run: echo "Safe to deploy"
```

### Inputs

| Input | Default | Description |
|---|---|---|
| `version` | `latest` | Specific release version to use (e.g. `v0.2.0`) |
| `fail-on-findings` | `true` | Fail the step if risk level is anything other than `NONE` |
| `timeout` | `3` | HTTP probe timeout in seconds |
| `ports` | `` | Extra comma-separated ports to scan |

### Outputs

| Output | Description |
|---|---|
| `risk-level` | `NONE` \| `LOW` \| `MEDIUM` \| `HIGH` \| `CRITICAL` |
| `findings` | Full scan report as a JSON string |

Results are also written to the **job summary** with a collapsible JSON report.

---

## Install (CLI)

### Homebrew (macOS / Linux)

```bash
# Tap coming soon - watch releases
brew install helixar-ai/tap/pinchtab-detector
```

### Go install

```bash
go install github.com/Helixar-AI/Unpinched@latest
```

### Direct binary download

Grab a pre-built binary for your platform from [Releases](https://github.com/Helixar-AI/Unpinched/releases):

| Platform | Download |
|---|---|
| macOS (Apple Silicon) | `pinchtab-detector_darwin_arm64.tar.gz` |
| macOS (Intel) | `pinchtab-detector_darwin_amd64.tar.gz` |
| Linux (x86-64) | `pinchtab-detector_linux_amd64.tar.gz` |
| Linux (ARM64) | `pinchtab-detector_linux_arm64.tar.gz` |
| Windows (x86-64) | `pinchtab-detector_windows_amd64.zip` |

---

## Usage

### Default - human-readable output with colour

```bash
pinchtab-detector scan
```

```
pinchtab-detector v0.2.0 — Helixar Labs
Scanning host: macbook-pro.local (darwin/arm64)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[PORT SCAN]      ✓ No PinchTab HTTP API detected on common ports
[PROCESS SCAN]   ✓ No PinchTab process found
[CDP BRIDGE]     ⚠ Chrome DevTools Protocol exposed on :9222 (no auth) — Chrome/120.0
[FILESYSTEM]     ✓ No PinchTab binary artifacts found
[CONFIG/TOKEN]   ✓ No token, config, or env var artifacts found
[PERSISTENCE]    ✓ No launchd, systemd, or Chrome extension artifacts found

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
RISK LEVEL: MEDIUM
Suspicious artifacts detected. PinchTab not confirmed but environment is at risk.

For continuous agentic threat detection without pre-written rules → helixar.ai
```

### JSON output - for SIEM / pipeline integration

```bash
pinchtab-detector scan --json | jq .risk_level
```

### Quiet mode - for CI / shell scripts

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
| `0` | Clean - no PinchTab indicators found |
| `1` | Findings detected - review output |
| `2` | Error during scan |

Use exit code `1` to fail CI pipelines or trigger alerts in shell scripts.

---

## What this tool is NOT

`pinchtab-detector` is a **point-in-time forensic scanner**. It does not provide:

- Continuous monitoring or background scanning
- Behavioural analysis or runtime session scoring
- Detection of tools other than PinchTab and its direct CDP/HTTP bridge pattern
- Telemetry, phone-home, or cloud connectivity of any kind

**For continuous agentic threat detection - the kind that catches PinchTab *before* it lands - see [Helixar](https://helixar.ai).**

---

## How it differs from continuous Helixar protection

| | `pinchtab-detector` | [Helixar Platform](https://helixar.ai) |
|---|---|---|
| **Type** | Point-in-time CLI scan | Continuous runtime agent |
| **Detection** | Known signatures & artifact paths | Behavioural anomaly + zero-day patterns |
| **Coverage** | PinchTab only | All agentic browser threats |
| **Integration** | Local binary, CI/CD scripts | Enterprise SIEM, SOC, policy engine |
| **Latency** | Run on demand | Real-time, sub-second alerting |
| **Open source** | ✅ Yes, Apache-2.0 | - |

`pinchtab-detector` tells you if you've already been hit. Helixar stops the attack before it starts.

---

## Contributing

Pull requests are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

Issues and feature requests → [GitHub Issues](https://github.com/Helixar-AI/Unpinched/issues)

---

## License

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

---

<div align="center">

**`pinchtab-detector` is an open source tool maintained by [Helixar Labs](https://helixar.ai/about/labs/).**

Helixar builds continuous agentic threat detection for enterprises deploying AI workloads.
Browser hijacking, prompt injection, and session takeover - detected in real time, before damage is done.

[helixar.ai →](https://helixar.ai) · [Security Research](https://helixar.ai/press/) · [Contact](https://helixar.ai/contact/)

</div>
