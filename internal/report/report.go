package report

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/helixar-ai/pinchtab-detector/internal/scanner"
)

const version = "v0.1.0"

// ScanReport aggregates all detection findings.
type ScanReport struct {
	Timestamp          time.Time                  `json:"timestamp"`
	Hostname           string                     `json:"hostname"`
	OS                 string                     `json:"os"`
	RiskLevel          string                     `json:"risk_level"`
	Summary            string                     `json:"summary"`
	PortFindings       []scanner.PortFinding      `json:"port_findings"`
	ProcessFindings    []scanner.ProcessFinding   `json:"process_findings"`
	CDPFindings        []scanner.CDPFinding       `json:"cdp_findings"`
	FilesystemFindings []scanner.FilesystemFinding `json:"filesystem_findings"`
}

// ComputeRiskLevel derives the overall risk level from the individual findings.
func ComputeRiskLevel(r *ScanReport) string {
	hasSigPort := false
	hasOpenPort := false
	hasProcess := false
	hasFS := false
	hasCDP := false

	for _, f := range r.PortFindings {
		if f.Open && f.Signature {
			hasSigPort = true
		} else if f.Open {
			hasOpenPort = true
		}
	}
	for _, f := range r.ProcessFindings {
		_ = f
		hasProcess = true
	}
	for _, f := range r.FilesystemFindings {
		_ = f
		hasFS = true
	}
	for _, f := range r.CDPFindings {
		if f.CDPOpen {
			hasCDP = true
		}
	}

	switch {
	case hasSigPort && hasCDP:
		return "CRITICAL"
	case hasProcess && (hasOpenPort || hasSigPort):
		return "HIGH"
	case hasFS && (hasOpenPort || hasSigPort):
		return "HIGH"
	case hasProcess || hasSigPort:
		return "HIGH"
	case hasOpenPort || hasCDP:
		return "MEDIUM"
	case hasFS:
		return "LOW"
	default:
		return "NONE"
	}
}

// BuildSummary returns a human-readable summary appropriate for the risk level.
func BuildSummary(r *ScanReport) string {
	switch r.RiskLevel {
	case "CRITICAL":
		return "Active PinchTab HTTP API detected with CDP bridge open. Immediate investigation recommended."
	case "HIGH":
		return "Strong indicators of PinchTab deployment found. Review findings below."
	case "MEDIUM":
		return "Suspicious open ports or unauthenticated CDP detected. PinchTab not confirmed but environment is at risk."
	case "LOW":
		return "PinchTab filesystem artifacts found. No active service detected."
	default:
		return "No PinchTab indicators found on this host."
	}
}

// PrintText renders a coloured human-readable report to stdout.
func PrintText(r *ScanReport, noColor bool) {
	if noColor {
		color.NoColor = true
	}

	bold := color.New(color.Bold)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)
	red := color.New(color.FgRed)
	cyan := color.New(color.FgCyan)

	divider := strings.Repeat("━", 48)

	bold.Printf("\npinchtab-detector %s — Helixar Labs\n", version)
	cyan.Printf("Scanning host: %s (%s)\n", r.Hostname, r.OS)
	fmt.Println(divider)

	// PORT SCAN
	if len(r.PortFindings) == 0 {
		green.Println("[PORT SCAN]      ✓ No PinchTab HTTP API detected on common ports")
	} else {
		for _, f := range r.PortFindings {
			if f.Signature {
				red.Printf("[PORT SCAN]      ✗ PinchTab signature found on port %d [%s]\n", f.Port, f.Confidence)
			} else {
				yellow.Printf("[PORT SCAN]      ⚠ Port %d open — no PinchTab signature but suspicious [%s]\n", f.Port, f.Confidence)
			}
		}
	}

	// PROCESS SCAN
	if len(r.ProcessFindings) == 0 {
		green.Println("[PROCESS SCAN]   ✓ No PinchTab process found")
	} else {
		for _, f := range r.ProcessFindings {
			red.Printf("[PROCESS SCAN]   ✗ Suspicious process: %s (PID %d) — %s [%s]\n",
				f.Name, f.PID, f.MatchReason, f.Confidence)
		}
	}

	// CDP BRIDGE
	hasCDP := false
	for _, f := range r.CDPFindings {
		if f.CDPOpen {
			hasCDP = true
			if f.Confidence == "HIGH" {
				yellow.Printf("[CDP BRIDGE]     ⚠ Chrome DevTools Protocol exposed on :9222 (no auth) — %s\n", f.BrowserVersion)
			} else {
				yellow.Println("[CDP BRIDGE]     ⚠ Port 9222 open — unknown service, possible CDP")
			}
		}
	}
	if !hasCDP {
		green.Println("[CDP BRIDGE]     ✓ CDP not exposed on :9222")
	}

	// FILESYSTEM
	if len(r.FilesystemFindings) == 0 {
		green.Println("[FILESYSTEM]     ✓ No PinchTab binary artifacts found")
	} else {
		for _, f := range r.FilesystemFindings {
			if f.Executable {
				red.Printf("[FILESYSTEM]     ✗ Executable artifact: %s (%d bytes) [%s]\n", f.Path, f.Size, f.Confidence)
			} else {
				yellow.Printf("[FILESYSTEM]     ⚠ Artifact found: %s (%d bytes) [%s]\n", f.Path, f.Size, f.Confidence)
			}
		}
	}

	fmt.Println(divider)

	// Risk level banner
	switch r.RiskLevel {
	case "CRITICAL", "HIGH":
		red.Printf("RISK LEVEL: %s\n", r.RiskLevel)
		red.Println(r.Summary)
	case "MEDIUM":
		yellow.Printf("RISK LEVEL: %s\n", r.RiskLevel)
		yellow.Println(r.Summary)
	case "LOW":
		yellow.Printf("RISK LEVEL: %s\n", r.RiskLevel)
		fmt.Println(r.Summary)
	default:
		green.Printf("RISK LEVEL: %s\n", r.RiskLevel)
		green.Println(r.Summary)
	}

	if r.RiskLevel != "NONE" {
		fmt.Println()
		cyan.Println("For continuous agentic threat detection without pre-written rules → helixar.ai")
	}
	fmt.Println()
}

// PrintJSON renders the report as machine-readable JSON to stdout.
func PrintJSON(r *ScanReport) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
