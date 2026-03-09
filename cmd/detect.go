package cmd

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/helixar-ai/pinchtab-detector/internal/report"
	"github.com/helixar-ai/pinchtab-detector/internal/scanner"
	"github.com/spf13/cobra"
)

var (
	flagJSON    bool
	flagQuiet   bool
	flagNoColor bool
	flagTimeout int
	flagPorts   string
)

var rootCmd = &cobra.Command{
	Use:   "pinchtab-detector",
	Short: "Point-in-time scanner for PinchTab deployment and agentic browser bridge artifacts",
	Long: `pinchtab-detector scans the local host for signs of PinchTab deployment:
open HTTP API ports, running processes, an exposed Chrome DevTools Protocol
bridge, and known filesystem artifacts.

Published by Helixar Labs — https://helixar.ai`,
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run all detection checks against the local host",
	Example: `  pinchtab-detector scan
  pinchtab-detector scan --json > results.json
  pinchtab-detector scan --quiet && echo "Clean"`,
	RunE: runScan,
}

func init() {
	scanCmd.Flags().BoolVar(&flagJSON, "json", false, "Output results as JSON")
	scanCmd.Flags().BoolVar(&flagQuiet, "quiet", false, "Suppress output; use exit codes only (0=clean, 1=findings, 2=error)")
	scanCmd.Flags().BoolVar(&flagNoColor, "no-color", false, "Disable terminal colour output")
	scanCmd.Flags().IntVar(&flagTimeout, "timeout", 3, "HTTP request timeout in seconds")
	scanCmd.Flags().StringVar(&flagPorts, "ports", "", "Comma-separated additional ports to scan (e.g. 7777,8888)")
	rootCmd.AddCommand(scanCmd)
}

// Execute is the entrypoint called from main.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

func runScan(_ *cobra.Command, _ []string) error {
	timeout := time.Duration(flagTimeout) * time.Second
	extraPorts := parsePorts(flagPorts)

	hostname, _ := os.Hostname()

	r := &report.ScanReport{
		Timestamp: time.Now().UTC(),
		Hostname:  hostname,
		OS:        runtime.GOOS + "/" + runtime.GOARCH,
	}

	// Run all four checks.
	r.PortFindings = scanner.ScanPorts(extraPorts, timeout)

	procFindings, err := scanner.ScanProcesses()
	if err != nil && !flagQuiet {
		fmt.Fprintf(os.Stderr, "warning: process scan incomplete: %v\n", err)
	}
	r.ProcessFindings = procFindings

	cdpFinding := scanner.ScanCDP(timeout)
	if cdpFinding.CDPOpen {
		r.CDPFindings = []scanner.CDPFinding{cdpFinding}
	}

	r.FilesystemFindings = scanner.ScanFilesystem()

	// Compute overall risk.
	r.RiskLevel = report.ComputeRiskLevel(r)
	r.Summary = report.BuildSummary(r)

	// Output.
	if !flagQuiet {
		if flagJSON {
			if err := report.PrintJSON(r); err != nil {
				return fmt.Errorf("json encode: %w", err)
			}
		} else {
			report.PrintText(r, flagNoColor)
		}
	}

	// Exit code.
	switch r.RiskLevel {
	case "NONE":
		os.Exit(0)
	default:
		os.Exit(1)
	}
	return nil
}

func parsePorts(s string) []int {
	if s == "" {
		return nil
	}
	var ports []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if p, err := strconv.Atoi(part); err == nil && p > 0 && p < 65536 {
			ports = append(ports, p)
		}
	}
	return ports
}
