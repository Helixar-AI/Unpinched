package scanner

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// PortFinding captures the result of a single port probe.
type PortFinding struct {
	Port       int
	Open       bool
	Signature  bool
	Response   string
	Confidence string // "HIGH" | "MEDIUM" | "LOW"
}

// defaultPorts are the ports checked unless overridden by --ports.
var defaultPorts = []int{
	3000, 4000,
	8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090,
	9222, 9229,
}

// signatureStrings are substrings that indicate a PinchTab HTTP API response.
var signatureStrings = []string{
	"pinchtab",
	"browser-bridge",
	"orchestrator",
	"helixar",
}

// ScanPorts probes each port and returns all findings (open or closed).
func ScanPorts(extraPorts []int, timeout time.Duration) []PortFinding {
	ports := dedupe(append(defaultPorts, extraPorts...))
	findings := make([]PortFinding, 0, len(ports))

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: timeout}).DialContext,
		},
	}

	for _, port := range ports {
		finding := probePort(client, port, timeout)
		if finding.Open {
			findings = append(findings, finding)
		}
	}
	return findings
}

func probePort(client *http.Client, port int, timeout time.Duration) PortFinding {
	f := PortFinding{Port: port, Confidence: "LOW"}

	// TCP dial to check if port is open at all.
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), timeout)
	if err != nil {
		return f // port closed
	}
	conn.Close()
	f.Open = true
	f.Confidence = "MEDIUM"

	// Attempt HTTP probe on common status endpoints.
	for _, path := range []string{"/api/status", "/status", "/"} {
		url := fmt.Sprintf("http://127.0.0.1:%d%s", port, path)
		resp, err := client.Get(url) //nolint:noctx
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		bodyStr := strings.ToLower(string(body))
		for _, sig := range signatureStrings {
			if strings.Contains(bodyStr, sig) {
				f.Signature = true
				f.Confidence = "HIGH"
				f.Response = truncate(string(body), 256)
				return f
			}
		}
		if f.Response == "" && len(body) > 0 {
			f.Response = truncate(string(body), 256)
		}
	}
	return f
}

func dedupe(ports []int) []int {
	seen := make(map[int]struct{}, len(ports))
	out := make([]int, 0, len(ports))
	for _, p := range ports {
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	return out
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
