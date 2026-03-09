package scanner

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// CDPFinding captures the result of the Chrome DevTools Protocol probe.
type CDPFinding struct {
	CDPOpen        bool
	BrowserVersion string
	WSDebuggerURL  string
	NoAuth         bool
	Confidence     string
}

type cdpVersionResponse struct {
	Browser              string `json:"Browser"`
	WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
	UserAgent            string `json:"User-Agent"`
}

// ScanCDP checks whether Chrome DevTools Protocol is exposed on localhost:9222.
func ScanCDP(timeout time.Duration) CDPFinding {
	f := CDPFinding{}

	client := &http.Client{Timeout: timeout}
	resp, err := client.Get("http://127.0.0.1:9222/json/version") //nolint:noctx
	if err != nil {
		return f
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return f
	}

	var ver cdpVersionResponse
	if err := json.Unmarshal(body, &ver); err != nil {
		// Port is open but didn't return recognisable JSON — still flag it.
		f.CDPOpen = true
		f.NoAuth = true
		f.Confidence = "MEDIUM"
		return f
	}

	if !strings.Contains(ver.Browser, "Chrome") && !strings.Contains(ver.Browser, "Chromium") {
		return f
	}

	f.CDPOpen = true
	f.BrowserVersion = ver.Browser
	f.WSDebuggerURL = ver.WebSocketDebuggerURL
	f.NoAuth = true // CDP on 9222 has no auth by default
	f.Confidence = "HIGH"

	// Elevated confidence if debugger URL indicates an active automation session.
	if ver.WebSocketDebuggerURL != "" {
		f.Confidence = "HIGH"
	}

	return f
}
