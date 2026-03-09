package scanner

import (
	"os"
	"strings"

	"github.com/shirou/gopsutil/v3/process"
)

// ProcessFinding captures a suspicious running process.
type ProcessFinding struct {
	PID         int32
	Name        string
	CmdLine     string
	MatchReason string
	Confidence  string
}

// targetProcessNames are the exact binary names (without extension) that indicate PinchTab is running.
var targetProcessNames = []string{
	"pinchtab",
	"pinchtab-server",
	"browser-bridge",
}

// stripExt removes a .exe suffix on Windows for normalised comparison.
func stripExt(name string) string {
	if strings.HasSuffix(name, ".exe") {
		return name[:len(name)-4]
	}
	return name
}

// ScanProcesses walks all running processes and returns suspicious findings.
func ScanProcesses() ([]ProcessFinding, error) {
	procs, err := process.Processes()
	if err != nil {
		return nil, err
	}

	var findings []ProcessFinding

	selfPID := int32(os.Getpid())

	for _, p := range procs {
		if p.Pid == selfPID {
			continue
		}

		name, _ := p.Name()
		cmdline, _ := p.Cmdline()

		nameLower := strings.ToLower(stripExt(name))
		cmdLower := strings.ToLower(cmdline)

		// Check for exact name match (avoids flagging this tool itself).
		for _, target := range targetProcessNames {
			if nameLower == target {
				findings = append(findings, ProcessFinding{
					PID:         p.Pid,
					Name:        name,
					CmdLine:     truncate(cmdline, 512),
					MatchReason: "process name matches known PinchTab binary: " + target,
					Confidence:  "HIGH",
				})
				goto nextProc
			}
		}

		// Check cmdline for PinchTab references.
		for _, target := range targetProcessNames {
			if strings.Contains(cmdLower, target) {
				findings = append(findings, ProcessFinding{
					PID:         p.Pid,
					Name:        name,
					CmdLine:     truncate(cmdline, 512),
					MatchReason: "command line references known PinchTab artifact: " + target,
					Confidence:  "HIGH",
				})
				goto nextProc
			}
		}

		// Flag processes listening on CDP port 9222 with an ambiguous binary name.
		{
			conns, err := p.Connections()
			if err == nil {
				for _, c := range conns {
					if c.Laddr.Port == 9222 && c.Status == "LISTEN" {
						findings = append(findings, ProcessFinding{
							PID:         p.Pid,
							Name:        name,
							CmdLine:     truncate(cmdline, 512),
							MatchReason: "process listening on CDP port 9222",
							Confidence:  "MEDIUM",
						})
						goto nextProc
					}
				}
			}
		}

	nextProc:
	}

	return findings, nil
}
