package scanner

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// FilesystemFinding captures a PinchTab artifact on disk.
type FilesystemFinding struct {
	Path       string
	Exists     bool
	Executable bool
	Size       int64
	Confidence string
}

// ScanFilesystem checks known paths and PATH entries for PinchTab artifacts.
func ScanFilesystem() []FilesystemFinding {
	paths := buildTargetPaths()
	var findings []FilesystemFinding

	for _, p := range paths {
		if f := probePath(p); f.Exists {
			findings = append(findings, f)
		}
	}

	// Also scan PATH directories for any binary containing "pinchtab".
	findings = append(findings, scanPATH()...)

	return findings
}

func buildTargetPaths() []string {
	home, _ := os.UserHomeDir()

	base := []string{
		"/usr/local/bin/pinchtab",
		"/usr/bin/pinchtab",
		"/tmp/pinchtab",
		"./pinchtab",
	}

	if home != "" {
		base = append(base,
			filepath.Join(home, ".local", "bin", "pinchtab"),
			filepath.Join(home, "pinchtab"),
		)
	}

	switch runtime.GOOS {
	case "darwin":
		if home != "" {
			base = append(base,
				filepath.Join(home, "Library", "Application Support", "pinchtab"),
			)
		}
	case "windows":
		if appdata := os.Getenv("APPDATA"); appdata != "" {
			base = append(base, filepath.Join(appdata, "pinchtab"))
		}
		if local := os.Getenv("LOCALAPPDATA"); local != "" {
			base = append(base, filepath.Join(local, "pinchtab"))
		}
		base = append(base, "./pinchtab.exe")
	}

	// Glob /tmp/pinchtab* variants.
	if matches, err := filepath.Glob("/tmp/pinchtab*"); err == nil {
		base = append(base, matches...)
	}

	return base
}

func probePath(path string) FilesystemFinding {
	f := FilesystemFinding{Path: path}
	info, err := os.Stat(path)
	if err != nil {
		return f
	}
	f.Exists = true
	f.Size = info.Size()
	f.Executable = isExecutable(info)
	if f.Executable {
		f.Confidence = "HIGH"
	} else {
		f.Confidence = "LOW"
	}
	return f
}

func scanPATH() []FilesystemFinding {
	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		return nil
	}

	var findings []FilesystemFinding
	sep := ":"
	if runtime.GOOS == "windows" {
		sep = ";"
	}

	for _, dir := range strings.Split(pathEnv, sep) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if strings.Contains(strings.ToLower(e.Name()), "pinchtab") {
				fullPath := filepath.Join(dir, e.Name())
				if f := probePath(fullPath); f.Exists {
					f.Confidence = "HIGH"
					findings = append(findings, f)
				}
			}
		}
	}
	return findings
}

func isExecutable(info os.FileInfo) bool {
	if runtime.GOOS == "windows" {
		name := strings.ToLower(info.Name())
		return strings.HasSuffix(name, ".exe") || strings.HasSuffix(name, ".bat") || strings.HasSuffix(name, ".cmd")
	}
	return info.Mode()&0o111 != 0
}
