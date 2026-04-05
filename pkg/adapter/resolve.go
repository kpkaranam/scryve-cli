package adapter

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// defaultBinDir is ~/.scryve/bin/ where scryve setup installs tools.
func defaultBinDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".scryve", "bin")
}

// ResolveBinary finds a tool binary by checking ~/.scryve/bin/ first,
// then falling back to system PATH. Returns error if not found anywhere.
func ResolveBinary(toolName string) (string, error) {
	// Check managed directory first
	binDir := defaultBinDir()
	binaryName := toolName
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	managed := filepath.Join(binDir, binaryName)
	if _, err := os.Stat(managed); err == nil {
		return managed, nil
	}

	// Fall back to system PATH
	p, err := exec.LookPath(toolName)
	if err != nil {
		return "", fmt.Errorf("%s: binary not found in ~/.scryve/bin/ or PATH", toolName)
	}
	return p, nil
}
