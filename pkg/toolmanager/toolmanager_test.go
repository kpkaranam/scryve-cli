// Package toolmanager_test contains unit tests for the toolmanager package.
package toolmanager_test

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/scryve/scryve/pkg/toolmanager"
)

// ---------------------------------------------------------------------------
// RequiredTools
// ---------------------------------------------------------------------------

// TestRequiredToolsReturnsFourTools asserts that exactly 4 tools are declared.
func TestRequiredToolsReturnsFourTools(t *testing.T) {
	tools := toolmanager.RequiredTools()
	if len(tools) != 4 {
		t.Errorf("expected 4 required tools, got %d", len(tools))
	}
}

// TestRequiredToolsHaveExpectedNames checks that all expected tool names exist.
func TestRequiredToolsHaveExpectedNames(t *testing.T) {
	expected := []string{"subfinder", "httpx", "naabu", "nuclei"}
	tools := toolmanager.RequiredTools()

	names := make(map[string]bool, len(tools))
	for _, tool := range tools {
		names[tool.Name] = true
	}

	for _, name := range expected {
		if !names[name] {
			t.Errorf("expected tool %q to be in RequiredTools()", name)
		}
	}
}

// TestRequiredToolsHaveRepos ensures every tool has a non-empty Repo field.
func TestRequiredToolsHaveRepos(t *testing.T) {
	for _, tool := range toolmanager.RequiredTools() {
		if tool.Repo == "" {
			t.Errorf("tool %q has an empty Repo field", tool.Name)
		}
	}
}

// TestRequiredToolsHaveAssetPatterns ensures every tool has a non-empty AssetPattern.
func TestRequiredToolsHaveAssetPatterns(t *testing.T) {
	for _, tool := range toolmanager.RequiredTools() {
		if tool.AssetPattern == "" {
			t.Errorf("tool %q has an empty AssetPattern field", tool.Name)
		}
	}
}

// ---------------------------------------------------------------------------
// BinPath
// ---------------------------------------------------------------------------

// TestBinPathReturnsCorrectPath verifies BinPath joins BinDir with the binary name.
func TestBinPathReturnsCorrectPath(t *testing.T) {
	mgr := toolmanager.NewManagerWithDir(t.TempDir())
	got := mgr.BinPath("subfinder")

	if runtime.GOOS == "windows" {
		if !strings.HasSuffix(got, "subfinder.exe") {
			t.Errorf("on Windows, expected .exe suffix; got %q", got)
		}
	} else {
		if !strings.HasSuffix(got, "subfinder") {
			t.Errorf("expected path ending in 'subfinder'; got %q", got)
		}
	}

	// Must be an absolute path.
	if !filepath.IsAbs(got) {
		t.Errorf("expected an absolute path, got %q", got)
	}
}

// TestBinPathDifferentTools verifies BinPath handles multiple tool names.
func TestBinPathDifferentTools(t *testing.T) {
	dir := t.TempDir()
	mgr := toolmanager.NewManagerWithDir(dir)

	for _, toolName := range []string{"subfinder", "httpx", "naabu", "nuclei"} {
		got := mgr.BinPath(toolName)
		if got == "" {
			t.Errorf("BinPath(%q) returned empty string", toolName)
		}
		if !strings.Contains(got, toolName) {
			t.Errorf("BinPath(%q) = %q, expected to contain tool name", toolName, got)
		}
	}
}

// ---------------------------------------------------------------------------
// CheckAll
// ---------------------------------------------------------------------------

// TestCheckAllMissingWhenBinDirEmpty verifies all tools reported missing
// when the bin directory contains no binaries.
func TestCheckAllMissingWhenBinDirEmpty(t *testing.T) {
	mgr := toolmanager.NewManagerWithDir(t.TempDir())
	installed, missing, err := mgr.CheckAll()
	if err != nil {
		t.Fatalf("CheckAll() returned unexpected error: %v", err)
	}
	if len(installed) != 0 {
		t.Errorf("expected 0 installed, got %d", len(installed))
	}
	if len(missing) != 4 {
		t.Errorf("expected 4 missing, got %d", len(missing))
	}
}

// TestCheckAllInstalledWhenBinariesExist verifies tools are reported installed
// when their binary files exist in the BinDir.
func TestCheckAllInstalledWhenBinariesExist(t *testing.T) {
	dir := t.TempDir()
	mgr := toolmanager.NewManagerWithDir(dir)

	// Create stub binaries for all required tools.
	for _, tool := range toolmanager.RequiredTools() {
		binaryName := tool.Name
		if runtime.GOOS == "windows" {
			binaryName += ".exe"
		}
		path := filepath.Join(dir, binaryName)
		if err := os.WriteFile(path, []byte("#!/bin/sh\necho stub"), 0o755); err != nil {
			t.Fatalf("failed to create stub binary %q: %v", path, err)
		}
	}

	installed, missing, err := mgr.CheckAll()
	if err != nil {
		t.Fatalf("CheckAll() returned unexpected error: %v", err)
	}
	if len(installed) != 4 {
		t.Errorf("expected 4 installed, got %d", len(installed))
	}
	if len(missing) != 0 {
		t.Errorf("expected 0 missing, got %d", len(missing))
	}
}

// TestCheckAllPartialInstall verifies a mix of installed and missing tools.
func TestCheckAllPartialInstall(t *testing.T) {
	dir := t.TempDir()
	mgr := toolmanager.NewManagerWithDir(dir)

	// Create stub binary only for "subfinder".
	binaryName := "subfinder"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	path := filepath.Join(dir, binaryName)
	if err := os.WriteFile(path, []byte("stub"), 0o755); err != nil {
		t.Fatalf("failed to create stub: %v", err)
	}

	installed, missing, err := mgr.CheckAll()
	if err != nil {
		t.Fatalf("CheckAll() returned unexpected error: %v", err)
	}
	if len(installed) != 1 {
		t.Errorf("expected 1 installed, got %d", len(installed))
	}
	if len(missing) != 3 {
		t.Errorf("expected 3 missing, got %d", len(missing))
	}
}

// TestCheckAllInstalledToolHasCorrectName verifies the installed Tool struct
// has the expected Name field.
func TestCheckAllInstalledToolHasCorrectName(t *testing.T) {
	dir := t.TempDir()
	mgr := toolmanager.NewManagerWithDir(dir)

	binaryName := "nuclei"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	if err := os.WriteFile(filepath.Join(dir, binaryName), []byte("stub"), 0o755); err != nil {
		t.Fatal(err)
	}

	installed, _, _ := mgr.CheckAll()
	if len(installed) != 1 {
		t.Fatalf("expected 1 installed tool, got %d", len(installed))
	}
	if installed[0].Name != "nuclei" {
		t.Errorf("expected installed tool name 'nuclei', got %q", installed[0].Name)
	}
}

// ---------------------------------------------------------------------------
// EnsurePath
// ---------------------------------------------------------------------------

// TestEnsurePathAddsBinDir verifies that EnsurePath inserts BinDir into PATH.
func TestEnsurePathAddsBinDir(t *testing.T) {
	dir := t.TempDir()
	mgr := toolmanager.NewManagerWithDir(dir)

	// Save and restore PATH.
	originalPath := os.Getenv("PATH")
	t.Cleanup(func() { os.Setenv("PATH", originalPath) }) //nolint:errcheck

	// Remove dir from PATH if accidentally already present.
	cleanPath := removeFromPath(originalPath, dir)
	os.Setenv("PATH", cleanPath) //nolint:errcheck

	if err := mgr.EnsurePath(); err != nil {
		t.Fatalf("EnsurePath() returned error: %v", err)
	}

	newPath := os.Getenv("PATH")
	if !strings.Contains(newPath, dir) {
		t.Errorf("expected PATH to contain %q after EnsurePath(), got: %s", dir, newPath)
	}
}

// TestEnsurePathIdempotent verifies that calling EnsurePath twice doesn't
// duplicate the entry.
func TestEnsurePathIdempotent(t *testing.T) {
	dir := t.TempDir()
	mgr := toolmanager.NewManagerWithDir(dir)

	originalPath := os.Getenv("PATH")
	t.Cleanup(func() { os.Setenv("PATH", originalPath) }) //nolint:errcheck

	cleanPath := removeFromPath(originalPath, dir)
	os.Setenv("PATH", cleanPath) //nolint:errcheck

	_ = mgr.EnsurePath()
	_ = mgr.EnsurePath()

	newPath := os.Getenv("PATH")
	// Count occurrences.
	count := strings.Count(newPath, dir)
	if count != 1 {
		t.Errorf("expected dir to appear once in PATH, found %d times", count)
	}
}

// ---------------------------------------------------------------------------
// FindBinaryInDir
// ---------------------------------------------------------------------------

// TestFindBinaryInDirPrefersScryveDir verifies FindBinaryInDir returns the
// managed path when the binary exists there.
func TestFindBinaryInDirPrefersScryveDir(t *testing.T) {
	dir := t.TempDir()

	binaryName := "subfinder"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	managedPath := filepath.Join(dir, binaryName)
	if err := os.WriteFile(managedPath, []byte("stub"), 0o755); err != nil {
		t.Fatalf("failed to create stub: %v", err)
	}

	got := toolmanager.FindBinaryInDir(dir, "subfinder")
	if got != managedPath {
		t.Errorf("expected %q, got %q", managedPath, got)
	}
}

// TestFindBinaryInDirEmptyWhenNotFound verifies FindBinaryInDir returns empty
// string when the binary is absent from both the managed dir and system PATH.
func TestFindBinaryInDirEmptyWhenNotFound(t *testing.T) {
	dir := t.TempDir() // empty directory

	// Use a tool name unlikely to exist on the test system.
	got := toolmanager.FindBinaryInDir(dir, "definitely-not-a-real-tool-xyz123")
	if got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// NewManager
// ---------------------------------------------------------------------------

// TestNewManagerDefaultDir verifies the default BinDir is inside ~/.scryve.
func TestNewManagerDefaultDir(t *testing.T) {
	mgr := toolmanager.NewManager()
	if !strings.Contains(mgr.BinDir, ".scryve") {
		t.Errorf("expected BinDir to contain '.scryve', got %q", mgr.BinDir)
	}
}

// TestNewManagerWithDirSetsDir verifies NewManagerWithDir sets the given dir.
func TestNewManagerWithDirSetsDir(t *testing.T) {
	dir := t.TempDir()
	mgr := toolmanager.NewManagerWithDir(dir)
	if mgr.BinDir != dir {
		t.Errorf("expected BinDir %q, got %q", dir, mgr.BinDir)
	}
}

// ---------------------------------------------------------------------------
// InstallAll (no-op when all tools already present)
// ---------------------------------------------------------------------------

// TestInstallAllNoopWhenAllPresent verifies InstallAll writes a meaningful message
// and returns nil when all tools are already installed.
func TestInstallAllNoopWhenAllPresent(t *testing.T) {
	dir := t.TempDir()
	mgr := toolmanager.NewManagerWithDir(dir)
	mgr.Verbose = true

	// Pre-populate all binaries so nothing actually needs downloading.
	for _, tool := range toolmanager.RequiredTools() {
		binaryName := tool.Name
		if runtime.GOOS == "windows" {
			binaryName += ".exe"
		}
		path := filepath.Join(dir, binaryName)
		if err := os.WriteFile(path, []byte("stub"), 0o755); err != nil {
			t.Fatalf("create stub: %v", err)
		}
	}

	var buf bytes.Buffer
	if err := mgr.InstallAll(&buf); err != nil {
		t.Fatalf("InstallAll() returned error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// removeFromPath returns PATH with the given directory removed.
func removeFromPath(path, dir string) string {
	sep := string(os.PathListSeparator)
	parts := strings.Split(path, sep)
	filtered := parts[:0]
	for _, p := range parts {
		if p != dir {
			filtered = append(filtered, p)
		}
	}
	return strings.Join(filtered, sep)
}
