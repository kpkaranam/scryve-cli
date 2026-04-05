// Package toolmanager handles detection, verification, and automatic
// installation of the external security tools that Scryve depends on.
//
// Tools are downloaded from GitHub Releases and placed in ~/.scryve/bin/ so
// they never conflict with system-level installations. The package is
// intentionally dependency-free (only stdlib) to keep the binary small.
package toolmanager

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// ---------------------------------------------------------------------------
// Tool descriptor
// ---------------------------------------------------------------------------

// Tool describes an external binary that Scryve depends on.
type Tool struct {
	// Name is the logical name used inside Scryve (e.g. "subfinder").
	Name string

	// BinaryName is the executable name on disk. On Windows the Manager
	// automatically appends ".exe"; callers should leave this without the
	// extension.
	BinaryName string

	// Repo is the GitHub repository in "owner/name" format.
	Repo string

	// AssetPattern is the release-asset filename template.
	// Placeholders: {version}, {os}, {arch}
	// Example: "subfinder_{version}_{os}_{arch}.zip"
	AssetPattern string

	// InstallCmd is an alternative installation command (e.g. "go install …").
	// Used only when no matching GitHub asset is found.
	InstallCmd string
}

// binaryFilename returns the platform-specific binary filename.
func (t Tool) binaryFilename() string {
	name := t.BinaryName
	if name == "" {
		name = t.Name
	}
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

// ---------------------------------------------------------------------------
// RequiredTools
// ---------------------------------------------------------------------------

// requiredTools is the canonical list of tools Scryve depends on.
var requiredTools = []Tool{
	{
		Name:         "subfinder",
		Repo:         "projectdiscovery/subfinder",
		AssetPattern: "subfinder_{version}_{os}_{arch}.zip",
	},
	{
		Name:         "httpx",
		Repo:         "projectdiscovery/httpx",
		AssetPattern: "httpx_{version}_{os}_{arch}.zip",
	},
	{
		Name:         "naabu",
		Repo:         "projectdiscovery/naabu",
		AssetPattern: "naabu_{version}_{os}_{arch}.zip",
	},
	{
		Name:         "nuclei",
		Repo:         "projectdiscovery/nuclei",
		AssetPattern: "nuclei_{version}_{os}_{arch}.zip",
	},
}

// RequiredTools returns a copy of the list of tools Scryve needs.
func RequiredTools() []Tool {
	out := make([]Tool, len(requiredTools))
	copy(out, requiredTools)
	return out
}

// ---------------------------------------------------------------------------
// Manager
// ---------------------------------------------------------------------------

// Manager handles tool installation and verification.
type Manager struct {
	// BinDir is the directory where managed tool binaries are stored.
	// Defaults to ~/.scryve/bin/.
	BinDir string

	// Verbose enables detailed progress output.
	Verbose bool
}

// NewManager creates a Manager with the default bin directory (~/.scryve/bin/).
func NewManager() *Manager {
	home, err := os.UserHomeDir()
	if err != nil {
		// Fallback to a relative directory when home is unavailable (CI, containers).
		home = "."
	}
	return &Manager{BinDir: filepath.Join(home, ".scryve", "bin")}
}

// NewManagerWithDir creates a Manager that stores binaries in dir.
// Intended for testing — production code should use NewManager().
func NewManagerWithDir(dir string) *Manager {
	return &Manager{BinDir: dir}
}

// ---------------------------------------------------------------------------
// BinPath
// ---------------------------------------------------------------------------

// BinPath returns the absolute path to the named tool binary inside BinDir.
func (m *Manager) BinPath(toolName string) string {
	binaryName := toolName
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	return filepath.Join(m.BinDir, binaryName)
}

// ---------------------------------------------------------------------------
// CheckAll
// ---------------------------------------------------------------------------

// CheckAll inspects BinDir and returns which tools are installed (binary file
// exists) and which are missing.
func (m *Manager) CheckAll() (installed []Tool, missing []Tool, err error) {
	for _, tool := range requiredTools {
		path := filepath.Join(m.BinDir, tool.binaryFilename())
		if fileExists(path) {
			installed = append(installed, tool)
		} else {
			missing = append(missing, tool)
		}
	}
	return installed, missing, nil
}

// ---------------------------------------------------------------------------
// EnsurePath
// ---------------------------------------------------------------------------

// EnsurePath adds BinDir to the current process PATH if it is not already
// present. This allows tools installed by Scryve to be found by os/exec
// without restarting the process.
func (m *Manager) EnsurePath() error {
	current := os.Getenv("PATH")
	sep := string(os.PathListSeparator)

	// Check each entry; add only when absent.
	for _, entry := range strings.Split(current, sep) {
		if entry == m.BinDir {
			return nil // already present
		}
	}

	var newPath string
	if current == "" {
		newPath = m.BinDir
	} else {
		newPath = m.BinDir + sep + current
	}
	return os.Setenv("PATH", newPath)
}

// ---------------------------------------------------------------------------
// InstallAll / InstallTool
// ---------------------------------------------------------------------------

// InstallAll downloads and installs all tools that are not already present in
// BinDir. Progress messages are written to w (may be nil).
func (m *Manager) InstallAll(w io.Writer) error {
	if w == nil {
		w = io.Discard
	}

	_, missing, err := m.CheckAll()
	if err != nil {
		return fmt.Errorf("toolmanager: CheckAll: %w", err)
	}
	if len(missing) == 0 {
		fmt.Fprintln(w, "All tools already installed.")
		return nil
	}

	if err := os.MkdirAll(m.BinDir, 0o755); err != nil {
		return fmt.Errorf("toolmanager: create BinDir %q: %w", m.BinDir, err)
	}

	for _, tool := range missing {
		if err := m.InstallTool(tool, w); err != nil {
			return fmt.Errorf("toolmanager: install %q: %w", tool.Name, err)
		}
	}
	return nil
}

// InstallTool downloads and installs a single tool into BinDir.
func (m *Manager) InstallTool(tool Tool, w io.Writer) error {
	if w == nil {
		w = io.Discard
	}

	if err := os.MkdirAll(m.BinDir, 0o755); err != nil {
		return fmt.Errorf("create bin dir: %w", err)
	}

	// Resolve latest release metadata from GitHub API.
	version, assetURL, err := resolveLatestRelease(tool)
	if err != nil {
		return fmt.Errorf("resolve release for %q: %w", tool.Name, err)
	}

	fmt.Fprintf(w, "  Downloading %s %s...", tool.Name, version)

	data, err := downloadBytes(assetURL)
	if err != nil {
		fmt.Fprintln(w, " failed")
		return fmt.Errorf("download asset: %w", err)
	}

	// Extract binary from archive.
	binaryData, err := extractBinary(tool.Name, assetURL, data)
	if err != nil {
		fmt.Fprintln(w, " failed")
		return fmt.Errorf("extract binary: %w", err)
	}

	// Write to BinDir.
	destPath := filepath.Join(m.BinDir, tool.binaryFilename())
	if err := os.WriteFile(destPath, binaryData, 0o755); err != nil {
		fmt.Fprintln(w, " failed")
		return fmt.Errorf("write binary: %w", err)
	}

	fmt.Fprintln(w, " done")
	return nil
}

// ---------------------------------------------------------------------------
// FindBinaryInDir
// ---------------------------------------------------------------------------

// FindBinaryInDir checks dir for the named binary first; if not found there,
// it falls back to exec.LookPath (system PATH). Returns empty string when the
// binary cannot be located anywhere.
func FindBinaryInDir(dir, toolName string) string {
	binaryName := toolName
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	managed := filepath.Join(dir, binaryName)
	if fileExists(managed) {
		return managed
	}

	// Fall back to system PATH.
	found, err := exec.LookPath(toolName)
	if err != nil {
		return ""
	}
	return found
}

// ---------------------------------------------------------------------------
// GitHub release resolution
// ---------------------------------------------------------------------------

// githubRelease is a minimal subset of the GitHub Releases API response.
type githubRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

// resolveLatestRelease contacts the GitHub Releases API and returns the version
// string and download URL for the best-matching asset.
func resolveLatestRelease(tool Tool) (version, assetURL string, err error) {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", tool.Repo)

	resp, err := http.Get(apiURL) //nolint:noctx
	if err != nil {
		return "", "", fmt.Errorf("GET %s: %w", apiURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("GitHub API returned %d for %s", resp.StatusCode, apiURL)
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", "", fmt.Errorf("decode release JSON: %w", err)
	}

	version = strings.TrimPrefix(release.TagName, "v")
	goos := normaliseOS(runtime.GOOS)
	goarch := normaliseArch(runtime.GOARCH)

	// Build expected asset name from the pattern.
	pattern := tool.AssetPattern
	pattern = strings.ReplaceAll(pattern, "{version}", version)
	pattern = strings.ReplaceAll(pattern, "{os}", goos)
	pattern = strings.ReplaceAll(pattern, "{arch}", goarch)

	for _, asset := range release.Assets {
		if strings.EqualFold(asset.Name, pattern) {
			return "v" + version, asset.BrowserDownloadURL, nil
		}
	}

	// Fallback: looser match — name contains tool name, os, arch.
	for _, asset := range release.Assets {
		lower := strings.ToLower(asset.Name)
		if strings.Contains(lower, tool.Name) &&
			strings.Contains(lower, goos) &&
			strings.Contains(lower, goarch) {
			return "v" + version, asset.BrowserDownloadURL, nil
		}
	}

	return "", "", fmt.Errorf("no matching release asset for %q (os=%s arch=%s) in %d assets",
		tool.Name, goos, goarch, len(release.Assets))
}

// normaliseOS maps GOOS values to the strings used in ProjectDiscovery releases.
func normaliseOS(goos string) string {
	switch goos {
	case "darwin":
		return "macOS" // ProjectDiscovery uses "macOS" in release filenames
	default:
		return goos // "linux", "windows"
	}
}

// normaliseArch maps GOARCH values to the strings used in ProjectDiscovery releases.
func normaliseArch(goarch string) string {
	switch goarch {
	case "amd64":
		return "amd64"
	case "arm64":
		return "arm64"
	case "386":
		return "386"
	default:
		return goarch
	}
}

// ---------------------------------------------------------------------------
// Archive extraction
// ---------------------------------------------------------------------------

// extractBinary extracts the tool binary from a zip or tar.gz archive.
// It searches for a file whose base name matches toolName (with or without
// the platform extension).
func extractBinary(toolName, assetURL string, data []byte) ([]byte, error) {
	if strings.HasSuffix(assetURL, ".zip") {
		return extractFromZip(toolName, data)
	}
	if strings.HasSuffix(assetURL, ".tar.gz") || strings.HasSuffix(assetURL, ".tgz") {
		return extractFromTarGz(toolName, data)
	}
	// Assume the data is the raw binary.
	return data, nil
}

// extractFromZip extracts the named binary from a zip archive.
func extractFromZip(toolName string, data []byte) ([]byte, error) {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}

	binaryBase := toolName
	if runtime.GOOS == "windows" {
		binaryBase += ".exe"
	}

	for _, f := range r.File {
		base := filepath.Base(f.Name)
		if strings.EqualFold(base, binaryBase) {
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("open zip entry %q: %w", f.Name, err)
			}
			defer rc.Close()
			return io.ReadAll(rc)
		}
	}
	return nil, fmt.Errorf("binary %q not found in zip archive", binaryBase)
}

// extractFromTarGz extracts the named binary from a .tar.gz archive.
func extractFromTarGz(toolName string, data []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("open gzip: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	binaryBase := toolName
	if runtime.GOOS == "windows" {
		binaryBase += ".exe"
	}

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar: %w", err)
		}
		base := filepath.Base(hdr.Name)
		if strings.EqualFold(base, binaryBase) {
			return io.ReadAll(tr)
		}
	}
	return nil, fmt.Errorf("binary %q not found in tar.gz archive", binaryBase)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// fileExists returns true when path exists and is a regular file.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// downloadBytes fetches a URL and returns the response body as bytes.
func downloadBytes(url string) ([]byte, error) {
	resp, err := http.Get(url) //nolint:noctx
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}
