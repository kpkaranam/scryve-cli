// Package compliance_test — tests for the baseMapper and loader edge cases.
package compliance_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scryve/scryve/pkg/compliance"
	"github.com/scryve/scryve/pkg/finding"
)

// ---------------------------------------------------------------------------
// baseMapper — exercised via LoadMapper with a custom YAML file
// ---------------------------------------------------------------------------

// buildTestYAML writes a minimal compliance YAML file to dir and returns its path.
func buildTestYAML(t *testing.T, dir string, content string) string {
	t.Helper()
	path := filepath.Join(dir, "test-framework.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write test YAML: %v", err)
	}
	return path
}

const baseMapperYAML = `
framework: test-framework
version: 1.0
description: Test compliance framework
controls:
  - id: CTRL-1
    title: Injection Prevention
    description: Prevent injection attacks
    cwes:
      - CWE-89
      - CWE-79
  - id: CTRL-2
    title: Auth Controls
    description: Authentication requirements
    cwes:
      - CWE-287
  - id: CTRL-3
    title: No CWE Control
    description: Control with no CWE mappings
    cwes: []
`

// TestBaseMapper_Framework verifies that Framework() returns the correct identifier.
func TestBaseMapper_Framework(t *testing.T) {
	dir := t.TempDir()
	path := buildTestYAML(t, dir, baseMapperYAML)

	mapper, err := compliance.LoadMapper(path)
	if err != nil {
		t.Fatalf("LoadMapper() error: %v", err)
	}
	if got := mapper.Framework(); got != "test-framework" {
		t.Errorf("Framework() = %q, want %q", got, "test-framework")
	}
}

// TestBaseMapper_Version verifies that Version() returns the correct version string.
func TestBaseMapper_Version(t *testing.T) {
	dir := t.TempDir()
	path := buildTestYAML(t, dir, baseMapperYAML)

	mapper, err := compliance.LoadMapper(path)
	if err != nil {
		t.Fatalf("LoadMapper() error: %v", err)
	}
	if got := mapper.Version(); got != "1.0" {
		t.Errorf("Version() = %q, want %q", got, "1.0")
	}
}

// TestBaseMapper_Controls verifies that Controls() returns all defined controls
// and that each has the expected fields.
func TestBaseMapper_Controls(t *testing.T) {
	dir := t.TempDir()
	path := buildTestYAML(t, dir, baseMapperYAML)

	mapper, err := compliance.LoadMapper(path)
	if err != nil {
		t.Fatalf("LoadMapper() error: %v", err)
	}

	controls := mapper.Controls()
	if len(controls) != 3 {
		t.Fatalf("Controls() returned %d controls, want 3", len(controls))
	}

	// Verify control IDs are present.
	controlIDs := make(map[string]bool)
	for _, c := range controls {
		controlIDs[c.ID] = true
	}
	for _, want := range []string{"CTRL-1", "CTRL-2", "CTRL-3"} {
		if !controlIDs[want] {
			t.Errorf("Controls() missing control %q", want)
		}
	}
}

// TestBaseMapper_MapFinding_CWELookup verifies CWE-based finding mapping via
// the baseMapper (loaded from YAML, not pciDSSMapper).
func TestBaseMapper_MapFinding_CWELookup(t *testing.T) {
	dir := t.TempDir()
	path := buildTestYAML(t, dir, baseMapperYAML)

	mapper, err := compliance.LoadMapper(path)
	if err != nil {
		t.Fatalf("LoadMapper() error: %v", err)
	}

	f := &finding.Finding{
		ID:       "test-cwe",
		Title:    "SQL Injection",
		Severity: finding.SeverityCritical,
		CWE:      "CWE-89",
	}

	mappings := mapper.MapFinding(f)
	if len(mappings) == 0 {
		t.Fatal("MapFinding() returned no mappings for CWE-89")
	}

	found := false
	for _, m := range mappings {
		if m.ControlID == "CTRL-1" {
			found = true
		}
		if m.Framework != "test-framework" {
			t.Errorf("mapping Framework = %q, want %q", m.Framework, "test-framework")
		}
		if m.Status != "fail" {
			t.Errorf("mapping Status = %q, want %q", m.Status, "fail")
		}
	}
	if !found {
		t.Error("MapFinding() for CWE-89 should produce CTRL-1 mapping")
	}
}

// TestBaseMapper_MapFinding_MultipleCWEsForSameControl verifies that a finding
// mapped via a CWE that appears in a control produces exactly one entry (no dupe).
func TestBaseMapper_MapFinding_MultipleCWEsForSameControl(t *testing.T) {
	dir := t.TempDir()
	path := buildTestYAML(t, dir, baseMapperYAML)

	mapper, err := compliance.LoadMapper(path)
	if err != nil {
		t.Fatalf("LoadMapper() error: %v", err)
	}

	// CWE-79 and CWE-89 both map to CTRL-1. Using either should produce 1 mapping for CTRL-1.
	for _, cwe := range []string{"CWE-79", "CWE-89"} {
		f := &finding.Finding{
			ID:  "test",
			CWE: cwe,
		}
		mappings := mapper.MapFinding(f)
		ctrl1Count := 0
		for _, m := range mappings {
			if m.ControlID == "CTRL-1" {
				ctrl1Count++
			}
		}
		if ctrl1Count != 1 {
			t.Errorf("CWE=%q: CTRL-1 appears %d times in mappings, want 1", cwe, ctrl1Count)
		}
	}
}

// TestBaseMapper_MapFinding_NilFinding verifies that MapFinding(nil) returns nil
// without panicking for the baseMapper.
func TestBaseMapper_MapFinding_NilFinding(t *testing.T) {
	dir := t.TempDir()
	path := buildTestYAML(t, dir, baseMapperYAML)

	mapper, err := compliance.LoadMapper(path)
	if err != nil {
		t.Fatalf("LoadMapper() error: %v", err)
	}

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("MapFinding(nil) panicked: %v", r)
		}
	}()

	mappings := mapper.MapFinding(nil)
	if len(mappings) > 0 {
		t.Errorf("MapFinding(nil) should return nil, got %d mappings", len(mappings))
	}
}

// TestBaseMapper_MapFinding_EmptyCWE verifies that a finding with an empty CWE
// returns no mappings from the baseMapper (it only does CWE lookups, unlike
// pciDSSMapper which has CVE and severity fallback rules).
func TestBaseMapper_MapFinding_EmptyCWE(t *testing.T) {
	dir := t.TempDir()
	path := buildTestYAML(t, dir, baseMapperYAML)

	mapper, err := compliance.LoadMapper(path)
	if err != nil {
		t.Fatalf("LoadMapper() error: %v", err)
	}

	f := &finding.Finding{
		ID:       "no-cwe",
		Title:    "Some Finding",
		Severity: finding.SeverityCritical, // high severity but no CWE — no fallback in baseMapper
		CVE:      "CVE-2021-12345",         // CVE present but no CVE rule in baseMapper
	}

	mappings := mapper.MapFinding(f)
	if len(mappings) != 0 {
		t.Errorf("baseMapper.MapFinding() with no CWE should return 0 mappings, got %d: %v", len(mappings), mappings)
	}
}

// TestBaseMapper_MapFinding_UnknownCWE verifies that a finding with a CWE that
// doesn't match any control returns an empty slice.
func TestBaseMapper_MapFinding_UnknownCWE(t *testing.T) {
	dir := t.TempDir()
	path := buildTestYAML(t, dir, baseMapperYAML)

	mapper, err := compliance.LoadMapper(path)
	if err != nil {
		t.Fatalf("LoadMapper() error: %v", err)
	}

	f := &finding.Finding{
		ID:  "unknown-cwe",
		CWE: "CWE-9999",
	}

	mappings := mapper.MapFinding(f)
	if len(mappings) != 0 {
		t.Errorf("MapFinding() for unknown CWE should return 0 mappings, got %d", len(mappings))
	}
}

// TestBaseMapper_MapFindings_BulkEnrichment verifies that MapFindings correctly
// enriches a slice of findings using the baseMapper's CWE-only logic.
func TestBaseMapper_MapFindings_BulkEnrichment(t *testing.T) {
	dir := t.TempDir()
	path := buildTestYAML(t, dir, baseMapperYAML)

	mapper, err := compliance.LoadMapper(path)
	if err != nil {
		t.Fatalf("LoadMapper() error: %v", err)
	}

	findings := []finding.Finding{
		{ID: "f1", CWE: "CWE-89", Severity: finding.SeverityCritical},
		{ID: "f2", CWE: "CWE-287", Severity: finding.SeverityMedium},
		{ID: "f3", CWE: "CWE-9999", Severity: finding.SeverityLow}, // unknown CWE — 0 mappings
		{ID: "f4", Severity: finding.SeverityInfo},                 // no CWE — 0 mappings
	}

	enriched := mapper.MapFindings(findings)

	if len(enriched) != 4 {
		t.Fatalf("MapFindings() returned %d findings, want 4", len(enriched))
	}

	// f1 (CWE-89) → CTRL-1
	if len(enriched[0].Compliance) == 0 {
		t.Error("f1 (CWE-89) should have at least 1 mapping")
	}
	// f2 (CWE-287) → CTRL-2
	if len(enriched[1].Compliance) == 0 {
		t.Error("f2 (CWE-287) should have at least 1 mapping")
	}
	// f3 (CWE-9999) → 0 mappings
	if len(enriched[2].Compliance) != 0 {
		t.Errorf("f3 (CWE-9999) should have 0 mappings, got %d", len(enriched[2].Compliance))
	}
	// f4 (no CWE) → 0 mappings
	if len(enriched[3].Compliance) != 0 {
		t.Errorf("f4 (no CWE) should have 0 mappings, got %d", len(enriched[3].Compliance))
	}
}

// TestBaseMapper_MapFindings_PreservesExistingMappings verifies that existing
// compliance mappings on findings are not removed during enrichment.
func TestBaseMapper_MapFindings_PreservesExistingMappings(t *testing.T) {
	dir := t.TempDir()
	path := buildTestYAML(t, dir, baseMapperYAML)

	mapper, err := compliance.LoadMapper(path)
	if err != nil {
		t.Fatalf("LoadMapper() error: %v", err)
	}

	existing := finding.ComplianceMapping{
		Framework: "pci-dss-4.0",
		ControlID: "6.2.4",
		Status:    "fail",
	}
	findings := []finding.Finding{
		{
			ID:         "f1",
			CWE:        "CWE-89",
			Compliance: []finding.ComplianceMapping{existing},
		},
	}

	enriched := mapper.MapFindings(findings)

	// Must still have the original mapping.
	foundExisting := false
	for _, m := range enriched[0].Compliance {
		if m.Framework == "pci-dss-4.0" && m.ControlID == "6.2.4" {
			foundExisting = true
		}
	}
	if !foundExisting {
		t.Error("MapFindings() removed existing compliance mapping")
	}

	// And must also have the new CTRL-1 mapping.
	foundNew := false
	for _, m := range enriched[0].Compliance {
		if m.ControlID == "CTRL-1" {
			foundNew = true
		}
	}
	if !foundNew {
		t.Error("MapFindings() did not add CTRL-1 mapping for CWE-89")
	}
}

// TestBaseMapper_EnsureIndex_LazyBuilt verifies that the CWE index is built
// lazily (on first MapFinding call) and that calling MapFinding twice produces
// consistent results (tests the ensureIndex path).
func TestBaseMapper_EnsureIndex_LazyBuilt(t *testing.T) {
	dir := t.TempDir()
	path := buildTestYAML(t, dir, baseMapperYAML)

	mapper, err := compliance.LoadMapper(path)
	if err != nil {
		t.Fatalf("LoadMapper() error: %v", err)
	}

	f := &finding.Finding{ID: "test", CWE: "CWE-89"}

	// Call MapFinding twice — second call exercises already-built index path.
	m1 := mapper.MapFinding(f)
	m2 := mapper.MapFinding(f)

	if len(m1) != len(m2) {
		t.Errorf("MapFinding called twice: first=%d, second=%d — results inconsistent", len(m1), len(m2))
	}
}

// ---------------------------------------------------------------------------
// parseFrameworkYAML edge cases
// ---------------------------------------------------------------------------

// TestParseFrameworkYAML_MissingFrameworkField verifies that loading a YAML file
// that lacks the 'framework' field returns an error.
func TestParseFrameworkYAML_MissingFrameworkField(t *testing.T) {
	const missingFramework = `
version: 1.0
controls:
  - id: C1
    title: Test
`
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte(missingFramework), 0o600); err != nil {
		t.Fatalf("write test YAML: %v", err)
	}

	_, err := compliance.LoadMapper(path)
	if err == nil {
		t.Fatal("LoadMapper() expected error for YAML missing 'framework' field, got nil")
	}
}

// TestParseFrameworkYAML_InvalidYAML verifies that a malformed YAML file returns
// a descriptive error.
func TestParseFrameworkYAML_InvalidYAML(t *testing.T) {
	const badYAML = `{this is not valid yaml: [`
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte(badYAML), 0o600); err != nil {
		t.Fatalf("write test YAML: %v", err)
	}

	_, err := compliance.LoadMapper(path)
	if err == nil {
		t.Fatal("LoadMapper() expected error for invalid YAML, got nil")
	}
}

// TestParseFrameworkYAML_EmptyFile verifies that an empty YAML file returns an
// error (missing 'framework' field).
func TestParseFrameworkYAML_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.yaml")
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatalf("write test YAML: %v", err)
	}

	_, err := compliance.LoadMapper(path)
	if err == nil {
		t.Fatal("LoadMapper() expected error for empty YAML, got nil")
	}
}

// ---------------------------------------------------------------------------
// LoadAllMappers edge cases
// ---------------------------------------------------------------------------

// TestLoadAllMappers_SkipsNonYAMLFiles verifies that non-.yaml files in a
// directory are silently ignored.
func TestLoadAllMappers_SkipsNonYAMLFiles(t *testing.T) {
	dir := t.TempDir()

	// Write a valid YAML file.
	validYAML := `framework: valid\nversion: 1.0\ncontrols: []`
	if err := os.WriteFile(filepath.Join(dir, "valid.yaml"), []byte(
		"framework: valid\nversion: 1.0\ncontrols: []\n",
	), 0o600); err != nil {
		t.Fatalf("write valid yaml: %v", err)
	}

	// Write files that should be ignored.
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("not yaml"), 0o600); err != nil {
		t.Fatalf("write txt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatalf("write json: %v", err)
	}
	_ = validYAML

	mappers, err := compliance.LoadAllMappers(dir)
	if err != nil {
		t.Fatalf("LoadAllMappers() unexpected error: %v", err)
	}
	if len(mappers) != 1 {
		t.Errorf("LoadAllMappers() returned %d mappers, want 1", len(mappers))
	}
}

// TestLoadAllMappers_AllFilesInvalid verifies that when all YAML files fail to
// parse, an error is returned.
func TestLoadAllMappers_AllFilesInvalid(t *testing.T) {
	dir := t.TempDir()

	// Both files are invalid (missing 'framework' field).
	for _, name := range []string{"a.yaml", "b.yaml"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("version: 1.0\n"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	_, err := compliance.LoadAllMappers(dir)
	if err == nil {
		t.Fatal("LoadAllMappers() expected error when all files fail to parse, got nil")
	}
}

// TestLoadAllMappers_MixedValidInvalid verifies that when some files are invalid
// and at least one is valid, the valid mappers are returned without error.
func TestLoadAllMappers_MixedValidInvalid(t *testing.T) {
	dir := t.TempDir()

	// Valid file.
	if err := os.WriteFile(filepath.Join(dir, "valid.yaml"), []byte(
		"framework: valid\nversion: 1.0\ncontrols: []\n",
	), 0o600); err != nil {
		t.Fatalf("write valid.yaml: %v", err)
	}
	// Invalid file (missing framework field).
	if err := os.WriteFile(filepath.Join(dir, "invalid.yaml"), []byte("version: 1.0\n"), 0o600); err != nil {
		t.Fatalf("write invalid.yaml: %v", err)
	}

	mappers, err := compliance.LoadAllMappers(dir)
	if err != nil {
		t.Fatalf("LoadAllMappers() unexpected error when mixed: %v", err)
	}
	if len(mappers) != 1 {
		t.Errorf("LoadAllMappers() returned %d mappers, want 1 valid one", len(mappers))
	}
}

// TestLoadAllMappers_YmlExtension verifies that .yml extension files are also
// loaded in addition to .yaml files.
func TestLoadAllMappers_YmlExtension(t *testing.T) {
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "framework.yml"), []byte(
		"framework: yml-framework\nversion: 2.0\ncontrols: []\n",
	), 0o600); err != nil {
		t.Fatalf("write framework.yml: %v", err)
	}

	mappers, err := compliance.LoadAllMappers(dir)
	if err != nil {
		t.Fatalf("LoadAllMappers() unexpected error: %v", err)
	}
	if len(mappers) != 1 {
		t.Fatalf("LoadAllMappers() returned %d mappers, want 1", len(mappers))
	}
	if mappers[0].Framework() != "yml-framework" {
		t.Errorf("mapper Framework() = %q, want %q", mappers[0].Framework(), "yml-framework")
	}
}

// TestLoadAllMappers_EmptyDirectory verifies that an empty directory returns
// an empty (non-nil) slice without error.
func TestLoadAllMappers_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()

	// Directory with no YAML files.
	mappers, err := compliance.LoadAllMappers(dir)
	if err != nil {
		t.Fatalf("LoadAllMappers() unexpected error for empty dir: %v", err)
	}
	if len(mappers) != 0 {
		t.Errorf("LoadAllMappers() returned %d mappers for empty dir, want 0", len(mappers))
	}
}

// ---------------------------------------------------------------------------
// isEmailFinding edge cases
// ---------------------------------------------------------------------------

// TestPCIDSSMapper_IsEmailFinding_TagDetection verifies that SPF/DKIM/DMARC
// detection works via tags even when the title doesn't mention them.
func TestPCIDSSMapper_IsEmailFinding_TagDetection(t *testing.T) {
	mapper, err := compliance.NewPCIDSSMapper()
	if err != nil {
		t.Fatalf("NewPCIDSSMapper() error: %v", err)
	}

	cases := []struct {
		name    string
		tags    []string
		wantMap bool
	}{
		{"tag spf uppercase", []string{"SPF"}, true},
		{"tag dkim", []string{"DKIM"}, true},
		{"tag dmarc", []string{"DMARC"}, true},
		{"tag unrelated", []string{"xss", "injection"}, false},
		{"tag mixed", []string{"xss", "spf"}, true},
		{"no tags no keywords", []string{}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &finding.Finding{
				ID:       "test",
				Title:    "Some Security Finding", // title has no email keywords
				Severity: finding.SeverityMedium,
				Tags:     tc.tags,
			}
			mappings := mapper.MapFinding(f)
			has421 := hasControlID(mappings, "4.2.1")
			if has421 != tc.wantMap {
				t.Errorf("tags=%v: has 4.2.1 mapping = %v, want %v", tc.tags, has421, tc.wantMap)
			}
		})
	}
}

// TestPCIDSSMapper_IsEmailFinding_TitleOnlyNoTags verifies that email keywords
// in title alone (no tags) trigger the 4.2.1 mapping.
func TestPCIDSSMapper_IsEmailFinding_TitleOnlyNoTags(t *testing.T) {
	mapper, err := compliance.NewPCIDSSMapper()
	if err != nil {
		t.Fatalf("NewPCIDSSMapper() error: %v", err)
	}

	cases := []struct {
		title   string
		want421 bool
	}{
		{"SPF Record Missing", true},
		{"dkim not configured", true},
		{"DMARC policy absent", true},
		{"HTTP Header Missing", false},
		{"Open Redirect", false},
	}

	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			f := &finding.Finding{
				ID:       "test",
				Title:    tc.title,
				Severity: finding.SeverityMedium,
				Tags:     nil, // no tags
			}
			mappings := mapper.MapFinding(f)
			has421 := hasControlID(mappings, "4.2.1")
			if has421 != tc.want421 {
				t.Errorf("title=%q: has 4.2.1 mapping = %v, want %v", tc.title, has421, tc.want421)
			}
		})
	}
}
