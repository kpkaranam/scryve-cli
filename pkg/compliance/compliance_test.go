// Package compliance_test exercises the compliance mapper system end-to-end.
// Tests cover YAML loading, CWE mapping, CVE mapping, severity-based mapping,
// and bulk enrichment of finding slices.
package compliance_test

import (
	"strings"
	"testing"

	"github.com/scryve/scryve/pkg/compliance"
	"github.com/scryve/scryve/pkg/finding"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// hasControlID returns true if any mapping in the slice matches controlID.
func hasControlID(mappings []finding.ComplianceMapping, controlID string) bool {
	for _, m := range mappings {
		if m.ControlID == controlID {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// YAML loading
// ---------------------------------------------------------------------------

// TestLoadEmbeddedPCIDSS verifies that the embedded PCI DSS YAML file can be
// parsed into a valid ComplianceMapper without error.
func TestLoadEmbeddedPCIDSS(t *testing.T) {
	mapper, err := compliance.NewPCIDSSMapper()
	if err != nil {
		t.Fatalf("NewPCIDSSMapper() error = %v", err)
	}
	if mapper.Framework() != "pci-dss-4.0" {
		t.Errorf("Framework() = %q, want %q", mapper.Framework(), "pci-dss-4.0")
	}
	if mapper.Version() != "4.0" {
		t.Errorf("Version() = %q, want %q", mapper.Version(), "4.0")
	}
}

// TestLoadMapperFromPath verifies loading from an explicit file path.
func TestLoadMapperFromPath(t *testing.T) {
	mapper, err := compliance.LoadMapper("../../data/compliance/pci-dss-4.0.yaml")
	if err != nil {
		t.Fatalf("LoadMapper() error = %v", err)
	}
	if mapper.Framework() != "pci-dss-4.0" {
		t.Errorf("Framework() = %q, want %q", mapper.Framework(), "pci-dss-4.0")
	}
}

// TestLoadAllMappers verifies that LoadAllMappers loads every YAML file in the
// data/compliance directory.
func TestLoadAllMappers(t *testing.T) {
	mappers, err := compliance.LoadAllMappers("../../data/compliance")
	if err != nil {
		t.Fatalf("LoadAllMappers() error = %v", err)
	}
	if len(mappers) == 0 {
		t.Fatal("LoadAllMappers() returned 0 mappers, want at least 1")
	}
	// Ensure the PCI DSS mapper is present.
	found := false
	for _, m := range mappers {
		if m.Framework() == "pci-dss-4.0" {
			found = true
		}
	}
	if !found {
		t.Error("LoadAllMappers() did not load the pci-dss-4.0 mapper")
	}
}

// TestLoadMapperBadPath verifies that a non-existent path returns an error.
func TestLoadMapperBadPath(t *testing.T) {
	_, err := compliance.LoadMapper("/nonexistent/path/to/file.yaml")
	if err == nil {
		t.Fatal("LoadMapper() expected error for bad path, got nil")
	}
}

// ---------------------------------------------------------------------------
// Controls()
// ---------------------------------------------------------------------------

// TestControlsReturnsAll verifies that Controls() returns all controls defined
// in the YAML (we expect at least 15 for PCI DSS 4.0).
func TestControlsReturnsAll(t *testing.T) {
	mapper, err := compliance.NewPCIDSSMapper()
	if err != nil {
		t.Fatalf("NewPCIDSSMapper() error = %v", err)
	}
	controls := mapper.Controls()
	if len(controls) < 15 {
		t.Errorf("Controls() returned %d controls, want at least 15", len(controls))
	}
}

// TestControlsHaveIDs verifies that every control returned by Controls() has a
// non-empty ID and Title.
func TestControlsHaveIDs(t *testing.T) {
	mapper, err := compliance.NewPCIDSSMapper()
	if err != nil {
		t.Fatalf("NewPCIDSSMapper() error = %v", err)
	}
	for _, c := range mapper.Controls() {
		if c.ID == "" {
			t.Errorf("control with empty ID found: %+v", c)
		}
		if c.Title == "" {
			t.Errorf("control %q has empty Title", c.ID)
		}
	}
}

// ---------------------------------------------------------------------------
// MapFinding — CWE-based mapping
// ---------------------------------------------------------------------------

// TestMapFindingCWE79MapsTo624And641 verifies that a finding with CWE-79 (XSS)
// maps to both requirement 6.2.4 and 6.4.1.
func TestMapFindingCWE79MapsTo624And641(t *testing.T) {
	mapper, err := compliance.NewPCIDSSMapper()
	if err != nil {
		t.Fatalf("NewPCIDSSMapper() error = %v", err)
	}

	f := finding.Finding{
		ID:       "test-1",
		Title:    "Cross-Site Scripting",
		Severity: finding.SeverityHigh,
		CWE:      "CWE-79",
	}

	mappings := mapper.MapFinding(&f)

	if !hasControlID(mappings, "6.2.4") {
		t.Error("CWE-79 should map to control 6.2.4")
	}
	if !hasControlID(mappings, "6.4.1") {
		t.Error("CWE-79 should map to control 6.4.1")
	}
}

// TestMapFindingCWE89SQLInjection verifies that SQL injection (CWE-89) maps to
// requirements 6.2.4 and 6.4.1.
func TestMapFindingCWE89SQLInjection(t *testing.T) {
	mapper, err := compliance.NewPCIDSSMapper()
	if err != nil {
		t.Fatalf("NewPCIDSSMapper() error = %v", err)
	}

	f := finding.Finding{
		ID:       "test-2",
		Title:    "SQL Injection",
		Severity: finding.SeverityCritical,
		CWE:      "CWE-89",
	}

	mappings := mapper.MapFinding(&f)

	if !hasControlID(mappings, "6.2.4") {
		t.Error("CWE-89 should map to control 6.2.4")
	}
	if !hasControlID(mappings, "6.4.1") {
		t.Error("CWE-89 should map to control 6.4.1")
	}
}

// TestMapFindingCWE319WeakCrypto verifies that cleartext transmission (CWE-319)
// maps to requirement 4.2.1.
func TestMapFindingCWE319WeakCrypto(t *testing.T) {
	mapper, err := compliance.NewPCIDSSMapper()
	if err != nil {
		t.Fatalf("NewPCIDSSMapper() error = %v", err)
	}

	f := finding.Finding{
		ID:       "test-3",
		Title:    "Cleartext Transmission of Sensitive Information",
		Severity: finding.SeverityHigh,
		CWE:      "CWE-319",
	}

	mappings := mapper.MapFinding(&f)

	if !hasControlID(mappings, "4.2.1") {
		t.Error("CWE-319 should map to control 4.2.1")
	}
}

// TestMapFindingAllMappingsHaveFailStatus verifies that every mapping produced
// from a failing finding has Status="fail".
func TestMapFindingAllMappingsHaveFailStatus(t *testing.T) {
	mapper, err := compliance.NewPCIDSSMapper()
	if err != nil {
		t.Fatalf("NewPCIDSSMapper() error = %v", err)
	}

	f := finding.Finding{
		ID:       "test-4",
		Title:    "XSS",
		Severity: finding.SeverityHigh,
		CWE:      "CWE-79",
	}

	mappings := mapper.MapFinding(&f)
	if len(mappings) == 0 {
		t.Fatal("MapFinding() returned no mappings")
	}
	for _, m := range mappings {
		if m.Status != "fail" {
			t.Errorf("mapping %q has Status=%q, want %q", m.ControlID, m.Status, "fail")
		}
		if m.Framework != "pci-dss-4.0" {
			t.Errorf("mapping %q has Framework=%q, want %q", m.ControlID, m.Framework, "pci-dss-4.0")
		}
	}
}

// TestMapFindingNoDuplicateControls verifies that MapFinding does not return
// duplicate control mappings.
func TestMapFindingNoDuplicateControls(t *testing.T) {
	mapper, err := compliance.NewPCIDSSMapper()
	if err != nil {
		t.Fatalf("NewPCIDSSMapper() error = %v", err)
	}

	// CWE-521 maps to 8.3.6
	f := finding.Finding{
		ID:       "test-5",
		Title:    "Weak Password",
		Severity: finding.SeverityMedium,
		CWE:      "CWE-521",
	}

	mappings := mapper.MapFinding(&f)
	seen := make(map[string]int)
	for _, m := range mappings {
		seen[m.ControlID]++
	}
	for id, count := range seen {
		if count > 1 {
			t.Errorf("control %q appears %d times in mappings, want 1", id, count)
		}
	}
}

// ---------------------------------------------------------------------------
// MapFinding — CVE-based mapping
// ---------------------------------------------------------------------------

// TestMapFindingCVEMapsTo631 verifies that a finding with a CVE identifier maps
// to requirement 6.3.1 (vulnerability management).
func TestMapFindingCVEMapsTo631(t *testing.T) {
	mapper, err := compliance.NewPCIDSSMapper()
	if err != nil {
		t.Fatalf("NewPCIDSSMapper() error = %v", err)
	}

	f := finding.Finding{
		ID:       "test-6",
		Title:    "Apache Log4Shell",
		Severity: finding.SeverityCritical,
		CVE:      "CVE-2021-44228",
	}

	mappings := mapper.MapFinding(&f)

	if !hasControlID(mappings, "6.3.1") {
		t.Error("CVE finding should map to control 6.3.1")
	}
}

// TestMapFindingCVEAndCWECombined verifies that a finding with both CVE and CWE
// produces mappings for both the CVE rule (6.3.1) and any CWE-based controls.
func TestMapFindingCVEAndCWECombined(t *testing.T) {
	mapper, err := compliance.NewPCIDSSMapper()
	if err != nil {
		t.Fatalf("NewPCIDSSMapper() error = %v", err)
	}

	f := finding.Finding{
		ID:       "test-7",
		Title:    "Deserialization Vulnerability",
		Severity: finding.SeverityCritical,
		CWE:      "CWE-502",
		CVE:      "CVE-2022-12345",
	}

	mappings := mapper.MapFinding(&f)

	// Should have 6.3.1 from CVE
	if !hasControlID(mappings, "6.3.1") {
		t.Error("CVE+CWE finding should include 6.3.1 from CVE")
	}
	// Should have 6.2.4 from CWE-502
	if !hasControlID(mappings, "6.2.4") {
		t.Error("CWE-502 should map to 6.2.4")
	}
}

// ---------------------------------------------------------------------------
// MapFinding — severity-based mapping (no CWE)
// ---------------------------------------------------------------------------

// TestMapFindingNoCWECriticalMapsTo631 verifies that a critical severity
// finding with no CWE still maps to requirement 6.3.1.
func TestMapFindingNoCWECriticalMapsTo631(t *testing.T) {
	mapper, err := compliance.NewPCIDSSMapper()
	if err != nil {
		t.Fatalf("NewPCIDSSMapper() error = %v", err)
	}

	f := finding.Finding{
		ID:       "test-8",
		Title:    "Generic Critical Finding",
		Severity: finding.SeverityCritical,
	}

	mappings := mapper.MapFinding(&f)

	if !hasControlID(mappings, "6.3.1") {
		t.Error("Critical severity finding with no CWE should map to 6.3.1")
	}
}

// TestMapFindingNoCWEHighMapsTo631 mirrors the critical test for high severity.
func TestMapFindingNoCWEHighMapsTo631(t *testing.T) {
	mapper, err := compliance.NewPCIDSSMapper()
	if err != nil {
		t.Fatalf("NewPCIDSSMapper() error = %v", err)
	}

	f := finding.Finding{
		ID:       "test-9",
		Title:    "Generic High Finding",
		Severity: finding.SeverityHigh,
	}

	mappings := mapper.MapFinding(&f)

	if !hasControlID(mappings, "6.3.1") {
		t.Error("High severity finding with no CWE should map to 6.3.1")
	}
}

// TestMapFindingNoCWEInfoNoMapping verifies that an informational finding with
// no CWE and no CVE does NOT get automatically mapped.
func TestMapFindingNoCWEInfoNoMapping(t *testing.T) {
	mapper, err := compliance.NewPCIDSSMapper()
	if err != nil {
		t.Fatalf("NewPCIDSSMapper() error = %v", err)
	}

	f := finding.Finding{
		ID:       "test-10",
		Title:    "Informational Finding",
		Severity: finding.SeverityInfo,
	}

	mappings := mapper.MapFinding(&f)

	if len(mappings) > 0 {
		t.Errorf("Info severity finding with no CWE/CVE should produce 0 mappings, got %d", len(mappings))
	}
}

// ---------------------------------------------------------------------------
// MapFinding — email security (SPF/DKIM/DMARC)
// ---------------------------------------------------------------------------

// TestMapFindingEmailSPFMapsTo421 verifies that an SPF-related finding maps to
// requirement 4.2.1 (cryptographic transmission).
func TestMapFindingEmailSPFMapsTo421(t *testing.T) {
	mapper, err := compliance.NewPCIDSSMapper()
	if err != nil {
		t.Fatalf("NewPCIDSSMapper() error = %v", err)
	}

	f := finding.Finding{
		ID:       "test-11",
		Title:    "Missing SPF Record",
		Severity: finding.SeverityMedium,
		Tags:     []string{"email", "spf"},
	}

	mappings := mapper.MapFinding(&f)

	if !hasControlID(mappings, "4.2.1") {
		t.Error("SPF finding should map to control 4.2.1")
	}
}

// TestMapFindingEmailDKIMMapsTo421 mirrors SPF test for DKIM.
func TestMapFindingEmailDKIMMapsTo421(t *testing.T) {
	mapper, err := compliance.NewPCIDSSMapper()
	if err != nil {
		t.Fatalf("NewPCIDSSMapper() error = %v", err)
	}

	f := finding.Finding{
		ID:       "test-12",
		Title:    "DKIM Not Configured",
		Severity: finding.SeverityMedium,
		Tags:     []string{"email", "dkim"},
	}

	mappings := mapper.MapFinding(&f)

	if !hasControlID(mappings, "4.2.1") {
		t.Error("DKIM finding should map to control 4.2.1")
	}
}

// TestMapFindingEmailDMARCMapsTo421 mirrors SPF test for DMARC.
func TestMapFindingEmailDMARCMapsTo421(t *testing.T) {
	mapper, err := compliance.NewPCIDSSMapper()
	if err != nil {
		t.Fatalf("NewPCIDSSMapper() error = %v", err)
	}

	f := finding.Finding{
		ID:       "test-13",
		Title:    "DMARC Policy Missing",
		Severity: finding.SeverityMedium,
		Tags:     []string{"email", "dmarc"},
	}

	mappings := mapper.MapFinding(&f)

	if !hasControlID(mappings, "4.2.1") {
		t.Error("DMARC finding should map to control 4.2.1")
	}
}

// TestMapFindingEmailTitleDetection verifies that email-related findings are
// detected via title keywords even without tags.
func TestMapFindingEmailTitleDetection(t *testing.T) {
	mapper, err := compliance.NewPCIDSSMapper()
	if err != nil {
		t.Fatalf("NewPCIDSSMapper() error = %v", err)
	}

	tests := []struct {
		title string
	}{
		{"SPF record not found"},
		{"DKIM signature missing"},
		{"DMARC policy not configured"},
		{"Missing SPF"},
		{"No DKIM record"},
	}

	for _, tt := range tests {
		t.Run(tt.title, func(t *testing.T) {
			f := finding.Finding{
				ID:       "test-email",
				Title:    tt.title,
				Severity: finding.SeverityMedium,
			}
			mappings := mapper.MapFinding(&f)
			if !hasControlID(mappings, "4.2.1") {
				t.Errorf("email finding %q should map to 4.2.1", tt.title)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// MapFindings — bulk enrichment
// ---------------------------------------------------------------------------

// TestMapFindingsEnrichesInPlace verifies that MapFindings adds ComplianceMapping
// entries to each finding in the slice.
func TestMapFindingsEnrichesInPlace(t *testing.T) {
	mapper, err := compliance.NewPCIDSSMapper()
	if err != nil {
		t.Fatalf("NewPCIDSSMapper() error = %v", err)
	}

	findings := []finding.Finding{
		{ID: "f1", Title: "XSS", Severity: finding.SeverityHigh, CWE: "CWE-79"},
		{ID: "f2", Title: "SQL Injection", Severity: finding.SeverityCritical, CWE: "CWE-89"},
		{ID: "f3", Title: "Log4Shell", Severity: finding.SeverityCritical, CVE: "CVE-2021-44228"},
	}

	enriched := mapper.MapFindings(findings)

	for i, f := range enriched {
		if len(f.Compliance) == 0 {
			t.Errorf("finding[%d] (ID=%q) was not enriched with compliance mappings", i, f.ID)
		}
	}
}

// TestMapFindingsReturnsCorrectCount verifies that MapFindings returns the same
// number of findings as were passed in.
func TestMapFindingsReturnsCorrectCount(t *testing.T) {
	mapper, err := compliance.NewPCIDSSMapper()
	if err != nil {
		t.Fatalf("NewPCIDSSMapper() error = %v", err)
	}

	input := []finding.Finding{
		{ID: "f1", Title: "A", Severity: finding.SeverityHigh, CWE: "CWE-79"},
		{ID: "f2", Title: "B", Severity: finding.SeverityMedium, CWE: "CWE-89"},
	}

	result := mapper.MapFindings(input)
	if len(result) != len(input) {
		t.Errorf("MapFindings() returned %d findings, want %d", len(result), len(input))
	}
}

// TestMapFindingsDoesNotLoseExistingMappings verifies that findings that already
// have compliance mappings do not lose them after enrichment.
func TestMapFindingsDoesNotLoseExistingMappings(t *testing.T) {
	mapper, err := compliance.NewPCIDSSMapper()
	if err != nil {
		t.Fatalf("NewPCIDSSMapper() error = %v", err)
	}

	existing := finding.ComplianceMapping{
		Framework: "iso-27001",
		ControlID: "A.14.2.1",
		Status:    "fail",
	}

	findings := []finding.Finding{
		{
			ID:         "f1",
			Title:      "XSS",
			Severity:   finding.SeverityHigh,
			CWE:        "CWE-79",
			Compliance: []finding.ComplianceMapping{existing},
		},
	}

	enriched := mapper.MapFindings(findings)

	found := false
	for _, m := range enriched[0].Compliance {
		if m.Framework == "iso-27001" && m.ControlID == "A.14.2.1" {
			found = true
		}
	}
	if !found {
		t.Error("MapFindings() removed existing non-PCI compliance mapping")
	}
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

// TestMapFindingUnknownCWELowSeverityNoMappings verifies that a finding with an
// unrecognized CWE and low severity returns no mappings.
func TestMapFindingUnknownCWELowSeverityNoMappings(t *testing.T) {
	mapper, err := compliance.NewPCIDSSMapper()
	if err != nil {
		t.Fatalf("NewPCIDSSMapper() error = %v", err)
	}

	f := finding.Finding{
		ID:       "test-edge-1",
		Title:    "Obscure Bug",
		Severity: finding.SeverityLow,
		CWE:      "CWE-9999",
	}

	mappings := mapper.MapFinding(&f)
	// Low severity + unknown CWE should not trigger 6.3.1 fallback.
	if hasControlID(mappings, "6.3.1") {
		t.Error("Low severity unknown-CWE finding should not trigger 6.3.1")
	}
}

// TestMapFindingNilFinding verifies that MapFinding handles a nil pointer
// gracefully without panicking.
func TestMapFindingNilFinding(t *testing.T) {
	mapper, err := compliance.NewPCIDSSMapper()
	if err != nil {
		t.Fatalf("NewPCIDSSMapper() error = %v", err)
	}

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("MapFinding(nil) panicked: %v", r)
		}
	}()

	mappings := mapper.MapFinding(nil)
	if len(mappings) > 0 {
		t.Error("MapFinding(nil) should return nil or empty slice")
	}
}

// TestCWENormalizationLowercase verifies the mapper handles lowercase CWE IDs.
func TestCWENormalizationLowercase(t *testing.T) {
	mapper, err := compliance.NewPCIDSSMapper()
	if err != nil {
		t.Fatalf("NewPCIDSSMapper() error = %v", err)
	}

	f := finding.Finding{
		ID: "cwe-lower", Title: "XSS", Severity: finding.SeverityHigh, CWE: "cwe-79",
	}
	mappings := mapper.MapFinding(&f)
	if !hasControlID(mappings, "6.2.4") {
		t.Error("lowercase cwe-79 should still map to 6.2.4")
	}
}

// TestCWEWithoutPrefixNormalized verifies that CWE values without the "CWE-"
// prefix are handled gracefully and produce the same mappings as the prefixed form.
func TestCWEWithoutPrefixNormalized(t *testing.T) {
	mapper, err := compliance.NewPCIDSSMapper()
	if err != nil {
		t.Fatalf("NewPCIDSSMapper() error = %v", err)
	}

	fWithPrefix := finding.Finding{
		ID: "cwe-prefix", Title: "XSS", Severity: finding.SeverityHigh, CWE: "CWE-79",
	}
	fWithoutPrefix := finding.Finding{
		ID: "cwe-no-prefix", Title: "XSS", Severity: finding.SeverityHigh, CWE: "79",
	}

	m1 := mapper.MapFinding(&fWithPrefix)
	m2 := mapper.MapFinding(&fWithoutPrefix)

	if len(m1) != len(m2) {
		t.Errorf("CWE with prefix produced %d mappings, without prefix produced %d — normalization inconsistent", len(m1), len(m2))
	}
}

// ---------------------------------------------------------------------------
// Framework metadata
// ---------------------------------------------------------------------------

// TestMapperFrameworkAndVersion verifies that Framework() and Version() return
// the expected constant strings for the PCI DSS mapper.
func TestMapperFrameworkAndVersion(t *testing.T) {
	mapper, err := compliance.NewPCIDSSMapper()
	if err != nil {
		t.Fatalf("NewPCIDSSMapper() error = %v", err)
	}

	const wantFramework = "pci-dss-4.0"
	const wantVersion = "4.0"

	if got := mapper.Framework(); got != wantFramework {
		t.Errorf("Framework() = %q, want %q", got, wantFramework)
	}
	if got := mapper.Version(); got != wantVersion {
		t.Errorf("Version() = %q, want %q", got, wantVersion)
	}
}

// TestControlLookupByID verifies that a known control ID can be found in the
// Controls() slice.
func TestControlLookupByID(t *testing.T) {
	mapper, err := compliance.NewPCIDSSMapper()
	if err != nil {
		t.Fatalf("NewPCIDSSMapper() error = %v", err)
	}

	wantIDs := []string{"6.2.4", "6.3.1", "4.2.1", "8.3.6", "11.3.1", "11.3.2"}
	controlMap := make(map[string]bool)
	for _, c := range mapper.Controls() {
		controlMap[c.ID] = true
	}

	for _, id := range wantIDs {
		if !controlMap[id] {
			t.Errorf("Controls() missing expected control %q", id)
		}
	}
}

// TestLoadAllMappersNonExistentDirReturnsError verifies that passing a
// non-existent directory to LoadAllMappers returns an error.
func TestLoadAllMappersNonExistentDirReturnsError(t *testing.T) {
	_, err := compliance.LoadAllMappers("/nonexistent/compliance/dir")
	if err == nil {
		t.Fatal("LoadAllMappers() expected error for non-existent dir, got nil")
	}
}

// Ensure strings package import does not trigger unused-import error.
var _ = strings.ToUpper
