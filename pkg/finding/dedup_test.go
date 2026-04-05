package finding_test

import (
	"testing"
	"time"

	"github.com/scryve/scryve/pkg/finding"
)

// newTestFinding returns a minimal Finding with required fields set.
func newTestFinding(tool, cwe, host, path string, port int) finding.Finding {
	return finding.Finding{
		Title:    "Test finding",
		Tool:     tool,
		CWE:      cwe,
		Host:     host,
		Port:     port,
		Path:     path,
		Severity: finding.SeverityHigh,
	}
}

// TestFingerprint_Determinism verifies that calling Fingerprint twice on the
// same Finding produces the same hash and sets f.Fingerprint.
func TestFingerprint_Determinism(t *testing.T) {
	f := newTestFinding("nmap", "CWE-200", "example.com", "/api/v1", 443)

	hash1 := finding.Fingerprint(&f)
	if f.Fingerprint == "" {
		t.Fatal("Fingerprint() did not set f.Fingerprint")
	}
	if hash1 != f.Fingerprint {
		t.Errorf("Fingerprint() returned %q but set f.Fingerprint to %q", hash1, f.Fingerprint)
	}

	// Second call must produce the identical hash.
	hash2 := finding.Fingerprint(&f)
	if hash1 != hash2 {
		t.Errorf("Fingerprint() is not deterministic: first=%q second=%q", hash1, hash2)
	}
}

// TestFingerprint_Uniqueness verifies that different (tool+cwe+host+port+path)
// combinations produce different hashes.
func TestFingerprint_Uniqueness(t *testing.T) {
	f1 := newTestFinding("nmap", "CWE-200", "example.com", "/api/v1", 443)
	f2 := newTestFinding("nuclei", "CWE-200", "example.com", "/api/v1", 443) // different tool
	f3 := newTestFinding("nmap", "CWE-200", "other.com", "/api/v1", 443)     // different host
	f4 := newTestFinding("nmap", "CWE-200", "example.com", "/api/v2", 443)   // different path
	f5 := newTestFinding("nmap", "CWE-200", "example.com", "/api/v1", 80)    // different port

	hashes := []string{
		finding.Fingerprint(&f1),
		finding.Fingerprint(&f2),
		finding.Fingerprint(&f3),
		finding.Fingerprint(&f4),
		finding.Fingerprint(&f5),
	}

	seen := make(map[string]bool, len(hashes))
	for _, h := range hashes {
		if seen[h] {
			t.Errorf("duplicate fingerprint detected: %q", h)
		}
		seen[h] = true
	}
}

// TestDeduplicate_RemovesDuplicates confirms that a slice with two identical
// findings is reduced to one, and that LastSeen is updated to the later time.
func TestDeduplicate_RemovesDuplicates(t *testing.T) {
	now := time.Now().UTC()
	later := now.Add(time.Hour)

	f1 := newTestFinding("nmap", "CWE-200", "example.com", "/api", 443)
	f1.FirstSeen = now
	f1.LastSeen = now

	f2 := newTestFinding("nmap", "CWE-200", "example.com", "/api", 443) // same key fields
	f2.FirstSeen = later
	f2.LastSeen = later

	result := finding.Deduplicate([]finding.Finding{f1, f2})
	if len(result) != 1 {
		t.Fatalf("Deduplicate() returned %d findings, want 1", len(result))
	}

	// LastSeen should be updated to the later time.
	if !result[0].LastSeen.Equal(later) {
		t.Errorf("LastSeen = %v, want %v", result[0].LastSeen, later)
	}
}

// TestDeduplicate_NoDuplicates confirms that a slice of unique findings is
// returned unchanged (same length, same order).
func TestDeduplicate_NoDuplicates(t *testing.T) {
	f1 := newTestFinding("nmap", "CWE-200", "host1.com", "/a", 80)
	f2 := newTestFinding("nuclei", "CWE-79", "host2.com", "/b", 443)
	f3 := newTestFinding("nmap", "CWE-89", "host3.com", "/c", 8080)

	input := []finding.Finding{f1, f2, f3}
	result := finding.Deduplicate(input)
	if len(result) != 3 {
		t.Fatalf("Deduplicate() returned %d findings, want 3", len(result))
	}
}

// TestDeduplicate_EmptySlice ensures the function handles an empty input
// without panicking and returns an empty (non-nil) slice.
func TestDeduplicate_EmptySlice(t *testing.T) {
	result := finding.Deduplicate([]finding.Finding{})
	if result == nil {
		t.Fatal("Deduplicate() returned nil for empty input, want empty slice")
	}
	if len(result) != 0 {
		t.Fatalf("Deduplicate() returned %d findings, want 0", len(result))
	}
}

// TestDeduplicate_KeepsFirstOccurrence verifies that when duplicates exist,
// the first Finding (by position) is kept.
func TestDeduplicate_KeepsFirstOccurrence(t *testing.T) {
	f1 := newTestFinding("nmap", "CWE-200", "example.com", "/api", 443)
	f1.Title = "First"

	f2 := newTestFinding("nmap", "CWE-200", "example.com", "/api", 443)
	f2.Title = "Second"

	result := finding.Deduplicate([]finding.Finding{f1, f2})
	if len(result) != 1 {
		t.Fatalf("Deduplicate() returned %d findings, want 1", len(result))
	}
	if result[0].Title != "First" {
		t.Errorf("Deduplicate() kept %q, want %q", result[0].Title, "First")
	}
}

// TestCountBySeverity verifies that the summary counts are correct across all
// severity levels.
func TestCountBySeverity(t *testing.T) {
	findings := []finding.Finding{
		{Severity: finding.SeverityCritical},
		{Severity: finding.SeverityCritical},
		{Severity: finding.SeverityHigh},
		{Severity: finding.SeverityMedium},
		{Severity: finding.SeverityMedium},
		{Severity: finding.SeverityMedium},
		{Severity: finding.SeverityLow},
		{Severity: finding.SeverityInfo},
		{Severity: finding.SeverityInfo},
	}

	summary := finding.CountBySeverity(findings)

	if summary.Total != 9 {
		t.Errorf("Total = %d, want 9", summary.Total)
	}
	if summary.Critical != 2 {
		t.Errorf("Critical = %d, want 2", summary.Critical)
	}
	if summary.High != 1 {
		t.Errorf("High = %d, want 1", summary.High)
	}
	if summary.Medium != 3 {
		t.Errorf("Medium = %d, want 3", summary.Medium)
	}
	if summary.Low != 1 {
		t.Errorf("Low = %d, want 1", summary.Low)
	}
	if summary.Info != 2 {
		t.Errorf("Info = %d, want 2", summary.Info)
	}
}

// TestCountBySeverity_EmptySlice verifies zero counts for empty input.
func TestCountBySeverity_EmptySlice(t *testing.T) {
	summary := finding.CountBySeverity([]finding.Finding{})
	if summary.Total != 0 || summary.Critical != 0 || summary.High != 0 ||
		summary.Medium != 0 || summary.Low != 0 || summary.Info != 0 {
		t.Errorf("CountBySeverity(empty) = %+v, want all zeros", summary)
	}
}
