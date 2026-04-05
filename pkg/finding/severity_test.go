// Package finding provides the universal data model for security findings
// produced by Scryve tool integrations.
package finding_test

import (
	"testing"

	"github.com/scryve/scryve/pkg/finding"
)

// TestSeverityFromCVSS_BoundaryValues exercises every boundary defined in the
// spec: critical 9.0–10.0, high 7.0–8.9, medium 4.0–6.9, low 0.1–3.9, info 0.
func TestSeverityFromCVSS_BoundaryValues(t *testing.T) {
	cases := []struct {
		score float64
		want  finding.Severity
	}{
		{score: 0.0, want: finding.SeverityInfo},
		{score: 0.1, want: finding.SeverityLow},
		{score: 3.9, want: finding.SeverityLow},
		{score: 4.0, want: finding.SeverityMedium},
		{score: 6.9, want: finding.SeverityMedium},
		{score: 7.0, want: finding.SeverityHigh},
		{score: 8.9, want: finding.SeverityHigh},
		{score: 9.0, want: finding.SeverityCritical},
		{score: 10.0, want: finding.SeverityCritical},
	}

	for _, tc := range cases {
		got := finding.SeverityFromCVSS(tc.score)
		if got != tc.want {
			t.Errorf("SeverityFromCVSS(%v) = %q, want %q", tc.score, got, tc.want)
		}
	}
}

// TestSeverityWeight_Ordering ensures the numeric weights reflect the correct
// ordering: critical > high > medium > low > info.
func TestSeverityWeight_Ordering(t *testing.T) {
	ordered := []finding.Severity{
		finding.SeverityCritical,
		finding.SeverityHigh,
		finding.SeverityMedium,
		finding.SeverityLow,
		finding.SeverityInfo,
	}
	expected := []int{4, 3, 2, 1, 0}

	for i, sev := range ordered {
		got := finding.SeverityWeight(sev)
		if got != expected[i] {
			t.Errorf("SeverityWeight(%q) = %d, want %d", sev, got, expected[i])
		}
	}

	// Enforce strict descending ordering.
	for i := 1; i < len(ordered); i++ {
		prev := finding.SeverityWeight(ordered[i-1])
		curr := finding.SeverityWeight(ordered[i])
		if prev <= curr {
			t.Errorf("ordering violation: weight(%q)=%d should be > weight(%q)=%d",
				ordered[i-1], prev, ordered[i], curr)
		}
	}
}

// TestSeverityFromString_CaseInsensitive verifies that parsing is
// case-insensitive and that unknown values default to info.
func TestSeverityFromString_CaseInsensitive(t *testing.T) {
	cases := []struct {
		input string
		want  finding.Severity
	}{
		{"critical", finding.SeverityCritical},
		{"CRITICAL", finding.SeverityCritical},
		{"Critical", finding.SeverityCritical},
		{"high", finding.SeverityHigh},
		{"HIGH", finding.SeverityHigh},
		{"High", finding.SeverityHigh},
		{"medium", finding.SeverityMedium},
		{"MEDIUM", finding.SeverityMedium},
		{"low", finding.SeverityLow},
		{"LOW", finding.SeverityLow},
		{"info", finding.SeverityInfo},
		{"INFO", finding.SeverityInfo},
		{"informational", finding.SeverityInfo},
		{"INFORMATIONAL", finding.SeverityInfo},
		// Unknown values must default to info.
		{"unknown", finding.SeverityInfo},
		{"", finding.SeverityInfo},
		{"NONE", finding.SeverityInfo},
	}

	for _, tc := range cases {
		got := finding.SeverityFromString(tc.input)
		if got != tc.want {
			t.Errorf("SeverityFromString(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
