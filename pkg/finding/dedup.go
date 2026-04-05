package finding

import (
	"crypto/sha256"
	"fmt"
)

// Fingerprint computes a SHA-256 hash from the stable identity fields of a
// Finding: Tool, CWE, Host, Port, and Path. The computed hash is stored in
// f.Fingerprint and also returned as a hex string. Calling Fingerprint
// multiple times with the same field values always produces the same result.
//
// The fingerprint is intentionally derived from fields that identify the
// class of issue at a location, not from dynamic fields like timestamps or
// evidence bodies. This ensures that re-scanning the same target produces the
// same fingerprint, enabling reliable deduplication across runs.
func Fingerprint(f *Finding) string {
	h := sha256.New()
	// Write each field with a null-byte separator so that adjacent fields
	// cannot collide (e.g. tool="ab" cwe="c" vs tool="a" cwe="bc").
	fmt.Fprintf(h, "%s\x00%s\x00%s\x00%d\x00%s",
		f.Tool, f.CWE, f.Host, f.Port, f.Path)
	fp := fmt.Sprintf("%x", h.Sum(nil))
	f.Fingerprint = fp
	return fp
}

// Deduplicate removes duplicate findings from the slice, keeping the first
// occurrence of each unique fingerprint. When a duplicate is found its
// LastSeen time is compared to the retained finding: the later of the two is
// preserved so that the retained entry reflects the most recent observation.
//
// Findings that do not yet have a Fingerprint set will have Fingerprint called
// on them automatically. The returned slice maintains the order of first
// occurrence.
func Deduplicate(findings []Finding) []Finding {
	if len(findings) == 0 {
		return []Finding{}
	}

	// index maps fingerprint → position in result.
	index := make(map[string]int, len(findings))
	result := make([]Finding, 0, len(findings))

	for i := range findings {
		f := findings[i] // copy so we can modify Fingerprint safely

		// Ensure fingerprint is populated.
		if f.Fingerprint == "" {
			Fingerprint(&f)
		}

		pos, seen := index[f.Fingerprint]
		if !seen {
			index[f.Fingerprint] = len(result)
			result = append(result, f)
			continue
		}

		// Duplicate: update LastSeen on the retained entry if the current
		// finding was observed later.
		if f.LastSeen.After(result[pos].LastSeen) {
			result[pos].LastSeen = f.LastSeen
		}
	}

	return result
}

// CountBySeverity tallies findings by severity level and returns a
// ResultSummary. The Total field equals the length of the input slice.
func CountBySeverity(findings []Finding) ResultSummary {
	summary := ResultSummary{
		Total: len(findings),
	}
	for _, f := range findings {
		switch f.Severity {
		case SeverityCritical:
			summary.Critical++
		case SeverityHigh:
			summary.High++
		case SeverityMedium:
			summary.Medium++
		case SeverityLow:
			summary.Low++
		default:
			summary.Info++
		}
	}
	return summary
}
