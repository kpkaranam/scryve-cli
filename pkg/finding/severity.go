package finding

import "strings"

// Severity represents the risk level of a Finding. The underlying string
// value is stored in lowercase for consistent JSON serialization.
type Severity string

const (
	// SeverityCritical maps to CVSS scores 9.0–10.0.
	SeverityCritical Severity = "critical"

	// SeverityHigh maps to CVSS scores 7.0–8.9.
	SeverityHigh Severity = "high"

	// SeverityMedium maps to CVSS scores 4.0–6.9.
	SeverityMedium Severity = "medium"

	// SeverityLow maps to CVSS scores 0.1–3.9.
	SeverityLow Severity = "low"

	// SeverityInfo maps to CVSS score 0.0 or when no score is available.
	SeverityInfo Severity = "info"
)

// SeverityFromCVSS converts a numeric CVSS v3 base score to a Severity level.
// The mapping follows the NVD/CVSS v3 severity ratings:
//
//	0.0       → info
//	0.1 – 3.9 → low
//	4.0 – 6.9 → medium
//	7.0 – 8.9 → high
//	9.0 – 10.0 → critical
func SeverityFromCVSS(score float64) Severity {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0.0:
		return SeverityLow
	default:
		return SeverityInfo
	}
}

// SeverityWeight returns a numeric weight for a Severity level, enabling
// sorting and comparison. Higher weight means greater severity:
//
//	critical → 4
//	high     → 3
//	medium   → 2
//	low      → 1
//	info     → 0
func SeverityWeight(s Severity) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// SeverityFromString parses a severity string in a case-insensitive manner.
// The string "informational" is accepted as an alias for "info".
// Any unrecognized value defaults to SeverityInfo.
func SeverityFromString(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityMedium
	case "low":
		return SeverityLow
	case "info", "informational":
		return SeverityInfo
	default:
		return SeverityInfo
	}
}
