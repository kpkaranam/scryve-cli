package email

import (
	"context"
	"fmt"
	"strings"
)

// ---------------------------------------------------------------------------
// SPF result types
// ---------------------------------------------------------------------------

// SPFPolicy describes the sender policy enforced at the end of an SPF record.
type SPFPolicy string

const (
	// SPFPolicyPass means +all — all senders are authorized (very permissive).
	SPFPolicyPass SPFPolicy = "+all"

	// SPFPolicySoftFail means ~all — unauthorized senders are soft-rejected.
	SPFPolicySoftFail SPFPolicy = "~all"

	// SPFPolicyFail means -all — unauthorized senders are hard-rejected (strict).
	SPFPolicyFail SPFPolicy = "-all"

	// SPFPolicyNeutral means ?all — no policy statement.
	SPFPolicyNeutral SPFPolicy = "?all"

	// SPFPolicyNone means no SPF record was found.
	SPFPolicyNone SPFPolicy = "none"
)

// SPFResult holds the outcome of an SPF check for a domain.
type SPFResult struct {
	// Found is true when a v=spf1 TXT record exists for the domain.
	Found bool

	// Record is the raw SPF TXT record string.
	Record string

	// Policy is the evaluated end-of-record policy directive.
	Policy SPFPolicy

	// IncludeCount is the number of "include:" mechanisms in the record.
	IncludeCount int

	// Error holds any error encountered during lookup or parsing.
	Error error
}

// IsStrict returns true when the SPF policy is -all (hard fail), which is the
// recommended configuration.
func (r SPFResult) IsStrict() bool {
	return r.Policy == SPFPolicyFail
}

// ---------------------------------------------------------------------------
// CheckSPF
// ---------------------------------------------------------------------------

// CheckSPF queries the TXT records for domain and evaluates the SPF policy.
// It uses the provided resolver so tests can inject a mock without real DNS.
//
// Evaluation rules:
//   - If no v=spf1 record is found, Result.Found is false and Policy is SPFPolicyNone.
//   - The "all" mechanism qualifier (+, -, ~, ?) sets the Policy.
//   - Include mechanisms (include:) are counted but not recursively evaluated.
func CheckSPF(ctx context.Context, domain string, resolver Resolver) SPFResult {
	records, err := resolver.LookupTXT(ctx, domain)
	if err != nil {
		return SPFResult{Error: fmt.Errorf("spf: lookup %q: %w", domain, err)}
	}

	// Find the SPF record among all TXT records.
	record := findSPFRecord(records)
	if record == "" {
		return SPFResult{Found: false, Policy: SPFPolicyNone}
	}

	policy, includeCount := parseSPFRecord(record)
	return SPFResult{
		Found:        true,
		Record:       record,
		Policy:       policy,
		IncludeCount: includeCount,
	}
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// findSPFRecord returns the first TXT record that begins with "v=spf1"
// (case-insensitive).  Returns "" when no SPF record is present.
func findSPFRecord(records []string) string {
	for _, r := range records {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(r)), "v=spf1") {
			return r
		}
	}
	return ""
}

// parseSPFRecord parses the raw SPF record string and returns the effective
// policy and the count of include: mechanisms.
func parseSPFRecord(record string) (SPFPolicy, int) {
	policy := SPFPolicyNone
	includeCount := 0

	parts := strings.Fields(record)
	for _, part := range parts {
		lower := strings.ToLower(part)

		// Count include: mechanisms.
		if strings.HasPrefix(lower, "include:") {
			includeCount++
			continue
		}

		// Evaluate "all" mechanism (may have qualifier prefix).
		if lower == "all" || lower == "+all" {
			policy = SPFPolicyPass
		} else if lower == "-all" {
			policy = SPFPolicyFail
		} else if lower == "~all" {
			policy = SPFPolicySoftFail
		} else if lower == "?all" {
			policy = SPFPolicyNeutral
		}
	}

	return policy, includeCount
}
