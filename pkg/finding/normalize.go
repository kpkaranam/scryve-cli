// Package finding — per-tool finding normalization (TASK-016).
//
// This file provides the top-level NormalizeRawFinding dispatcher and
// individual tool-specific normalizers that convert adapter.RawFinding values
// into fully-populated finding.Finding structs.
package finding

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/scryve/scryve/pkg/adapter"
)

// NormalizeRawFinding converts an adapter.RawFinding into a Finding by
// dispatching to a tool-specific normalizer based on raw.ToolName.
//
// Every returned Finding has:
//   - Tool set to raw.ToolName
//   - FirstSeen and LastSeen set to the current time
//   - Fingerprint auto-generated via finding.Fingerprint()
//
// For unknown tools the raw ToolOutput map is preserved in Metadata["tool_output"]
// so that no information is discarded.
func NormalizeRawFinding(raw adapter.RawFinding) Finding {
	var f Finding

	switch raw.ToolName {
	case string(adapter.AdapterIDNuclei):
		f = NormalizeNuclei(raw)
	case string(adapter.AdapterIDHTTPX):
		f = NormalizeHTTPX(raw)
	case string(adapter.AdapterIDNaabu):
		f = NormalizeNaabu(raw)
	case string(adapter.AdapterIDSubfinder):
		f = NormalizeSubfinder(raw)
	default:
		f = normalizeUnknown(raw)
	}

	// Ensure timing fields are always set.
	now := time.Now()
	if f.FirstSeen.IsZero() {
		f.FirstSeen = now
	}
	if f.LastSeen.IsZero() {
		f.LastSeen = now
	}

	// Auto-generate fingerprint.
	if f.Fingerprint == "" {
		Fingerprint(&f)
	}

	return f
}

// NormalizeNuclei converts a Nuclei JSON-lines result (stored as a
// map[string]interface{} in raw.ToolOutput) into a Finding.
//
// Field mapping:
//   - Title          ← info.name
//   - Description    ← info.description
//   - Severity       ← info.severity (via SeverityFromString)
//   - CVSS           ← info.classification.cvss-score
//   - CWE            ← info.classification.cwe-id[0]
//   - CVE            ← info.classification.cve-id[0]
//   - Host           ← host
//   - IP             ← ip
//   - Port           ← port (string or float64 → int)
//   - Path           ← matched-at
//   - Evidence.URL   ← matched-at
//   - Evidence.Proof ← curl-command
//   - Tags           ← info.tags
func NormalizeNuclei(raw adapter.RawFinding) Finding {
	f := Finding{
		Tool:     "nuclei",
		Severity: SeverityInfo,
		Metadata: raw.ToolOutput,
	}

	if raw.ToolOutput == nil {
		return f
	}

	// Host, IP, Port.
	f.Host = stringField(raw.ToolOutput, "host")
	f.IP = stringField(raw.ToolOutput, "ip")
	f.Port = parsePort(raw.ToolOutput["port"])

	// matched-at → Path and Evidence.URL.
	matchedAt := stringField(raw.ToolOutput, "matched-at")
	f.Path = matchedAt
	f.Evidence.URL = matchedAt

	// curl-command → Evidence.Proof.
	f.Evidence.Proof = stringField(raw.ToolOutput, "curl-command")

	// info block.
	if info, ok := raw.ToolOutput["info"].(map[string]interface{}); ok {
		f.Title = stringField(info, "name")
		f.Description = stringField(info, "description")
		f.Severity = SeverityFromString(stringField(info, "severity"))
		f.Tags = stringSliceField(info, "tags")

		// classification block.
		if class, ok := info["classification"].(map[string]interface{}); ok {
			// cvss-score may be float64 or a string.
			if v, ok := class["cvss-score"]; ok {
				f.CVSS = toFloat64(v)
			}
			// cwe-id is a []interface{} — take the first entry.
			f.CWE = firstStringSlice(class, "cwe-id")
			// cve-id is a []interface{} — take the first entry.
			f.CVE = firstStringSlice(class, "cve-id")
		}
	}

	// Fall back to template-id for title when info.name is empty.
	if f.Title == "" {
		f.Title = stringField(raw.ToolOutput, "template-id")
	}
	return f
}

// NormalizeHTTPX converts an httpx probe result into an informational Finding
// representing a live HTTP/HTTPS service.
//
// Field mapping:
//   - Title    ← "HTTP Service: <title>" or "HTTP Service: <url>" when title is empty
//   - Host     ← hostname extracted from url
//   - Port     ← port extracted from url (defaults: 443 for https, 80 for http)
//   - Protocol ← scheme extracted from url
//   - Tags     ← technologies detected
//   - Severity ← always SeverityInfo (asset discovery, not a vulnerability)
func NormalizeHTTPX(raw adapter.RawFinding) Finding {
	f := Finding{
		Tool:     "httpx",
		Severity: SeverityInfo,
		Metadata: raw.ToolOutput,
	}

	if raw.ToolOutput == nil {
		return f
	}

	rawURL := stringField(raw.ToolOutput, "url")
	title := stringField(raw.ToolOutput, "title")
	techs := stringSliceField(raw.ToolOutput, "technologies")

	// Build title: prefer page title, fall back to URL.
	if title != "" {
		f.Title = "HTTP Service: " + title
	} else if rawURL != "" {
		f.Title = "HTTP Service: " + rawURL
	} else {
		f.Title = "HTTP Service"
	}

	// Parse host, port, and protocol from the URL.
	if rawURL != "" {
		if parsed, err := url.Parse(rawURL); err == nil {
			f.Protocol = parsed.Scheme
			host := parsed.Hostname()
			f.Host = host

			portStr := parsed.Port()
			if portStr != "" {
				if p, err := strconv.Atoi(portStr); err == nil {
					f.Port = p
				}
			} else {
				// Default port by scheme.
				switch strings.ToLower(parsed.Scheme) {
				case "https":
					f.Port = 443
				case "http":
					f.Port = 80
				}
			}
		}
	}

	f.Tags = techs

	return f
}

// NormalizeNaabu converts a naabu port-scan result into an informational
// Finding representing an open TCP port.
//
// Field mapping:
//   - Title    ← "Open Port: <host>:<port>"
//   - Host     ← host
//   - Port     ← port (string → int)
//   - Severity ← always SeverityInfo
func NormalizeNaabu(raw adapter.RawFinding) Finding {
	f := Finding{
		Tool:     "naabu",
		Severity: SeverityInfo,
		Metadata: raw.ToolOutput,
	}

	if raw.ToolOutput == nil {
		return f
	}

	host := stringField(raw.ToolOutput, "host")
	portStr := stringField(raw.ToolOutput, "port")

	f.Host = host

	if portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			f.Port = p
		}
	}

	if host != "" && portStr != "" {
		f.Title = fmt.Sprintf("Open Port: %s:%s", host, portStr)
	} else if host != "" {
		f.Title = fmt.Sprintf("Open Port: %s", host)
	} else {
		f.Title = "Open Port"
	}

	return f
}

// NormalizeSubfinder converts a subfinder subdomain-discovery result into an
// informational Finding representing a discovered subdomain.
//
// Field mapping:
//   - Title    ← "Subdomain: <host>"
//   - Host     ← host
//   - Severity ← always SeverityInfo
func NormalizeSubfinder(raw adapter.RawFinding) Finding {
	f := Finding{
		Tool:     "subfinder",
		Severity: SeverityInfo,
		Metadata: raw.ToolOutput,
	}

	if raw.ToolOutput == nil {
		return f
	}

	host := stringField(raw.ToolOutput, "host")
	f.Host = host

	if host != "" {
		f.Title = "Subdomain: " + host
	} else {
		f.Title = "Subdomain"
	}

	return f
}

// normalizeUnknown handles tool outputs from adapters that do not have a
// dedicated normalizer.  The raw ToolOutput is preserved in Metadata so that
// no information is silently dropped.
func normalizeUnknown(raw adapter.RawFinding) Finding {
	f := Finding{
		Tool:     raw.ToolName,
		Severity: SeverityInfo,
		Title:    fmt.Sprintf("Finding from %s", raw.ToolName),
	}

	if raw.ToolOutput != nil {
		f.Metadata = map[string]interface{}{
			"tool_output": raw.ToolOutput,
		}
		// Best-effort host extraction.
		f.Host = stringField(raw.ToolOutput, "host")
	}

	return f
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// stringField returns the string value for key in m, or "" if missing or
// not a string.
func stringField(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}

// stringSliceField returns a []string for key in m, handling both
// []interface{} and []string source types.  Returns nil when the key is
// absent or is not a slice.
func stringSliceField(m map[string]interface{}, key string) []string {
	if m == nil {
		return nil
	}
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}

	switch typed := v.(type) {
	case []string:
		if len(typed) == 0 {
			return nil
		}
		out := make([]string, len(typed))
		copy(out, typed)
		return out
	case []interface{}:
		if len(typed) == 0 {
			return nil
		}
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	}
	return nil
}

// firstStringSlice returns the first string element of a []interface{} value
// stored under key in m.  Returns "" if absent or not a non-empty slice.
func firstStringSlice(m map[string]interface{}, key string) string {
	items := stringSliceField(m, key)
	if len(items) == 0 {
		return ""
	}
	return items[0]
}

// toFloat64 converts v to float64, handling both float64 and string inputs.
// Returns 0 on failure.
func toFloat64(v interface{}) float64 {
	if v == nil {
		return 0
	}
	switch typed := v.(type) {
	case float64:
		return typed
	case float32:
		return float64(typed)
	case int:
		return float64(typed)
	case int64:
		return float64(typed)
	case string:
		if f, err := strconv.ParseFloat(typed, 64); err == nil {
			return f
		}
	}
	return 0
}

// parsePort converts a port value (string or float64) to an int.
// Returns 0 when the value is nil, empty, or not parseable.
func parsePort(v interface{}) int {
	if v == nil {
		return 0
	}
	switch typed := v.(type) {
	case string:
		if typed == "" {
			return 0
		}
		if p, err := strconv.Atoi(typed); err == nil {
			return p
		}
	case float64:
		return int(typed)
	case int:
		return typed
	case int64:
		return int(typed)
	}
	return 0
}
