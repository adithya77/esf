package factory

import (
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
)

// RedactionMask replaces a scrubbed value. It keeps evidence readable while
// making the value unrecoverable.
const RedactionMask = "[REDACTED]"

// redactionRule pairs a pattern with the replacement used when it matches.
//
// Each rule keeps whatever part of the match is diagnostically useful (the
// header name, the key name, the URL scheme) and masks only the value.
type redactionRule struct {
	name    string
	pattern *regexp.Regexp
	replace string
}

// redactionRules match common credential shapes in captured output.
//
// Agent output is captured verbatim into durable artifacts. An agent that
// echoes an environment variable, a curl command or a stack trace could
// otherwise persist a credential into evidence that outlives the run.
// Scrubbing on the way to storage is the last line of defence; the first is not
// putting secrets where the agent can see them.
var redactionRules = []redactionRule{
	{
		name:    "bearer-token",
		pattern: regexp.MustCompile(`(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}`),
		replace: "${1} " + RedactionMask,
	},
	{
		name:    "authorization-header",
		pattern: regexp.MustCompile(`(?i)\b(authorization\s*[:=]\s*)(\S+)`),
		replace: "${1}" + RedactionMask,
	},
	{
		name:    "openai-style-key",
		pattern: regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{16,}\b`),
		replace: RedactionMask,
	},
	{
		name:    "github-token",
		pattern: regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{16,}\b`),
		replace: RedactionMask,
	},
	{
		name:    "slack-token",
		pattern: regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`),
		replace: RedactionMask,
	},
	{
		name:    "aws-access-key-id",
		pattern: regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		replace: RedactionMask,
	},
	{
		name:    "google-api-key",
		pattern: regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`),
		replace: RedactionMask,
	},
	{
		name:    "url-embedded-credentials",
		pattern: regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@`),
		replace: "${1}" + RedactionMask + "@",
	},
	{
		name:    "sensitive-assignment",
		pattern: regexp.MustCompile(`(?i)\b([A-Z0-9_]*(?:API_?KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)[A-Z0-9_]*)\s*[:=]\s*["']?[^\s"']{4,}`),
		replace: "${1}=" + RedactionMask,
	},
}

// RedactionRuleNames returns the names of the built-in redaction rules, for
// documentation and tests.
func RedactionRuleNames() []string {
	names := make([]string, 0, len(redactionRules))
	for _, rule := range redactionRules {
		names = append(names, rule.name)
	}
	return names
}

// Redactor scrubs known secret VALUES and credential-shaped substrings from
// text before it is persisted.
//
// The zero value is usable and applies only the pattern rules. Methods are
// nil-safe so callers never need to branch on whether redaction is configured.
type Redactor struct {
	// values are exact secret strings registered by the operator at startup.
	// mu guards values: activities register credentials while other runs on
	// the same worker are redacting.
	mu     sync.RWMutex
	values []string
}

// NewRedactor creates a redactor for the given secret values.
//
// Empty values are ignored, as are values shorter than four characters: masking
// such a value would corrupt unrelated text, and a secret that short is not a
// secret.
func NewRedactor(secrets ...string) *Redactor {
	r := &Redactor{}
	r.Add(secrets...)
	return r
}

// Add registers more secret values.
func (r *Redactor) Add(secrets ...string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, secret := range secrets {
		trimmed := strings.TrimSpace(secret)
		if len(trimmed) < 4 || slices.Contains(r.values, trimmed) {
			continue
		}
		r.values = append(r.values, trimmed)
	}
	// Longest first, so a longer secret is not partially masked by a shorter
	// one that happens to be its prefix.
	sort.Slice(r.values, func(i, j int) bool { return len(r.values[i]) > len(r.values[j]) })
}

// ValueCount reports how many literal secret values are registered.
func (r *Redactor) ValueCount() int {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.values)
}

// Redact returns text with every known secret and every credential-shaped
// substring replaced by the mask.
func (r *Redactor) Redact(text string) string {
	if text == "" {
		return ""
	}
	if r != nil {
		r.mu.RLock()
		for _, value := range r.values {
			if strings.Contains(text, value) {
				text = strings.ReplaceAll(text, value, RedactionMask)
			}
		}
		r.mu.RUnlock()
	}
	for _, rule := range redactionRules {
		text = rule.pattern.ReplaceAllString(text, rule.replace)
	}
	return text
}

// RedactBytes is Redact for byte slices.
func (r *Redactor) RedactBytes(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	return []byte(r.Redact(string(data)))
}
