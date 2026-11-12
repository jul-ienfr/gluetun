package observability

import (
	"regexp"
	"strings"
)

var (
	bearerPattern = regexp.MustCompile(
		`(?i)(bearer\s+)[A-Za-z0-9._~+/\-=]+`)
	secretPattern = regexp.MustCompile(
		`(?i)((?:api[_-]?key|token|password|secret)\s*[=:]\s*)` +
			`("[^"]*"|'[^']*'|[^\s,;&]+)`)
	userInfoPattern = regexp.MustCompile(
		`(?i)(https?://)[^/@\s]+@`)
)

// IsSensitiveKey reports whether a field key holds a secret.
func IsSensitiveKey(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
	normalized = strings.ReplaceAll(normalized, " ", "")
	switch {
	case normalized == "key":
		return true
	case strings.Contains(normalized, "password"),
		strings.Contains(normalized, "passwd"),
		strings.Contains(normalized, "passphrase"),
		strings.Contains(normalized, "secret"),
		strings.Contains(normalized, "token"),
		strings.Contains(normalized, "apikey"),
		strings.Contains(normalized, "api_key"),
		strings.Contains(normalized, "privatekey"),
		strings.Contains(normalized, "private_key"),
		strings.Contains(normalized, "presharedkey"),
		strings.Contains(normalized, "pre_shared_key"),
		strings.Contains(normalized, "encrypted_key"),
		strings.Contains(normalized, "header_protection_key"),
		strings.Contains(normalized, "authorization"),
		strings.Contains(normalized, "credential"):
		return true
	}
	return false
}

// ScrubText redacts credentials embedded in free-form text.
func ScrubText(text string) string {
	text = bearerPattern.ReplaceAllString(text, "${1}***")
	text = secretPattern.ReplaceAllString(text, "${1}***")
	text = userInfoPattern.ReplaceAllString(text, "${1}***@")
	return text
}

// ScrubMap returns a deep copy of fields with sensitive values redacted.
func ScrubMap(fields map[string]any) map[string]any {
	if fields == nil {
		return nil
	}
	scrubbed := make(map[string]any, len(fields))
	for key, value := range fields {
		if IsSensitiveKey(key) {
			scrubbed[key] = "***"
			continue
		}
		scrubbed[key] = scrubValue(value)
	}
	return scrubbed
}

func scrubValue(value any) any {
	switch typed := value.(type) {
	case string:
		return ScrubText(typed)
	case map[string]any:
		return ScrubMap(typed)
	case map[string]string:
		scrubbed := make(map[string]string, len(typed))
		for key, item := range typed {
			if IsSensitiveKey(key) {
				scrubbed[key] = "***"
				continue
			}
			scrubbed[key] = ScrubText(item)
		}
		return scrubbed
	case []any:
		scrubbed := make([]any, len(typed))
		for i, item := range typed {
			scrubbed[i] = scrubValue(item)
		}
		return scrubbed
	case []string:
		scrubbed := make([]string, len(typed))
		for i, item := range typed {
			scrubbed[i] = ScrubText(item)
		}
		return scrubbed
	default:
		return value
	}
}
