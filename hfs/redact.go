package hfs

import (
	"encoding/json"
	"sort"
	"strings"
)

// Bounds applied by Redact. A SIEM keeps what it receives, often for years,
// under access controls Hexward does not own, so evidence leaves a product
// small and secret-free. These match the bounds the AI Assist client uses.
const (
	maxEvidenceKeys   = 24
	maxEvidenceString = 400
	maxEvidenceList   = 12
	maxEvidenceDepth  = 3
)

// secretKeyMarkers mark an evidence key as secret-like (case-insensitive
// substring). Matching keys are dropped entirely, at every nesting level —
// not masked — so not even the shape of a credential leaves the product.
var secretKeyMarkers = []string{
	"password", "passwd", "passphrase", "secret", "token", "apikey",
	"api_key", "api-key", "private", "credential", "cookie", "session",
	"authorization", "bearer", "license_key", "licence_key", "signature",
}

// Redact returns a bounded, secret-free copy of a product's evidence map:
//
//   - keys containing a secret marker are dropped, at every level;
//   - at most 24 keys per map are kept, in sorted key order (deterministic);
//   - strings are cut to 400 runes with a trailing "…";
//   - lists keep their first 12 items;
//   - nesting deeper than 3 levels becomes "[omitted: nested too deep]".
//
// The input is never modified. A nil or empty result returns nil.
func Redact(in map[string]any) map[string]any {
	return redactMap(in, 1)
}

func redactMap(in map[string]any, depth int) map[string]any {
	if len(in) == 0 {
		return nil
	}
	keys := make([]string, 0, len(in))
	for k := range in {
		if isSecretKey(k) {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > maxEvidenceKeys {
		keys = keys[:maxEvidenceKeys]
	}
	if len(keys) == 0 {
		return nil
	}
	out := make(map[string]any, len(keys))
	for _, k := range keys {
		out[k] = redactValue(in[k], depth)
	}
	return out
}

func redactValue(v any, depth int) any {
	switch t := v.(type) {
	case nil, bool, int, int8, int16, int32, int64, uint, uint8, uint16,
		uint32, uint64, float32, float64, json.Number:
		return t
	case string:
		return truncateRunes(t, maxEvidenceString)
	case map[string]any:
		if depth >= maxEvidenceDepth {
			return "[omitted: nested too deep]"
		}
		return redactMap(t, depth+1)
	case []any:
		if depth >= maxEvidenceDepth {
			return "[omitted: nested too deep]"
		}
		n := min(len(t), maxEvidenceList)
		out := make([]any, 0, n)
		for _, item := range t[:n] {
			out = append(out, redactValue(item, depth+1))
		}
		return out
	case []string:
		n := min(len(t), maxEvidenceList)
		out := make([]any, 0, n)
		for _, s := range t[:n] {
			out = append(out, truncateRunes(s, maxEvidenceString))
		}
		return out
	default:
		// Product-specific types are round-tripped through JSON so the
		// consumer sees the shape the product's own API would show, then
		// redacted like any other value.
		b, err := json.Marshal(t)
		if err != nil {
			return "[omitted: not serialisable]"
		}
		var generic any
		if err := json.Unmarshal(b, &generic); err != nil {
			return "[omitted: not serialisable]"
		}
		return redactValue(generic, depth)
	}
}

func isSecretKey(k string) bool {
	lk := strings.ToLower(k)
	for _, m := range secretKeyMarkers {
		if strings.Contains(lk, m) {
			return true
		}
	}
	return false
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
