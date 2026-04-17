package fileresolver

import (
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// PatternMatcher compiles cataloger glob patterns into tiered lookup structures
// for efficient matching during filesystem walks.
//
// Three tiers (fastest to slowest):
//  1. Basename map: O(1) lookup for patterns like **/package.json
//  2. Extension map: O(1) lookup for patterns like **/*.jar
//  3. Complex slice: doublestar.Match for everything else (typically <10 patterns)
type PatternMatcher struct {
	basenames     map[string]bool
	extensions    map[string]bool
	complex       []string
	knownPatterns map[string]bool
}

// NewPatternMatcher builds a PatternMatcher from the given glob patterns.
// Brace expansion is performed before classification so that patterns like
// **/{go,go.exe} are split into **/go and **/go.exe first.
func NewPatternMatcher(patterns []string) (*PatternMatcher, error) {
	m := &PatternMatcher{
		basenames:     make(map[string]bool),
		extensions:    make(map[string]bool),
		knownPatterns: make(map[string]bool),
	}

	for _, p := range patterns {
		// Record the original pattern as known (before expansion).
		m.knownPatterns[p] = true

		// Expand braces, then classify each expanded pattern.
		expanded := expandBraces(p)
		for _, ep := range expanded {
			m.classify(ep)
		}
	}

	return m, nil
}

// Matches reports whether filePath is matched by any compiled pattern.
func (m *PatternMatcher) Matches(filePath string) bool {
	base := filepath.Base(filePath)

	// Tier 1: basename exact match.
	if m.basenames[base] {
		return true
	}

	// Tier 2: extension match.
	ext := filepath.Ext(filePath)
	if ext != "" && m.extensions[ext] {
		return true
	}

	// Tier 3: complex patterns via doublestar.
	// doublestar expects forward slashes; on all platforms we use "/" as separator
	// in glob patterns. Convert the path to use forward slashes for matching.
	normalized := filepath.ToSlash(filePath)
	// Ensure the path starts with "/" so that **/ anchors work correctly.
	if !strings.HasPrefix(normalized, "/") {
		normalized = "/" + normalized
	}
	for _, pat := range m.complex {
		matched, err := doublestar.Match(pat, normalized)
		if err == nil && matched {
			return true
		}
	}

	return false
}

// IsKnownPattern reports whether pattern was one of the original patterns
// passed to NewPatternMatcher (before brace expansion).
func (m *PatternMatcher) IsKnownPattern(pattern string) bool {
	return m.knownPatterns[pattern]
}

// classify puts an already-expanded pattern into the appropriate tier.
func (m *PatternMatcher) classify(pattern string) {
	dir, base := splitGlobDirBase(pattern)

	// Tier 1: basename — directory part is solely "**/" (or "**") and base has no wildcards.
	if isDoubleStarOnly(dir) && !containsWildcard(base) {
		m.basenames[base] = true
		return
	}

	// Tier 2: extension — directory part is solely "**/" and base is "*.ext" with no further wildcards.
	if isDoubleStarOnly(dir) && isSimpleExtensionGlob(base) {
		ext := base[1:] // strip leading "*", leaving ".ext"
		m.extensions[ext] = true
		return
	}

	// Tier 3: everything else.
	m.complex = append(m.complex, pattern)
}

// splitGlobDirBase splits a glob pattern into its directory and base components,
// analogous to filepath.Split but without cleaning.
func splitGlobDirBase(pattern string) (dir, base string) {
	i := strings.LastIndex(pattern, "/")
	if i < 0 {
		return "", pattern
	}
	return pattern[:i+1], pattern[i+1:]
}

// isDoubleStarOnly reports whether dir is exactly "**/" or "**".
func isDoubleStarOnly(dir string) bool {
	return dir == "**/" || dir == "**"
}

// containsWildcard reports whether s contains any glob metacharacter.
func containsWildcard(s string) bool {
	return strings.ContainsAny(s, "*?[{")
}

// isSimpleExtensionGlob reports whether base is of the form "*.ext"
// where ext contains no wildcards or dots.
func isSimpleExtensionGlob(base string) bool {
	if len(base) < 3 {
		return false
	}
	if base[0] != '*' || base[1] != '.' {
		return false
	}
	rest := base[2:] // the extension without the dot
	return len(rest) > 0 && !containsWildcard(rest) && !strings.Contains(rest, ".")
}

// expandBraces performs simple single-level brace expansion.
// For example, **/{go,go.exe} → ["**/go", "**/go.exe"].
// Only one pair of braces is expanded per call; nested braces are not supported.
func expandBraces(pattern string) []string {
	open := strings.Index(pattern, "{")
	if open < 0 {
		return []string{pattern}
	}
	close := strings.Index(pattern[open:], "}")
	if close < 0 {
		// Malformed brace expression — treat as literal.
		return []string{pattern}
	}
	close += open // absolute index

	prefix := pattern[:open]
	suffix := pattern[close+1:]
	inner := pattern[open+1 : close]

	alternatives := strings.Split(inner, ",")
	result := make([]string, 0, len(alternatives))
	for _, alt := range alternatives {
		result = append(result, prefix+strings.TrimSpace(alt)+suffix)
	}
	return result
}
