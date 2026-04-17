package fileresolver

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPatternMatcher(t *testing.T) {
	patterns := []string{
		"**/package.json",
		"**/*.jar",
		"**/*dist-info/METADATA",
		"**/{go,go.exe}",
	}

	m, err := NewPatternMatcher(patterns)
	require.NoError(t, err)
	require.NotNil(t, m)
}

func TestPatternMatcherMatchesBasename(t *testing.T) {
	patterns := []string{
		"**/package.json",
		"**/go.sum",
		"**/Cargo.lock",
	}

	m, err := NewPatternMatcher(patterns)
	require.NoError(t, err)

	tests := []struct {
		path    string
		matches bool
	}{
		{"/usr/local/lib/node_modules/foo/package.json", true},
		{"/app/package.json", true},
		{"package.json", true},
		{"/usr/local/lib/go.sum", true},
		{"/src/Cargo.lock", true},
		{"/usr/local/lib/package-lock.json", false},
		{"/usr/local/lib/go.mod", false},
		{"/usr/local/lib/Cargo.toml", false},
		{"/usr/local/package.json.bak", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.matches, m.Matches(tt.path))
		})
	}
}

func TestPatternMatcherMatchesExtension(t *testing.T) {
	patterns := []string{
		"**/*.jar",
		"**/*.war",
		"**/*.gemspec",
	}

	m, err := NewPatternMatcher(patterns)
	require.NoError(t, err)

	tests := []struct {
		path    string
		matches bool
	}{
		{"/usr/local/lib/foo.jar", true},
		{"/app/target/myapp.war", true},
		{"/usr/lib/ruby/gems/rack.gemspec", true},
		{"/usr/local/lib/foo.jar.sha1", false},
		{"/usr/local/lib/foo.tar", false},
		{"/usr/local/lib/foo.txt", false},
		{"/usr/local/lib/noextension", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.matches, m.Matches(tt.path))
		})
	}
}

func TestPatternMatcherMatchesComplex(t *testing.T) {
	patterns := []string{
		"**/*dist-info/METADATA",
		"**/specifications/**/*.gemspec",
	}

	m, err := NewPatternMatcher(patterns)
	require.NoError(t, err)

	tests := []struct {
		path    string
		matches bool
	}{
		{"/usr/lib/python3/dist-packages/requests-2.28.0.dist-info/METADATA", true},
		{"/usr/local/lib/python3.11/site-packages/pip-23.0.dist-info/METADATA", true},
		{"/usr/lib/ruby/gems/2.7.0/specifications/rack-2.2.3.gemspec", true},
		{"/usr/lib/ruby/gems/3.0.0/specifications/nested/foo-1.0.gemspec", true},
		// Negative cases
		{"/usr/lib/python3/METADATA", false},
		{"/usr/lib/ruby/gems/rack.gemspec", false},
		{"/usr/lib/python3/dist-packages/requests-2.28.0.dist-info/RECORD", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.matches, m.Matches(tt.path))
		})
	}
}

func TestPatternMatcherIsKnownPattern(t *testing.T) {
	patterns := []string{
		"**/package.json",
		"**/*.jar",
		"**/*dist-info/METADATA",
	}

	m, err := NewPatternMatcher(patterns)
	require.NoError(t, err)

	assert.True(t, m.IsKnownPattern("**/package.json"))
	assert.True(t, m.IsKnownPattern("**/*.jar"))
	assert.True(t, m.IsKnownPattern("**/*dist-info/METADATA"))

	assert.False(t, m.IsKnownPattern("**/unknown.txt"))
	assert.False(t, m.IsKnownPattern("**/*.rpm"))
	assert.False(t, m.IsKnownPattern(""))
	assert.False(t, m.IsKnownPattern("**/package.json.bak"))
}

func TestPatternMatcherBraceExpansion(t *testing.T) {
	patterns := []string{
		"**/{go,go.exe}",
		"**/{package.json,package-lock.json}",
	}

	m, err := NewPatternMatcher(patterns)
	require.NoError(t, err)

	tests := []struct {
		path    string
		matches bool
	}{
		{"/usr/local/bin/go", true},
		{"/usr/local/bin/go.exe", true},
		{"/app/package.json", true},
		{"/app/package-lock.json", true},
		// Negative cases
		{"/usr/local/bin/gofmt", false},
		{"/usr/local/bin/go.sum", false},
		{"/app/package.json.bak", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.matches, m.Matches(tt.path))
		})
	}
}

func TestPatternMatcherBraceExpansionKnownPatterns(t *testing.T) {
	// The original brace pattern should be recorded as known, not the expanded ones
	patterns := []string{
		"**/{go,go.exe}",
	}

	m, err := NewPatternMatcher(patterns)
	require.NoError(t, err)

	// Original pattern should be known
	assert.True(t, m.IsKnownPattern("**/{go,go.exe}"))
	// Expanded patterns should NOT be individually known (original is what callers pass)
	assert.False(t, m.IsKnownPattern("**/go"))
	assert.False(t, m.IsKnownPattern("**/go.exe"))
}
