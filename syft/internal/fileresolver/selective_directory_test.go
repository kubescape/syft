//go:build !windows
// +build !windows

package fileresolver

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTempFiles creates a temporary directory containing the named files
// (with trivial content) and returns the directory path together with a
// cleanup function.
func createTempFiles(t *testing.T, names ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range names {
		path := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte("data:"+name), 0o644))
	}
	return dir
}

// TestSelectiveDirectoryFallbackFilesByPath verifies that FilesByPath finds
// files that were skipped during selective indexing via the filesystem fallback.
func TestSelectiveDirectoryFallbackFilesByPath(t *testing.T) {
	// Two files: only "indexed.txt" is in the pattern set so only it ends up in
	// the in-memory index.  "dynamic.txt" must be found via fallback.
	dir := createTempFiles(t, "indexed.txt", "dynamic.txt")

	// Build a matcher that only knows about "indexed.txt".
	matcher, err := NewPatternMatcher([]string{"**/indexed.txt"})
	require.NoError(t, err)

	resolver, err := NewSelectiveDirectory(dir, "", matcher)
	require.NoError(t, err)

	// ── indexed file ──────────────────────────────────────────────────────────
	locs, err := resolver.FilesByPath("/indexed.txt")
	require.NoError(t, err)
	require.Len(t, locs, 1, "indexed.txt should be found via the index")

	// ── fallback file ─────────────────────────────────────────────────────────
	locs, err = resolver.FilesByPath("/dynamic.txt")
	require.NoError(t, err)
	require.Len(t, locs, 1, "dynamic.txt should be found via the filesystem fallback")

	// ── both at once ──────────────────────────────────────────────────────────
	locs, err = resolver.FilesByPath("/indexed.txt", "/dynamic.txt")
	require.NoError(t, err)
	assert.Len(t, locs, 2, "both files should be returned when queried together")

	// ── non-existent path returns nothing ─────────────────────────────────────
	locs, err = resolver.FilesByPath("/no-such-file.txt")
	require.NoError(t, err)
	assert.Empty(t, locs)
}

// TestSelectiveDirectoryFallbackFilesByGlob verifies that:
//   - known patterns use the index (fast path), and
//   - unknown patterns trigger a filesystem walk (fallback).
func TestSelectiveDirectoryFallbackFilesByGlob(t *testing.T) {
	// Three files.  The matcher knows about *.txt patterns; *.dat files are not
	// in the original pattern set and must be found via fallback.
	dir := createTempFiles(t, "a.txt", "b.txt", "c.dat")

	matcher, err := NewPatternMatcher([]string{"**/*.txt"})
	require.NoError(t, err)

	resolver, err := NewSelectiveDirectory(dir, "", matcher)
	require.NoError(t, err)

	// ── known pattern — index path ────────────────────────────────────────────
	locs, err := resolver.FilesByGlob("**/*.txt")
	require.NoError(t, err)
	assert.Len(t, locs, 2, "both .txt files should be found via the index")

	// ── unknown pattern — fallback walk ───────────────────────────────────────
	locs, err = resolver.FilesByGlob("**/*.dat")
	require.NoError(t, err)
	require.Len(t, locs, 1, "c.dat should be found via the filesystem fallback")
	assert.Contains(t, locs[0].RealPath, "c.dat")

	// ── pattern that matches nothing ─────────────────────────────────────────
	locs, err = resolver.FilesByGlob("**/*.bin")
	require.NoError(t, err)
	assert.Empty(t, locs)
}

// TestSelectiveDirectoryHasPath verifies HasPath falls back to the filesystem.
func TestSelectiveDirectoryHasPath(t *testing.T) {
	dir := createTempFiles(t, "indexed.txt", "dynamic.txt")

	matcher, err := NewPatternMatcher([]string{"**/indexed.txt"})
	require.NoError(t, err)

	resolver, err := NewSelectiveDirectory(dir, "", matcher)
	require.NoError(t, err)

	assert.True(t, resolver.HasPath("/indexed.txt"), "indexed.txt should be found in the index")
	assert.True(t, resolver.HasPath("/dynamic.txt"), "dynamic.txt should be found via fallback")
	assert.False(t, resolver.HasPath("/missing.txt"), "missing.txt should not be found")
}

// TestSelectiveDirectoryFilesByMIMEType verifies that FilesByMIMEType finds
// executable binaries via the filesystem fallback when the index has no MIME
// information (which is the case for selective indexing).
func TestSelectiveDirectoryFilesByMIMEType(t *testing.T) {
	dir := t.TempDir()

	// Create a fake ELF binary: 4-byte magic + some content, with execute bit.
	elfPath := filepath.Join(dir, "fakebinary")
	elfContent := []byte{0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00}
	require.NoError(t, os.WriteFile(elfPath, elfContent, 0o755))

	// Create a regular non-executable file.
	textPath := filepath.Join(dir, "readme.txt")
	require.NoError(t, os.WriteFile(textPath, []byte("hello"), 0o644))

	// Create an executable file whose content is NOT an ELF (so magic check rejects it).
	notElfPath := filepath.Join(dir, "script.sh")
	require.NoError(t, os.WriteFile(notElfPath, []byte("#!/bin/sh\necho hi\n"), 0o755))

	// Build a selective resolver that does NOT index the binary
	// (pattern only covers *.txt so binary is not in the index).
	matcher, err := NewPatternMatcher([]string{"**/*.txt"})
	require.NoError(t, err)

	resolver, err := NewSelectiveDirectory(dir, "", matcher)
	require.NoError(t, err)

	// Query for ELF and generic executable MIME types.
	locs, err := resolver.FilesByMIMEType("application/x-executable", "application/x-elf")
	require.NoError(t, err)

	// Only the fake ELF should be returned.
	require.Len(t, locs, 1, "expected exactly one ELF file to be found via the fallback")
	assert.Contains(t, string(locs[0].RealPath), "fakebinary", "the ELF file should be in the results")

	// Querying for a non-executable MIME type should return nothing (fallback
	// only handles executable types).
	locs, err = resolver.FilesByMIMEType("text/plain")
	require.NoError(t, err)
	assert.Empty(t, locs, "non-executable MIME type should return no results from the fallback")
}

// TestSelectiveDirectoryFileContentsByLocation verifies that content can be
// read for both indexed and non-indexed files.
func TestSelectiveDirectoryFileContentsByLocation(t *testing.T) {
	dir := createTempFiles(t, "indexed.txt", "dynamic.txt")

	matcher, err := NewPatternMatcher([]string{"**/indexed.txt"})
	require.NoError(t, err)

	resolver, err := NewSelectiveDirectory(dir, "", matcher)
	require.NoError(t, err)

	// Indexed file — content via index.
	locs, err := resolver.FilesByPath("/indexed.txt")
	require.NoError(t, err)
	require.Len(t, locs, 1)
	rc, err := resolver.FileContentsByLocation(locs[0])
	require.NoError(t, err)
	require.NotNil(t, rc)
	_ = rc.Close()

	// Non-indexed file — content via fallback.
	locs, err = resolver.FilesByPath("/dynamic.txt")
	require.NoError(t, err)
	require.Len(t, locs, 1)
	rc, err = resolver.FileContentsByLocation(locs[0])
	require.NoError(t, err)
	require.NotNil(t, rc)
	_ = rc.Close()
}
