package fileresolver

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
)

// executableMIMETypes is the set of MIME types this fallback can detect.
var executableMIMETypes = map[string]struct{}{
	"application/x-executable":                    {},
	"application/x-elf":                           {},
	"application/x-sharedlib":                     {},
	"application/vnd.microsoft.portable-executable": {},
	"application/x-mach-binary":                   {},
}

var _ file.Resolver = (*SelectiveDirectory)(nil)

// SelectiveDirectory wraps a Directory resolver built with a PatternMatcher (selective index).
// For queries matching known static patterns it uses the index (fast path).
// For unknown/dynamic queries it falls back to direct filesystem access.
type SelectiveDirectory struct {
	*Directory
	matcher *PatternMatcher
	root    string
	base    string
}

// NewSelectiveDirectory creates a Directory resolver with a selective index and wraps it.
func NewSelectiveDirectory(root, base string, matcher *PatternMatcher, pathFilters ...PathIndexVisitor) (*SelectiveDirectory, error) {
	dir, err := NewFromDirectory(root, base, matcher, pathFilters...)
	if err != nil {
		return nil, err
	}
	return &SelectiveDirectory{
		Directory: dir,
		matcher:   matcher,
		root:      dir.Chroot.Root(),
		base:      dir.Chroot.Base(),
	}, nil
}

// FilesByPath returns locations for the given paths.  It first tries the index;
// any path not found there is looked up directly on the filesystem.
func (s *SelectiveDirectory) FilesByPath(userPaths ...string) ([]file.Location, error) {
	// Attempt index lookup first.
	found, err := s.Directory.FilesByPath(userPaths...)
	if err != nil {
		return nil, err
	}

	// Build a set of paths that were resolved via the index.
	foundPaths := make(map[string]bool, len(found))
	for _, loc := range found {
		foundPaths[string(loc.RealPath)] = true
		if loc.AccessPath != "" {
			foundPaths[loc.AccessPath] = true
		}
	}

	// For each user path not resolved by the index, try the filesystem directly.
	for _, userPath := range userPaths {
		nativePath, err := s.Chroot.ToNativePath(userPath)
		if err != nil {
			continue
		}

		// Skip if the index already resolved this path.
		responsePath := s.responsePath(nativePath)
		if foundPaths[responsePath] || foundPaths[nativePath] {
			continue
		}

		fi, err := os.Stat(nativePath)
		if err != nil {
			continue
		}
		// Skip directories.
		if fi.IsDir() {
			continue
		}

		ref := stereoscopeFile.NewFileReference(stereoscopeFile.Path(nativePath))
		loc := file.NewVirtualLocationFromDirectory(
			responsePath,  // real path (chroot-relative)
			responsePath,  // access path
			*ref,
		)
		found = append(found, loc)
	}

	return found, nil
}

// FilesByGlob returns locations matching the given glob patterns.
// Known patterns use the index; unknown patterns fall back to a filesystem walk.
func (s *SelectiveDirectory) FilesByGlob(patterns ...string) ([]file.Location, error) {
	var result []file.Location
	seen := make(map[string]bool)

	for _, pattern := range patterns {
		var locs []file.Location
		var err error

		if s.matcher != nil && s.matcher.IsKnownPattern(pattern) {
			// Fast path: pattern was part of the original cataloger set → index covers it.
			locs, err = s.Directory.FilesByGlob(pattern)
			if err != nil {
				return nil, err
			}
		} else {
			// Slow path: walk the root and match with doublestar.
			locs, err = s.globFallback(pattern)
			if err != nil {
				return nil, err
			}
		}

		for _, loc := range locs {
			key := string(loc.RealPath)
			if !seen[key] {
				seen[key] = true
				result = append(result, loc)
			}
		}
	}

	return result, nil
}

// globFallback resolves a glob pattern that is NOT in the selective index.
// It uses three strategies in order of speed:
//  1. Basename index lookup for **/name patterns (O(1))
//  2. Scoped directory walk for **/path/to/dir/* patterns (walk subtree only)
//  3. Full filesystem walk for everything else (last resort)
func (s *SelectiveDirectory) globFallback(pattern string) ([]file.Location, error) {
	// Strategy 1: basename index for simple **/name patterns.
	if s.Directory.allBasenames != nil {
		if basename, ok := extractSimpleBasename(pattern); ok {
			return s.basenameIndexLookup(basename)
		}
	}

	// Strategy 2: extract directory prefix from **/path/to/dir/* patterns.
	// If the pattern has a fixed directory prefix, either walk that subtree
	// or return empty if the directory doesn't exist (no need for a full walk).
	if dirPart, filePart, ok := extractGlobDirAndFile(pattern); ok {
		candidate := filepath.Join(s.root, dirPart)
		if fi, err := os.Stat(candidate); err == nil && fi.IsDir() {
			return s.scopedWalk(candidate, filePart)
		}
		// Directory doesn't exist → no matches possible, skip the full walk.
		return nil, nil
	}

	// Strategy 3: full walk (last resort for truly complex patterns).
	return s.fullWalk(pattern)
}

// extractGlobDirAndFile checks if a pattern starts with **/ followed by a
// fixed directory path and ends with a simple file glob. For example:
//
//	**/go/pkg/mod/github.com/foo@v1/*  →  dirPart="go/pkg/mod/github.com/foo@v1", filePart="*"
//
// Returns the directory portion, the file-level pattern, and true.
// The caller is responsible for checking whether the directory exists on disk.
func extractGlobDirAndFile(pattern string) (dirPart, filePattern string, ok bool) {
	if !strings.HasPrefix(pattern, "**/") {
		return "", "", false
	}
	rest := pattern[3:] // e.g. "go/pkg/mod/foo@v1/*"

	// Find the last slash — everything before it is a directory path,
	// everything after is the file pattern.
	lastSlash := strings.LastIndex(rest, "/")
	if lastSlash < 0 {
		return "", "", false // no directory component → handled by basename lookup
	}

	dir := rest[:lastSlash]    // "go/pkg/mod/foo@v1"
	file := rest[lastSlash+1:] // "*"

	// The directory part must not contain glob wildcards (otherwise we can't
	// resolve it to a single directory).
	if strings.ContainsAny(dir, "*?[{") {
		return "", "", false
	}

	return dir, file, true
}

// scopedWalk walks only the specified directory and matches files against filePattern.
func (s *SelectiveDirectory) scopedWalk(walkRoot, filePattern string) ([]file.Location, error) {
	var locs []file.Location

	entries, err := os.ReadDir(walkRoot)
	if err != nil {
		return nil, nil // directory doesn't exist or is inaccessible
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		matched, matchErr := doublestar.Match(filePattern, name)
		if matchErr != nil || !matched {
			continue
		}

		fullPath := filepath.Join(walkRoot, name)
		responsePath := s.responsePath(fullPath)
		ref := stereoscopeFile.NewFileReference(stereoscopeFile.Path(fullPath))
		loc := file.NewVirtualLocationFromDirectory(
			responsePath,
			responsePath,
			*ref,
		)
		locs = append(locs, loc)
	}

	return locs, nil
}

// fullWalk is the last-resort fallback that walks the entire filesystem.
func (s *SelectiveDirectory) fullWalk(pattern string) ([]file.Location, error) {
	nativePattern, err := s.requestGlob(pattern)
	if err != nil {
		nativePattern = pattern
	}

	var locs []file.Location

	err = filepath.Walk(s.root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if info == nil || info.IsDir() || !info.Mode().IsRegular() {
			return nil
		}

		matched, matchErr := doublestar.Match(nativePattern, path)
		if matchErr != nil || !matched {
			return nil
		}

		responsePath := s.responsePath(path)
		ref := stereoscopeFile.NewFileReference(stereoscopeFile.Path(path))
		loc := file.NewVirtualLocationFromDirectory(responsePath, responsePath, *ref)
		locs = append(locs, loc)
		return nil
	})

	return locs, err
}

// extractSimpleBasename checks if a pattern is a simple **/basename pattern
// (possibly with wildcards in the basename like **/python*).
// Returns the basename part and true if the pattern matches this form.
func extractSimpleBasename(pattern string) (string, bool) {
	if !strings.HasPrefix(pattern, "**/") {
		return "", false
	}
	rest := pattern[3:]
	// No path separators in the basename part
	if strings.Contains(rest, "/") {
		return "", false
	}
	return rest, true
}

// basenameIndexLookup finds files matching a basename pattern using the pre-built index.
func (s *SelectiveDirectory) basenameIndexLookup(basenamePattern string) ([]file.Location, error) {
	var locs []file.Location
	hasWildcard := strings.ContainsAny(basenamePattern, "*?[{")

	if !hasWildcard {
		// Exact match — O(1) lookup
		paths := s.Directory.allBasenames[basenamePattern]
		for _, path := range paths {
			responsePath := s.responsePath(path)
			ref := stereoscopeFile.NewFileReference(stereoscopeFile.Path(path))
			locs = append(locs, file.NewVirtualLocationFromDirectory(responsePath, responsePath, *ref))
		}
	} else {
		// Wildcard in basename — scan all basenames and match with doublestar
		for basename, paths := range s.Directory.allBasenames {
			matched, err := doublestar.Match(basenamePattern, basename)
			if err != nil || !matched {
				continue
			}
			for _, path := range paths {
				responsePath := s.responsePath(path)
				ref := stereoscopeFile.NewFileReference(stereoscopeFile.Path(path))
				locs = append(locs, file.NewVirtualLocationFromDirectory(responsePath, responsePath, *ref))
			}
		}
	}

	return locs, nil
}

// FilesByMIMEType first tries the index (which is empty when MIME detection was
// skipped). If the index returns nothing it falls back to a lightweight
// filesystem walk that detects executables via permission bits and magic bytes.
func (s *SelectiveDirectory) FilesByMIMEType(types ...string) ([]file.Location, error) {
	locs, err := s.Directory.FilesByMIMEType(types...)
	if err != nil {
		return nil, err
	}
	if len(locs) > 0 {
		return locs, nil
	}

	return s.mimeTypeFallback(types...)
}

// mimeTypeFallback returns locations from the pre-built executable list collected
// during the indexing walk. Only executable MIME types are supported; requests for
// other types return empty results immediately.
func (s *SelectiveDirectory) mimeTypeFallback(types ...string) ([]file.Location, error) {
	// Check whether any of the requested types are in our executable set.
	anyExecutable := false
	for _, t := range types {
		if isExecutableMIMEType(t) {
			anyExecutable = true
			break
		}
	}
	if !anyExecutable {
		// We only support executable detection; bail early for other types.
		return nil, nil
	}

	log.Tracef("SelectiveDirectory.FilesByMIMEType: using pre-built executable list (%d files)", len(s.Directory.executables))

	var locs []file.Location
	for _, path := range s.Directory.executables {
		responsePath := s.responsePath(path)
		ref := stereoscopeFile.NewFileReference(stereoscopeFile.Path(path))
		loc := file.NewVirtualLocationFromDirectory(
			responsePath,
			responsePath,
			*ref,
		)
		locs = append(locs, loc)
	}

	return locs, nil
}

// detectExecutableMIMEType reads the first 4 bytes of path and returns the
// corresponding executable MIME type, or "" if the file is not a recognised
// executable format.
func detectExecutableMIMEType(path string) string {
	f, err := os.Open(path) //nolint:gosec
	if err != nil {
		return ""
	}
	defer f.Close()

	var magic [4]byte
	n, err := f.Read(magic[:])
	if err != nil || n < 2 {
		return ""
	}

	// ELF: \x7fELF
	if n >= 4 && magic[0] == 0x7f && magic[1] == 0x45 && magic[2] == 0x4c && magic[3] == 0x46 {
		return "application/x-elf"
	}

	// PE/COFF: MZ
	if magic[0] == 0x4d && magic[1] == 0x5a {
		return "application/vnd.microsoft.portable-executable"
	}

	// Mach-O (all four byte-order / bitness variants)
	if n >= 4 {
		switch {
		case magic[0] == 0xfe && magic[1] == 0xed && magic[2] == 0xfa && magic[3] == 0xce:
			return "application/x-mach-binary"
		case magic[0] == 0xfe && magic[1] == 0xed && magic[2] == 0xfa && magic[3] == 0xcf:
			return "application/x-mach-binary"
		case magic[0] == 0xcf && magic[1] == 0xfa && magic[2] == 0xed && magic[3] == 0xfe:
			return "application/x-mach-binary"
		case magic[0] == 0xce && magic[1] == 0xfa && magic[2] == 0xed && magic[3] == 0xfe:
			return "application/x-mach-binary"
		}
	}

	return ""
}

// isExecutableMIMEType reports whether t belongs to the set of MIME types this
// fallback is able to detect.
func isExecutableMIMEType(t string) bool {
	_, ok := executableMIMETypes[t]
	return ok
}

// FileContentsByLocation returns the contents of the given file.
// It tries the index first; on failure it opens the file directly from the filesystem.
func (s *SelectiveDirectory) FileContentsByLocation(location file.Location) (io.ReadCloser, error) {
	rc, err := s.Directory.FileContentsByLocation(location)
	if err == nil {
		return rc, nil
	}

	// Fallback: open the native path directly.
	nativePath, pathErr := s.Chroot.ToNativePath(string(location.RealPath))
	if pathErr != nil {
		return nil, err // return original error
	}
	return stereoscopeFile.NewLazyReadCloser(nativePath), nil
}

// FileMetadataByLocation returns metadata for the given file.
// It tries the index first; on failure it stats the file on the filesystem.
func (s *SelectiveDirectory) FileMetadataByLocation(location file.Location) (file.Metadata, error) {
	m, err := s.Directory.FileMetadataByLocation(location)
	if err == nil {
		return m, nil
	}

	// Fallback: stat the native path.
	nativePath, pathErr := s.Chroot.ToNativePath(string(location.RealPath))
	if pathErr != nil {
		return file.Metadata{}, err // return original error
	}

	fi, statErr := os.Stat(nativePath)
	if statErr != nil {
		return file.Metadata{}, statErr
	}

	return NewMetadataFromPathSkipMIME(nativePath, fi), nil
}

// HasPath reports whether the given path exists — checking the index first then the filesystem.
func (s *SelectiveDirectory) HasPath(userPath string) bool {
	if s.Directory.HasPath(userPath) {
		return true
	}

	nativePath, err := s.Chroot.ToNativePath(userPath)
	if err != nil {
		return false
	}

	_, err = os.Stat(nativePath)
	return err == nil
}

// RelativeFileByPath finds a file by path, using the fallback-aware FilesByPath.
func (s *SelectiveDirectory) RelativeFileByPath(_ file.Location, path string) *file.Location {
	locs, err := s.FilesByPath(path)
	if err != nil || len(locs) == 0 {
		return nil
	}
	return &locs[0]
}
