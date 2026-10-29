package binutils

import (
	"bytes"
	"io"

	"github.com/anchore/syft/syft/internal/elfutil"
)

// HasSection reports whether an ELF carries a named section.
// Returns false for non-ELF files, and for an ELF syft declines to expand (no error).
// Cost: ~3 KB of I/O (headers + section header table only).
func HasSection(reader io.ReaderAt, sectionName string) bool {
	f, err := elfutil.NewFile(reader)
	if err != nil {
		return false
	}
	defer f.Close()

	return f.Section(sectionName) != nil
}

// HasSymbolName reads the raw string table section and checks whether a symbol name appears as a
// null-terminated string. Reads only the string table bytes (~10-50 KB) without per-symbol metadata.
// Checks .dynstr first, falls back to .strtab.
// Returns false for non-ELF files (no error).
func HasSymbolName(reader io.ReaderAt, symbolName string) bool {
	f, err := elfutil.NewFile(reader)
	if err != nil {
		return false
	}
	defer f.Close()

	// Build the search pattern: the symbol name surrounded by null bytes.
	// Symbol names in string tables are null-terminated, and each is preceded
	// by the null terminator of the previous entry.
	pattern := append([]byte{0}, []byte(symbolName)...)
	pattern = append(pattern, 0)

	// Check .dynstr first (dynamic linking string table — most common)
	for _, sectionName := range []string{".dynstr", ".strtab"} {
		sec := f.Section(sectionName)
		if sec == nil {
			continue
		}
		data, err := sec.Data()
		if err != nil {
			continue
		}
		if bytes.Contains(data, pattern) {
			return true
		}
	}

	return false
}

// MissingSectionInELF reports whether reader is an ELF that does not carry the named section.
//
// It fails open, and both ways of failing matter. A non-ELF file returns false because a section
// pre-filter cannot speak for Mach-O or PE binaries. An ELF that elfutil refuses to expand also
// returns false: the caller's own path is bounded and may still read the file — debug/buildinfo
// reaches .go.buildinfo through the program headers — so answering "section absent" here would
// drop packages that the unfiltered scan still finds.
func MissingSectionInELF(reader io.ReaderAt, sectionName string) bool {
	f, err := elfutil.NewFile(reader)
	if err != nil {
		return false
	}
	defer f.Close()

	return f.Section(sectionName) == nil
}
