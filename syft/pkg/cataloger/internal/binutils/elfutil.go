package binutils

import (
	"bytes"
	"debug/elf"
	"io"
)

// HasSection opens ELF headers and checks if a named section exists.
// Returns false for non-ELF files (no error).
// Cost: ~3 KB of I/O (headers + section header table only).
func HasSection(reader io.ReaderAt, sectionName string) bool {
	f, err := elf.NewFile(reader)
	if err != nil {
		return false
	}
	defer f.Close()

	return f.Section(sectionName) != nil
}

// HasSymbolName opens ELF headers, reads the raw string table section,
// and checks if a symbol name appears as a null-terminated string.
// Reads only the string table bytes (~10-50 KB) without per-symbol metadata.
// Checks .dynstr first, falls back to .strtab.
// Returns false for non-ELF files (no error).
func HasSymbolName(reader io.ReaderAt, symbolName string) bool {
	f, err := elf.NewFile(reader)
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
