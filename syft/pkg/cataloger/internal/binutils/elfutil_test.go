package binutils

import (
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHasSection(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ELF tests only run on Linux")
	}

	// Use the Go test binary itself — it's a Go-compiled ELF binary
	// and will have .go.buildinfo, .text, .rodata, etc.
	self, err := os.Open("/proc/self/exe")
	require.NoError(t, err)
	defer self.Close()

	tests := []struct {
		name     string
		section  string
		expected bool
	}{
		{
			name:     "go binary has .go.buildinfo",
			section:  ".go.buildinfo",
			expected: true,
		},
		{
			name:     "go binary has .text",
			section:  ".text",
			expected: true,
		},
		{
			name:     "go binary does not have .dep-v0",
			section:  ".dep-v0",
			expected: false,
		},
		{
			name:     "go binary does not have .note.package",
			section:  ".note.package",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HasSection(self, tt.section)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHasSection_NonELF(t *testing.T) {
	f, err := os.CreateTemp("", "not-elf-*")
	require.NoError(t, err)
	defer os.Remove(f.Name())

	_, err = f.WriteString("this is not an ELF file")
	require.NoError(t, err)
	_, err = f.Seek(0, 0)
	require.NoError(t, err)

	result := HasSection(f, ".text")
	assert.False(t, result, "non-ELF file should return false")
}

func TestHasSymbolName(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ELF tests only run on Linux")
	}

	self, err := os.Open("/proc/self/exe")
	require.NoError(t, err)
	defer self.Close()

	tests := []struct {
		name       string
		symbolName string
		expected   bool
	}{
		{
			// Go test binaries are dynamically linked and include C runtime symbols in .dynstr.
			// malloc is present in all dynamically-linked Go test binaries via cgo.
			name:       "go binary has malloc symbol",
			symbolName: "malloc",
			expected:   true,
		},
		{
			name:       "go binary does not have __svm_version_info",
			symbolName: "__svm_version_info",
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HasSymbolName(self, tt.symbolName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHasSymbolName_NonELF(t *testing.T) {
	f, err := os.CreateTemp("", "not-elf-*")
	require.NoError(t, err)
	defer os.Remove(f.Name())

	_, err = f.WriteString("this is not an ELF file")
	require.NoError(t, err)
	_, err = f.Seek(0, 0)
	require.NoError(t, err)

	result := HasSymbolName(f, "anything")
	assert.False(t, result, "non-ELF file should return false")
}
