package pkg

import (
	"context"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
)

// Cataloger describes behavior for an object to participate in parsing container image or file system
// contents for the purpose of discovering Packages. Each concrete implementation should focus on discovering Packages
// for a specific Package Type or ecosystem.
type Cataloger interface {
	// Name returns a string that uniquely describes a cataloger
	Name() string
	// Catalog is given an object to resolve file references and content, this function returns any discovered Packages after analyzing the catalog source.
	Catalog(context.Context, file.Resolver) ([]Package, []artifact.Relationship, error)
}

// GlobProvider is an optional interface that catalogers can implement to expose
// the static file patterns they will query during cataloging. This enables
// selective file indexing — only files matching declared patterns are indexed.
// Returned patterns may include both glob patterns (from WithParserByGlobs) and
// exact paths (from WithParserByPath); exact paths are valid degenerate globs.
// Catalogers matching solely by MIME type return an empty slice; callers must
// treat an empty result as "no pattern-based prefiltering is available."
type GlobProvider interface {
	Globs() []string
}
