package resolvers

import (
	"context"
)

type ContextServiceResolver interface {
	GetPreciseContext(ctx context.Context, input *GetPreciseContextInput) (PreciseContextOutputResolver, error)
}

type GetPreciseContextInput struct {
	Input PreciseContextInput
}

type PreciseContextInput struct {
	// The name of the repository
	RepositoryName string
	// Closest ancestor commit on remote branch
	ClosestRemoteCommitSHA string
	// The file that is currently open in the editor
	ActiveFile string
	// The contents of the file that is currently open in the editor
	ActiveFileContent string
	// The selected content of the active file
	ActiveFileSelectionRange *ActiveFileSelectionRangeInput
}

type ActiveFileSelectionRangeInput struct {
	StartLine      int32
	StartCharacter int32
	EndLine        int32
	EndCharacter   int32
}

type PreciseContextResolver interface {
	ScipSymbolName() string
	FuzzySymbolName() string
	ScipDescriptorSuffix() string
	FuzzyDescriptorSuffix() string
	RepositoryName() string
	Text() string
	FilePath() string
}

type PreciseContextOutputResolver interface {
	Context() []PreciseContextResolver
}
