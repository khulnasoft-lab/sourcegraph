package database

import (
	"context"
	"database/sql"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/sourcegraph/sourcegraph/internal/api"
	"github.com/sourcegraph/sourcegraph/internal/database/basestore"
	"github.com/sourcegraph/sourcegraph/lib/errors"

	codeownerspb "github.com/sourcegraph/sourcegraph/internal/own/codeowners/proto"
)

// CodeownersStore currently allows to store only the most recent version of CODEOWNERS
// file for main branch of given repository.
type CodeownersStore interface {
	basestore.ShareableStore
	// Put updates the newest CODEOWNERS file for given repository's HEAD.
	PutHead(context.Context, api.RepoName, *codeownerspb.File) error
	// GetHead returns the CODEOWNERS file associated with
	// or nil, if there is none.
	GetHead(ctx context.Context, repoName api.RepoName) (*codeownerspb.File, error)
}

var _ CodeownersStore = (*codeownersStore)(nil)

type codeownersStore struct {
	*basestore.Store
}

func (s *codeownersStore) PutHead(ctx context.Context, repoName api.RepoName, f *codeownerspb.File) error {
	b, err := proto.Marshal(f)
	if err != nil {
		return err
	}
	fmt.Printf("WRITE %v\n", b)
	q := `
		WITH inline_repo_bytes AS (
			SELECT r.id AS repo_id, $1::bytea AS proto
			FROM repo AS r
			WHERE r.name = $2
		)
		INSERT INTO codeowners_head (repo_id, proto)
		SELECT * FROM inline_repo_bytes
		ON CONFLICT (repo_id)
		DO UPDATE SET proto = $1::bytea
		RETURNING repo_id
	`
	// Discard the result of the scan, but run it to see if repo
	// with given name was found.
	err = s.Handle().QueryRowContext(ctx, q, b, repoName).Scan(new(int))
	if err == sql.ErrNoRows {
		return errors.Wrapf(err, "repo %q not found", repoName)
	}
	if err != nil {
		return err
	}
	return nil
}

func (s *codeownersStore) GetHead(ctx context.Context, repoName api.RepoName) (*codeownerspb.File, error) {
	q := `
		SELECT h.proto
		FROM codeowners_head AS h
		INNER JOIN repo AS r
		ON h.repo_id = r.id
		WHERE r.name = $1
	`
	var b []byte
	err := s.Handle().QueryRowContext(ctx, q, repoName).Scan(&b)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	fmt.Printf("READ %v\n", b)
	var p codeownerspb.File
	if err := proto.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	return &p, nil
}
