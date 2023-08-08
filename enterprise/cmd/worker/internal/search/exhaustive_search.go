package search

import (
	"context"
	"time"

	"github.com/sourcegraph/log"

	"github.com/sourcegraph/sourcegraph/internal/goroutine"
	"github.com/sourcegraph/sourcegraph/internal/observation"
	"github.com/sourcegraph/sourcegraph/internal/search/exhaustive"
	"github.com/sourcegraph/sourcegraph/internal/workerutil"
	"github.com/sourcegraph/sourcegraph/internal/workerutil/dbworker"
	dbworkerstore "github.com/sourcegraph/sourcegraph/internal/workerutil/dbworker/store"
	"github.com/sourcegraph/sourcegraph/lib/errors"
)

// NewExhaustiveSearchWorker creates a background routine that periodically runs the exhaustive search.
func NewExhaustiveSearchWorker(
	ctx context.Context,
	observationCtx *observation.Context,
	workerStore dbworkerstore.Store[*exhaustive.Job],
) goroutine.BackgroundRoutine {
	handler := &exhaustiveSearchHandler{
		logger: log.Scoped("exhaustive-search", "The background worker running exhaustive searches"),
	}

	opts := workerutil.WorkerOptions{
		Name:              "exhaustive_search_worker",
		Description:       "runs the exhaustive search",
		NumHandlers:       5,
		Interval:          1 * time.Second,
		HeartbeatInterval: 15 * time.Second,
		Metrics:           workerutil.NewMetrics(observationCtx, "exhaustive_search_worker"),
	}

	return dbworker.NewWorker[*exhaustive.Job](ctx, workerStore, handler, opts)
}

type exhaustiveSearchHandler struct {
	logger log.Logger
}

var _ workerutil.Handler[*exhaustive.Job] = &exhaustiveSearchHandler{}

func (e *exhaustiveSearchHandler) Handle(ctx context.Context, logger log.Logger, record *exhaustive.Job) error {
	// TODO at the moment this does nothing. This will be implemented in a future PR.
	return errors.New("not implemented")
}
