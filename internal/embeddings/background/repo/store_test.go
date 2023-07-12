package repo

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/keegancsmith/sqlf"
	"github.com/sourcegraph/log/logtest"
	"github.com/stretchr/testify/require"

	"github.com/sourcegraph/sourcegraph/internal/api"
	"github.com/sourcegraph/sourcegraph/internal/codeintel/policies/shared"
	"github.com/sourcegraph/sourcegraph/internal/conf"
	"github.com/sourcegraph/sourcegraph/internal/database"
	"github.com/sourcegraph/sourcegraph/internal/database/dbtest"
	"github.com/sourcegraph/sourcegraph/internal/types"
	"github.com/sourcegraph/sourcegraph/lib/pointers"
	"github.com/sourcegraph/sourcegraph/schema"
)

func TestRepoEmbeddingJobsStore(t *testing.T) {
	t.Parallel()

	logger := logtest.Scoped(t)
	db := database.NewDB(logger, dbtest.NewDB(logger, t))
	repoStore := db.Repos()

	ctx := context.Background()

	createdRepo := &types.Repo{Name: "github.com/sourcegraph/sourcegraph", URI: "github.com/sourcegraph/sourcegraph", ExternalRepo: api.ExternalRepoSpec{}}
	err := repoStore.Create(ctx, createdRepo)
	require.NoError(t, err)

	createdRepo2 := &types.Repo{Name: "github.com/sourcegraph/zoekt", URI: "github.com/sourcegraph/zoekt", ExternalRepo: api.ExternalRepoSpec{}}
	err = repoStore.Create(ctx, createdRepo2)
	require.NoError(t, err)

	store := NewRepoEmbeddingJobsStore(db)

	// no job exists
	exists, err := repoStore.RepoEmbeddingExists(ctx, createdRepo.ID)
	require.NoError(t, err)
	require.Equal(t, exists, false)

	// Create three repo embedding jobs.
	id1, err := store.CreateRepoEmbeddingJob(ctx, createdRepo.ID, "deadbeef")
	require.NoError(t, err)

	id2, err := store.CreateRepoEmbeddingJob(ctx, createdRepo.ID, "coffee")
	require.NoError(t, err)

	id3, err := store.CreateRepoEmbeddingJob(ctx, createdRepo2.ID, "tea")
	require.NoError(t, err)

	count, err := store.CountRepoEmbeddingJobs(ctx, ListOpts{})
	require.NoError(t, err)
	require.Equal(t, 3, count)

	pattern := "oek" // matching zoekt
	count, err = store.CountRepoEmbeddingJobs(ctx, ListOpts{Query: &pattern})
	require.NoError(t, err)
	require.Equal(t, 1, count)

	pattern = "unknown"
	count, err = store.CountRepoEmbeddingJobs(ctx, ListOpts{Query: &pattern})
	require.NoError(t, err)
	require.Equal(t, 0, count)

	first := 10
	jobs, err := store.ListRepoEmbeddingJobs(ctx, ListOpts{PaginationArgs: &database.PaginationArgs{First: &first, OrderBy: database.OrderBy{{Field: "id"}}, Ascending: true}})
	require.NoError(t, err)

	// only queued job exists
	exists, err = repoStore.RepoEmbeddingExists(ctx, createdRepo.ID)
	require.NoError(t, err)
	require.Equal(t, exists, false)

	// Expect to get the three repo embedding jobs in the list.
	require.Equal(t, 3, len(jobs))
	require.Equal(t, id1, jobs[0].ID)
	require.Equal(t, id2, jobs[1].ID)
	require.Equal(t, id3, jobs[2].ID)

	// Check that we get the correct repo embedding job for repo and revision.
	lastEmbeddingJobForRevision, err := store.GetLastRepoEmbeddingJobForRevision(ctx, createdRepo.ID, "deadbeef")
	require.NoError(t, err)

	require.Equal(t, id1, lastEmbeddingJobForRevision.ID)

	// Complete the second job and check if we get it back when calling GetLastCompletedRepoEmbeddingJob.
	stateCompleted := "completed"
	setJobState(t, ctx, store, id2, stateCompleted)
	lastCompletedJob, err := store.GetLastCompletedRepoEmbeddingJob(ctx, createdRepo.ID)
	require.NoError(t, err)

	require.Equal(t, id2, lastCompletedJob.ID)

	// completed job present
	exists, err = repoStore.RepoEmbeddingExists(ctx, createdRepo.ID)
	require.NoError(t, err)
	require.Equal(t, exists, true)

	// Check that we get the correct repo embedding job if we filter by "state".
	jobs, err = store.ListRepoEmbeddingJobs(ctx, ListOpts{State: &stateCompleted, PaginationArgs: &database.PaginationArgs{First: &first, OrderBy: database.OrderBy{{Field: "id"}}, Ascending: true}})
	require.NoError(t, err)
	require.Equal(t, 1, len(jobs))
	require.Equal(t, id2, jobs[0].ID)

	t.Run("update stats", func(t *testing.T) {
		stats, err := store.GetRepoEmbeddingJobStats(ctx, jobs[0].ID)
		require.NoError(t, err)
		require.Equal(t, EmbedRepoStats{}, stats, "expected empty stats")

		updatedStats := EmbedRepoStats{
			IsIncremental: false,
			CodeIndexStats: EmbedFilesStats{
				FilesScheduled: 123,
				FilesEmbedded:  12,
				FilesSkipped:   map[string]int{"longLine": 10},
				ChunksEmbedded: 20,
				BytesEmbedded:  200,
			},
			TextIndexStats: EmbedFilesStats{
				FilesScheduled: 456,
				FilesEmbedded:  45,
				FilesSkipped:   map[string]int{"longLine": 20, "autogenerated": 12},
				ChunksEmbedded: 40,
				BytesEmbedded:  400,
			},
		}
		err = store.UpdateRepoEmbeddingJobStats(ctx, jobs[0].ID, &updatedStats)
		require.NoError(t, err)

		stats, err = store.GetRepoEmbeddingJobStats(ctx, jobs[0].ID)
		require.NoError(t, err)
		require.Equal(t, updatedStats, stats)
	})
}

func TestCancelRepoEmbeddingJob(t *testing.T) {
	t.Parallel()

	logger := logtest.Scoped(t)
	db := database.NewDB(logger, dbtest.NewDB(logger, t))
	repoStore := db.Repos()

	ctx := context.Background()

	createdRepo := &types.Repo{Name: "github.com/sourcegraph/sourcegraph", URI: "github.com/sourcegraph/sourcegraph", ExternalRepo: api.ExternalRepoSpec{}}
	err := repoStore.Create(ctx, createdRepo)
	require.NoError(t, err)

	store := NewRepoEmbeddingJobsStore(db)

	// Create two repo embedding jobs.
	id1, err := store.CreateRepoEmbeddingJob(ctx, createdRepo.ID, "deadbeef")
	require.NoError(t, err)

	id2, err := store.CreateRepoEmbeddingJob(ctx, createdRepo.ID, "coffee")
	require.NoError(t, err)

	// Cancel the first one.
	err = store.CancelRepoEmbeddingJob(ctx, id1)
	require.NoError(t, err)

	// Move the second job to 'processing' state and cancel it too
	setJobState(t, ctx, store, id2, "processing")
	err = store.CancelRepoEmbeddingJob(ctx, id2)
	require.NoError(t, err)

	first := 10
	jobs, err := store.ListRepoEmbeddingJobs(ctx, ListOpts{PaginationArgs: &database.PaginationArgs{First: &first, OrderBy: database.OrderBy{{Field: "id"}}, Ascending: true}})
	require.NoError(t, err)

	// Expect to get the two repo embedding jobs in the list.
	require.Equal(t, 2, len(jobs))
	require.Equal(t, id1, jobs[0].ID)
	require.Equal(t, true, jobs[0].Cancel)
	require.Equal(t, "canceled", jobs[0].State)
	require.Equal(t, id2, jobs[1].ID)
	require.Equal(t, true, jobs[1].Cancel)

	// Attempting to cancel a non-existent job should fail
	err = store.CancelRepoEmbeddingJob(ctx, id1+42)
	require.Error(t, err)

	// Attempting to cancel a completed job should fail
	id3, err := store.CreateRepoEmbeddingJob(ctx, createdRepo.ID, "avocado")
	require.NoError(t, err)

	setJobState(t, ctx, store, id3, "completed")
	err = store.CancelRepoEmbeddingJob(ctx, id3)
	require.Error(t, err)
}

func TestGetEmbeddableRepos(t *testing.T) {
	t.Parallel()

	logger := logtest.Scoped(t)
	db := database.NewDB(logger, dbtest.NewDB(logger, t))
	repoStore := db.Repos()
	ctx := context.Background()

	// Create two repositories
	firstRepo := &types.Repo{Name: "github.com/sourcegraph/sourcegraph", URI: "github.com/sourcegraph/sourcegraph", ExternalRepo: api.ExternalRepoSpec{}}
	err := repoStore.Create(ctx, firstRepo)
	require.NoError(t, err)

	secondRepo := &types.Repo{Name: "github.com/sourcegraph/zoekt", URI: "github.com/sourcegraph/zoekt", ExternalRepo: api.ExternalRepoSpec{}}
	err = repoStore.Create(ctx, secondRepo)
	require.NoError(t, err)

	// Clone the repos
	gitserverStore := db.GitserverRepos()
	err = gitserverStore.SetCloneStatus(ctx, firstRepo.Name, types.CloneStatusCloned, "test")
	require.NoError(t, err)

	err = gitserverStore.SetCloneStatus(ctx, secondRepo.Name, types.CloneStatusCloned, "test")
	require.NoError(t, err)

	// Create a embeddings policy that applies to all repos
	store := NewRepoEmbeddingJobsStore(db)
	err = createGlobalPolicy(ctx, store)
	require.NoError(t, err)

	// At first, both repos should be embeddable.
	repos, err := store.GetEmbeddableRepos(ctx, EmbeddableRepoOpts{MinimumInterval: 1 * time.Hour})
	require.NoError(t, err)
	require.Equal(t, 2, len(repos))

	// Create and queue an embedding job for the first repo.
	_, err = store.CreateRepoEmbeddingJob(ctx, firstRepo.ID, "coffee")
	require.NoError(t, err)

	// Only the second repo should be embeddable, since the first was recently queued
	repos, err = store.GetEmbeddableRepos(ctx, EmbeddableRepoOpts{MinimumInterval: 1 * time.Hour})
	require.NoError(t, err)
	require.Equal(t, 1, len(repos))
}

func TestEmbeddingsPolicyWithFailures(t *testing.T) {
	t.Parallel()

	logger := logtest.Scoped(t)
	db := database.NewDB(logger, dbtest.NewDB(logger, t))
	repoStore := db.Repos()
	ctx := context.Background()

	// Create two repositories
	firstRepo := &types.Repo{Name: "github.com/sourcegraph/sourcegraph", URI: "github.com/sourcegraph/sourcegraph", ExternalRepo: api.ExternalRepoSpec{}}
	err := repoStore.Create(ctx, firstRepo)
	require.NoError(t, err)

	secondRepo := &types.Repo{Name: "github.com/sourcegraph/zoekt", URI: "github.com/sourcegraph/zoekt", ExternalRepo: api.ExternalRepoSpec{}}
	err = repoStore.Create(ctx, secondRepo)
	require.NoError(t, err)

	// Clone the repos
	gitserverStore := db.GitserverRepos()
	err = gitserverStore.SetCloneStatus(ctx, firstRepo.Name, types.CloneStatusCloned, "test")
	require.NoError(t, err)

	err = gitserverStore.SetCloneStatus(ctx, secondRepo.Name, types.CloneStatusCloned, "test")
	require.NoError(t, err)

	// Create a embeddings policy that applies to all repos
	store := NewRepoEmbeddingJobsStore(db)
	err = createGlobalPolicy(ctx, store)
	require.NoError(t, err)

	// At first, both repos should be embeddable.
	repos, err := store.GetEmbeddableRepos(ctx, EmbeddableRepoOpts{MinimumInterval: 1 * time.Hour})
	require.NoError(t, err)
	require.Equal(t, 2, len(repos))

	// Create and queue an embedding job for the first repo.
	_, err = store.CreateRepoEmbeddingJob(ctx, firstRepo.ID, "coffee")
	require.NoError(t, err)

	// Only the second repo should be embeddable, since the first was recently queued
	repos, err = store.GetEmbeddableRepos(ctx, EmbeddableRepoOpts{MinimumInterval: 1 * time.Hour})
	require.NoError(t, err)
	require.Equal(t, 1, len(repos))
}

func TestGetEmbeddableReposLimit(t *testing.T) {
	logger := logtest.Scoped(t)
	db := database.NewDB(logger, dbtest.NewDB(logger, t))
	repoStore := db.Repos()
	ctx := context.Background()

	// Create two repositories
	firstRepo := &types.Repo{Name: "github.com/sourcegraph/sourcegraph", URI: "github.com/sourcegraph/sourcegraph", ExternalRepo: api.ExternalRepoSpec{}}
	err := repoStore.Create(ctx, firstRepo)
	require.NoError(t, err)

	secondRepo := &types.Repo{Name: "github.com/sourcegraph/zoekt", URI: "github.com/sourcegraph/zoekt", ExternalRepo: api.ExternalRepoSpec{}}
	err = repoStore.Create(ctx, secondRepo)
	require.NoError(t, err)

	// Clone the repos
	gitserverStore := db.GitserverRepos()
	err = gitserverStore.SetCloneStatus(ctx, firstRepo.Name, types.CloneStatusCloned, "test")
	require.NoError(t, err)

	err = gitserverStore.SetCloneStatus(ctx, secondRepo.Name, types.CloneStatusCloned, "test")
	require.NoError(t, err)

	// Create an embeddings policy that applies to all repos
	store := NewRepoEmbeddingJobsStore(db)
	err = createGlobalPolicy(ctx, store)
	require.NoError(t, err)

	cases := []struct {
		policyRepositoryMatchLimit int
		wantMatches                int
	}{
		{
			policyRepositoryMatchLimit: -1, // unlimited
			wantMatches:                2,
		},
		{
			policyRepositoryMatchLimit: 0,
			wantMatches:                0,
		},
		{
			policyRepositoryMatchLimit: 1,
			wantMatches:                1,
		},
		{
			policyRepositoryMatchLimit: 2,
			wantMatches:                2,
		},
		{
			policyRepositoryMatchLimit: 3,
			wantMatches:                2,
		},
	}

	for _, tt := range cases {
		t.Run(fmt.Sprintf("policyRepositoryMatchLimit=%d", tt.policyRepositoryMatchLimit), func(t *testing.T) {
			repos, err := store.GetEmbeddableRepos(ctx, EmbeddableRepoOpts{MinimumInterval: 1 * time.Hour, PolicyRepositoryMatchLimit: &tt.policyRepositoryMatchLimit})
			require.NoError(t, err)
			require.Equal(t, tt.wantMatches, len(repos))
		})
	}
}

func TestGetEmbeddableRepoOpts(t *testing.T) {
	conf.Mock(&conf.Unified{})
	defer conf.Mock(nil)
	conf.Mock(&conf.Unified{SiteConfiguration: schema.SiteConfiguration{
		CodyEnabled: pointers.Ptr(true),
		LicenseKey:  "asdf",
	}})

	opts := GetEmbeddableRepoOpts()
	require.Equal(t, 24*time.Hour, opts.MinimumInterval)
	require.Equal(t, 5000, *opts.PolicyRepositoryMatchLimit)

	opts = GetEmbeddableRepoOpts()
	require.Equal(t, 24*time.Hour, opts.MinimumInterval)
	require.Equal(t, 5000, *opts.PolicyRepositoryMatchLimit)

	limit := 5
	conf.Mock(&conf.Unified{
		SiteConfiguration: schema.SiteConfiguration{
			CodyEnabled: pointers.Ptr(true),
			Embeddings: &schema.Embeddings{
				Provider:                   "openai",
				AccessToken:                "asdf",
				MinimumInterval:            "1h",
				PolicyRepositoryMatchLimit: &limit,
			},
		},
	})

	opts = GetEmbeddableRepoOpts()
	require.Equal(t, 1*time.Hour, opts.MinimumInterval)
	require.Equal(t, 5, *opts.PolicyRepositoryMatchLimit)
}

func setJobState(t *testing.T, ctx context.Context, store RepoEmbeddingJobsStore, jobID int, state string) {
	t.Helper()
	err := store.Exec(ctx, sqlf.Sprintf("UPDATE repo_embedding_jobs SET state = %s, finished_at = now() WHERE id = %s", state, jobID))
	if err != nil {
		t.Fatalf("failed to set repo embedding job state: %s", err)
	}
}

const insertGlobalPolicyStr = `
INSERT INTO lsif_configuration_policies (
	repository_id,
	repository_patterns,
	name,
	type,
	pattern,
	retention_enabled,
	retention_duration_hours,
	retain_intermediate_commits,
	indexing_enabled,
	index_commit_max_age_hours,
	index_intermediate_commits,
	embeddings_enabled
) VALUES  (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
      `

func createGlobalPolicy(ctx context.Context, store RepoEmbeddingJobsStore) error {
	q := sqlf.Sprintf(insertGlobalPolicyStr,
		nil,
		nil,
		"global",
		string(shared.GitObjectTypeCommit),
		"HEAD",
		false,
		nil,
		false,
		false,
		nil,
		false,
		true, // Embeddings enabled
	)
	return store.Exec(ctx, q)
}
