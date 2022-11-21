package graphqlutil

import (
	"sync"

	"github.com/graph-gophers/graphql-go"

	"github.com/sourcegraph/sourcegraph/internal/database"
)

type ConnectionResolverArgs struct {
	First  *int32
	Last   *int32
	After  *string
	Before *string
}

func (a *ConnectionResolverArgs) Limit() (limit int32) {
	if a == nil {
		return 0
	}

	if a.First != nil {
		limit = *a.First
	} else if a.Last != nil {
		limit = *a.Last
	}

	return
}

type ConnectionResolver[N ConnectionNode] struct {
	store ConnectionResolverStore[N]
	args  *ConnectionResolverArgs
	data  connectionData[N]
	once  resolveOnce
}

type ConnectionNode interface {
	ID() graphql.ID
}

type ConnectionResolverStore[N ConnectionNode] interface {
	ComputeTotal() (*int32, error)
	ComputeNodes(*database.PaginationArgs) ([]*N, error)
	MarshalCursor(*N) (*string, error)
	UnMarshalCursor(string) (*int32, error)
}

type connectionData[N ConnectionNode] struct {
	total      *int32
	totalError error

	nodes      []*N
	nodesError error
}

type resolveOnce struct {
	total sync.Once
	nodes sync.Once
}

func (r *ConnectionResolver[N]) paginationArgs() (*database.PaginationArgs, error) {
	if r.args == nil {
		return nil, nil
	}

	paginationArgs := database.PaginationArgs{}

	if r.args.First != nil {
		limit := *r.args.First + 1
		paginationArgs.First = &limit
	} else if r.args.Last != nil {
		limit := *r.args.Last + 1
		paginationArgs.Last = &limit
	}

	if r.args.After != nil {
		after, err := r.store.UnMarshalCursor(*r.args.After)
		if err != nil {
			return nil, err
		}

		paginationArgs.After = after
	}

	if r.args.Before != nil {
		before, err := r.store.UnMarshalCursor(*r.args.Before)
		if err != nil {
			return nil, err
		}

		paginationArgs.Before = before
	}

	return &paginationArgs, nil
}

func (r *ConnectionResolver[N]) TotalCount() (int32, error) {
	r.once.total.Do(func() {
		r.data.total, r.data.totalError = r.store.ComputeTotal()
	})

	if r.data.totalError != nil || r.data.total == nil {
		return 0, r.data.totalError
	}

	return *r.data.total, r.data.totalError
}

func (r *ConnectionResolver[N]) Nodes() ([]*N, error) {
	r.once.nodes.Do(func() {
		paginationArgs, err := r.paginationArgs()
		if err != nil {
			r.data.nodesError = err
			return
		}

		r.data.nodes, r.data.nodesError = r.store.ComputeNodes(paginationArgs)

		// TODO(naman): add explaonondsfksjdh
		if r.args.Last != nil {
			// two-way swap list reversal
			for i, j := 0, len(r.data.nodes)-1; i < j; i, j = i+1, j-1 {
				r.data.nodes[i], r.data.nodes[j] = r.data.nodes[j], r.data.nodes[i]
			}
		}
	})

	nodes := r.data.nodes
	if len(nodes) > int(r.args.Limit()) {
		if r.args.Last != nil {
			nodes = nodes[1:]
		} else {
			nodes = nodes[:len(nodes)-1]
		}
	}

	return nodes, r.data.nodesError
}

func (r *ConnectionResolver[N]) PageInfo() (*ConnectionPageInfo[N], error) {
	nodes, err := r.Nodes()
	if err != nil {
		return nil, err
	}

	return &ConnectionPageInfo[N]{
		len(r.data.nodes),
		nodes,
		r.store,
		r.args,
	}, nil
}

type ConnectionPageInfo[N ConnectionNode] struct {
	// TODO(naman): rename this
	rawNodesCount int
	nodes         []*N
	store         ConnectionResolverStore[N]
	args          *ConnectionResolverArgs
}

func (p *ConnectionPageInfo[N]) HasNextPage() bool {
	if p.args.Before != nil {
		return true
	}

	return p.rawNodesCount > int(p.args.Limit())
}

func (p *ConnectionPageInfo[N]) HasPreviousPage() bool {
	if p.args.After != nil {
		return true
	}

	if p.args.Before != nil {
		return p.rawNodesCount > int(p.args.Limit())
	}

	return false
}

func (p *ConnectionPageInfo[N]) EndCursor() (cursor *string, err error) {
	if len(p.nodes) == 0 {
		return nil, nil
	}

	endNode := p.nodes[len(p.nodes)-1]

	cursor, err = p.store.MarshalCursor(endNode)

	return
}

func (p *ConnectionPageInfo[N]) StartCursor() (cursor *string, err error) {
	if len(p.nodes) == 0 {
		return nil, nil
	}

	startNode := p.nodes[0]

	cursor, err = p.store.MarshalCursor(startNode)

	return
}

func NewConnectionResolver[N ConnectionNode](store ConnectionResolverStore[N], connectionArgs *ConnectionResolverArgs) *ConnectionResolver[N] {
	return &ConnectionResolver[N]{
		store,
		connectionArgs,
		connectionData[N]{},
		resolveOnce{sync.Once{}, sync.Once{}},
	}
}
