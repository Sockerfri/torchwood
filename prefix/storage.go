package prefix

import (
	"context"
	"errors"
)

type Storage interface {
	// Load retrieves the node with the given label.
	Load(ctx context.Context, label Label) (*Node, error)

	// Store stores the given nodes. If a node with the same label already
	// exists, it is replaced. The nodes can be in any order.
	Store(ctx context.Context, nodes ...*Node) error
}

type memoryStorage struct {
	nodes map[Label]*Node
}

func NewMemoryStorage() Storage {
	return &memoryStorage{
		nodes: make(map[Label]*Node),
	}
}

var ErrNodeNotFound = errors.New("node not found")

func (s *memoryStorage) Load(ctx context.Context, label Label) (*Node, error) {
	if node, ok := s.nodes[label]; ok {
		return node, nil
	}
	return nil, ErrNodeNotFound
}

func (s *memoryStorage) Store(ctx context.Context, nodes ...*Node) error {
	for _, node := range nodes {
		s.nodes[node.Label] = node
	}
	return nil
}
