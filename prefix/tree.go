// Package prefix implements a compressed binary Merkle trie, or prefix tree: an
// append-only compressed key-value accumulator based on a sparse binary Merkle
// tree. Keys and values are arbitrary 32-byte strings.
//
// This data structure is sometimes improperly called a "Merkle Patricia Trie",
// despite not implementing the PATRICIA optimization, which elides the actual
// key bits from the intermediate nodes.
//
// It is compatible with the whatsapp_v1 configuration of the akd library, with
// NodeHashingMode::NoLeafEpoch.
//
// This package is NOT STABLE, regardless of the module version, and the API may
// change without notice.
package prefix

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
)

type HashFunc func([]byte) [32]byte

type Node struct {
	Label Label
	// If the node is the root, Left and/or Right may be EmptyNodeLabel.
	// If the node is a leaf or empty, Left and Right are undefined.
	Left, Right Label
	// Hash is Hash(value || Hash(Label.Bytes())) where value is
	//   - the entry value for leaf nodes,
	//   - the hash of the children for internal nodes, or
	//   - EmptyValue for empty nodes.
	Hash [32]byte
}

func (n *Node) String() string {
	var s strings.Builder
	fmt.Fprintf(&s, "Node{%s", n.Label)
	if !n.Label.IsLeaf() && n.Label != EmptyNodeLabel {
		fmt.Fprintf(&s, " l:%s r:%s", n.Left, n.Right)
	}
	fmt.Fprintf(&s, " h:%x}", n.Hash)
	return s.String()
}

func nodeHash(h HashFunc, label Label, value [32]byte) [32]byte {
	l := make([]byte, 0, 4+32)
	l = binary.BigEndian.AppendUint32(l, label.bitLen)
	l = append(l, label.bytes[:]...)
	labelHash := h(l)
	return h(append(value[:], labelHash[:]...))
}

func internalNodeValue(h HashFunc, left, right *Node) [32]byte {
	return h(append(left.Hash[:], right.Hash[:]...))
}

func newRootNode(h HashFunc) *Node {
	return &Node{
		Label: RootLabel,
		Hash:  nodeHash(h, RootLabel, h([]byte{0x00})),
		Left:  EmptyNodeLabel,
		Right: EmptyNodeLabel,
	}
}

func newEmptyNode(h HashFunc) *Node {
	// It's unclear if the nested nodeHash is intentional. If it's not, it might
	// be because the akd_core Configuration method that returns the empty root
	// value is called empty_root_value, while the one that returns the empty
	// sibling value is called empty_node_hash despite both returning values.
	//
	// Anyway, empty_root_value returns H(0x00) while empty_node_hash returns
	// H(EmptyNodeLabel || H(0x00)).
	//
	// This is harmless, so we match it to interoperate with akd.
	hash := nodeHash(h, EmptyNodeLabel, nodeHash(h, EmptyNodeLabel, h([]byte{0x00})))
	return &Node{Label: EmptyNodeLabel, Hash: hash}
}

func newLeaf(h HashFunc, label, value [32]byte) *Node {
	l := Label{256, label}
	return &Node{Label: l, Hash: nodeHash(h, l, value)}
}

// newParentNode returns a new internal (or root) node with the provided
// children, of which at most one may be an empty node.
func newParentNode(h HashFunc, a, b *Node) (*Node, error) {
	label := LongestCommonPrefix(b.Label, a.Label)
	if label.BitLen() == 256 {
		return nil, errors.New("nodes are equal")
	}
	if a.Label == EmptyNodeLabel {
		a, b = b, a
	}
	if a.Label == EmptyNodeLabel {
		return nil, errors.New("both nodes are empty")
	}
	parent := &Node{Label: label}
	switch a.Label.SideOf(label) {
	case Left:
		parent.Left = a.Label
		parent.Right = b.Label
		parent.Hash = nodeHash(h, label, internalNodeValue(h, a, b))
	case Right:
		parent.Left = b.Label
		parent.Right = a.Label
		parent.Hash = nodeHash(h, label, internalNodeValue(h, b, a))
	default:
		return nil, errors.New("internal error: non-empty node is not on either side of prefix")
	}
	return parent, nil
}

type Tree struct {
	s Storage
	h HashFunc
}

func NewTree(h HashFunc, s Storage) *Tree {
	return &Tree{h: h, s: s}
}

func InitStorage(ctx context.Context, h HashFunc, s Storage) error {
	return s.Store(ctx, newEmptyNode(h), newRootNode(h))
}

func (t *Tree) RootHash(ctx context.Context) ([32]byte, error) {
	root, err := t.s.Load(ctx, RootLabel)
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to load root: %w", err)
	}
	return root.Hash, nil
}

type ProofNode struct {
	Label Label
	Hash  [32]byte
}

func (t *Tree) Lookup(ctx context.Context, label [32]byte) ([]ProofNode, error) {
	l := Label{256, label}
	if _, err := t.s.Load(ctx, l); err != nil {
		return nil, fmt.Errorf("failed to load node %s: %w", l, err)
	}
	path, err := loadPath(ctx, t.s, l)
	if err != nil {
		return nil, fmt.Errorf("failed to load path for node %s: %w", l, err)
	}
	proof := make([]ProofNode, 0, len(path))
	for _, sibling := range path {
		proof = append(proof, ProofNode{
			Label: sibling.Label,
			Hash:  sibling.Hash,
		})
	}
	return proof, nil
}

// loadPath loads the siblings of the path to reach the given node
// (intuitively, the inclusion proof). If the node is not present, the
// sequence stops with what would be its sibling if it were present. The
// returned nodes are ordered from the node sibling up to the root's child.
func loadPath(ctx context.Context, s Storage, label Label) ([]*Node, error) {
	// If the Storage has a custom implementation of LoadPath, use it.
	if s, ok := s.(interface {
		LoadPath(context.Context, Label) ([]*Node, error)
	}); ok {
		return s.LoadPath(ctx, label)
	}
	var nodes []*Node
	node, err := s.Load(ctx, RootLabel)
	if err != nil {
		return nil, fmt.Errorf("failed to load root: %w", err)
	}
	for node.Label != label {
		if !label.HasPrefix(node.Label) {
			if node.Label != EmptyNodeLabel {
				nodes = append(nodes, node)
			}
			break
		}
		left, err := s.Load(ctx, node.Left)
		if err != nil {
			return nil, fmt.Errorf("failed to load left node %s: %w", node.Left, err)
		}
		right, err := s.Load(ctx, node.Right)
		if err != nil {
			return nil, fmt.Errorf("failed to load left node %s: %w", node.Right, err)
		}
		switch label.SideOf(node.Label) {
		case Left:
			nodes = append(nodes, right)
			node = left
		case Right:
			nodes = append(nodes, left)
			node = right
		}
	}
	slices.Reverse(nodes)
	return nodes, nil
}

func (t *Tree) Insert(ctx context.Context, label, value [32]byte) error {
	leaf := newLeaf(t.h, label, value)

	path, err := loadPath(ctx, t.s, leaf.Label)
	if err != nil {
		return err
	}

	node := leaf
	var changed []*Node
	changed = append(changed, node)
	for _, sibling := range path {
		node, err = newParentNode(t.h, sibling, node)
		if err != nil {
			return err
		}
		changed = append(changed, node)
	}

	return t.s.Store(ctx, changed...)
}

func VerifyMembershipProof(h HashFunc, label, value [32]byte, proof []ProofNode, root [32]byte) error {
	node := newLeaf(h, label, value)
	for _, sibling := range proof {
		var err error
		node, err = newParentNode(h, node, &Node{
			Label: sibling.Label,
			Hash:  sibling.Hash,
		})
		if err != nil {
			return fmt.Errorf("failed to compute parent node: %w", err)
		}
	}
	if node.Label != RootLabel {
		return fmt.Errorf("proof does not lead to root, got %s", node.Label)
	}
	if node.Hash != root {
		return fmt.Errorf("proof does not match root hash, got %x, want %x", node.Hash, root)
	}
	return nil
}
