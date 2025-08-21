//go:build go1.24

package prefix_test

import (
	"encoding/binary"
	"encoding/hex"
	"math/rand/v2"
	"runtime"
	"testing"

	"lukechampine.com/blake3"

	. "filippo.io/torchwood/prefix"
	"filippo.io/torchwood/prefix/prefixsqlite"
)

func testAllStorage(t *testing.T, f func(t *testing.T, newStorage func(t *testing.T) Storage)) {
	t.Run("memory", func(t *testing.T) {
		f(t, func(t *testing.T) Storage {
			return NewMemoryStorage()
		})
	})

	t.Run("sqlite", func(t *testing.T) {
		f(t, func(t *testing.T) Storage {
			store, err := prefixsqlite.NewSQLiteStorage(t.Context(), "file::memory:?cache=shared")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { fatalIfErr(t, store.Close()) })
			return store
		})
	})
}

func TestFullTree(t *testing.T) {
	testAllStorage(t, testFullTree)
}
func testFullTree(t *testing.T, newStorage func(t *testing.T) Storage) {
	store := newStorage(t)
	fatalIfErr(t, InitStorage(t.Context(), blake3.Sum256, store))
	tree := NewTree(blake3.Sum256, store)

	for n := range 1000 {
		var label [32]byte
		binary.LittleEndian.PutUint16(label[:], uint16(n))
		value := blake3.Sum256(label[:])
		fatalIfErr(t, tree.Insert(t.Context(), label, value))
	}

	rootHash, err := tree.RootHash(t.Context())
	fatalIfErr(t, err)

	store = newStorage(t)
	fatalIfErr(t, InitStorage(t.Context(), blake3.Sum256, store))
	tree = NewTree(blake3.Sum256, store)

	for n := 999; n >= 0; n-- {
		var label [32]byte
		binary.LittleEndian.PutUint16(label[:], uint16(n))
		value := blake3.Sum256(label[:])
		fatalIfErr(t, tree.Insert(t.Context(), label, value))
	}

	rootHash1, err := tree.RootHash(t.Context())
	fatalIfErr(t, err)
	if rootHash1 != rootHash {
		t.Fatalf("after inserting in reverse order: got %x, want %x", rootHash1, rootHash)
	}

	store = newStorage(t)
	fatalIfErr(t, InitStorage(t.Context(), blake3.Sum256, store))
	tree = NewTree(blake3.Sum256, store)

	for _, n := range rand.Perm(1000) {
		var label [32]byte
		binary.LittleEndian.PutUint16(label[:], uint16(n))
		value := blake3.Sum256(label[:])
		fatalIfErr(t, tree.Insert(t.Context(), label, value))
	}

	rootHash1, err = tree.RootHash(t.Context())
	fatalIfErr(t, err)
	if rootHash1 != rootHash {
		t.Fatalf("after inserting in random order: got %x, want %x", rootHash1, rootHash)
	}
}

func TestAccumulated(t *testing.T) {
	testAllStorage(t, testAccumulated)
}
func testAccumulated(t *testing.T, newStorage func(t *testing.T) Storage) {
	if _, ok := newStorage(t).(*prefixsqlite.Storage); ok && testing.Short() {
		t.Skip("skipping accumulated test for sqlite storage in short mode")
	}

	source := blake3.New(0, nil).XOF()
	sink := blake3.New(32, nil)

	for range 100 {
		store := newStorage(t)
		fatalIfErr(t, InitStorage(t.Context(), blake3.Sum256, store))
		tree := NewTree(blake3.Sum256, store)
		rootHash, err := tree.RootHash(t.Context())
		fatalIfErr(t, err)
		sink.Write(rootHash[:])
		for range 1000 {
			var label, value [32]byte
			source.Read(label[:])
			source.Read(value[:])
			fatalIfErr(t, tree.Insert(t.Context(), label, value))
			rootHash, err := tree.RootHash(t.Context())
			fatalIfErr(t, err)
			sink.Write(rootHash[:])
		}
	}

	exp := "dfa5cc5758518f612c53d3434688996895373f29e2df61b7f7c26f0e25b095eb"
	result := sink.Sum(nil)
	if hex.EncodeToString(result) != exp {
		t.Fatalf("expected hash %s, got %x", exp, result)
	}
}

func TestMemoryUsage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping memory usage test in short mode")
	}

	store := NewMemoryStorage()
	fatalIfErr(t, InitStorage(t.Context(), blake3.Sum256, store))
	tree := NewTree(blake3.Sum256, store)

	runtime.GC()
	var start runtime.MemStats
	runtime.ReadMemStats(&start)

	source := blake3.New(0, nil).XOF()
	for n := range 1000000 {
		var label, value [32]byte
		source.Read(label[:])
		source.Read(value[:])
		fatalIfErr(t, tree.Insert(t.Context(), label, value))

		switch n + 1 {
		case 1000, 10000, 100000, 1000000:
			runtime.GC()
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			t.Logf("Memory usage after inserting % 8d nodes: % 10d bytes", n+1, int64(m.Alloc)-int64(start.Alloc))
		}
	}
}

func TestMembershipProof(t *testing.T) {
	testAllStorage(t, testMembershipProof)
}
func testMembershipProof(t *testing.T, newStorage func(t *testing.T) Storage) {
	store := newStorage(t)
	fatalIfErr(t, InitStorage(t.Context(), blake3.Sum256, store))
	tree := NewTree(blake3.Sum256, store)

	inserted := make(map[[32]byte]bool)
	check := func(i int) {
		rootHash, err := tree.RootHash(t.Context())
		fatalIfErr(t, err)

		for n := range 100 {
			var label [32]byte
			binary.LittleEndian.PutUint16(label[:], uint16(n))
			value := blake3.Sum256(label[:])

			present, proof, err := tree.Lookup(t.Context(), label)
			fatalIfErr(t, err)
			if inserted[label] {
				if !present {
					t.Fatalf("label %x not found in tree after insertion", label)
				}
				if err := VerifyMembershipProof(blake3.Sum256, label, value, proof, rootHash); err != nil {
					t.Fatalf("membership proof for %x with %d entries failed: %v", label, i, err)
				}
				if err := VerifyNonMembershipProof(blake3.Sum256, label, proof, rootHash); err == nil {
					t.Fatalf("non-membership proof for %x with %d entries should have failed", label, i)
				}
			} else {
				if present {
					t.Fatalf("label %x found in tree after insertion, but it should not be", label)
				}
				if err := VerifyNonMembershipProof(blake3.Sum256, label, proof, rootHash); err != nil {
					t.Fatalf("non-membership proof for %x with %d entries failed: %v", label, i, err)
				}
				if err := VerifyMembershipProof(blake3.Sum256, label, value, proof, rootHash); err == nil {
					t.Fatalf("membership proof for %x with %d entries should have failed", label, i)
				}
			}
		}
	}

	// Run the check on the emtpy tree.
	check(0)

	for i, n := range rand.Perm(100) {
		var label [32]byte
		binary.LittleEndian.PutUint16(label[:], uint16(n))
		value := blake3.Sum256(label[:])
		fatalIfErr(t, tree.Insert(t.Context(), label, value))
		inserted[label] = true
		check(i + 1)
	}
}

func fatalIfErr(t *testing.T, err error) {
	if err != nil {
		t.Helper()
		t.Fatal(err)
	}
}
