package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// TestProbeProofLeafHashMatchesRequestedIndex verifies that MakeProof returns
// the leaf hash corresponding to the requested block index, not the first block.
func TestProbeProofLeafHashMatchesRequestedIndex(t *testing.T) {
	blocks := []string{"alpha", "beta", "gamma", "delta"}
	for idx := 1; idx < len(blocks); idx++ {
		p, err := MakeProof(blocks, idx)
		if err != nil {
			t.Fatalf("MakeProof(blocks, %d): %v", idx, err)
		}
		expected := sha256.Sum256([]byte(blocks[idx]))
		want := hex.EncodeToString(expected[:])
		if p.LeafHash != want {
			t.Errorf("MakeProof(blocks, %d).LeafHash = %q; want %q (hash of %q)",
				idx, p.LeafHash, want, blocks[idx])
		}
	}
}
