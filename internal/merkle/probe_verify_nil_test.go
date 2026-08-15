package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// TestProbeVerifyNilStepsSingleLeaf checks that verifying a single-leaf tree
// (empty proof path, root == leaf hash) returns true. The nil vs empty-slice
// distinction in the steps parameter must not affect the outcome.
func TestProbeVerifyNilStepsSingleLeaf(t *testing.T) {
	block := "hello-world"
	h := sha256.Sum256([]byte(block))
	leaf := hex.EncodeToString(h[:])

	// nil steps — should still verify when root equals leaf.
	valid, err := Verify(leaf, nil, leaf)
	if err != nil {
		t.Fatalf("Verify returned error for nil steps: %v", err)
	}
	if !valid {
		t.Fatal("Verify should return true when steps is nil and root equals leaf hash")
	}
}
