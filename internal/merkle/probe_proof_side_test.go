package merkle

import "testing"

// TestProbeProofSideDirectionCorrectness verifies the side field semantics in
// a generated proof. For a 4-leaf tree [a,b,c,d], the proof for index 0 must
// have its first step side == "right" (the sibling is to the right), and the
// proof for index 1 must have its first step side == "left".
func TestProbeProofSideDirectionCorrectness(t *testing.T) {
	blocks := []string{"a", "b", "c", "d"}

	// Index 0 is at an even position; its sibling (index 1) is to the right.
	p0, err := MakeProof(blocks, 0)
	if err != nil {
		t.Fatalf("MakeProof(blocks, 0): %v", err)
	}
	if len(p0.Steps) == 0 {
		t.Fatal("expected non-empty proof steps for 4-leaf tree index 0")
	}
	if p0.Steps[0].Side != SideRight {
		t.Errorf("proof index 0, step 0: side=%q; want %q", p0.Steps[0].Side, SideRight)
	}

	// Index 1 is at an odd position; its sibling (index 0) is to the left.
	p1, err := MakeProof(blocks, 1)
	if err != nil {
		t.Fatalf("MakeProof(blocks, 1): %v", err)
	}
	if len(p1.Steps) == 0 {
		t.Fatal("expected non-empty proof steps for 4-leaf tree index 1")
	}
	if p1.Steps[0].Side != SideLeft {
		t.Errorf("proof index 1, step 0: side=%q; want %q", p1.Steps[0].Side, SideLeft)
	}
}
