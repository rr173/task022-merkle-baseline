package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// refLeaf 计算 block 的叶子哈希（十六进制），与实现保持一致。
func refLeaf(block string) string {
	h := sha256.Sum256([]byte(block))
	return hex.EncodeToString(h[:])
}

// refRoot 用与实现相同的"奇数层复制末尾节点"策略计算根哈希（十六进制），
// 作为测试的独立参照（内部用原始字节拼接）。
func refRoot(blocks []string) string {
	if len(blocks) == 0 {
		return ""
	}
	level := make([][32]byte, len(blocks))
	for i, b := range blocks {
		level[i] = sha256.Sum256([]byte(b))
	}
	for len(level) > 1 {
		if len(level)%2 == 1 {
			level = append(level, level[len(level)-1])
		}
		nxt := make([][32]byte, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			var buf [64]byte
			copy(buf[:32], level[i][:])
			copy(buf[32:], level[i+1][:])
			nxt[i/2] = sha256.Sum256(buf[:])
		}
		level = nxt
	}
	return hex.EncodeToString(level[0][:])
}

func TestBuildEmpty(t *testing.T) {
	root, count, err := Build(nil)
	if !errors.Is(err, ErrEmptyBlocks) {
		t.Fatalf("empty blocks should error, got root=%q count=%d err=%v", root, count, err)
	}
}

func TestBuildSingleLeafRootEqualsLeafHash(t *testing.T) {
	block := "only-one"
	root, count, err := Build([]string{block})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 1 {
		t.Errorf("leaf_count=%d want 1", count)
	}
	if root != refLeaf(block) {
		t.Errorf("single-leaf root should equal leaf hash, got %q want %q", root, refLeaf(block))
	}
}

func TestBuildFourLeavesMatchesReference(t *testing.T) {
	blocks := []string{"a", "b", "c", "d"}
	root, count, err := Build(blocks)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 4 {
		t.Errorf("leaf_count=%d want 4", count)
	}
	if root != refRoot(blocks) {
		t.Errorf("root mismatch: got %q want %q", root, refRoot(blocks))
	}
}

func TestBuildOddDuplicationEquivalentToExplicitDup(t *testing.T) {
	// 3 个块 [a,b,c] 的根必须等于把 c 复制为第 4 个叶子 [a,b,c,c] 的根。
	abc, _, err := Build([]string{"a", "b", "c"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	abcc, _, err := Build([]string{"a", "b", "c", "c"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if abc != abcc {
		t.Errorf("dup-last equivalence: [a,b,c]=%q != [a,b,c,c]=%q", abc, abcc)
	}
}

func TestBuildOddDiffersFromZeroPadding(t *testing.T) {
	// [a,b,c]（复制 c）必须不同于把第 4 个叶子替换成另一个块 [a,b,c,x]。
	abc, _, _ := Build([]string{"a", "b", "c"})
	abcx, _, _ := Build([]string{"a", "b", "c", "x"})
	if abc == abcx {
		t.Error("dup-last root should differ from a distinct 4th leaf")
	}
}

func TestBuildFiveLeavesMatchesReference(t *testing.T) {
	// 5 个块：叶子层与内部层都出现奇数复制，逐层验证。
	blocks := []string{"a", "b", "c", "d", "e"}
	root, count, err := Build(blocks)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 5 {
		t.Errorf("leaf_count=%d want 5", count)
	}
	if root != refRoot(blocks) {
		t.Errorf("root mismatch: got %q want %q", root, refRoot(blocks))
	}
}

func TestMakeProofSingleLeafEmptySteps(t *testing.T) {
	p, err := MakeProof([]string{"solo"}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.Steps) != 0 {
		t.Errorf("single-leaf proof should be empty, got %v", p.Steps)
	}
	if p.LeafHash != refLeaf("solo") {
		t.Errorf("leaf_hash mismatch: got %q want %q", p.LeafHash, refLeaf("solo"))
	}
	if p.Root != p.LeafHash {
		t.Errorf("single-leaf root should equal leaf hash: root=%q leaf=%q", p.Root, p.LeafHash)
	}
}

func TestMakeProofEmptyBlocks(t *testing.T) {
	if _, err := MakeProof(nil, 0); !errors.Is(err, ErrEmptyBlocks) {
		t.Fatalf("empty blocks should error, got %v", err)
	}
}

func TestMakeProofIndexOutOfRange(t *testing.T) {
	if _, err := MakeProof([]string{"a", "b"}, 2); !errors.Is(err, ErrIndexOutOfRange) {
		t.Fatalf("index 2 should be out of range, got %v", err)
	}
}

func TestMakeProofNegativeIndex(t *testing.T) {
	if _, err := MakeProof([]string{"a", "b"}, -1); !errors.Is(err, ErrIndexOutOfRange) {
		t.Fatalf("index -1 should be out of range, got %v", err)
	}
}

func TestMakeProofLastLeafInOddTree(t *testing.T) {
	// 3 个块，最后一个叶子的兄弟是自身（复制）。
	p, err := MakeProof([]string{"a", "b", "c"}, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.Steps) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(p.Steps))
	}
	// 第一步的兄弟必须等于该叶子的哈希（复制自身）。
	if p.Steps[0].Sibling != p.LeafHash {
		t.Errorf("first sibling should equal leaf hash (self-dup): %q vs %q", p.Steps[0].Sibling, p.LeafHash)
	}
	if p.Steps[0].Side != SideRight {
		t.Errorf("first side=%q want right", p.Steps[0].Side)
	}
}

func TestVerifyValid(t *testing.T) {
	blocks := []string{"a", "b", "c", "d"}
	p, err := MakeProof(blocks, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	valid, err := Verify(p.LeafHash, p.Steps, p.Root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !valid {
		t.Error("valid proof should verify")
	}
}

func TestVerifyAllIndicesOddTree(t *testing.T) {
	blocks := []string{"a", "b", "c", "d", "e"}
	root, _, err := Build(blocks)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for i := range blocks {
		p, err := MakeProof(blocks, i)
		if err != nil {
			t.Fatalf("index %d: %v", i, err)
		}
		valid, err := Verify(p.LeafHash, p.Steps, p.Root)
		if err != nil {
			t.Fatalf("index %d verify error: %v", i, err)
		}
		if !valid {
			t.Errorf("index %d should verify", i)
		}
		if p.Root != root {
			t.Errorf("index %d root mismatch", i)
		}
	}
}

func TestVerifyEmptyStepsRootEqualsLeaf(t *testing.T) {
	leaf := refLeaf("alone")
	valid, err := Verify(leaf, nil, leaf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !valid {
		t.Error("empty proof + root==leaf should verify")
	}
}

func TestVerifyEmptyStepsRootDiffers(t *testing.T) {
	leaf := refLeaf("alone")
	other := refLeaf("other")
	valid, err := Verify(leaf, nil, other)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid {
		t.Error("empty proof + root!=leaf should not verify")
	}
}

func TestVerifySideSensitive(t *testing.T) {
	// 2 叶子树：翻转唯一一步的方向必须导致验证失败。
	p, err := MakeProof([]string{"a", "b"}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	flipped := make([]ProofStep, len(p.Steps))
	copy(flipped, p.Steps)
	if flipped[0].Side == SideRight {
		flipped[0].Side = SideLeft
	} else {
		flipped[0].Side = SideRight
	}
	valid, err := Verify(p.LeafHash, flipped, p.Root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid {
		t.Error("flipped side should not verify")
	}
}

func TestVerifyTamperedLeaf(t *testing.T) {
	p, _ := MakeProof([]string{"a", "b", "c", "d"}, 1)
	valid, err := Verify(refLeaf("tampered"), p.Steps, p.Root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid {
		t.Error("tampered leaf should not verify")
	}
}

func TestVerifyTamperedRoot(t *testing.T) {
	p, _ := MakeProof([]string{"a", "b", "c", "d"}, 1)
	valid, err := Verify(p.LeafHash, p.Steps, refLeaf("wrong-root"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid {
		t.Error("tampered root should not verify")
	}
}

func TestVerifyTamperedSibling(t *testing.T) {
	p, _ := MakeProof([]string{"a", "b", "c", "d"}, 0)
	tampered := make([]ProofStep, len(p.Steps))
	copy(tampered, p.Steps)
	tampered[0].Sibling = refLeaf("wrong-sibling")
	valid, err := Verify(p.LeafHash, tampered, p.Root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid {
		t.Error("tampered sibling should not verify")
	}
}

func TestVerifyBadHex(t *testing.T) {
	if _, err := Verify("not-hex", nil, refLeaf("a")); err == nil {
		t.Error("non-hex leaf hash should error")
	}
	if _, err := Verify(refLeaf("a"), nil, "tooshort"); err == nil {
		t.Error("non-hex root should error")
	}
}

func TestVerifyBadSide(t *testing.T) {
	p, _ := MakeProof([]string{"a", "b"}, 0)
	bad := make([]ProofStep, len(p.Steps))
	copy(bad, p.Steps)
	bad[0].Side = "up"
	if _, err := Verify(p.LeafHash, bad, p.Root); err == nil {
		t.Error("invalid side should error")
	} else if !strings.Contains(err.Error(), "方向") {
		t.Errorf("error should mention direction, got %v", err)
	}
}
