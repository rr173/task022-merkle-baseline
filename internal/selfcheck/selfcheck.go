// Package selfcheck 提供无需外部依赖的自检：通过 httptest 启动真实 HTTP
// 服务，覆盖根哈希、证明、验证端点与各边界约束。成功返回 0，任一失败返回 1。
package selfcheck

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"

	"task022-merkle/internal/httpapi"
	"task022-merkle/internal/merkle"
)

// refLeaf 计算 block 的叶子哈希（十六进制）。
func refLeaf(block string) string {
	h := sha256.Sum256([]byte(block))
	return hex.EncodeToString(h[:])
}

// refRoot 用"奇数层复制末尾节点"策略独立计算根哈希作为参照。
func refRoot(blocks []string) string {
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

// Run 执行自检并返回退出码。
func Run() int {
	passed, failed := 0, 0
	check := func(name string, fn func() error) {
		if err := fn(); err != nil {
			failed++
			fmt.Printf("FAIL %-36s %v\n", name, err)
		} else {
			passed++
			fmt.Printf("PASS %s\n", name)
		}
	}

	srv := httptest.NewServer(httpapi.New().Handler())
	defer srv.Close()

	do := func(method, path, body string) (*http.Response, []byte, error) {
		var r io.Reader
		if body != "" {
			r = bytes.NewReader([]byte(body))
		}
		req, err := http.NewRequest(method, srv.URL+path, r)
		if err != nil {
			return nil, nil, err
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, nil, err
		}
		data, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, data, readErr
	}
	marshal := func(m map[string]any) string {
		b, _ := json.Marshal(m)
		return string(b)
	}

	// 根哈希端点。
	root := func(body string) (int, string, int, error) {
		resp, data, err := do(http.MethodPost, "/root", body)
		if err != nil {
			return 0, "", 0, err
		}
		var out struct {
			Root      string `json:"root"`
			LeafCount int    `json:"leaf_count"`
			Error     string `json:"error"`
		}
		_ = json.Unmarshal(data, &out)
		return resp.StatusCode, out.Root, out.LeafCount, nil
	}

	// 证明端点。
	proof := func(body string) (int, *merkle.Proof, string, error) {
		resp, data, err := do(http.MethodPost, "/proof", body)
		if err != nil {
			return 0, nil, "", err
		}
		var out merkle.Proof
		_ = json.Unmarshal(data, &out)
		if out.Steps == nil {
			out.Steps = []merkle.ProofStep{}
		}
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		return resp.StatusCode, &out, e.Error, nil
	}

	// 验证端点。
	verify := func(body string) (int, bool, string, error) {
		resp, data, err := do(http.MethodPost, "/verify", body)
		if err != nil {
			return 0, false, "", err
		}
		var out struct {
			Valid bool   `json:"valid"`
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &out)
		return resp.StatusCode, out.Valid, out.Error, nil
	}

	blocksBody := func(blocks []string) string {
		return marshal(map[string]any{"blocks": blocks})
	}
	proofBody := func(blocks []string, index int) string {
		return marshal(map[string]any{"blocks": blocks, "index": index})
	}
	verifyBody := func(leaf string, steps []merkle.ProofStep, rootHex string) string {
		return marshal(map[string]any{"leaf_hash": leaf, "steps": steps, "root": rootHex})
	}

	// ---- 健康检查 ----
	check("健康检查", func() error {
		resp, _, err := do(http.MethodGet, "/healthz", "")
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("status=%d", resp.StatusCode)
		}
		return nil
	})

	// ---- 根哈希端点 ----
	check("根哈希四叶子匹配参照", func() error {
		blocks := []string{"a", "b", "c", "d"}
		status, rootHex, count, err := root(blocksBody(blocks))
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("status=%d", status)
		}
		if count != 4 {
			return fmt.Errorf("leaf_count=%d want 4", count)
		}
		if rootHex != refRoot(blocks) {
			return fmt.Errorf("root=%q want %q", rootHex, refRoot(blocks))
		}
		return nil
	})

	check("单叶子根等于叶子哈希", func() error {
		status, rootHex, count, err := root(blocksBody([]string{"solo"}))
		if err != nil {
			return err
		}
		if status != http.StatusOK || count != 1 {
			return fmt.Errorf("status=%d count=%d want 200/1", status, count)
		}
		if rootHex != refLeaf("solo") {
			return fmt.Errorf("root=%q want leaf hash %q", rootHex, refLeaf("solo"))
		}
		return nil
	})

	check("奇数复制等价显式复制", func() error {
		status1, r1, _, err := root(blocksBody([]string{"a", "b", "c"}))
		if err != nil {
			return err
		}
		status2, r2, _, err := root(blocksBody([]string{"a", "b", "c", "c"}))
		if err != nil {
			return err
		}
		if status1 != http.StatusOK || status2 != http.StatusOK {
			return fmt.Errorf("status=%d/%d", status1, status2)
		}
		if r1 != r2 {
			return fmt.Errorf("[a,b,c]=%q != [a,b,c,c]=%q", r1, r2)
		}
		return nil
	})

	check("奇数复制区别于零填充", func() error {
		// [a,b,c]（复制 c）必须不同于 [a,b,c,x]。
		_, r1, _, err := root(blocksBody([]string{"a", "b", "c"}))
		if err != nil {
			return err
		}
		_, r2, _, err := root(blocksBody([]string{"a", "b", "c", "x"}))
		if err != nil {
			return err
		}
		if r1 == r2 {
			return fmt.Errorf("dup-last root %q should differ from distinct-4th-leaf root", r1)
		}
		return nil
	})

	check("五叶子根匹配参照", func() error {
		blocks := []string{"a", "b", "c", "d", "e"}
		status, rootHex, count, err := root(blocksBody(blocks))
		if err != nil {
			return err
		}
		if status != http.StatusOK || count != 5 {
			return fmt.Errorf("status=%d count=%d want 200/5", status, count)
		}
		if rootHex != refRoot(blocks) {
			return fmt.Errorf("root=%q want %q", rootHex, refRoot(blocks))
		}
		return nil
	})

	check("空数据块根端点返回400", func() error {
		status, _, _, err := root(blocksBody([]string{}))
		if err != nil {
			return err
		}
		if status != http.StatusBadRequest {
			return fmt.Errorf("status=%d want 400", status)
		}
		return nil
	})

	// ---- 证明端点 ----
	check("证明四叶子索引0", func() error {
		blocks := []string{"a", "b", "c", "d"}
		status, p, errStr, err := proof(proofBody(blocks, 0))
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("status=%d err=%s", status, errStr)
		}
		if p.LeafHash != refLeaf("a") {
			return fmt.Errorf("leaf_hash=%q want %q", p.LeafHash, refLeaf("a"))
		}
		if len(p.Steps) != 2 {
			return fmt.Errorf("steps=%d want 2", len(p.Steps))
		}
		return nil
	})

	check("证明奇数树末位叶子(复制自身)", func() error {
		// 3 叶子，索引 2 的第一步兄弟等于自身叶子哈希。
		status, p, errStr, err := proof(proofBody([]string{"a", "b", "c"}, 2))
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("status=%d err=%s", status, errStr)
		}
		if len(p.Steps) != 2 {
			return fmt.Errorf("steps=%d want 2", len(p.Steps))
		}
		if p.Steps[0].Sibling != p.LeafHash {
			return fmt.Errorf("first sibling should equal leaf (self-dup): %q vs %q", p.Steps[0].Sibling, p.LeafHash)
		}
		if p.Steps[0].Side != "right" {
			return fmt.Errorf("side=%q want right", p.Steps[0].Side)
		}
		return nil
	})

	check("单叶子证明为空", func() error {
		status, p, errStr, err := proof(proofBody([]string{"only"}, 0))
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("status=%d err=%s", status, errStr)
		}
		if len(p.Steps) != 0 {
			return fmt.Errorf("steps=%v want empty", p.Steps)
		}
		if p.Root != p.LeafHash {
			return fmt.Errorf("root=%q should equal leaf=%q", p.Root, p.LeafHash)
		}
		return nil
	})

	check("证明索引越界返回400", func() error {
		status, _, _, err := proof(proofBody([]string{"a", "b"}, 2))
		if err != nil {
			return err
		}
		if status != http.StatusBadRequest {
			return fmt.Errorf("status=%d want 400", status)
		}
		return nil
	})

	check("证明负索引返回400", func() error {
		status, _, _, err := proof(proofBody([]string{"a", "b"}, -1))
		if err != nil {
			return err
		}
		if status != http.StatusBadRequest {
			return fmt.Errorf("status=%d want 400", status)
		}
		return nil
	})

	check("证明空数据块返回400", func() error {
		status, _, _, err := proof(proofBody([]string{}, 0))
		if err != nil {
			return err
		}
		if status != http.StatusBadRequest {
			return fmt.Errorf("status=%d want 400", status)
		}
		return nil
	})

	// ---- 验证端点 ----
	check("验证正确证明成立", func() error {
		_, p, _, err := proof(proofBody([]string{"a", "b", "c", "d"}, 1))
		if err != nil {
			return err
		}
		status, valid, errStr, err := verify(verifyBody(p.LeafHash, p.Steps, p.Root))
		if err != nil {
			return err
		}
		if status != http.StatusOK || !valid {
			return fmt.Errorf("status=%d valid=%v err=%s want 200/true", status, valid, errStr)
		}
		return nil
	})

	check("验证五叶子所有索引成立", func() error {
		blocks := []string{"a", "b", "c", "d", "e"}
		rootHex, _, _ := merkle.Build(blocks)
		for i := range blocks {
			_, p, _, err := proof(proofBody(blocks, i))
			if err != nil {
				return err
			}
			status, valid, errStr, err := verify(verifyBody(p.LeafHash, p.Steps, rootHex))
			if err != nil {
				return err
			}
			if status != http.StatusOK || !valid {
				return fmt.Errorf("index %d: status=%d valid=%v err=%s", i, status, valid, errStr)
			}
		}
		return nil
	})

	check("空证明+根等于叶子成立", func() error {
		leaf := refLeaf("alone")
		status, valid, errStr, err := verify(verifyBody(leaf, []merkle.ProofStep{}, leaf))
		if err != nil {
			return err
		}
		if status != http.StatusOK || !valid {
			return fmt.Errorf("status=%d valid=%v err=%s want 200/true", status, valid, errStr)
		}
		return nil
	})

	check("方向取反验证不成立", func() error {
		_, p, _, err := proof(proofBody([]string{"a", "b"}, 0))
		if err != nil {
			return err
		}
		flipped := make([]merkle.ProofStep, len(p.Steps))
		copy(flipped, p.Steps)
		if flipped[0].Side == "right" {
			flipped[0].Side = "left"
		} else {
			flipped[0].Side = "right"
		}
		status, valid, errStr, err := verify(verifyBody(p.LeafHash, flipped, p.Root))
		if err != nil {
			return err
		}
		if status != http.StatusOK || valid {
			return fmt.Errorf("status=%d valid=%v err=%s want 200/false", status, valid, errStr)
		}
		return nil
	})

	check("篡改叶子哈希验证不成立", func() error {
		_, p, _, err := proof(proofBody([]string{"a", "b", "c", "d"}, 1))
		if err != nil {
			return err
		}
		status, valid, errStr, err := verify(verifyBody(refLeaf("tampered"), p.Steps, p.Root))
		if err != nil {
			return err
		}
		if status != http.StatusOK || valid {
			return fmt.Errorf("status=%d valid=%v err=%s want 200/false", status, valid, errStr)
		}
		return nil
	})

	check("篡改根哈希验证不成立", func() error {
		_, p, _, err := proof(proofBody([]string{"a", "b", "c", "d"}, 1))
		if err != nil {
			return err
		}
		status, valid, errStr, err := verify(verifyBody(p.LeafHash, p.Steps, refLeaf("wrong-root")))
		if err != nil {
			return err
		}
		if status != http.StatusOK || valid {
			return fmt.Errorf("status=%d valid=%v err=%s want 200/false", status, valid, errStr)
		}
		return nil
	})

	check("篡改兄弟哈希验证不成立", func() error {
		_, p, _, err := proof(proofBody([]string{"a", "b", "c", "d"}, 0))
		if err != nil {
			return err
		}
		tampered := make([]merkle.ProofStep, len(p.Steps))
		copy(tampered, p.Steps)
		tampered[0].Sibling = refLeaf("wrong-sibling")
		status, valid, errStr, err := verify(verifyBody(p.LeafHash, tampered, p.Root))
		if err != nil {
			return err
		}
		if status != http.StatusOK || valid {
			return fmt.Errorf("status=%d valid=%v err=%s want 200/false", status, valid, errStr)
		}
		return nil
	})

	check("非法哈希验证返回400", func() error {
		status, _, errStr, err := verify(verifyBody("not-hex", []merkle.ProofStep{}, refLeaf("a")))
		if err != nil {
			return err
		}
		if status != http.StatusBadRequest {
			return fmt.Errorf("status=%d want 400, err=%s", status, errStr)
		}
		return nil
	})

	check("非法方向验证返回400", func() error {
		_, p, _, err := proof(proofBody([]string{"a", "b"}, 0))
		if err != nil {
			return err
		}
		bad := make([]merkle.ProofStep, len(p.Steps))
		copy(bad, p.Steps)
		bad[0].Side = "up"
		status, _, errStr, err := verify(verifyBody(p.LeafHash, bad, p.Root))
		if err != nil {
			return err
		}
		if status != http.StatusBadRequest {
			return fmt.Errorf("status=%d want 400, err=%s", status, errStr)
		}
		return nil
	})

	// ---- 请求格式校验 ----
	check("非法 JSON 被拒(400)", func() error {
		status, _, _, err := root("{not json")
		if err != nil {
			return err
		}
		if status != http.StatusBadRequest {
			return fmt.Errorf("status=%d want 400", status)
		}
		return nil
	})

	check("多段 JSON 被拒(400)", func() error {
		status, _, _, err := root(blocksBody([]string{"a"}) + blocksBody([]string{"b"}))
		if err != nil {
			return err
		}
		if status != http.StatusBadRequest {
			return fmt.Errorf("status=%d want 400", status)
		}
		return nil
	})

	check("未知字段被拒(400)", func() error {
		status, _, _, err := root(marshal(map[string]any{"blocks": []string{"a"}, "extra": 1}))
		if err != nil {
			return err
		}
		if status != http.StatusBadRequest {
			return fmt.Errorf("status=%d want 400", status)
		}
		return nil
	})

	// proof 端点对单叶子树返回的 steps 必须是空数组 [] 而非 null。
	check("证明空 steps 序列化为数组", func() error {
		resp, data, err := do(http.MethodPost, "/proof", proofBody([]string{"only"}, 0))
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("status=%d", resp.StatusCode)
		}
		if !strings.Contains(string(data), `"steps":[]`) {
			return fmt.Errorf("expected \"steps\":[] in response, got: %s", data)
		}
		return nil
	})

	fmt.Printf("\n%d passed, %d failed\n", passed, failed)
	if failed > 0 {
		return 1
	}
	return 0
}
