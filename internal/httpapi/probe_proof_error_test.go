package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestProbeProofEndpointReturns400OnIndexOutOfRange verifies that the /proof
// endpoint responds with HTTP 400 when the requested index exceeds the blocks
// length. A valid error message must be present in the response body.
func TestProbeProofEndpointReturns400OnIndexOutOfRange(t *testing.T) {
	srv := httptest.NewServer(New().Handler())
	defer srv.Close()

	body := `{"blocks":["a","b"],"index":5}`
	resp, err := http.Post(srv.URL+"/proof", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("/proof with out-of-range index: status=%d; want 400", resp.StatusCode)
	}

	var result struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if result.Error == "" {
		t.Error("expected non-empty error message in 400 response")
	}
}
