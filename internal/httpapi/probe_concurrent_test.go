package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// TestProbeConcurrentRequestsSafe verifies that the API can handle many
// concurrent requests without panicking or corrupting internal state.
// All goroutines hit the /root endpoint simultaneously.
func TestProbeConcurrentRequestsSafe(t *testing.T) {
	srv := httptest.NewServer(New().Handler())
	defer srv.Close()

	const workers = 100
	const iterations = 50
	body := `{"blocks":["x","y","z"]}`

	var wg sync.WaitGroup
	wg.Add(workers)
	errCh := make(chan error, workers*iterations)

	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				resp, err := http.Post(srv.URL+"/root", "application/json", strings.NewReader(body))
				if err != nil {
					errCh <- err
					return
				}
				resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Errorf("unexpected status %d", resp.StatusCode)
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("request error: %v", err)
	}
}
