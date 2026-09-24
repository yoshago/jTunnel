package relayproxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewHandlerWithoutAgentReturnsBadGateway(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://relay.local/webhook", nil)
	recorder := httptest.NewRecorder()

	NewHandler(&Registry{}, time.Second).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("expected status %d, got %d", http.StatusBadGateway, recorder.Code)
	}
	if recorder.Body.String() != "no agent connected\n" {
		t.Fatalf("unexpected response body %q", recorder.Body.String())
	}
}
