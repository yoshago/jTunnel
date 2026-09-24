package agentproxy

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleStreamForwardsRequest(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/base/webhook" {
			t.Errorf("expected forwarded path /base/webhook, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan struct{})
	go func() {
		HandleStream(serverConn, target.URL+"/base", http.DefaultClient)
		close(done)
	}()

	req, err := http.NewRequest(http.MethodGet, "http://relay.local/webhook", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if err := req.Write(clientConn); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(clientConn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("expected 200 ok, got %d %q", resp.StatusCode, body)
	}
	<-done
}

func TestHandleStreamReturnsBadGatewayWhenTargetFails(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan struct{})
	go func() {
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("target unavailable")
		})}
		HandleStream(serverConn, "http://target.invalid", client)
		close(done)
	}()

	req, err := http.NewRequest(http.MethodGet, "http://relay.local/webhook", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if err := req.Write(clientConn); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(clientConn), req)
	if err != nil {
		t.Fatalf("read error response: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read error body: %v", err)
	}
	if resp.StatusCode != http.StatusBadGateway || string(body) != http.StatusText(http.StatusBadGateway) {
		t.Fatalf("expected 502 Bad Gateway, got %d %q", resp.StatusCode, body)
	}
	<-done
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}