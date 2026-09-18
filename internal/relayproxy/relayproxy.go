// Package relayproxy implements the Relay's public-facing L7 HTTP proxy: it
// takes an incoming public HTTP request, forwards it to the connected Agent
// over a fresh Yamux stream, and relays the Agent's HTTP response back to
// the public client.
package relayproxy

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/yoshago/jTunnel/internal/httputil"
)

// Registry tracks the single active agent session for this MVP.
type Registry struct {
	mu     sync.Mutex
	active *yamux.Session
}

type deadlineRefreshingReader struct {
	reader  io.Reader
	stream  interface{ SetDeadline(time.Time) error }
	timeout time.Duration
}

func (r *deadlineRefreshingReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		if deadlineErr := r.stream.SetDeadline(time.Now().Add(r.timeout)); err == nil {
			err = deadlineErr
		}
	}
	return n, err
}

// SetActive installs session as the active one and returns any previous
// session that was replaced, so the caller can close it.
func (r *Registry) SetActive(session *yamux.Session) (previous *yamux.Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	previous = r.active
	r.active = session
	return previous
}

// Clear removes session from the registry, but only if it's still the
// active one (a stale, already-replaced session disconnecting shouldn't
// wipe out a newer one).
func (r *Registry) Clear(session *yamux.Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active == session {
		r.active = nil
	}
}

// IsActive reports whether any agent is currently connected.
func (r *Registry) IsActive() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.active != nil
}

// Active returns the currently connected agent's session, or nil if none.
func (r *Registry) Active() *yamux.Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.active
}

// NewHandler returns an http.Handler that forwards each incoming public HTTP
// request to the currently connected agent over a fresh Yamux stream
// (serialized with req.Write), and copies the agent's HTTP response
// (parsed with http.ReadResponse) back to the public client.
func NewHandler(registry *Registry, timeout time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session := registry.Active()
		if session == nil {
			http.Error(w, "no agent connected", http.StatusBadGateway)
			return
		}

		stream, err := session.Open()
		if err != nil {
			http.Error(w, fmt.Sprintf("open tunnel stream: %v", err), http.StatusBadGateway)
			return
		}
		defer stream.Close()

		if timeout > 0 {
			if err := stream.SetDeadline(time.Now().Add(timeout)); err != nil {
				http.Error(w, fmt.Sprintf("set stream deadline: %v", err), http.StatusBadGateway)
				return
			}
		}

		// Write a header-only copy so hop-by-hop headers and framing (Close)
		// don't leak from the public client's connection onto this hop.
		outReq := r.Clone(r.Context())
		outReq.Close = false
		httputil.RemoveHopByHopHeaders(outReq.Header)
		setForwardingHeaders(outReq, r)

		if err := outReq.Write(stream); err != nil {
			http.Error(w, fmt.Sprintf("forward request: %v", err), http.StatusBadGateway)
			return
		}

		resp, err := http.ReadResponse(bufio.NewReader(stream), r)
		if err != nil {
			http.Error(w, fmt.Sprintf("read agent response: %v", err), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		// Give body streaming an idle timeout that is refreshed after each
		// successful read, so continuously active responses can run indefinitely.
		if timeout > 0 {
			if err := stream.SetDeadline(time.Now().Add(timeout)); err != nil {
				http.Error(w, fmt.Sprintf("reset stream deadline: %v", err), http.StatusBadGateway)
				return
			}
		}

		httputil.RemoveHopByHopHeaders(resp.Header)
		httputil.CopyHeader(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		body := io.Reader(resp.Body)
		if timeout > 0 {
			body = &deadlineRefreshingReader{reader: resp.Body, stream: stream, timeout: timeout}
		}
		if _, err := io.Copy(w, body); err != nil {
			// Status/headers are already flushed at this point; nothing left to do but log.
			log.Printf("relayproxy: copy response body: %v", err)
		}
	})
}

func setForwardingHeaders(outReq, incoming *http.Request) {
	for key := range outReq.Header {
		if strings.EqualFold(key, "Forwarded") || strings.EqualFold(key, "X-Forwarded-For") ||
			strings.EqualFold(key, "X-Forwarded-Host") || strings.EqualFold(key, "X-Forwarded-Proto") ||
			strings.HasPrefix(strings.ToLower(key), "x-forwarded-") {
			delete(outReq.Header, key)
		}
	}

	clientIP := incoming.RemoteAddr
	if host, _, err := net.SplitHostPort(incoming.RemoteAddr); err == nil {
		clientIP = host
	}
	proto := "http"
	if incoming.TLS != nil {
		proto = "https"
	}

	outReq.Header.Set("Forwarded", fmt.Sprintf("for=%s;host=%s;proto=%s", clientIP, incoming.Host, proto))
	outReq.Header.Set("X-Forwarded-For", clientIP)
	outReq.Header.Set("X-Forwarded-Host", incoming.Host)
	outReq.Header.Set("X-Forwarded-Proto", proto)
}
