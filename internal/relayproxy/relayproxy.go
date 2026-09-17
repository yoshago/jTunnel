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
	"net/http"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

// Registry tracks the single active agent session for this MVP.
type Registry struct {
	mu     sync.Mutex
	active *yamux.Session
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

		if err := r.Write(stream); err != nil {
			http.Error(w, fmt.Sprintf("forward request: %v", err), http.StatusBadGateway)
			return
		}

		resp, err := http.ReadResponse(bufio.NewReader(stream), r)
		if err != nil {
			http.Error(w, fmt.Sprintf("read agent response: %v", err), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		copyHeader(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		if _, err := io.Copy(w, resp.Body); err != nil {
			// Status/headers are already flushed at this point; nothing left to do but log.
			log.Printf("relayproxy: copy response body: %v", err)
		}
	})
}

func copyHeader(dst, src http.Header) {
	for key, values := range src {
		for _, v := range values {
			dst.Add(key, v)
		}
	}
}
