// Package agentproxy implements the Agent's local forwarder: it reads an
// HTTP request that arrived over a Yamux stream from the Relay, forwards it
// to a local target (e.g. a local n8n instance), and writes the target's
// HTTP response back onto the stream.
package agentproxy

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/yoshago/jTunnel/internal/httputil"
)

// HandleStream reads one HTTP request from stream, forwards it to target
// (a base URL such as "http://127.0.0.1:5678") using client, and writes the
// target's HTTP response back to stream. It closes stream before returning.
func HandleStream(stream net.Conn, target string, client *http.Client) {
	defer stream.Close()

	req, err := http.ReadRequest(bufio.NewReader(stream))
	if err != nil {
		log.Printf("agentproxy: read request: %v", err)
		return
	}

	log.Printf("Received request: %s %s", req.Method, req.URL)

	targetURL, err := url.Parse(target)
	if err != nil {
		log.Printf("agentproxy: parse target %q: %v", target, err)
		return
	}

	// req, as parsed off the wire, is in server form (URL has only
	// path/query, no scheme/host). Rewrite it into client form so it can be
	// forwarded with http.Client, which also forbids RequestURI being set.
	req.URL.Scheme = targetURL.Scheme
	req.URL.Host = targetURL.Host
	req.URL.Path = httputil.JoinURLPath(targetURL.Path, req.URL.Path)
	req.Host = targetURL.Host
	req.RequestURI = ""

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("agentproxy: forward to local target: %v", err)
		writeErrorResponse(stream, req)
		return
	}
	defer resp.Body.Close()

	if err := resp.Write(stream); err != nil {
		log.Printf("agentproxy: write response: %v", err)
	}
}

// writeErrorResponse best-effort reports a local forwarding failure back to
// the Relay as a 502 so the public client gets a response instead of a hang.
// The body is a fixed generic message; the real error is only logged locally.
func writeErrorResponse(stream net.Conn, req *http.Request) {
	resp := &http.Response{
		StatusCode: http.StatusBadGateway,
		Status:     fmt.Sprintf("%d %s", http.StatusBadGateway, http.StatusText(http.StatusBadGateway)), Proto: "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Request:    req,
		Header:     make(http.Header),
	}
	body := http.StatusText(http.StatusBadGateway)
	resp.Body = io.NopCloser(strings.NewReader(body))
	resp.ContentLength = int64(len(body))
	if err := resp.Write(stream); err != nil {
		log.Printf("agentproxy: write error response: %v", err)
	}
}
