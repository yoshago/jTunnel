package relayproxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yoshago/jTunnel/internal/muxsession"
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

func TestNewHandlerForwardsRequestAndResponse(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	clientSession, err := muxsession.NewClientSession(clientConn)
	if err != nil {
		t.Fatalf("new client session: %v", err)
	}
	serverSession, err := muxsession.NewServerSession(serverConn)
	if err != nil {
		clientSession.Close()
		t.Fatalf("new server session: %v", err)
	}
	defer clientSession.Close()
	defer serverSession.Close()

	registry := &Registry{}
	registry.SetActive(serverSession)

	serverDone := make(chan error, 1)
	go func() {
		stream, err := clientSession.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer stream.Close()

		request, err := http.ReadRequest(bufio.NewReader(stream))
		if err != nil {
			serverDone <- err
			return
		}
		if request.URL.Path != "/webhook" {
			serverDone <- &unexpectedValueError{field: "path", want: "/webhook", got: request.URL.Path}
			return
		}
		if request.Header.Get("Connection") != "" || request.Header.Get("X-Hop") != "" {
			serverDone <- &unexpectedValueError{field: "hop-by-hop headers", want: "removed", got: request.Header.Get("Connection") + ":" + request.Header.Get("X-Hop")}
			return
		}
		if request.Header.Get("X-Forwarded-Proto") != "http" {
			serverDone <- &unexpectedValueError{field: "forwarded proto", want: "http", got: request.Header.Get("X-Forwarded-Proto")}
			return
		}

		response := &http.Response{
			StatusCode:    http.StatusCreated,
			Status:        "201 Created",
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        make(http.Header),
			Body:          io.NopCloser(strings.NewReader("created")),
			ContentLength: 7,
		}
		response.Header.Set("Connection", "close")
		response.Header.Set("X-Upstream", "yes")
		serverDone <- response.Write(stream)
	}()

	request := httptest.NewRequest(http.MethodGet, "http://relay.local/webhook", nil)
	request.RemoteAddr = "192.0.2.10:1234"
	request.Header.Set("Connection", "X-Hop")
	request.Header.Set("X-Hop", "remove-me")
	recorder := httptest.NewRecorder()
	NewHandler(registry, time.Second).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusCreated || recorder.Body.String() != "created" {
		t.Fatalf("expected 201 created, got %d %q", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Connection") != "" {
		t.Fatalf("response hop-by-hop header was forwarded: %q", recorder.Header().Get("Connection"))
	}
	if recorder.Header().Get("X-Upstream") != "yes" {
		t.Fatalf("expected upstream response header")
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("mock agent: %v", err)
	}
}

type unexpectedValueError struct {
	field string
	want  string
	got   string
}

func (e *unexpectedValueError) Error() string {
	return e.field + ": want " + e.want + ", got " + e.got
}
