package httputil

import (
	"net/http"
	"testing"
)

func TestJoinURLPath(t *testing.T) {
	tests := []struct {
		name, base, request, want string
	}{
		{"empty base", "", "/webhook", "/webhook"},
		{"both slash", "/base/", "/webhook", "/base/webhook"},
		{"neither slash", "/base", "webhook", "/base/webhook"},
		{"base slash only", "/base/", "webhook", "/base/webhook"},
		{"request slash only", "/base", "/webhook", "/base/webhook"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := JoinURLPath(test.base, test.request); got != test.want {
				t.Fatalf("JoinURLPath(%q, %q) = %q, want %q", test.base, test.request, got, test.want)
			}
		})
	}
}

func TestCopyHeader(t *testing.T) {
	dst := make(http.Header)
	src := http.Header{"X-Test": {"one", "two"}}

	CopyHeader(dst, src)
	if got := dst.Values("X-Test"); len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Fatalf("unexpected copied values: %v", got)
	}
}

func TestRemoveHopByHopHeaders(t *testing.T) {
	header := make(http.Header)
	header.Set("Connection", "X-Custom")
	header.Set("X-Custom", "remove")
	header.Set("Keep-Alive", "remove")
	header.Set("X-EndToEnd", "keep")
	header.Set("Transfer-Encoding", "remove")
	header.Set("Proxy-Authorization", "remove")

	RemoveHopByHopHeaders(header)
	for _, name := range []string{"Connection", "X-Custom", "Keep-Alive", "Transfer-Encoding", "Proxy-Authorization"} {
		if header.Get(name) != "" {
			t.Fatalf("expected %s to be removed", name)
		}
	}
	if header.Get("X-EndToEnd") != "keep" {
		t.Fatalf("expected end-to-end header to remain")
	}
}
