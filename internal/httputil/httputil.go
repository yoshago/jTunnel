// Package httputil contains helpers shared by the two HTTP proxy halves.
package httputil

import (
	"net/http"
	"strings"
)

// JoinURLPath combines a target base path with an incoming request path,
// preserving the base path instead of discarding it.
func JoinURLPath(base, requestPath string) string {
	if base == "" {
		return requestPath
	}
	baseSlash := strings.HasSuffix(base, "/")
	pathSlash := strings.HasPrefix(requestPath, "/")
	switch {
	case baseSlash && pathSlash:
		return base + requestPath[1:]
	case !baseSlash && !pathSlash:
		return base + "/" + requestPath
	default:
		return base + requestPath
	}
}

// CopyHeader copies all values from src to dst.
func CopyHeader(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

// RemoveHopByHopHeaders strips connection-specific headers plus any headers
// individually named by a Connection header value.
func RemoveHopByHopHeaders(header http.Header) {
	for _, connection := range header.Values("Connection") {
		for _, name := range strings.Split(connection, ",") {
			header.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Proxy-Connection",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	} {
		header.Del(name)
	}
}
