package reqip

import (
	"net/http"
	"testing"
)

func TestSource_UntrustedPeerIgnoresHeaders(t *testing.T) {
	r := &http.Request{RemoteAddr: "198.51.100.7:54321", Header: http.Header{}}
	r.Header.Set("X-Forwarded-For", "203.0.113.9")

	if got := Source(r); got != "198.51.100.7" {
		t.Errorf("Source() = %q, want %q (headers from a non-loopback peer must be ignored)", got, "198.51.100.7")
	}
}

func TestSource_TrustedPeerUsesXRealIP(t *testing.T) {
	r := &http.Request{RemoteAddr: "127.0.0.1:54321", Header: http.Header{}}
	r.Header.Set("X-Real-IP", "203.0.113.9")

	if got := Source(r); got != "203.0.113.9" {
		t.Errorf("Source() = %q, want %q", got, "203.0.113.9")
	}
}

func TestSource_TrustedPeerUsesFirstXForwardedFor(t *testing.T) {
	r := &http.Request{RemoteAddr: "127.0.0.1:54321", Header: http.Header{}}
	r.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.1")

	if got := Source(r); got != "203.0.113.9" {
		t.Errorf("Source() = %q, want %q", got, "203.0.113.9")
	}
}

func TestSource_TrustedPeerNoHeadersFallsBackToLoopback(t *testing.T) {
	r := &http.Request{RemoteAddr: "127.0.0.1:54321", Header: http.Header{}}
	if got := Source(r); got != "127.0.0.1" {
		t.Errorf("Source() = %q, want %q", got, "127.0.0.1")
	}
}

func TestSource_NoPortInRemoteAddr(t *testing.T) {
	r := &http.Request{RemoteAddr: "198.51.100.7", Header: http.Header{}}
	if got := Source(r); got != "198.51.100.7" {
		t.Errorf("Source() = %q, want %q", got, "198.51.100.7")
	}
}
