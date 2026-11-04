package publicip

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestPublicIPv4(t *testing.T) {
	for _, s := range []string{"8.8.8.8", "1.1.1.1"} {
		if !IsPublic(netip.MustParseAddr(s)) {
			t.Errorf("rejected %s", s)
		}
	}
	for _, s := range []string{"0.0.0.0", "10.1.1.1", "172.16.0.1", "192.168.1.1", "100.64.1.1", "127.0.0.1", "169.254.1.1", "192.0.2.1", "198.18.1.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "255.255.255.255", "::1", "2001:4860:4860::8888", "::ffff:8.8.8.8"} {
		if IsPublic(netip.MustParseAddr(s)) {
			t.Errorf("accepted %s", s)
		}
	}
}

func TestDetectionFallbackProxyAndLimits(t *testing.T) {
	proxyCalls := 0
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxyCalls++; http.Error(w, "proxy", 500) }))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/invalid":
			fmt.Fprint(w, "10.0.0.1")
		case "/large":
			fmt.Fprint(w, strings.Repeat(" ", 1025)+"8.8.8.8")
		case "/redirect":
			http.Redirect(w, r, "/ok", 302)
		case "/ok":
			fmt.Fprint(w, " 8.8.8.8\n")
		default:
			http.Error(w, "unavailable", 503)
		}
	}))
	defer s.Close()
	d := New([]string{s.URL + "/invalid", s.URL + "/large", s.URL + "/redirect", s.URL + "/error", s.URL + "/ok"}, time.Second)
	tr := d.Client.Transport.(*http.Transport)
	tr.TLSClientConfig = s.Client().Transport.(*http.Transport).TLSClientConfig
	if tr.Proxy != nil {
		t.Fatal("proxy must be disabled")
	}
	ip, err := d.Detect(context.Background())
	if err != nil || ip.String() != "8.8.8.8" {
		t.Fatalf("%s %v", ip, err)
	}
	if proxyCalls != 0 {
		t.Fatal("used environment proxy")
	}
	d.Sources = []string{s.URL + "/invalid"}
	if _, err = d.Detect(context.Background()); err == nil {
		t.Fatal("invalid address accepted")
	}
}

func TestDetectionTimeout(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer s.Close()
	d := New([]string{s.URL}, 20*time.Millisecond)
	if _, err := d.Detect(context.Background()); err == nil {
		t.Fatal("expected timeout")
	}
}
