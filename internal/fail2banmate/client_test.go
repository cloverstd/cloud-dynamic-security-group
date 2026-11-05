package fail2banmate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newTestClient(t *testing.T, h http.HandlerFunc, timeout time.Duration) *Client {
	t.Helper()
	s := httptest.NewTLSServer(h)
	t.Cleanup(s.Close)
	t.Setenv("TEST_MATE_TOKEN", "fixture-private-token")
	c := New(s.URL, "TEST_MATE_TOKEN", timeout)
	c.http.Transport = s.Client().Transport
	return c
}

func TestSyncAndDryRun(t *testing.T) {
	ip := netip.MustParseAddr("8.8.8.8")
	var writes atomic.Int32
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/integrations/v1/whitelist/home" ||
			r.Header.Get("Authorization") != "Bearer fixture-private-token" {
			t.Error("incorrect integration request")
		}
		switch r.Method {
		case http.MethodGet:
			if b, _ := io.ReadAll(r.Body); len(b) != 0 {
				t.Error("dry run sent a body")
			}
			w.WriteHeader(404)
			fmt.Fprint(w, `{"code":"rule_not_found"}`)
		case http.MethodPut:
			writes.Add(1)
			var payload struct{ IP netip.Addr }
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.IP != ip {
				t.Error("incorrect PUT payload")
			}
			fmt.Fprint(w, `{"id":"test","key":"home","ip":"8.8.8.8","expires_at":86400}`)
		default:
			t.Errorf("unexpected method %s", r.Method)
		}
	}, time.Second)
	if wouldChange, err := c.Sync(t.Context(), "home", ip, true); !wouldChange || err != nil {
		t.Fatalf("dry run: %t, %v", wouldChange, err)
	}
	if writes.Load() != 0 {
		t.Fatal("dry run wrote a rule")
	}
	for range 2 {
		if _, err := c.Sync(t.Context(), "home", ip, false); err != nil {
			t.Fatal(err)
		}
	}
	if writes.Load() != 2 {
		t.Fatal("unchanged IP was not renewed")
	}
}

func TestFailuresAreSafeAndClassified(t *testing.T) {
	ip := netip.MustParseAddr("8.8.8.8")
	for _, code := range []int{301, 400, 401, 429, 500, 503} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			var calls atomic.Int32
			c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Location", "/redirected")
				w.WriteHeader(code)
				fmt.Fprint(w, "fixture-private-token 8.8.8.8")
			}, time.Second)
			_, err := c.Sync(t.Context(), "home", ip, false)
			if err == nil || Retryable(err) != (code == 429 || code >= 500) || calls.Load() != 1 {
				t.Fatalf("bad error or redirect handling: %v", err)
			}
			for _, sensitive := range []string{ip.String(), "fixture-private-token", c.baseURL} {
				if strings.Contains(err.Error(), sensitive) {
					t.Fatal("sensitive data leaked in error")
				}
			}
		})
	}
}

func TestTimeoutAndResponseBound(t *testing.T) {
	ip := netip.MustParseAddr("8.8.8.8")
	slow := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(time.Second):
		}
	}, 25*time.Millisecond)
	if _, err := slow.Sync(t.Context(), "home", ip, false); !Retryable(err) {
		t.Fatalf("timeout should be retryable: %v", err)
	}
	large := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, strings.Repeat("x", 5000))
	}, time.Second)
	if _, err := large.Sync(t.Context(), "home", ip, false); err == nil || Retryable(err) {
		t.Fatalf("oversized response should fail without retry: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := large.Sync(ctx, "home", ip, false); err == nil {
		t.Fatal("canceled context should fail")
	}
}
