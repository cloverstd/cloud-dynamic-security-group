package publicip

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// IsPublic rejects special-use IPv4 ranges, including CGNAT and documentation IPs.
func IsPublic(ip netip.Addr) bool {
	if !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	for _, cidr := range specialRanges {
		if cidr.Contains(ip) {
			return false
		}
	}
	return true
}

var specialRanges = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{"0.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

type Detector struct {
	Client  *http.Client
	Sources []string
}

func New(sources []string, timeout time.Duration) *Detector {
	dialer := &net.Dialer{Timeout: timeout}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, _, address string) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp4", address)
	}
	return &Detector{Sources: sources, Client: &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (d *Detector) Detect(ctx context.Context) (netip.Addr, error) {
	for _, source := range d.Sources {
		if ctx.Err() != nil {
			return netip.Addr{}, ctx.Err()
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
		if err != nil {
			continue
		}
		resp, err := d.Client.Do(req)
		if err != nil {
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1025))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || readErr != nil || len(body) > 1024 {
			continue
		}
		ip, err := netip.ParseAddr(strings.TrimSpace(string(body)))
		if err == nil && IsPublic(ip) {
			return ip, nil
		}
	}
	return netip.Addr{}, errors.New("public IPv4 detection failed for all sources")
}
