// Package cloud contains provider-neutral rules and official SDK adapters.
package cloud

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"strings"
)

type Rule struct {
	ID          string
	CIDR        string
	Description string
	Protocol    string
	Action      string
	Start       int
	End         int
	Priority    int
	Restricted  bool
}

func (r Rule) Managed(marker string) bool {
	p, err := netip.ParsePrefix(r.CIDR)
	return err == nil && p.Addr().Is4() && p.Bits() == 32 && r.Description == marker && strings.EqualFold(r.Protocol, "tcp") && strings.EqualFold(r.Action, "accept") && r.Start == 1 && r.End == 65535 && !r.Restricted
}

type Snapshot struct {
	Rules   []Rule
	Version string
}
type Provider interface {
	Discover(context.Context, []string) ([]string, error)
	List(context.Context, string) (Snapshot, error)
	Add(context.Context, string, Rule) error
	Delete(context.Context, string, Rule, string) error
}

// Error deliberately excludes SDK messages, URLs, request bodies and credentials.
type Error struct {
	Code      string
	Retryable bool
}

func (e *Error) Error() string { return "cloud API: " + e.Code }

func APIError(code string) error {
	if !regexp.MustCompile(`^[A-Za-z0-9_.-]{1,120}$`).MatchString(code) {
		code = "RequestFailed"
	}
	lower := strings.ToLower(code)
	retry := false
	for _, part := range []string{"throttl", "limitexceeded.request", "requestlimit", "flowlimit", "serviceunavailable", "internalerror", "internalfailure", "timeout", "versionmismatch", "networkerror", "requesterror", "clienterror.http", "newrulenotconfirmed", "oldrulenotremoved"} {
		if strings.Contains(lower, part) {
			retry = true
		}
	}
	return &Error{Code: code, Retryable: retry}
}

func Retryable(err error) bool { var e *Error; return errors.As(err, &e) && e.Retryable }

func Mask(value string) string {
	if value == "" {
		return ""
	}
	return "sha256:" + fingerprint(value)
}

// Caller invokes cloud APIs using an official SDK. Output excludes API envelopes.
type Caller interface {
	Call(context.Context, string, string, map[string]any, any) error
}

func decode(value any, out any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return APIError("InvalidResponse")
	}
	if json.Unmarshal(b, out) != nil {
		return APIError("InvalidResponse")
	}
	return nil
}

func unique(values []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, v := range values {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
