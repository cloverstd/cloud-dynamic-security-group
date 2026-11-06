package fail2banmate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"
)

type Client struct {
	baseURL  string
	tokenEnv string
	http     *http.Client
}

func New(baseURL, tokenEnv string, timeout time.Duration) *Client {
	return &Client{
		baseURL: baseURL, tokenEnv: tokenEnv,
		http: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

type retryableError struct{ error }

func Retryable(err error) bool {
	var transient retryableError
	return errors.As(err, &transient)
}

// Sync writes the current address or, in dry-run mode, checks whether it would
// change. Errors deliberately omit URLs, credentials, and response content.
func (c *Client) Sync(ctx context.Context, key string, ip netip.Addr, dryRun bool) (bool, error) {
	token := os.Getenv(c.tokenEnv)
	if strings.TrimSpace(token) == "" || strings.ContainsAny(token, "\r\n") {
		return false, errors.New("Fail2ban Mate Token environment variable is missing or invalid")
	}
	endpoint, err := url.JoinPath(c.baseURL, "api/integrations/v1/whitelist", key)
	if err != nil {
		return false, errors.New("invalid Fail2ban Mate endpoint")
	}
	method := http.MethodPut
	var body io.Reader
	if dryRun {
		method = http.MethodGet
	} else {
		payload, err := json.Marshal(struct {
			IP netip.Addr `json:"ip"`
		}{ip})
		if err != nil {
			return false, errors.New("invalid Fail2ban Mate address")
		}
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return false, errors.New("invalid Fail2ban Mate request")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if !dryRun {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return false, retryableError{errors.New("Fail2ban Mate request failed")}
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK && !(dryRun && res.StatusCode == http.StatusNotFound) {
		err := fmt.Errorf("Fail2ban Mate returned HTTP %d", res.StatusCode)
		if res.StatusCode == http.StatusTooManyRequests || res.StatusCode >= 500 {
			return false, retryableError{err}
		}
		return false, err
	}
	const limit = 4096
	payload, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil {
		return false, retryableError{errors.New("could not read Fail2ban Mate response")}
	}
	var rule struct {
		ID        string     `json:"id"`
		Key       string     `json:"key"`
		IP        netip.Addr `json:"ip"`
		ExpiresAt int64      `json:"expires_at"`
		Code      string     `json:"code"`
	}
	if len(payload) > limit || json.Unmarshal(payload, &rule) != nil {
		return false, errors.New("invalid Fail2ban Mate response")
	}
	if res.StatusCode == http.StatusNotFound && rule.Code == "rule_not_found" {
		return true, nil
	}
	if res.StatusCode != http.StatusOK || rule.ID == "" || rule.Key != key || !rule.IP.IsValid() ||
		rule.ExpiresAt <= 0 || (!dryRun && rule.IP != ip) {
		return false, errors.New("invalid Fail2ban Mate rule response")
	}
	return rule.IP != ip, nil
}
