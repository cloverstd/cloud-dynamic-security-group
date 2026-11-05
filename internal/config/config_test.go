package config

import (
	"strings"
	"testing"
	"time"
)

const valid = `owner_id: home
accounts:
  - name: example
    provider: tencent
    access_key_id_env: EXAMPLE_ID
    secret_access_key_env: EXAMPLE_SECRET
targets:
  - name: server
    account: example
    region: ap-singapore
    instance_ids: [ins-example]
`

func TestExampleConfiguration(t *testing.T) {
	if _, err := Load("../../config.example.yaml"); err != nil {
		t.Fatal(err)
	}
}

func TestDefaultsAndValidation(t *testing.T) {
	c, err := Decode(strings.NewReader(valid))
	if err != nil {
		t.Fatal(err)
	}
	if c.Interval != time.Minute || c.Timeout != 10*time.Second || len(c.IPSources) != 1 {
		t.Fatal("missing defaults")
	}
	for _, input := range []string{strings.Replace(valid, "owner_id: home", "owner_id: bad:name", 1), valid + "unknown_secret: never-print-this\n", valid + "---\nowner_id: second\n", valid + "ip_sources: [http://example.invalid]\n", valid + "interval: 0s\n", strings.Replace(valid, "EXAMPLE_SECRET", "literal/credential", 1), strings.Replace(valid, "account: example", "account: missing", 1)} {
		if _, err := Decode(strings.NewReader(input)); err == nil {
			t.Fatal("accepted invalid config")
		} else if strings.Contains(err.Error(), "never-print-this") {
			t.Fatal("leaked config value")
		}
	}
}

func TestLighthouseInstanceIDs(t *testing.T) {
	for _, ids := range []string{"lhins-example", "ins-example, lhins-example"} {
		input := strings.Replace(valid, "instance_ids: [ins-example]", "instance_ids: ["+ids+"]", 1)
		if _, err := Decode(strings.NewReader(input)); err != nil {
			t.Fatalf("Tencent IDs %q: %v", ids, err)
		}
	}
	for _, id := range []string{"lhins-", "lhins-bad/id", "lhins-bad id", "lhins-bad.example"} {
		input := strings.Replace(valid, "ins-example", id, 1)
		if _, err := Decode(strings.NewReader(input)); err == nil {
			t.Fatalf("accepted malformed Lighthouse ID %q", id)
		}
	}
	for _, provider := range []string{"aliyun", "volcengine"} {
		input := strings.ReplaceAll(strings.Replace(valid, "provider: tencent", "provider: "+provider, 1), "ins-example", "lhins-example")
		if _, err := Decode(strings.NewReader(input)); err == nil {
			t.Fatalf("accepted Lighthouse ID for %s", provider)
		}
	}
}

func TestFail2banMateStandaloneConfiguration(t *testing.T) {
	base := "owner_id: home\nfail2ban_mate:\n  base_url: https://mate.example.com\n  token_env: MATE_TOKEN\n"
	c, err := Decode(strings.NewReader(base))
	if err != nil || c.Fail2banMate == nil || len(c.Targets) != 0 {
		t.Fatalf("standalone configuration rejected: %v", err)
	}
	if _, err := Decode(strings.NewReader(valid + strings.TrimPrefix(base, "owner_id: home\n"))); err != nil {
		t.Fatalf("mixed configuration rejected: %v", err)
	}
	for _, invalid := range []string{
		"owner_id: home\n",
		base + "interval: 24h\n",
		strings.Replace(base, "https://", "http://", 1),
		strings.Replace(base, "mate.example.com", "user:secret@mate.example.com", 1),
		strings.Replace(base, "mate.example.com", "mate.example.com/path", 1),
		strings.Replace(base, "mate.example.com", "mate.example.com?token=secret", 1),
		strings.Replace(base, "MATE_TOKEN", "literal/token", 1),
	} {
		if _, err := Decode(strings.NewReader(invalid)); err == nil {
			t.Fatal("accepted invalid integration configuration")
		} else if strings.Contains(err.Error(), "secret") {
			t.Fatal("configuration error leaked a value")
		}
	}
}
