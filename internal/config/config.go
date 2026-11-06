package config

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"time"

	"go.yaml.in/yaml/v3"
)

type Config struct {
	OwnerID      string        `yaml:"owner_id"`
	Interval     time.Duration `yaml:"interval"`
	Timeout      time.Duration `yaml:"timeout"`
	IPSources    []string      `yaml:"ip_sources"`
	Accounts     []Account     `yaml:"accounts"`
	Targets      []Target      `yaml:"targets"`
	Fail2banMate *Fail2banMate `yaml:"fail2ban_mate"`
}

type Fail2banMate struct {
	BaseURL  string `yaml:"base_url"`
	TokenEnv string `yaml:"token_env"`
}

type Account struct {
	Name               string `yaml:"name"`
	Provider           string `yaml:"provider"`
	AccessKeyIDEnv     string `yaml:"access_key_id_env"`
	SecretAccessKeyEnv string `yaml:"secret_access_key_env"`
	SecurityTokenEnv   string `yaml:"security_token_env"`
}

type Target struct {
	Name        string   `yaml:"name"`
	Account     string   `yaml:"account"`
	Region      string   `yaml:"region"`
	InstanceIDs []string `yaml:"instance_ids"`
}

var namePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,32}$`)
var regionPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)
var envPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var instancePattern = regexp.MustCompile(`^i(?:ns)?-[A-Za-z0-9]+$`)
var lighthouseInstancePattern = regexp.MustCompile(`^lhins-[A-Za-z0-9]+$`)

func Load(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, errors.New("cannot open configuration")
	}
	defer f.Close()
	return Decode(f)
}

func Decode(r io.Reader) (Config, error) {
	c := Config{Interval: 60 * time.Second, Timeout: 10 * time.Second, IPSources: []string{"https://api.ipify.org"}}
	d := yaml.NewDecoder(io.LimitReader(r, 1<<20))
	d.KnownFields(true)
	if err := d.Decode(&c); err != nil {
		return c, errors.New("invalid YAML configuration (unknown fields or invalid values)")
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return c, errors.New("configuration must contain one YAML document")
	}
	return c, c.Validate()
}

func (c Config) Validate() error {
	if !namePattern.MatchString(c.OwnerID) {
		return errors.New("owner_id must contain 1-32 letters, digits, underscores or hyphens")
	}
	if c.Interval < time.Second || c.Timeout < time.Second || c.Timeout > 5*time.Minute {
		return errors.New("interval must be >= 1s; timeout must be between 1s and 5m")
	}
	if len(c.IPSources) == 0 {
		return errors.New("ip_sources cannot be empty")
	}
	for _, source := range c.IPSources {
		u, err := url.Parse(source)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("ip_sources must be HTTPS URLs without credentials, query strings or fragments")
		}
	}
	accounts := map[string]string{}
	for _, a := range c.Accounts {
		if !namePattern.MatchString(a.Name) || accounts[a.Name] != "" {
			return errors.New("account names must be unique safe aliases (1-32 characters)")
		}
		if a.Provider != "aliyun" && a.Provider != "tencent" && a.Provider != "volcengine" {
			return errors.New("provider must be aliyun, tencent or volcengine")
		}
		if !envPattern.MatchString(a.AccessKeyIDEnv) || !envPattern.MatchString(a.SecretAccessKeyEnv) || (a.SecurityTokenEnv != "" && !envPattern.MatchString(a.SecurityTokenEnv)) {
			return errors.New("credentials must reference environment variable names")
		}
		accounts[a.Name] = a.Provider
	}
	if c.Fail2banMate != nil {
		u, err := url.Parse(c.Fail2banMate.BaseURL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
			u.ForceQuery || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" ||
			(u.Path != "" && u.Path != "/") {
			return errors.New("fail2ban_mate.base_url must be an HTTPS origin without credentials, path, query or fragment")
		}
		if !envPattern.MatchString(c.Fail2banMate.TokenEnv) {
			return errors.New("fail2ban_mate.token_env must reference an environment variable name")
		}
		if c.Interval >= 24*time.Hour {
			return errors.New("interval must be less than 24h with fail2ban_mate")
		}
	} else if len(c.Targets) == 0 {
		return errors.New("at least one cloud target or fail2ban_mate must be configured")
	}
	names := map[string]bool{}
	for _, t := range c.Targets {
		if !namePattern.MatchString(t.Name) || names[t.Name] {
			return errors.New("target names must be unique safe aliases (1-32 characters)")
		}
		if accounts[t.Account] == "" || !regionPattern.MatchString(t.Region) || len(t.InstanceIDs) == 0 {
			return fmt.Errorf("target %s requires an existing account, region and instance_ids", t.Name)
		}
		for _, id := range t.InstanceIDs {
			if !instancePattern.MatchString(id) && !(accounts[t.Account] == "tencent" && lighthouseInstancePattern.MatchString(id)) {
				return fmt.Errorf("target %s contains an invalid instance ID", t.Name)
			}
		}
		names[t.Name] = true
	}
	return nil
}
