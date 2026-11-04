package syncer

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/cloverstd/cloud-dynamic-security-group/internal/cloud"
	"github.com/cloverstd/cloud-dynamic-security-group/internal/config"
)

type detector struct{ err error }

func (d detector) Detect(context.Context) (netip.Addr, error) {
	return netip.MustParseAddr("8.8.8.8"), d.err
}

type fake struct {
	rules                          []cloud.Rule
	events                         []string
	listCount                      int
	listHook                       func(*fake) error
	addErr, deleteErr, discoverErr error
	deleteNoop                     bool
	groups                         []string
}

func (f *fake) Discover(context.Context, []string) ([]string, error) { return f.groups, f.discoverErr }
func (f *fake) List(context.Context, string) (cloud.Snapshot, error) {
	f.listCount++
	f.events = append(f.events, "list")
	if f.listHook != nil {
		if err := f.listHook(f); err != nil {
			return cloud.Snapshot{}, err
		}
	}
	return cloud.Snapshot{Rules: append([]cloud.Rule{}, f.rules...), Version: "current-version"}, nil
}
func (f *fake) Add(_ context.Context, _ string, r cloud.Rule) error {
	f.events = append(f.events, "add")
	if f.addErr != nil {
		return f.addErr
	}
	f.rules = append(f.rules, r)
	return nil
}
func (f *fake) Delete(_ context.Context, _ string, r cloud.Rule, version string) error {
	f.events = append(f.events, "delete")
	if version != "current-version" {
		return errors.New("stale version")
	}
	if f.deleteErr != nil {
		return f.deleteErr
	}
	if f.deleteNoop {
		return nil
	}
	for i, x := range f.rules {
		if x.CIDR == r.CIDR && x.Description == r.Description && x.Priority == r.Priority {
			f.rules = append(f.rules[:i], f.rules[i+1:]...)
			break
		}
	}
	return nil
}
func rule(ip, owner string) cloud.Rule {
	return cloud.Rule{CIDR: ip + "/32", Description: "cdsg:v1:" + owner + ":tcp4", Protocol: "tcp", Action: "accept", Start: 1, End: 65535, Priority: 1}
}
func engine(f *fake) (*Engine, *bytes.Buffer) {
	buf := new(bytes.Buffer)
	return &Engine{Config: config.Config{OwnerID: "home", Accounts: []config.Account{{Name: "account"}}, Targets: []config.Target{{Name: "server", Account: "account", Region: "region", InstanceIDs: []string{"i-example"}}}}, Detector: detector{}, Factory: func(config.Account, string, time.Duration) (cloud.Provider, error) { return f, nil }, Log: slog.New(slog.NewTextHandler(buf, nil))}, buf
}
func writes(f *fake) string {
	var out []string
	for _, event := range f.events {
		if event != "list" {
			out = append(out, event)
		}
	}
	return strings.Join(out, ",")
}

func TestReconciliationLifecycle(t *testing.T) {
	f := &fake{groups: []string{"sg-example"}, rules: []cloud.Rule{rule("1.1.1.1", "home"), rule("9.9.9.9", "other"), rule("4.2.2.2", "manual")}}
	e, logs := engine(f)
	if err := e.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if writes(f) != "add,delete" {
		t.Fatalf("wrong order %v", f.events)
	}
	if len(f.rules) != 3 {
		t.Fatal("changed unrelated rules")
	}
	if strings.Contains(logs.String(), "8.8.8.8") || strings.Contains(logs.String(), "sg-example") {
		t.Fatal("unmasked runtime data")
	}
	f.events = nil
	if err := e.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if writes(f) != "" {
		t.Fatal("unchanged IP caused writes")
	}
	// A fresh engine recovers ownership from cloud descriptions after restart.
	e, _ = engine(f)
	if err := e.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	for i, r := range f.rules {
		if r.CIDR == "8.8.8.8/32" {
			f.rules = append(f.rules[:i], f.rules[i+1:]...)
			break
		}
	}
	f.events = nil
	if err := e.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if writes(f) != "add" {
		t.Fatal("did not repair deleted rule")
	}
}

func TestFailuresNeverRemoveOldRules(t *testing.T) {
	for _, test := range []string{"add", "confirmation", "list", "conflict", "disappeared", "delete", "detect", "discovery"} {
		t.Run(test, func(t *testing.T) {
			f := &fake{groups: []string{"sg-example"}, rules: []cloud.Rule{rule("1.1.1.1", "home")}}
			e, _ := engine(f)
			switch test {
			case "add":
				f.addErr = cloud.APIError("QuotaExceeded")
			case "confirmation":
				f.listHook = func(f *fake) error {
					if f.listCount > 1 {
						f.rules = f.rules[:1]
					}
					return nil
				}
			case "list":
				f.listHook = func(*fake) error { return cloud.APIError("AccessDenied") }
			case "conflict":
				f.rules = append(f.rules, rule("8.8.8.8", "other"))
			case "disappeared":
				f.listHook = func(f *fake) error {
					if f.listCount >= 3 {
						f.rules = f.rules[:1]
					}
					return nil
				}
			case "delete":
				f.deleteErr = cloud.APIError("AccessDenied")
			case "detect":
				e.Detector = detector{errors.New("detection failed")}
			case "discovery":
				f.discoverErr = cloud.APIError("InstanceNotFound")
			}
			if e.Sync(context.Background()) == nil {
				t.Fatal("expected error")
			}
			if f.rules[0].CIDR != "1.1.1.1/32" {
				t.Fatal("lost old rule")
			}
			if test != "delete" && strings.Contains(writes(f), "delete") {
				t.Fatal("deleted before confirming current rule")
			}
		})
	}
}

func TestDryRunAndSharedGroup(t *testing.T) {
	f := &fake{groups: []string{"sg-example"}, rules: []cloud.Rule{rule("1.1.1.1", "home")}}
	e, _ := engine(f)
	e.DryRun = true
	e.Config.Targets = append(e.Config.Targets, e.Config.Targets[0])
	if err := e.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if writes(f) != "" || f.listCount != 1 {
		t.Fatal("dry run wrote or shared group was repeated")
	}
}

func TestVersionConflictAndCleanupRecovery(t *testing.T) {
	f := &fake{groups: []string{"sg-example"}, rules: []cloud.Rule{rule("1.1.1.1", "home")}, deleteErr: cloud.APIError("UnsupportedOperation.VersionMismatch")}
	f.listHook = func(f *fake) error {
		if f.listCount >= 4 {
			f.deleteErr = nil
		}
		return nil
	}
	e, _ := engine(f)
	if err := e.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.rules) != 1 || f.rules[0].CIDR != "8.8.8.8/32" {
		t.Fatal("did not recover conflict")
	}
}

func TestPartialFailureContinues(t *testing.T) {
	f := &fake{groups: []string{"sg-example"}}
	e, _ := engine(f)
	e.Config.Targets = append([]config.Target{{Name: "failed", Account: "account", Region: "bad"}}, e.Config.Targets...)
	e.Factory = func(_ config.Account, region string, _ time.Duration) (cloud.Provider, error) {
		if region == "bad" {
			return nil, cloud.APIError("AccessDenied")
		}
		return f, nil
	}
	if e.Sync(context.Background()) == nil {
		t.Fatal("missing failure")
	}
	if writes(f) != "add" {
		t.Fatal("other target did not complete")
	}
}

func TestUnconfirmedDeletionHasBoundedRetries(t *testing.T) {
	f := &fake{groups: []string{"sg-example"}, rules: []cloud.Rule{rule("1.1.1.1", "home"), rule("8.8.8.8", "home")}, deleteNoop: true}
	e, _ := engine(f)
	if err := e.Sync(context.Background()); err == nil {
		t.Fatal("unconfirmed deletion reported success")
	}
	if writes(f) != "delete,delete,delete" {
		t.Fatalf("unbounded or missing retries: %s", writes(f))
	}
	if len(f.rules) != 2 {
		t.Fatal("lost current rule")
	}
}
