package syncer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/cloverstd/cloud-dynamic-security-group/internal/cloud"
	"github.com/cloverstd/cloud-dynamic-security-group/internal/config"
	"github.com/cloverstd/cloud-dynamic-security-group/internal/fail2banmate"
)

type Detector interface {
	Detect(context.Context) (netip.Addr, error)
}
type Factory func(config.Account, string, time.Duration) (cloud.Provider, error)
type WhitelistSyncer interface {
	Sync(context.Context, string, netip.Addr, bool) (bool, error)
}

type Engine struct {
	Config       config.Config
	Detector     Detector
	Factory      Factory
	Log          *slog.Logger
	DryRun       bool
	Fail2banMate WhitelistSyncer
}

func retry(ctx context.Context, retryable func(error) bool, fn func() error) error {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		err = fn()
		if err == nil || !retryable(err) {
			return err
		}
		if attempt < 2 {
			timer := time.NewTimer(time.Duration(1<<attempt) * 200 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	return err
}

func (e *Engine) Sync(ctx context.Context) error {
	ip, err := e.Detector.Detect(ctx)
	if err != nil {
		return err
	}
	accounts := map[string]config.Account{}
	for _, a := range e.Config.Accounts {
		accounts[a.Name] = a
	}
	seen := map[string]bool{}
	var failures []error
	if e.Fail2banMate != nil {
		var wouldChange bool
		err := retry(ctx, fail2banmate.Retryable, func() error {
			var err error
			wouldChange, err = e.Fail2banMate.Sync(ctx, e.Config.OwnerID, ip, e.DryRun)
			return err
		})
		if err != nil {
			failures = append(failures, err)
		} else if e.DryRun {
			e.Log.Info("Fail2ban Mate whitelist preview", "owner", e.Config.OwnerID, "ip", cloud.Mask(ip.String()), "would_change_ip", wouldChange)
		} else {
			e.Log.Info("Fail2ban Mate whitelist renewed", "owner", e.Config.OwnerID, "ip", cloud.Mask(ip.String()))
		}
	}
	for _, t := range e.Config.Targets {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		account := accounts[t.Account]
		marker := "cdsg:v1:" + e.Config.OwnerID + ":tcp4"
		if account.Provider == "volcengine" {
			// Volcengine descriptions allow dots but reject colons. Keep the
			// provider's exact marker in snapshots and deletion parameters.
			marker = "cdsg.v1." + e.Config.OwnerID + ".tcp4"
		}
		desired := cloud.Rule{CIDR: ip.String() + "/32", Description: marker, Protocol: "tcp", Action: "accept", Start: 1, End: 65535, Priority: 1}
		p, err := e.Factory(account, t.Region, e.Config.Timeout)
		if err == nil {
			var groups []string
			err = retry(ctx, cloud.Retryable, func() error { var de error; groups, de = p.Discover(ctx, t.InstanceIDs); return de })
			if err == nil {
				for _, g := range groups {
					key := t.Account + "/" + t.Region + "/" + g
					if seen[key] {
						continue
					}
					seen[key] = true
					groupErr := retry(ctx, cloud.Retryable, func() error { return e.reconcile(ctx, p, t.Name, g, desired) })
					if groupErr != nil {
						e.Log.Error("security group sync failed", "target", t.Name, "group", cloud.Mask(g), "error", groupErr)
						failures = append(failures, fmt.Errorf("target %s: %w", t.Name, groupErr))
					}
				}
			}
		}
		if err != nil {
			e.Log.Error("target discovery failed", "target", t.Name, "error", err)
			failures = append(failures, fmt.Errorf("target %s: %w", t.Name, err))
		}
	}
	return errors.Join(failures...)
}

func matches(r, d cloud.Rule) bool {
	return r.Managed(d.Description) && r.CIDR == d.CIDR && r.Priority == d.Priority
}
func hasCurrent(s cloud.Snapshot, d cloud.Rule) bool {
	for _, r := range s.Rules {
		if matches(r, d) {
			return true
		}
	}
	return false
}

func (e *Engine) reconcile(ctx context.Context, p cloud.Provider, target, group string, d cloud.Rule) error {
	s, err := p.List(ctx, group)
	if err != nil {
		return err
	}
	if !hasCurrent(s, d) {
		// Never claim an otherwise identical manual rule, even when the cloud
		// reports duplicate-rule creation as successful (Alibaba Cloud).
		for _, r := range s.Rules {
			copy := r
			copy.Description = d.Description
			if copy.Managed(d.Description) && r.CIDR == d.CIDR && r.Description != d.Description {
				return cloud.APIError("UnmanagedRuleConflict")
			}
		}
		e.Log.Info("add current IP rule", "target", target, "group", cloud.Mask(group), "ip", cloud.Mask(d.CIDR), "dry_run", e.DryRun)
		if !e.DryRun {
			if err = p.Add(ctx, group, d); err != nil {
				return err
			}
			s, err = p.List(ctx, group)
			if err != nil {
				return err
			}
			if !hasCurrent(s, d) {
				return cloud.APIError("NewRuleNotConfirmed")
			}
		}
	}
	if e.DryRun {
		for _, r := range s.Rules {
			if r.Managed(d.Description) && !matches(r, d) {
				e.Log.Info("would delete old IP rule", "target", target, "group", cloud.Mask(group), "ip", cloud.Mask(r.CIDR), "dry_run", true)
			}
		}
		return nil
	}
	// Read again before each deletion: Tencent indices shift after writes, and
	// Volcengine rules have no stable IDs. Never use a cached index or tuple.
	var lastDeleted *cloud.Rule
	for deletes := 0; deletes < 4096; deletes++ {
		s, err = p.List(ctx, group)
		if err != nil {
			return err
		}
		if !hasCurrent(s, d) {
			return cloud.APIError("CurrentRuleDisappeared")
		}
		var old *cloud.Rule
		for _, r := range s.Rules {
			if r.Managed(d.Description) && !matches(r, d) {
				copy := r
				old = &copy
				break
			}
		}
		if old == nil {
			e.Log.Info("security group synchronized", "target", target, "group", cloud.Mask(group))
			return nil
		}
		if lastDeleted != nil && *lastDeleted == *old {
			return cloud.APIError("OldRuleNotRemoved")
		}
		e.Log.Info("delete old IP rule", "target", target, "group", cloud.Mask(group), "ip", cloud.Mask(old.CIDR))
		if err = p.Delete(ctx, group, *old, s.Version); err != nil {
			return err
		}
		lastDeleted = old
	}
	return cloud.APIError("CleanupLimit")
}
