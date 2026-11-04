package syncer

import (
	"context"
	"encoding/json"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/cloverstd/cloud-dynamic-security-group/internal/cloud"
	"github.com/cloverstd/cloud-dynamic-security-group/internal/config"
)

type apiCallFunc func(context.Context, string, string, map[string]any, any) error

func (f apiCallFunc) Call(ctx context.Context, service, action string, args map[string]any, out any) error {
	return f(ctx, service, action, args, out)
}

func TestLighthouseReconciliation(t *testing.T) {
	for _, mode := range []string{"sync", "dry-run", "add-failure", "conflict", "version-conflict"} {
		t.Run(mode, func(t *testing.T) {
			old := map[string]any{
				"Protocol": "TCP", "Port": "ALL", "CidrBlock": "1.1.1.1/32",
				"Action": "ACCEPT", "FirewallRuleDescription": "cdsg:v1:home:tcp4",
			}
			manual := map[string]any{
				"Protocol": "TCP", "Port": "1-65535", "CidrBlock": "9.9.9.9/32",
				"Action": "ACCEPT", "FirewallRuleDescription": "manual",
			}
			if mode == "conflict" {
				manual["CidrBlock"] = "8.8.8.8/32"
			}
			rules := []map[string]any{old, manual}
			version, deletes := int64(1), 0
			var writes []string
			p := &cloud.Adapter{Name: "tencent", API: apiCallFunc(func(_ context.Context, service, action string, args map[string]any, out any) error {
				if service != "lighthouse" {
					t.Fatalf("unexpected service %s", service)
				}
				result := map[string]any{}
				switch action {
				case "DescribeInstances":
					if ids := args["InstanceIds"].([]string); len(ids) != 1 || ids[0] != "lhins-example" {
						t.Fatal("incorrect instance discovery")
					}
					result = map[string]any{"TotalCount": 1, "InstanceSet": []any{map[string]any{"InstanceId": "lhins-example"}}}
				case "DescribeFirewallRules":
					result = map[string]any{"TotalCount": len(rules), "FirewallVersion": version, "FirewallRuleSet": rules}
				case "CreateFirewallRules":
					writes = append(writes, "add")
					if mode == "add-failure" {
						return cloud.APIError("LimitExceeded.FirewallRulesLimitExceeded")
					}
					rules = append(rules, args["FirewallRules"].([]any)[0].(map[string]any))
					version++
				case "DeleteFirewallRules":
					writes = append(writes, "delete")
					deletes++
					if args["FirewallVersion"] != version {
						t.Fatal("delete used a stale firewall version")
					}
					if mode == "version-conflict" && deletes == 1 {
						version++
						return cloud.APIError("UnsupportedOperation.FirewallVersionMismatch")
					}
					deleted := args["FirewallRules"].([]any)[0].(map[string]any)
					if !maps.Equal(deleted, old) {
						t.Fatal("deleted a rule other than the old owned rule")
					}
					rules = rules[1:]
					version++
				default:
					t.Fatalf("unexpected action %s", action)
				}
				if action != "DescribeInstances" && args["InstanceId"] != "lhins-example" {
					t.Fatal("incorrect firewall instance")
				}
				b, err := json.Marshal(result)
				if err != nil {
					return err
				}
				return json.Unmarshal(b, out)
			})}
			e, logs := engine(&fake{})
			e.Config.Accounts[0].Provider = "tencent"
			e.Config.Targets[0].InstanceIDs = []string{"lhins-example"}
			e.Factory = func(config.Account, string, time.Duration) (cloud.Provider, error) { return p, nil }
			e.DryRun = mode == "dry-run"
			err := e.Sync(context.Background())
			wantError := mode == "add-failure" || mode == "conflict"
			if (err != nil) != wantError {
				t.Fatalf("unexpected sync result: %v", err)
			}
			expectedWrites := map[string]string{"sync": "add,delete", "dry-run": "", "add-failure": "add", "conflict": "", "version-conflict": "add,delete,delete"}
			if strings.Join(writes, ",") != expectedWrites[mode] {
				t.Fatalf("incorrect write ordering: %v", writes)
			}
			if len(rules) != 2 {
				t.Fatalf("unexpected remaining rules: %v", rules)
			}
			if wantError || e.DryRun {
				if !maps.Equal(rules[0], old) || !maps.Equal(rules[1], manual) {
					t.Fatal("old or manual rule lost on dry run/failure")
				}
			} else {
				if !maps.Equal(rules[0], manual) || rules[1]["CidrBlock"] != "8.8.8.8/32" || rules[1]["FirewallRuleDescription"] != "cdsg:v1:home:tcp4" {
					t.Fatal("current rule missing or manual rule changed")
				}
				writes = nil
				if err := e.Sync(context.Background()); err != nil || len(writes) != 0 {
					t.Fatalf("unchanged IP caused writes: %v %v", writes, err)
				}
			}
			for _, sensitive := range []string{"8.8.8.8", "1.1.1.1", "lhins-example"} {
				if strings.Contains(logs.String(), sensitive) {
					t.Fatal("runtime data appeared in logs without masking")
				}
			}
		})
	}
}
