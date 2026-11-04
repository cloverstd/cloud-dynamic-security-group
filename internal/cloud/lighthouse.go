package cloud

import (
	"context"
	"strconv"
	"strings"
)

func (p *Adapter) lighthouse(id string) bool {
	return p.Name == "tencent" && strings.HasPrefix(id, "lhins-")
}

func (p *Adapter) listLighthouse(ctx context.Context, instance string) (Snapshot, error) {
	snapshot := Snapshot{}
	offset, total := 0, 0
	for page := 0; page < 10000; page++ {
		out, err := p.call(ctx, "lighthouse", "DescribeFirewallRules", map[string]any{
			"InstanceId": instance, "Offset": offset, "Limit": 100,
		})
		if err != nil {
			return Snapshot{}, err
		}
		var metadata struct {
			TotalCount      *int
			FirewallVersion *int64
		}
		if err := decode(out, &metadata); err != nil || metadata.TotalCount == nil || *metadata.TotalCount < 0 {
			return Snapshot{}, APIError("InvalidRuleResponse")
		}
		if metadata.FirewallVersion == nil || *metadata.FirewallVersion < 0 {
			return Snapshot{}, APIError("MissingRuleVersion")
		}
		version := strconv.FormatInt(*metadata.FirewallVersion, 10)
		if page == 0 {
			snapshot.Version = version
			total = *metadata.TotalCount
		} else {
			// Never combine pages from different firewall revisions.
			if snapshot.Version != version {
				return Snapshot{}, APIError("UnsupportedOperation.FirewallVersionMismatch")
			}
			if total != *metadata.TotalCount {
				return Snapshot{}, APIError("IncompletePagination")
			}
		}
		rules, err := ruleArray(out, "FirewallRuleSet")
		if err != nil {
			return Snapshot{}, err
		}
		offset += len(rules)
		if offset > total || (len(rules) == 0 && offset < total) {
			return Snapshot{}, APIError("IncompletePagination")
		}
		for _, v := range rules {
			snapshot.Rules = append(snapshot.Rules, normalizeLighthouse(object(v)))
		}
		if offset == total {
			return snapshot, nil
		}
	}
	return Snapshot{}, APIError("PaginationLimit")
}

func normalizeLighthouse(m map[string]any) Rule {
	r := Rule{
		CIDR: str(m["CidrBlock"]), Description: str(m["FirewallRuleDescription"]),
		Protocol: str(m["Protocol"]), Port: str(m["Port"]), Action: str(m["Action"]),
		Priority:   1, // Lighthouse does not expose a rule priority.
		Restricted: !empty(m["Ipv6CidrBlock"]),
	}
	if strings.EqualFold(r.Port, "ALL") {
		r.Start, r.End = 1, 65535
	} else {
		// Reject lists and trailing characters rather than matching a prefix.
		start, end, isRange := strings.Cut(r.Port, "-")
		if !isRange {
			end = start
		}
		s, errStart := strconv.Atoi(start)
		e, errEnd := strconv.Atoi(end)
		if errStart == nil && errEnd == nil && s >= 1 && e <= 65535 && s <= e {
			r.Start, r.End = s, e
		}
	}
	return r
}

func (p *Adapter) addLighthouse(ctx context.Context, instance string, r Rule) error {
	_, err := p.call(ctx, "lighthouse", "CreateFirewallRules", map[string]any{
		"InstanceId": instance,
		"FirewallRules": []any{map[string]any{
			"Protocol": "TCP", "Port": "1-65535", "CidrBlock": r.CIDR,
			"Action": "ACCEPT", "FirewallRuleDescription": r.Description,
		}},
	})
	return err
}

func (p *Adapter) deleteLighthouse(ctx context.Context, instance string, r Rule, version string) error {
	if version == "" {
		return APIError("MissingRuleVersion")
	}
	v, err := strconv.ParseInt(version, 10, 64)
	if err != nil || v < 0 {
		return APIError("InvalidRuleVersion")
	}
	_, err = p.call(ctx, "lighthouse", "DeleteFirewallRules", map[string]any{
		"InstanceId": instance, "FirewallVersion": v,
		"FirewallRules": []any{map[string]any{
			"Protocol": r.Protocol, "Port": r.Port, "CidrBlock": r.CIDR,
			"Action": r.Action, "FirewallRuleDescription": r.Description,
		}},
	})
	return err
}
