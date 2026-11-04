package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type Adapter struct {
	Name string
	API  Caller
}

func object(v any) map[string]any { m, _ := v.(map[string]any); return m }
func str(v any) string            { s, _ := v.(string); return s }
func integer(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	case string:
		i, _ := strconv.Atoi(n)
		return i
	}
	return 0
}
func array(v any) []any { a, _ := v.([]any); return a }
func ruleArray(m map[string]any, key string) ([]any, error) {
	v, present := m[key]
	if !present {
		return nil, APIError("IncompleteRuleResponse")
	}
	if v == nil {
		return nil, nil
	}
	items, ok := v.([]any)
	if !ok {
		return nil, APIError("InvalidRuleResponse")
	}
	for _, item := range items {
		if object(item) == nil {
			return nil, APIError("InvalidRuleResponse")
		}
	}
	return items, nil
}
func stringsFrom(v any) []string {
	var s []string
	for _, x := range array(v) {
		if str(x) != "" {
			s = append(s, str(x))
		}
	}
	return s
}
func empty(v any) bool {
	if v == nil {
		return true
	}
	switch x := v.(type) {
	case string:
		return x == ""
	case map[string]any:
		for _, y := range x {
			if !empty(y) {
				return false
			}
		}
		return true
	case []any:
		return len(x) == 0
	}
	return false
}

func (p *Adapter) call(ctx context.Context, service, action string, args map[string]any) (map[string]any, error) {
	var out map[string]any
	if err := p.API.Call(ctx, service, action, args, &out); err != nil {
		return nil, err
	}
	if out == nil {
		return nil, APIError("InvalidResponse")
	}
	return out, nil
}

// A single explicit instance is queried at a time. Pagination is still consumed
// completely; missing IDs fail before any security group from that target is used.
func (p *Adapter) Discover(ctx context.Context, ids []string) ([]string, error) {
	var groups []string
	for _, id := range unique(ids) {
		found := false
		instanceGroups := []string{}
		token := ""
		offset := 0
		tokens := map[string]bool{}
		for page := 0; ; page++ {
			if page >= 10000 {
				return nil, APIError("PaginationLimit")
			}
			service := "ecs"
			args := map[string]any{}
			switch p.Name {
			case "tencent":
				service = "cvm"
				args = map[string]any{"InstanceIds": []string{id}, "Limit": 100, "Offset": offset}
			case "aliyun":
				b, _ := json.Marshal([]string{id})
				args = map[string]any{"InstanceIds": string(b), "MaxResults": 100}
				if token != "" {
					args["NextToken"] = token
				}
			case "volcengine":
				args = map[string]any{"InstanceIds.1": id, "MaxResults": 100}
				if token != "" {
					args["NextToken"] = token
				}
			default:
				return nil, APIError("UnsupportedProvider")
			}
			out, err := p.call(ctx, service, "DescribeInstances", args)
			if err != nil {
				return nil, err
			}
			var instances []any
			switch p.Name {
			case "tencent":
				instances = array(out["InstanceSet"])
			case "aliyun":
				instances = array(object(out["Instances"])["Instance"])
			case "volcengine":
				instances = array(out["Instances"])
			}
			for _, value := range instances {
				inst := object(value)
				if str(inst["InstanceId"]) != id {
					continue
				}
				found = true
				if p.Name == "volcengine" {
					for _, nv := range array(inst["NetworkInterfaces"]) {
						ni := object(nv)
						if strings.EqualFold(str(ni["Type"]), "primary") {
							instanceGroups = append(instanceGroups, stringsFrom(ni["SecurityGroupIds"])...)
						}
					}
				} else if p.Name == "aliyun" {
					instanceGroups = append(instanceGroups, stringsFrom(object(inst["SecurityGroupIds"])["SecurityGroupId"])...)
				} else {
					instanceGroups = append(instanceGroups, stringsFrom(inst["SecurityGroupIds"])...)
				}
			}
			if p.Name == "tencent" {
				offset += len(instances)
				if offset >= integer(out["TotalCount"]) {
					break
				}
				if len(instances) == 0 {
					return nil, APIError("IncompletePagination")
				}
			} else {
				token = str(out["NextToken"])
				if token == "" {
					break
				}
				if tokens[token] {
					return nil, APIError("RepeatedPaginationToken")
				}
				tokens[token] = true
			}
		}
		if !found {
			return nil, APIError("InstanceNotFound")
		}
		if len(instanceGroups) == 0 {
			return nil, APIError("InstanceHasNoSecurityGroups")
		}
		groups = append(groups, instanceGroups...)
	}
	return unique(groups), nil
}

func (p *Adapter) List(ctx context.Context, group string) (Snapshot, error) {
	snapshot := Snapshot{}
	token := ""
	tokens := map[string]bool{}
	for page := 0; ; page++ {
		if page >= 10000 {
			return Snapshot{}, APIError("PaginationLimit")
		}
		args := map[string]any{"SecurityGroupId": group}
		action := ""
		switch p.Name {
		case "tencent":
			action = "DescribeSecurityGroupPolicies"
		case "volcengine":
			action = "DescribeSecurityGroupAttributes"
		case "aliyun":
			action = "DescribeSecurityGroupAttribute"
			args["Direction"] = "ingress"
			args["MaxResults"] = 1000
			if token != "" {
				args["NextToken"] = token
			}
		default:
			return Snapshot{}, APIError("UnsupportedProvider")
		}
		service := "vpc"
		if p.Name == "aliyun" {
			service = "ecs"
		}
		out, err := p.call(ctx, service, action, args)
		if err != nil {
			return Snapshot{}, err
		}
		var permissions []any
		switch p.Name {
		case "tencent":
			set := object(out["SecurityGroupPolicySet"])
			snapshot.Version = str(set["Version"])
			if snapshot.Version == "" {
				return Snapshot{}, APIError("MissingRuleVersion")
			}
			permissions, err = ruleArray(set, "Ingress")
		case "volcengine":
			permissions, err = ruleArray(out, "Permissions")
		case "aliyun":
			permissions, err = ruleArray(object(out["Permissions"]), "Permission")
		}
		if err != nil {
			return Snapshot{}, err
		}
		for _, v := range permissions {
			r, include := p.normalize(object(v))
			if include {
				snapshot.Rules = append(snapshot.Rules, r)
			}
		}
		if p.Name != "aliyun" {
			break
		}
		token = str(out["NextToken"])
		if token == "" {
			break
		}
		if tokens[token] {
			return Snapshot{}, APIError("RepeatedPaginationToken")
		}
		tokens[token] = true
	}
	return snapshot, nil
}

func (p *Adapter) normalize(m map[string]any) (Rule, bool) {
	r := Rule{Priority: integer(m["Priority"]), Description: str(m["Description"]), Action: str(m["Policy"])}
	switch p.Name {
	case "tencent":
		r.ID = strconv.Itoa(integer(m["PolicyIndex"]))
		r.Priority = 1 // Index is ordering, not a stable rule priority.
		r.CIDR = str(m["CidrBlock"])
		r.Description = str(m["PolicyDescription"])
		r.Protocol = str(m["Protocol"])
		r.Action = str(m["Action"])
		ports := str(m["Port"])
		if strings.EqualFold(ports, "all") {
			r.Start = 1
			r.End = 65535
		} else {
			fmt.Sscanf(ports, "%d-%d", &r.Start, &r.End)
		}
		_, hasIndex := m["PolicyIndex"]
		r.Restricted = !hasIndex || !empty(m["AddressTemplate"]) || !empty(m["ServiceTemplate"]) || !empty(m["SecurityGroupId"]) || !empty(m["Ipv6CidrBlock"])
	case "volcengine":
		if !strings.EqualFold(str(m["Direction"]), "ingress") {
			return r, false
		}
		r.CIDR = str(m["CidrIp"])
		r.Protocol = str(m["Protocol"])
		r.Start = integer(m["PortStart"])
		r.End = integer(m["PortEnd"])
		r.Restricted = !empty(m["SourceGroupId"]) || !empty(m["PrefixListId"])
	case "aliyun":
		if !strings.EqualFold(str(m["Direction"]), "ingress") {
			return r, false
		}
		r.ID = str(m["SecurityGroupRuleId"])
		r.CIDR = str(m["SourceCidrIp"])
		r.Protocol = str(m["IpProtocol"])
		fmt.Sscanf(str(m["PortRange"]), "%d/%d", &r.Start, &r.End)
		dest := str(m["DestCidrIp"])
		sourcePorts := str(m["SourcePortRange"])
		r.Restricted = r.ID == "" || !empty(m["SourceGroupId"]) || !empty(m["SourcePrefixListId"]) || !empty(m["Ipv6SourceCidrIp"]) || (dest != "" && dest != "0.0.0.0/0") || (sourcePorts != "" && sourcePorts != "1/65535" && sourcePorts != "-1/-1") || !empty(m["Ipv6DestCidrIp"])
	}
	return r, true
}

func (p *Adapter) Add(ctx context.Context, group string, r Rule) error {
	args := map[string]any{"SecurityGroupId": group}
	service := "vpc"
	action := ""
	switch p.Name {
	case "tencent":
		action = "CreateSecurityGroupPolicies"
		args["SecurityGroupPolicySet"] = map[string]any{"Ingress": []any{map[string]any{"PolicyIndex": 0, "Protocol": "TCP", "Port": "1-65535", "CidrBlock": r.CIDR, "Action": "ACCEPT", "PolicyDescription": r.Description}}}
	case "volcengine":
		action = "AuthorizeSecurityGroupIngress"
		args["Protocol"] = "tcp"
		args["PortStart"] = 1
		args["PortEnd"] = 65535
		args["CidrIp"] = r.CIDR
		args["Policy"] = "accept"
		args["Priority"] = 1
		args["Description"] = r.Description
	case "aliyun":
		service = "ecs"
		action = "AuthorizeSecurityGroup"
		args["Permissions.1.IpProtocol"] = "tcp"
		args["Permissions.1.PortRange"] = "1/65535"
		args["Permissions.1.SourceCidrIp"] = r.CIDR
		args["Permissions.1.Policy"] = "accept"
		args["Permissions.1.Priority"] = 1
		args["Permissions.1.Description"] = r.Description
	default:
		return APIError("UnsupportedProvider")
	}
	_, err := p.call(ctx, service, action, args)
	return err
}

func (p *Adapter) Delete(ctx context.Context, group string, r Rule, version string) error {
	args := map[string]any{"SecurityGroupId": group}
	service := "vpc"
	action := ""
	switch p.Name {
	case "tencent":
		if version == "" {
			return APIError("MissingRuleVersion")
		}
		index, err := strconv.Atoi(r.ID)
		if err != nil {
			return APIError("InvalidRuleIndex")
		}
		action = "DeleteSecurityGroupPolicies"
		args["SecurityGroupPolicySet"] = map[string]any{"Version": version, "Ingress": []any{map[string]any{"PolicyIndex": index}}}
	case "volcengine":
		action = "RevokeSecurityGroupIngress"
		args["Protocol"] = r.Protocol
		args["PortStart"] = r.Start
		args["PortEnd"] = r.End
		args["CidrIp"] = r.CIDR
		args["Policy"] = r.Action
		args["Priority"] = r.Priority
		args["Description"] = r.Description
	case "aliyun":
		if r.ID == "" {
			return APIError("MissingRuleID")
		}
		service = "ecs"
		action = "RevokeSecurityGroup"
		args["SecurityGroupRuleId.1"] = r.ID
	default:
		return APIError("UnsupportedProvider")
	}
	_, err := p.call(ctx, service, action, args)
	return err
}
