package cloud

import (
	"context"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

func lighthouseRule() map[string]any {
	return map[string]any{
		"Protocol": "TCP", "Port": "1-65535", "CidrBlock": "8.8.8.8/32",
		"Action": "ACCEPT", "FirewallRuleDescription": "cdsg:v1:home:tcp4",
		"AppType": "自定义",
	}
}

func TestLighthouseSDKRoutingSigningAndErrors(t *testing.T) {
	for _, action := range []string{"DescribeInstances", "DescribeFirewallRules", "CreateFirewallRules", "DeleteFirewallRules"} {
		t.Run(action, func(t *testing.T) {
			c := &sdkCaller{provider: "tencent", region: "ap-singapore", key: "example-id", secret: "example-secret", token: "example-token", timeout: time.Second}
			apiError := false
			c.http = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Scheme != "https" || r.URL.Host != "lighthouse.tencentcloudapi.com" || r.Header.Get("X-TC-Version") != "2020-03-24" || r.Header.Get("X-TC-Action") != action || r.Header.Get("X-TC-Region") != "ap-singapore" {
					t.Fatal("incorrect Lighthouse endpoint or API headers")
				}
				if !strings.Contains(r.Header.Get("Authorization"), "/lighthouse/tc3_request") || r.Header.Get("X-TC-Token") != "example-token" {
					t.Fatal("missing Lighthouse signing scope or session token")
				}
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["InstanceId"] != "lhins-example" {
					t.Fatal("invalid Lighthouse request body")
				}
				payload := `{"Response":{"FirewallVersion":7,"RequestId":"example"}}`
				if apiError {
					payload = `{"Response":{"Error":{"Code":"UnsupportedOperation.FirewallVersionMismatch","Message":"sensitive-error-content"},"RequestId":"example"}}`
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(payload)), Request: r}, nil
			})}
			var out map[string]any
			if err := c.Call(context.Background(), "lighthouse", action, map[string]any{"InstanceId": "lhins-example"}, &out); err != nil || out["FirewallVersion"] != float64(7) {
				t.Fatalf("response decoding: %v %v", out, err)
			}
			apiError = true
			err := c.Call(context.Background(), "lighthouse", action, map[string]any{"InstanceId": "lhins-example"}, &out)
			if err == nil || !Retryable(err) || strings.Contains(err.Error(), "sensitive-error-content") {
				t.Fatalf("Lighthouse error sanitization/retry: %v", err)
			}
		})
	}
	if !Retryable(APIError("UnsupportedOperation.FirewallBusy")) || Retryable(APIError("LimitExceeded.FirewallRulesLimitExceeded")) {
		t.Fatal("incorrect Lighthouse transient/quota classification")
	}
}

func TestDiscoverMixedTencentInstances(t *testing.T) {
	queries := []string{}
	p := Adapter{Name: "tencent", API: callFunc(func(_ context.Context, service, action string, args map[string]any, out any) error {
		if action != "DescribeInstances" || args["Limit"] != 100 {
			t.Fatal("incorrect instance query")
		}
		id := args["InstanceIds"].([]string)[0]
		queries = append(queries, service)
		inst := map[string]any{"InstanceId": id}
		total := 1
		switch id {
		case "ins-example":
			if service != "cvm" || args["Offset"] != 0 {
				t.Fatal("CVM routed to wrong service")
			}
			inst["SecurityGroupIds"] = []string{"sg-example"}
		case "lhins-example":
			if service != "lighthouse" {
				t.Fatal("Lighthouse routed to wrong service")
			}
			total = 2
			if args["Offset"] == 1 {
				inst["InstanceId"] = "lhins-unrelated"
			} else if args["Offset"] != 0 {
				t.Fatal("incorrect Lighthouse pagination")
			}
		case "lhins-missing":
			return decode(map[string]any{"TotalCount": 0, "InstanceSet": []any{}}, out)
		default:
			t.Fatal("unexpected instance query")
		}
		return decode(map[string]any{"TotalCount": total, "InstanceSet": []any{inst}}, out)
	})}
	groups, err := p.Discover(context.Background(), []string{"ins-example", "lhins-example", "lhins-example"})
	if err != nil || !reflect.DeepEqual(groups, []string{"sg-example", "lhins-example"}) || !reflect.DeepEqual(queries, []string{"cvm", "lighthouse", "lighthouse"}) {
		t.Fatalf("mixed discovery: %v %v %v", groups, err, queries)
	}
	groups, err = p.Discover(context.Background(), []string{"ins-example", "lhins-missing"})
	if err == nil || len(groups) != 0 {
		t.Fatal("partial discovery escaped a missing Lighthouse instance")
	}
}

func TestLighthouseRulePaginationAndDeletionIdentity(t *testing.T) {
	calls := 0
	p := Adapter{Name: "tencent", API: callFunc(func(_ context.Context, service, action string, args map[string]any, out any) error {
		calls++
		if service != "lighthouse" || args["InstanceId"] != "lhins-example" {
			t.Fatal("incorrect firewall routing")
		}
		switch action {
		case "DescribeFirewallRules":
			if args["Offset"] != calls-1 || args["Limit"] != 100 {
				t.Fatal("incorrect firewall pagination")
			}
			r := lighthouseRule()
			if calls == 2 {
				r["Port"] = "ALL"
			}
			return decode(map[string]any{"TotalCount": 2, "FirewallVersion": 7, "FirewallRuleSet": []any{r}}, out)
		case "CreateFirewallRules":
			r := object(array(args["FirewallRules"])[0])
			expected := lighthouseRule()
			delete(expected, "AppType")
			if !reflect.DeepEqual(r, expected) {
				t.Fatalf("incorrect create rule: %v", r)
			}
		case "DeleteFirewallRules":
			r := object(array(args["FirewallRules"])[0])
			expected := lighthouseRule()
			delete(expected, "AppType")
			expected["Port"] = "ALL"
			if args["FirewallVersion"] != int64(7) || !reflect.DeepEqual(r, expected) {
				t.Fatalf("delete lost version or original tuple: %v", args)
			}
		default:
			t.Fatalf("unexpected API action %s", action)
		}
		return decode(map[string]any{}, out)
	})}
	s, err := p.List(context.Background(), "lhins-example")
	if err != nil || s.Version != "7" || len(s.Rules) != 2 || calls != 2 {
		t.Fatalf("firewall pagination: %v %v", s, err)
	}
	for _, r := range s.Rules {
		if !r.Managed("cdsg:v1:home:tcp4") || r.Priority != 1 {
			t.Fatal("full TCP rule was not recognized")
		}
	}
	if err := p.Add(context.Background(), "lhins-example", s.Rules[0]); err != nil {
		t.Fatal(err)
	}
	if err := p.Delete(context.Background(), "lhins-example", s.Rules[1], s.Version); err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"", "-1", "7.5", "invalid", "9223372036854775808"} {
		if err := p.Delete(context.Background(), "lhins-example", s.Rules[1], version); err == nil {
			t.Fatalf("accepted invalid version %q", version)
		}
	}
	if calls != 4 {
		t.Fatal("invalid version caused API request")
	}
}

func TestLighthouseIncompleteOrChangingRulesFailClosed(t *testing.T) {
	for _, test := range []string{"missing-rules", "invalid-rules", "null-rule", "missing-total", "missing-version", "invalid-version", "short-page", "excess-rules", "changed-version", "changed-total", "api-error"} {
		t.Run(test, func(t *testing.T) {
			calls := 0
			p := Adapter{Name: "tencent", API: callFunc(func(_ context.Context, _, _ string, _ map[string]any, out any) error {
				calls++
				result := map[string]any{"TotalCount": 2, "FirewallVersion": 7, "FirewallRuleSet": []any{lighthouseRule()}}
				if calls == 2 {
					switch test {
					case "missing-rules":
						delete(result, "FirewallRuleSet")
					case "invalid-rules":
						result["FirewallRuleSet"] = "invalid"
					case "null-rule":
						result["FirewallRuleSet"] = []any{nil}
					case "missing-total":
						delete(result, "TotalCount")
					case "missing-version":
						delete(result, "FirewallVersion")
					case "invalid-version":
						result["FirewallVersion"] = 7.5
					case "short-page":
						result["FirewallRuleSet"] = []any{}
					case "excess-rules":
						result["FirewallRuleSet"] = []any{lighthouseRule(), lighthouseRule()}
					case "changed-version":
						result["FirewallVersion"] = 8
					case "changed-total":
						result["TotalCount"] = 3
					case "api-error":
						return APIError("AccessDenied")
					}
				}
				return decode(result, out)
			})}
			s, err := p.List(context.Background(), "lhins-example")
			if err == nil || len(s.Rules) != 0 || s.Version != "" || calls != 2 {
				t.Fatalf("partial snapshot escaped: %v %v, calls=%d", s, err, calls)
			}
			if test == "changed-version" && !Retryable(err) {
				t.Fatal("firewall version change must be retryable")
			}
		})
	}
	for _, rules := range []any{[]any{}, nil} {
		p := Adapter{Name: "tencent", API: callFunc(func(_ context.Context, _, _ string, _ map[string]any, out any) error {
			return decode(map[string]any{"TotalCount": 0, "FirewallVersion": 0, "FirewallRuleSet": rules}, out)
		})}
		if s, err := p.List(context.Background(), "lhins-example"); err != nil || len(s.Rules) != 0 || s.Version != "0" {
			t.Fatalf("empty firewall rejected: %v %v", s, err)
		}
	}
}

func TestLighthouseRuleOwnershipAndRestrictions(t *testing.T) {
	for _, changes := range []map[string]any{
		{"Port": "1-65535,80"}, {"Port": "1-65535junk"}, {"Port": "0-65535"},
		{"Port": "1-65536"}, {"Port": "80"}, {"Port": "65535-1"},
		{"Protocol": "ALL"}, {"Protocol": "UDP"}, {"Action": "DROP"},
		{"Ipv6CidrBlock": "::/0"}, {"CidrBlock": "::/0"}, {"CidrBlock": "0.0.0.0/0"},
		{"FirewallRuleDescription": "cdsg:v1:other:tcp4"},
	} {
		m := lighthouseRule()
		maps.Copy(m, changes)
		if r := normalizeLighthouse(m); r.Managed("cdsg:v1:home:tcp4") {
			t.Fatalf("accepted unrelated or malformed rule: %v", changes)
		}
	}
}
