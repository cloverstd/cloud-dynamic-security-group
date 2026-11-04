package cloud

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/cloverstd/cloud-dynamic-security-group/internal/config"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

type callFunc func(context.Context, string, string, map[string]any, any) error

func (f callFunc) Call(c context.Context, s, a string, m map[string]any, o any) error {
	return f(c, s, a, m, o)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOfficialSDKEnvelopesSigningAndTokens(t *testing.T) {
	for _, name := range []string{"aliyun", "tencent", "volcengine"} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			c := &sdkCaller{provider: name, region: "cn-beijing", key: "example-id", secret: "example-secret", token: "example-session", timeout: time.Second}
			c.http = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.Scheme != "https" {
					t.Fatal("expected TLS")
				}
				if r.Context().Err() != nil {
					t.Fatal("unexpected canceled request")
				}
				var envelope any
				switch name {
				case "tencent":
					if r.Header.Get("Authorization") == "" || r.Header.Get("X-TC-Token") != "example-session" || r.Header.Get("X-TC-Action") != "DescribeInstances" {
						t.Fatal("Tencent SDK omitted signed headers")
					}
					var body map[string]any
					if json.NewDecoder(r.Body).Decode(&body) != nil || body["Limit"] != float64(100) {
						t.Fatal("invalid request body")
					}
					envelope = map[string]any{"Response": map[string]any{"ok": true, "RequestId": "example"}}
				case "volcengine":
					if r.Header.Get("Authorization") == "" || r.URL.Query().Get("Action") != "DescribeInstances" || r.URL.Query().Get("InstanceIds.1") != "i-example" {
						t.Fatalf("invalid Volcengine request path or signature")
					}
					if r.Header.Get("X-Security-Token") != "example-session" {
						t.Fatal("missing session token")
					}
					envelope = map[string]any{"ResponseMetadata": map[string]any{"RequestId": "example"}, "Result": map[string]any{"ok": true}}
				case "aliyun":
					if r.Header.Get("Authorization") == "" {
						t.Fatal("missing Alibaba signature")
					}
					if r.Body == nil {
						r.Body = http.NoBody
					}
					if err := r.ParseForm(); err != nil {
						t.Fatal(err)
					}
					if strings.Join(r.Header["x-acs-security-token"], "") != "example-session" && r.Form.Get("SecurityToken") != "example-session" {
						t.Fatal("missing Alibaba session token")
					}
					if r.Form.Get("RegionId") != "cn-beijing" {
						t.Fatal("missing region")
					}
					envelope = map[string]any{"ok": true, "RequestId": "example"}
				}
				b, _ := json.Marshal(envelope)
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(b))), Request: r}, nil
			})}
			args := map[string]any{"Limit": 100, "InstanceIds.1": "i-example"}
			service := "ecs"
			if name == "tencent" {
				service = "cvm"
			}
			var out map[string]any
			if err := c.Call(context.Background(), service, "DescribeInstances", args, &out); err != nil {
				t.Fatal(err)
			}
			if calls != 1 || out["ok"] != true {
				t.Fatalf("failed to unwrap response: %v", out)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if c.Call(ctx, service, "DescribeInstances", args, &out) == nil || calls != 1 {
				t.Fatal("canceled call was sent")
			}
		})
	}
}

func TestDiscoverPaginationAndPrimaryNIC(t *testing.T) {
	for _, name := range []string{"aliyun", "tencent", "volcengine"} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			p := Adapter{Name: name}
			p.API = callFunc(func(_ context.Context, service, action string, args map[string]any, out any) error {
				calls++
				if action != "DescribeInstances" {
					t.Fatal(action)
				}
				result := map[string]any{}
				if calls == 1 {
					inst := map[string]any{"InstanceId": "i-example"}
					switch name {
					case "tencent":
						inst["SecurityGroupIds"] = []string{"sg-example", "sg-example"}
						result = map[string]any{"TotalCount": 2, "InstanceSet": []any{inst}}
					case "aliyun":
						inst["SecurityGroupIds"] = map[string]any{"SecurityGroupId": []string{"sg-example"}}
						result = map[string]any{"NextToken": "next", "Instances": map[string]any{"Instance": []any{inst}}}
					case "volcengine":
						inst["NetworkInterfaces"] = []any{
							map[string]any{"Type": "primary", "SecurityGroupIds": []string{"sg-example"}},
							map[string]any{"Type": "secondary", "SecurityGroupIds": []string{"sg-ignore"}},
						}
						result = map[string]any{"NextToken": "next", "Instances": []any{inst}}
					}
				} else {
					if name == "tencent" {
						if args["Offset"] != 1 {
							t.Fatal("offset")
						}
						result = map[string]any{"TotalCount": 2, "InstanceSet": []any{map[string]any{"InstanceId": "i-unrelated"}}}
					} else if args["NextToken"] != "next" {
						t.Fatal("token")
					}
				}
				return decode(result, out)
			})
			groups, err := p.Discover(context.Background(), []string{"i-example"})
			if err != nil || !reflect.DeepEqual(groups, []string{"sg-example"}) || calls != 2 {
				t.Fatalf("%v %v, calls %d", groups, err, calls)
			}
			p.API = callFunc(func(_ context.Context, _, _ string, _ map[string]any, out any) error {
				return decode(map[string]any{}, out)
			})
			if _, err = p.Discover(context.Background(), []string{"i-missing"}); err == nil {
				t.Fatal("missing instance accepted")
			}
		})
	}
}

func TestAlibabaRulePaginationFailureIsAtomic(t *testing.T) {
	calls := 0
	p := Adapter{Name: "aliyun", API: callFunc(func(_ context.Context, _, _ string, args map[string]any, out any) error {
		calls++
		if calls == 1 {
			return decode(map[string]any{"Permissions": map[string]any{"Permission": []any{map[string]any{"Direction": "ingress"}}}, "NextToken": "next"}, out)
		}
		if args["NextToken"] != "next" {
			t.Fatal("no pagination")
		}
		return APIError("AccessDenied")
	})}
	s, err := p.List(context.Background(), "sg-example")
	if err == nil || len(s.Rules) != 0 || calls != 2 {
		t.Fatal("partial rules escaped failed query")
	}
}

func TestRuleParametersAndDeletionIdentity(t *testing.T) {
	for _, name := range []string{"aliyun", "tencent", "volcengine"} {
		t.Run(name, func(t *testing.T) {
			p := Adapter{Name: name}
			calls := 0
			p.API = callFunc(func(_ context.Context, _, action string, args map[string]any, out any) error {
				calls++
				if args["SecurityGroupId"] != "sg-example" {
					t.Fatal("group")
				}
				if calls == 1 {
					switch name {
					case "tencent":
						set := object(args["SecurityGroupPolicySet"])
						r := object(array(set["Ingress"])[0])
						if r["Port"] != "1-65535" || r["PolicyIndex"] != 0 || r["Protocol"] != "TCP" || r["PolicyDescription"] != "cdsg:v1:home:tcp4" {
							t.Fatal("Tencent add parameters")
						}
					case "volcengine":
						if args["PortStart"] != 1 || args["PortEnd"] != 65535 || args["Priority"] != 1 || args["Protocol"] != "tcp" {
							t.Fatal("Volcengine add parameters")
						}
					case "aliyun":
						if args["Permissions.1.PortRange"] != "1/65535" || args["Permissions.1.SourceCidrIp"] != "8.8.8.8/32" || args["Permissions.1.Description"] != "cdsg:v1:home:tcp4" {
							t.Fatal("Alibaba add parameters")
						}
					}
				} else {
					switch name {
					case "tencent":
						set := object(args["SecurityGroupPolicySet"])
						if set["Version"] != "latest" || object(array(set["Ingress"])[0])["PolicyIndex"] != 7 {
							t.Fatal("delete missing index/version")
						}
					case "volcengine":
						if args["Description"] != "cdsg:v1:home:tcp4" || args["CidrIp"] != "8.8.8.8/32" || args["Priority"] != 1 {
							t.Fatal("delete missing tuple")
						}
					case "aliyun":
						if args["SecurityGroupRuleId.1"] != "sgr-example" {
							t.Fatal("delete missing ID")
						}
					}
				}
				return decode(map[string]any{}, out)
			})
			r := Rule{ID: "sgr-example", CIDR: "8.8.8.8/32", Description: "cdsg:v1:home:tcp4", Protocol: "tcp", Action: "accept", Start: 1, End: 65535, Priority: 1}
			if err := p.Add(context.Background(), "sg-example", r); err != nil {
				t.Fatal(err)
			}
			if name == "tencent" {
				r.ID = "7"
			}
			if err := p.Delete(context.Background(), "sg-example", r, "latest"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRuleOwnershipAndRestrictions(t *testing.T) {
	p := Adapter{Name: "aliyun"}
	base := map[string]any{"Direction": "ingress", "Policy": "accept", "IpProtocol": "TCP", "PortRange": "1/65535", "SourceCidrIp": "8.8.8.8/32", "SecurityGroupRuleId": "sgr-example", "Description": "cdsg:v1:home:tcp4", "Priority": float64(1)}
	r, ok := p.normalize(base)
	if !ok || !r.Managed("cdsg:v1:home:tcp4") || r.Managed("cdsg:v1:other:tcp4") {
		t.Fatal("ownership matching")
	}
	for _, field := range []string{"SourcePrefixListId", "SourceGroupId", "DestCidrIp", "SourcePortRange"} {
		m := map[string]any{}
		for k, v := range base {
			m[k] = v
		}
		m[field] = "restricted"
		r, _ := p.normalize(m)
		if r.Managed("cdsg:v1:home:tcp4") {
			t.Fatalf("accepted restricted %s", field)
		}
	}
	if err := sanitized(errors.New("sensitive URL and credentials")); strings.Contains(err.Error(), "sensitive") {
		t.Fatal("SDK error leak")
	}
	if !Retryable(APIError("RequestLimitExceeded")) || Retryable(APIError("LimitExceeded.SecurityGroupPolicySet")) {
		t.Fatal("bad retry classification")
	}
}

func TestOfficialSDKErrorsAreSanitized(t *testing.T) {
	for _, name := range []string{"aliyun", "tencent", "volcengine"} {
		t.Run(name, func(t *testing.T) {
			for _, code := range []string{"AccessDenied", "QuotaExceeded", "RequestLimitExceeded"} {
				c := &sdkCaller{provider: name, region: "cn-beijing", key: "example-id", secret: "example-secret", timeout: time.Second}
				c.http = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					apiErr := map[string]any{"Code": code, "Message": "sensitive-error-content"}
					var body any
					switch name {
					case "tencent":
						body = map[string]any{"Response": map[string]any{"Error": apiErr, "RequestId": "example"}}
					case "volcengine":
						body = map[string]any{"ResponseMetadata": map[string]any{"Error": apiErr, "RequestId": "example"}}
					case "aliyun":
						body = map[string]any{"Code": code, "Message": "sensitive-error-content", "RequestId": "example"}
					}
					b, _ := json.Marshal(body)
					return &http.Response{StatusCode: 400, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(b))), Request: r}, nil
				})}
				var out map[string]any
				err := c.Call(context.Background(), "vpc", "DescribeSecurityGroupPolicies", map[string]any{}, &out)
				if err == nil || strings.Contains(err.Error(), "sensitive-error-content") || !strings.Contains(err.Error(), code) {
					t.Fatalf("error classification: %v", err)
				}
				if Retryable(err) != (code == "RequestLimitExceeded") {
					t.Fatalf("retry classification: %v", err)
				}
			}
		})
	}
}

func TestIncompleteRulesAndRepeatedPaginationFailClosed(t *testing.T) {
	for _, name := range []string{"aliyun", "tencent", "volcengine"} {
		p := Adapter{Name: name, API: callFunc(func(_ context.Context, _, _ string, _ map[string]any, out any) error {
			return decode(map[string]any{}, out)
		})}
		if _, err := p.List(context.Background(), "sg-example"); err == nil {
			t.Fatalf("accepted missing %s rules", name)
		}
	}
	p := Adapter{Name: "aliyun", API: callFunc(func(_ context.Context, _, _ string, _ map[string]any, out any) error {
		return decode(map[string]any{"NextToken": "same", "Permissions": map[string]any{"Permission": []any{}}}, out)
	})}
	if _, err := p.List(context.Background(), "sg-example"); err == nil {
		t.Fatal("accepted repeated token")
	}
}

func TestCredentialsAndDebugGuard(t *testing.T) {
	a := config.Account{Provider: "aliyun", AccessKeyIDEnv: "CDSG_TEST_ID", SecretAccessKeyEnv: "CDSG_TEST_SECRET", SecurityTokenEnv: "CDSG_TEST_TOKEN"}
	t.Setenv("DEBUG", "")
	t.Setenv(a.AccessKeyIDEnv, "example-id")
	t.Setenv(a.SecretAccessKeyEnv, "example-secret")
	t.Setenv(a.SecurityTokenEnv, "")
	if _, err := New(a, "cn-beijing", time.Second); err == nil {
		t.Fatal("accepted empty configured token")
	}
	t.Setenv(a.SecurityTokenEnv, "example-token")
	if _, err := New(a, "cn-beijing", time.Second); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEBUG", "dara")
	if _, err := New(a, "cn-beijing", time.Second); err == nil {
		t.Fatal("allowed unredacted SDK logging")
	}
}
