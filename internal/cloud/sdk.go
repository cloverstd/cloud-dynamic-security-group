package cloud

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	"github.com/alibabacloud-go/tea/dara"
	tc "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	tcerr "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	tchttp "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/http"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	"github.com/volcengine/volcengine-go-sdk/volcengine"
	"github.com/volcengine/volcengine-go-sdk/volcengine/credentials"
	"github.com/volcengine/volcengine-go-sdk/volcengine/request"
	"github.com/volcengine/volcengine-go-sdk/volcengine/session"
	"github.com/volcengine/volcengine-go-sdk/volcengine/universal"
	"github.com/volcengine/volcengine-go-sdk/volcengine/volcengineerr"

	"github.com/cloverstd/cloud-dynamic-security-group/internal/config"
)

type sdkCaller struct {
	provider, region, key, secret, token string
	timeout                              time.Duration
	http                                 *http.Client
}

func New(a config.Account, region string, timeout time.Duration) (Provider, error) {
	// Tea can enable unredacted HTTP logging from DEBUG at package init time.
	// Refuse requests in that mode instead of risking credential disclosure.
	for _, flag := range strings.Split(os.Getenv("DEBUG"), ",") {
		if flag == "dara" || flag == "sdk" {
			return nil, errors.New("SDK request debug logging is enabled; unset DEBUG")
		}
	}
	key, secret := os.Getenv(a.AccessKeyIDEnv), os.Getenv(a.SecretAccessKeyEnv)
	if key == "" || secret == "" {
		return nil, errors.New("required credential environment variables are empty")
	}
	token := ""
	if a.SecurityTokenEnv != "" {
		token = os.Getenv(a.SecurityTokenEnv)
		if token == "" {
			return nil, errors.New("configured security token environment variable is empty")
		}
	}
	c := &sdkCaller{provider: a.Provider, region: region, key: key, secret: secret, token: token, timeout: timeout, http: &http.Client{Timeout: timeout}}
	return &Adapter{Name: a.Provider, API: c}, nil
}

type contextHTTP struct {
	ctx    context.Context
	client *http.Client
}

func (c contextHTTP) Call(r *http.Request, _ *http.Transport) (*http.Response, error) {
	return c.client.Do(r.WithContext(c.ctx))
}

func sanitized(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return APIError("Timeout")
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return APIError("NetworkError")
	}
	var te *tcerr.TencentCloudSDKError
	if errors.As(err, &te) {
		return APIError(te.GetCode())
	}
	var ve volcengineerr.Error
	if errors.As(err, &ve) {
		return APIError(ve.Code())
	}
	var ae interface{ GetCode() *string }
	if errors.As(err, &ae) && ae.GetCode() != nil {
		return APIError(*ae.GetCode())
	}
	return APIError("RequestFailed")
}

func (c *sdkCaller) Call(ctx context.Context, service, action string, args map[string]any, out any) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	switch c.provider {
	case "tencent":
		cp := profile.NewClientProfile()
		cp.HttpProfile.ReqTimeout = int(c.timeout.Seconds())
		cp.NetworkFailureMaxRetries = 0
		cp.RateLimitExceededMaxRetries = 0
		client := tc.NewCommonClient(tc.NewTokenCredential(c.key, c.secret, c.token), c.region, cp)
		if c.http.Transport != nil {
			client.WithHttpTransport(c.http.Transport)
		}
		version := "2017-03-12"
		if service == "lighthouse" {
			version = "2020-03-24"
		}
		req := tchttp.NewCommonRequest(service, version, action)
		req.SetContext(ctx)
		if err := req.SetActionParameters(args); err != nil {
			return sanitized(err)
		}
		resp := tchttp.NewCommonResponse()
		if err := client.Send(req, resp); err != nil {
			return sanitized(err)
		}
		var envelope struct{ Response json.RawMessage }
		if json.Unmarshal(resp.GetBody(), &envelope) != nil || len(envelope.Response) == 0 {
			return APIError("InvalidResponse")
		}
		if json.Unmarshal(envelope.Response, out) != nil {
			return APIError("InvalidResponse")
		}
		return nil
	case "volcengine":
		sess, err := session.NewSession(&volcengine.Config{Region: volcengine.String(c.region), Credentials: credentials.NewStaticCredentials(c.key, c.secret, c.token), HTTPClient: c.http, MaxRetries: volcengine.Int(0)})
		if err != nil {
			return sanitized(err)
		}
		sess.Handlers.Validate.PushFront(func(r *request.Request) { r.SetContext(ctx) })
		resp, err := universal.New(sess).DoCall(universal.RequestUniversal{ServiceName: service, Action: action, Version: "2020-04-01", HttpMethod: universal.GET}, &args)
		if err != nil {
			return sanitized(err)
		}
		if resp == nil {
			return APIError("InvalidResponse")
		}
		// The universal map API retains the ResponseMetadata/Result envelope.
		payload := (*resp)["Result"]
		if payload == nil {
			if action == "AuthorizeSecurityGroupIngress" || action == "RevokeSecurityGroupIngress" {
				return nil
			}
			return APIError("InvalidResponse")
		}
		return decode(payload, out)
	case "aliyun":
		client, err := openapi.NewClient(&openapi.Config{AccessKeyId: dara.String(c.key), AccessKeySecret: dara.String(c.secret), SecurityToken: dara.String(c.token), RegionId: dara.String(c.region), Endpoint: dara.String("ecs." + c.region + ".aliyuncs.com"), HttpClient: contextHTTP{ctx, c.http}})
		if err != nil {
			return sanitized(err)
		}
		// Preserve typed OpenAPI errors so only the code is exposed to callers.
		client.DisableSDKError = dara.Bool(true)
		query := map[string]*string{"RegionId": dara.String(c.region)}
		for k, v := range args {
			query[k] = dara.String(fmt.Sprint(v))
		}
		resp, err := client.CallApi(&openapi.Params{Action: dara.String(action), Version: dara.String("2014-05-26"), Protocol: dara.String("HTTPS"), Pathname: dara.String("/"), Method: dara.String("POST"), AuthType: dara.String("AK"), BodyType: dara.String("json"), ReqBodyType: dara.String("formData"), Style: dara.String("RPC")}, &openapi.OpenApiRequest{Query: query}, &dara.RuntimeOptions{Autoretry: dara.Bool(false), ReadTimeout: dara.Int(int(c.timeout.Milliseconds())), ConnectTimeout: dara.Int(int(c.timeout.Milliseconds()))})
		if err != nil {
			return sanitized(err)
		}
		if resp["body"] == nil {
			return APIError("InvalidResponse")
		}
		return decode(resp["body"], out)
	}
	return APIError("UnsupportedProvider")
}
