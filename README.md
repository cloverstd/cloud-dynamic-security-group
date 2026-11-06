# Cloud Dynamic Security Group

像 DDNS 一样，定期探测 NAT 后方机器的公网 IPv4，并更新云主机安全组中的 IP 白名单。

支持火山引擎 ECS、腾讯云 CVM、腾讯云轻量应用服务器（Lighthouse）、阿里云 ECS。配置实例 ID，程序自动发现实例级／主网卡绑定的全部安全组；轻量应用服务器直接管理实例防火墙。为当前出口 IP 的 `/32` 添加入站 TCP `1–65535` 放行规则，并清理本部署标记的旧 IP 规则。

## 快速开始

需要 Go 1.26.10 或更高版本，也可以直接使用 Docker 构建。

```sh
CGO_ENABLED=0 go build -trimpath -o bin/cdsg ./cmd/cdsg
cp config.example.yaml config.yaml
cp .env.example .env
chmod 600 config.yaml .env
```

编辑 `config.yaml`，填写实际地域、实例 ID，删除不使用的目标和账号；在本地 `.env` 中填写凭证。`.env` 必须由自己管理，内容仅使用 `KEY=value` 格式。程序读取进程环境变量，不会自动加载 `.env`：

```sh
set -a
. ./.env
set +a

# 首次先预览：仅探测 IP、查询实例和规则，展示拟执行的操作
./bin/cdsg sync --config config.yaml --dry-run

# 单次同步；任一目标失败返回非零退出码
./bin/cdsg sync --config config.yaml

# 启动时立即同步，之后每轮结束等待 interval 再检查
./bin/cdsg run --config config.yaml
```

退出码：`0` 成功或正常信号退出；`1` 单次同步失败；`2` 命令或配置错误。常驻模式记录每轮错误并继续下一轮，收到 SIGINT／SIGTERM 后退出。cron 使用 `sync`，并通过 `flock` 防止多个进程重叠；同一 `owner_id` 的同一安全组应由单个进程负责。

## 同步 Fail2ban Mate

登录 [Fail2ban Mate 后台](https://fail2ban.cloverstd.com/admin)，在「接口接入」创建 Token，将它保存到进程环境变量 `FAIL2BAN_MATE_TOKEN`（Docker Compose 可以使用本地 `.env`）。在 `config.yaml` 启用：

```yaml
owner_id: home
interval: 60s
timeout: 10s
fail2ban_mate:
  base_url: https://fail2ban.cloverstd.com
  token_env: FAIL2BAN_MATE_TOKEN
```

这份配置可独立运行，也可添加 `accounts` 和 `targets` 同步云安全组。每轮将探测到的 IPv4 写入同一条动态规则，换 IP 时替换旧地址，每次成功同步续期 24 小时。配置间隔应留出重试时间。使用 `sync --dry-run` 可检查接入和当前规则，不会更新或续期。

轮换 Token 后更新环境变量并重启进程或容器。要停止放行，在后台撤销该调用方的 Token。单独删除规则后，只要调用程序还在运行，下轮就会重建。停止程序而未撤销时，规则在最后一次成功同步后 24 小时过期。不同出口使用不同 `owner_id`，同一规则由一个进程负责。

## 配置

完整的三云示例见 [config.example.yaml](config.example.yaml)。只使用腾讯云时可以简化为：

```yaml
owner_id: home
interval: 60s
timeout: 10s
ip_sources:
  - https://api.ipify.org
accounts:
  - name: personal
    provider: tencent
    access_key_id_env: TENCENTCLOUD_SECRET_ID
    secret_access_key_env: TENCENTCLOUD_SECRET_KEY
targets:
  - name: server
    account: personal
    region: ap-singapore
    instance_ids: [ins-example]
```

- `owner_id`：1–32 位字母、数字、下划线或连字符。跨重启保持稳定，不同出口部署使用不同值。不要使用公网 IP、密钥或账号 ID。
- `interval`：检查间隔，默认 `60s`，最小 `1s`。
- `timeout`：每次探测／云请求的超时，默认 `10s`，支持 `1s` 至 `5m`。
- `ip_sources`：按顺序尝试的 HTTPS 纯文本 IPv4 查询接口；默认 `https://api.ipify.org`。地址不允许包含用户凭证、查询参数或片段；不跟随重定向。
- `accounts`：可配置多个账号，`provider` 为 `volcengine`、`tencent` 或 `aliyun`。凭证字段填写**环境变量名**。可选 `security_token_env` 用于 STS 临时令牌；配置后变量必须非空。长期运行使用临时凭证时，需要在过期前更新进程环境并重启。
- `targets`：指定本地日志别名、账号名、地域和一个或多个实例 ID。账号及目标别名只接受 1–32 位字母、数字、下划线和连字符。不同目标可以引用同一账号。

腾讯云轻量应用服务器同样使用 `provider: tencent` 和现有腾讯云凭证，将 `instance_ids` 填为 `lhins-…` 即可；程序根据 ID 自动选择 Lighthouse API，无需配置安全组 ID。一个目标中可以同时包含 CVM 的 `ins-…` 和轻量实例的 `lhins-…`。例如，在上面的 `targets` 中添加：

```yaml
  - name: lighthouse
    account: personal
    region: ap-singapore
    instance_ids: [lhins-example]
```

公网 IP 探测强制走 IPv4，忽略 `HTTP_PROXY`／`HTTPS_PROXY`，不读取本机网卡的内网地址。最多读取 1024 字节，只接受公网单个 IPv4；探测全部失败时，本轮不访问云端修改规则。云 API 请求仍可使用系统代理。VPN／系统路由和多出口 NAT 会影响探测结果，应让查询服务和访问目标云主机的连接使用同一出口。

## 更新与归属

腾讯云和阿里云规则使用精确备注 `cdsg:v1:<owner_id>:tcp4`；火山引擎使用 `cdsg.v1.<owner_id>.tcp4`，因为其[规则备注不允许冒号](https://docs.volcengine.com/docs/6401/70748)。程序只管理具有对应平台精确备注的 IPv4 `/32`、完整 TCP 端口入站允许规则；带额外来源组、前缀列表或五元组限制的规则不纳入清理。

每轮执行：

1. 探测公网 IP，并重新查询所有指定实例；实例缺失或普通云主机没有可用安全组时，该目标不写入。
2. 对当前轮中相同账号和地域的共享安全组／轻量实例防火墙去重，完整读取规则。
3. 添加当前 IP；再次查询并确认备注、来源、协议、端口和优先级。
4. 逐条清理本标记的过期规则；每次删除前重新查询，确认当前 IP 的规则仍存在。
5. 再次查询，直到确认旧规则已经清理完毕。

当前 IP 的规则已存在时不重复添加；即使 IP 没变，也会修复被手动删除的规则，并继续上轮失败的清理。重启时通过云端备注恢复，不依赖本地状态文件。

新规则添加或确认失败时保留旧规则。清理失败时保留新规则，并在下轮继续。超时、限流、临时服务错误和版本冲突最多尝试 3 次；每次重试重新读取云端状态，不复用旧索引。各安全组及目标独立处理，最终汇总失败。

腾讯云 CVM 新增规则插入索引 `0`；清理时携带最新版本和索引，版本冲突后重新读取。已有当前规则因其他规则插入而改变索引时，不反复重建。轻量应用服务器分页读取实例防火墙，所有分页必须属于同一版本；删除使用最新 `FirewallVersion` 和完整规则参数，版本冲突或防火墙忙时重新读取并重试。阿里云和火山引擎使用优先级 `1`；阿里云按规则 ID 删除，火山引擎按重新核对的完整参数删除。火山引擎没有规则版本条件删除，读取与删除之间应避免人工或其他程序修改相同规则。

如果当前 IP 已有相同形状的人工规则或其他部署规则，返回 `UnmanagedRuleConflict`，不修改备注、不清理旧规则。阿里云的“重复规则添加成功但不新增”也必须通过重新查询确认归属后才允许清理。两套部署若共享同一出口和安全组，应统一由一个 `owner_id` 管理。

## Docker

发布镜像：`ghcr.io/cloverstd/cloud-dynamic-security-group:latest`，包含 Linux amd64 和 arm64。

```sh
docker compose -f compose.example.yaml pull
docker compose -f compose.example.yaml run --rm cdsg sync --config /config/config.yaml --dry-run
docker compose -f compose.example.yaml up -d
docker compose -f compose.example.yaml logs --tail 50
```

Compose 从本地 `.env` 注入凭证，并只读挂载 `config.yaml`。镜像包含程序和 CA 证书，以非 root 用户运行；构建上下文采用允许列表，不包含真实配置、`.env`、文档或 Git 历史。非 root 容器用户需要读取配置；Linux 上可以保留 `600` 并将文件所有者设为 UID `65532`，或通过受控的组读权限提供访问。

每次推送到 `main`，GitHub Actions 会在测试、漏洞及密钥扫描全部通过后构建并推送 GHCR，更新 `latest` 和 `sha-<完整提交 SHA>` 标签；推送 `v*` 标签时发布同名镜像标签。Pull Request 只运行验证，不发布镜像。工作流使用内置 `GITHUB_TOKEN`，不需要配置额外的镜像仓库密码或云凭证。

GHCR 首次发布的包可能默认为私有；如需匿名拉取，在 [Package settings](https://github.com/users/cloverstd/packages/container/cloud-dynamic-security-group/settings) 中将可见性设为 Public。私有包需要先使用具有 `read:packages` 权限的凭证执行 `docker login ghcr.io`。

固定版本可将 Compose 中的 `latest` 换成 `sha-<完整提交 SHA>` 或发布标签。自行构建可执行 `docker build -t cdsg:local .`；Dockerfile 通过交叉编译支持 `docker buildx build --platform linux/amd64,linux/arm64 ...`，不需要 QEMU。

## 云账号最小操作权限

只需要以下查询和入站规则增删权限，不需要创建安全组、绑定实例、修改出站规则或修改实例权限。按使用的实例类型授予对应权限即可。资源级策略应按平台支持情况限制在目标实例和安全组；查询操作如不支持资源级授权，单独授予查询权限。

| 平台 | 必需 Action |
|---|---|
| 火山引擎 | `ecs:DescribeInstances`、`vpc:DescribeSecurityGroupAttributes`、`vpc:AuthorizeSecurityGroupIngress`、`vpc:RevokeSecurityGroupIngress` |
| 腾讯云 CVM | `cvm:DescribeInstances`、`vpc:DescribeSecurityGroupPolicies`、`vpc:CreateSecurityGroupPolicies`、`vpc:DeleteSecurityGroupPolicies` |
| 腾讯云轻量应用服务器 | `lighthouse:DescribeInstances`、`lighthouse:DescribeFirewallRules`、`lighthouse:CreateFirewallRules`、`lighthouse:DeleteFirewallRules` |
| 阿里云 | `ecs:DescribeInstances`、`ecs:DescribeSecurityGroupAttribute`、`ecs:AuthorizeSecurityGroup`、`ecs:RevokeSecurityGroup` |

`--dry-run` 只需要查询权限。官方接口参考：[火山引擎实例查询](https://docs.volcengine.com/docs/ecs/DescribeInstances?lang=en)、[火山引擎规则查询](https://docs.volcengine.com/docs/virtual-private-cloud/describe-security-group-attributes-queryingthedetailsofsecuritygroup?lang=en)、[腾讯云规则查询](https://cloud.tencent.com/document/api/215/15804)、[腾讯云规则删除及版本校验](https://cloud.tencent.com/document/product/215/15809)、[阿里云规则添加](https://help.aliyun.com/zh/ecs/developer-reference/api-ecs-2014-05-26-authorizesecuritygroup)、[阿里云规则查询及分页](https://help.aliyun.com/zh/ecs/developer-reference/api-ecs-2014-05-26-describesecuritygroupattribute)。

轻量应用服务器接口参考：[实例查询](https://cloud.tencent.com/document/product/1207/47573)、[防火墙查询及分页](https://cloud.tencent.com/document/api/1207/48252)、[添加规则](https://cloud.tencent.com/document/api/1207/48254)、[删除规则及版本校验](https://cloud.tencent.com/document/product/1207/48253)。

## 边界与清理

支持标准 ECS／CVM 的实例级及主网卡安全组，以及腾讯云轻量应用服务器的实例防火墙；不支持其他云厂商的轻量实例、附加网卡或 IPv6。共享安全组的所有关联实例都会受到规则影响。放行规则不会覆盖已有拒绝策略、主机防火墙或服务监听配置，也不会收窄已存在的全网开放规则。

删除配置中的目标、解绑安全组、修改 `owner_id` 或停止程序后，已有规则会保留。清理步骤：停止旧进程，找到原地域及安全组（轻量应用服务器进入对应实例的防火墙），在控制台按对应平台的完整备注筛选（火山引擎为 `cdsg.v1.<原 owner_id>.tcp4`，腾讯云和阿里云为 `cdsg:v1:<原 owner_id>:tcp4`），核对来源、协议、端口和入站方向后删除对应规则。程序不扫描整个账号清理配置范围以外的安全组或实例防火墙。

规则配额不足时，新增失败并保留旧规则；需要先释放配额后重试。人工修改了托管规则的备注或形状时，该规则不再自动删除，应按上面的步骤核对清理。

## 脱敏与验证

凭证只在运行时读取。日志输出安全别名、操作、错误码，以及 IP／资源 ID 的短 SHA-256 摘要，不输出完整 IP、资源 ID、凭证、签名、SDK 错误正文或请求响应。检测到第三方 SDK 的 `DEBUG=dara`／`DEBUG=sdk` 请求日志开关时，程序拒绝发起云请求，请先清除该开关。

`.gitignore` 排除本地配置、`.env`、密钥和日志；公开示例仅包含占位符。提交前检查 `git diff --cached`，并执行密钥扫描：

```sh
go test -race ./...
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
docker build -t cdsg:local .
docker run --rm -v "$PWD:/repo" zricethezav/gitleaks:v8.24.3 dir /repo --redact --no-banner
# 首次提交后、push 前扫描待推送历史
docker run --rm -v "$PWD:/repo" zricethezav/gitleaks:v8.24.3 git /repo --redact --no-banner --log-opts="--all"
```

测试使用模拟 HTTP／SDK 接口，覆盖三家官方 SDK 的签名、临时令牌、响应解析、分页、同步和故障保留流程。CI 执行 race 测试、vet、漏洞扫描、Docker 构建和全历史密钥扫描。真实云联调需要部署者提供本地凭证与测试实例，先执行 `--dry-run` 再单次同步；自动化测试不等同于真实云联调。
