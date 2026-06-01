# NJAU Proxy

一个轻量的 HTTPS 出站中转 API。Cloudflare Workers 或 Pages 调用阿里云服务器上的 HTTPS 域名，宿主机上的现有 Node 反向代理将请求转发到 `127.0.0.1:8787`。Fastify 容器通过宿主机的 Tailscale Android exit node 使用校园网出口访问白名单站点。

## 架构

```text
Cloudflare Workers/Pages
        |
        | HTTPS
        v
宿主机现有 Node 反向代理
        |
        | http://127.0.0.1:8787
        v
Docker Compose: Fastify API
        |
        | network_mode: host
        v
宿主机 Tailscale -> Android exit node -> 校园网 -> 目标网站
```

容器使用 Linux 的 host 网络模式，不声明 `ports`。Fastify 只监听 `127.0.0.1:8787`，不会直接向公网开放端口。

## 快速启动

要求：Linux 服务器已安装 Docker Engine 和 Docker Compose 插件。

```bash
git clone <YOUR_REPOSITORY_URL> /opt/njau-proxy
cd /opt/njau-proxy

cp .env.example .env
openssl rand -hex 32
```

将生成的随机值写入 `.env` 的 `PROXY_TOKEN`，然后启动：

```bash
docker compose up -d --build
docker compose ps
docker compose logs -f
```

检查本机健康状态：

```bash
curl http://127.0.0.1:8787/healthz
```

预期返回：

```json
{"ok":true}
```

更新代码后重新构建：

```bash
cd /opt/njau-proxy
docker compose up -d --build
```

## 环境变量

`.env.example` 提供了完整配置：

```dotenv
PROXY_TOKEN=replace-with-a-long-random-token
ALLOWED_HOSTS=libyy.njau.edu.cn,authserver.njau.edu.cn,vpn2.njau.edu.cn
HOST=127.0.0.1
PORT=8787
RATE_LIMIT_MAX=60
RATE_LIMIT_WINDOW=1 minute
MAX_RESPONSE_BYTES=5242880
LOG_LEVEL=info
```

- `PROXY_TOKEN`：必填，至少 16 个字符。生产环境建议使用 `openssl rand -hex 32`。
- `ALLOWED_HOSTS`：逗号分隔的精确主机名白名单，不自动允许子域名。
- `RATE_LIMIT_MAX`：单个来源在窗口期内允许的请求数。
- `MAX_RESPONSE_BYTES`：解压后的上游响应体大小限制，默认 5 MiB。

不要将 `.env` 提交到版本库。

## 宿主机 Node 反向代理

你现有的 Node 反向代理只需将 HTTPS 域名对应的后端目标设为：

```text
http://127.0.0.1:8787
```

建议只向公网路由 `/proxy/fetch`。TLS 证书、域名解析、反代框架和公网端口继续由宿主机现有服务管理。

## Tailscale Android Exit Node

### 1. 配置安卓手机

1. 将安卓手机连接到校园网。
2. 安装 Tailscale，并加入与阿里云服务器相同的 tailnet。
3. 在安卓客户端中选择 `Exit node > Run exit node`。
4. 打开 Tailscale 管理台，在该设备的路由设置中批准 `Use as exit node`。
5. 建议为该手机关闭 key expiry，并在长时间运行时保持接电。

安卓 exit node 使用 userspace routing，性能有限，适合本项目这类轻量 API。参考：[Tailscale Exit Nodes](https://tailscale.com/docs/features/exit-nodes)。

### 2. 配置阿里云宿主机

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
tailscale status
sudo tailscale set --exit-node=<ANDROID_DEVICE_NAME>
tailscale status
```

也可以使用 Tailscale 分配给安卓手机的 IP：

```bash
sudo tailscale set --exit-node=<ANDROID_TAILSCALE_IP>
```

确认默认出站已经切换：

```bash
curl https://ifconfig.me
```

该公网 IP 应与安卓手机校园网出口一致。由于 Compose 使用 `network_mode: host`，容器请求沿用宿主机的 Tailscale 出站路径。

## API

### `POST /proxy/fetch`

请求头：

```http
Authorization: Bearer ${PROXY_TOKEN}
Content-Type: application/json
```

请求体：

```json
{
  "url": "https://libyy.njau.edu.cn/xxx",
  "method": "GET",
  "headers": {},
  "body": null,
  "timeoutMs": 15000
}
```

成功响应：

```json
{
  "ok": true,
  "status": 200,
  "headers": {},
  "body": "...",
  "contentType": "text/html"
}
```

错误响应：

```json
{
  "ok": false,
  "error": {
    "code": "ERROR_CODE",
    "message": "..."
  }
}
```

服务只允许 HTTPS、端口 `443` 和方法 `GET|POST|PUT|DELETE`。每次请求和每次重定向都会重新检查精确域名白名单和 DNS 解析结果。localhost、私网、链路本地、保留地址、metadata 地址及 IPv4-mapped IPv6 均会被拒绝。

### 服务器测试

```bash
curl -H "Authorization: Bearer xxx" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://libyy.njau.edu.cn","method":"GET"}' \
  https://proxy.example.com/proxy/fetch
```

将 `xxx` 替换为 `.env` 中的 `PROXY_TOKEN`，将域名替换为你实际配置的域名。

## Cloudflare Worker 示例

示例位于 `examples/cloudflare-worker/`。先进入目录并安装 Wrangler：

```bash
cd examples/cloudflare-worker
npm init -y
npm install --save-dev wrangler
```

编辑 `wrangler.jsonc` 中的 `PROXY_ENDPOINT`，再设置 secret 并部署：

```bash
npx wrangler secret put PROXY_TOKEN
npx wrangler deploy
```

本地开发可创建不提交版本库的 `.dev.vars`：

```dotenv
PROXY_TOKEN=replace-with-the-same-token-as-server
```

Cloudflare 官方建议通过 secret 管理敏感值，而不是将 Token 写入源码或 `vars`：[Workers Secrets](https://developers.cloudflare.com/workers/configuration/secrets/)。

Worker 调用示例：

```bash
curl -H "Content-Type: application/json" \
  -d '{"url":"https://libyy.njau.edu.cn","method":"GET"}' \
  https://<YOUR_WORKER_DOMAIN>/
```

## 本地验证

宿主机安装 Node.js 24 后可运行：

```bash
npm install
npm test
npm run check
```

测试覆盖鉴权、白名单、HTTPS 限制、私网与 metadata DNS 拦截、1 MiB 请求体限制、30 秒超时上限、重定向检查、跨域重定向凭据清理、上游响应限制错误和速率限制。
