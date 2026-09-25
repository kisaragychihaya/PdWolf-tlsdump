---
name: tls-capture-debug
description: 用 tlsdump 抓取并调试 TLS/HTTPS 连接。当用户需要排查 TLS 握手失败、证书错误（证书不受信、pinning、自签上游）、SNI/域名不匹配、HTTP/2 协商问题、代理或 MITM 解密不生效，或想捕获分析 HTTPS 请求响应内容时使用。也适用于"为什么这个 HTTPS 请求失败/抓不到/没解密"类问题。
---

# TLS 抓包调试（tlsdump）

用 [tlsdump](https://github.com/kisaragychihaya/PdWolf-tlsdump) 做 HTTPS 流量解密 + 按域名白名单记录（JSONL），白名单外流量纯转发不记录。两种模式：**proxy**（本地代理，推荐首选）和 **tun**（虚拟网卡接管全网流量，需管理员/root）。

## 准备工作

1. 确认 tlsdump 可用：Release 下载或 `go build -o tlsdump.exe ./cmd/tlsdump`（Windows 构建需先按 README 放置 wintun.dll）。
2. 首次运行后在 `ca/` 生成根证书。**客户端必须信任它**，否则抓到的全是证书错误：
   - curl：`--cacert ca/ca.crt`（Windows 的 curl 还必须加 `--ssl-no-revoke`，schannel 会对无 CRL 的本地 CA 报吊销状态未知）
   - 系统级：导入系统信任库（Windows 双击 ca.crt 安装到"受信任的根证书颁发机构"）
3. 调试时始终加 `-v`，判定日志都在 Debug 级。

## 工作流 A：proxy 模式（首选，按应用抓）

```bash
tlsdump -mode proxy -listen 127.0.0.1:8080 \
    -domains example.com,api.example.com \
    -record rec.jsonl -v

# 客户端走代理（curl 示例；其他应用设 HTTP/SOCKS 代理或系统代理）
curl -x 127.0.0.1:8080 --cacert ca/ca.crt https://example.com/        # Linux/macOS
curl -x 127.0.0.1:8080 --cacert ca/ca.crt --ssl-no-revoke https://example.com/  # Windows
```

域名多时用文件：`-domains domains.txt`（每行一个，支持 `#` 注释）。迭代调试推荐 YAML + 热重载（改配置不重启）：

```yaml
# debug.yaml
mode: proxy
listen: 127.0.0.1:8080
domains: [example.com]
record: rec.jsonl
verbose: true
body_limit: 65536
```

```bash
tlsdump -config debug.yaml   # 改 yaml 后 2 秒内自动生效；domains/body_limit/record 可热重载
```

## 工作流 B：tun 模式（接管整台机器流量）

```bash
sudo tlsdump -mode tun -domains example.com -record rec.jsonl -v   # Windows 用管理员终端
```

- 程序会加 `0.0.0.0/1` + `128.0.0.0/1` 两条大路由接管全部 IPv4（含 UDP/DNS）。
- **必须 Ctrl+C 或 SIGTERM 退出**才会清理路由；异常退出后运行 `tlsdump -tun-reset` 恢复。
- **不要与其他 TUN 工具（Clash TUN 等）同时运行**，路由互相冲突会直接断网。
- macOS 设备名固定为内核分配的 `utunN`；出口异常时 `-tun-physical-iface en0` 显式指定网卡。

## 读结果：判定日志 + JSONL

Debug 日志（stderr）中每条连接的判定关键词：

| 日志 | 含义 |
|---|---|
| `intercept TLS sni=...` | 命中白名单，已 MITM 解密 |
| `bypass TLS sni=... host=...` | TLS 但未命中白名单，盲转发。**看 sni/host 是否如预期** |
| `bypass HTTP host=...` | 明文 HTTP 未命中白名单 |
| `bypass unknown traffic` | 首字节既非 TLS 也非 HTTP（可能是私有协议/代理协议不对） |
| `conn open` / `conn closed` | 连接生命周期；只有 open 没有 closed 说明连接卡死 |
| `tun: stats`（每 5s） | tun 模式收发计数，定位流量断在哪一段 |

JSONL 每行一条请求/响应（可用 `jq` 或 `python -m json.tool` 查看）：

```bash
jq -r '[.time, .mode, .host, .method, .uri, .status] | @tsv' rec.jsonl
jq -r 'select(.host=="api.example.com") | .req_body' rec.jsonl
```

关键字段：`mode`（mitm/http）、`status`、`req_body`/`resp_body`（非 UTF-8 自动 base64）、`*_body_truncated`（超 `-body-limit` 截断，调大 `-body-limit` 重试）。

## 常见 TLS 问题排查路径

1. **抓不到任何记录** → 客户端没走代理（检查代理设置/CONNECT 是否到达，看有没有 `conn open` 日志）。
2. **`bypass TLS` 但域名在白名单里** → 比对日志里的 `sni=` 和 `host=`：SNI 缺失（IP 直连）时回退用目标 host；多域名证书/SNI 与实际请求域名不一致也会这样。确认白名单后缀匹配（`example.com` 自动含子域名）。
3. **客户端报证书不受信** → CA 没装好（见准备工作）；curl 在 Windows 缺 `--ssl-no-revoke`。
4. **`CERT_TRUST_IS_PARTIAL_CHAIN`（Windows schannel）** → 该连接被 **bypass** 了（拿到的是真实网站证书，而 curl 只带了本地 CA）。这是预期行为，不是错误。
5. **TLS 握手失败 / upstream 证书错误** → 上游自签或证书 pinning：加 `-insecure-skip-verify`（仅调试用）。
6. **解密成功但响应异常** → 看 JSONL 的 `status` 和 `resp_headers`；HTTP/2（ALPN h2）与 HTTP/1.1 路径不同，可用 `curl --http1.1` 对比排查。
7. **tun 模式断网** → 多半是路由回路或其他 TUN 工具冲突；`-tun-no-route` 跳过路由配置做隔离排查，`-tun-reset` 清理残留。

## 安全红线

- `ca/ca.key` 是根 CA 私钥，不外发、不提交。
- `rec.jsonl` 含解密后的明文流量，按敏感数据处理，调试完及时清理。
- `-insecure-skip-verify` 只在调试自签/pinning 上游时使用。

## 快速参数参考

| 参数 | 说明 |
|---|---|
| `-mode` | `proxy`（默认）/ `tun` |
| `-config` | YAML 配置文件（支持热重载，见 README「配置文件」一节） |
| `-domains` | 逗号分隔域名或列表文件；`-tun-exclude-domains` 额外豁免域名（tun 模式） |
| `-record` | JSONL 输出（默认 stdout）；`-body-limit` 每体记录上限（默认 16384） |
| `-v` | Debug 日志（判定关键词都在这级） |
| `-tun-reset` | 清理 tun 模式残留路由 |
