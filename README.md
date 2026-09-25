# tlsdump

HTTPS 流量解密 + 按域名白名单记录的工具。对域名列表内的请求做 MITM 解密并记录为 JSONL；列表外的流量纯转发（bypass），不记录。

## 模式

- **proxy**：本地 HTTP/CONNECT 代理，`curl -x` 可用。
- **tun**：创建虚拟网卡（Windows 用 wintun，Linux 用 /dev/net/tun，macOS 用 utun）配合 gVisor netstack 透明接管全网 TCP/UDP 流量。**需要管理员 / root 权限**。

## 构建

```bash
go build ./...                            # 构建全部包（Linux / macOS 可直接构建）
go build -o tlsdump.exe ./cmd/tlsdump     # 产出可执行文件
```

Windows 构建还需要 `wintun.dll`（被 `internal/tun/wintun_windows.go` 以 `go:embed` 嵌入）。该 DLL **不入库**，需从官方分发包取对应架构版本：

```bash
curl -sSL -o wintun.zip https://www.wintun.net/builds/wintun-0.14.1.zip
unzip -o wintun.zip
cp wintun/bin/amd64/wintun.dll internal/tun/wintun.dll   # arm64 构建取 bin/arm64/
```

GitHub Actions 的 Windows 构建会自动完成上述下载（amd64 / arm64 各取对应架构）。

## 用法

```bash
# proxy 模式（默认）
tlsdump -mode proxy -listen 127.0.0.1:8080 \
    -domains example.com,api.example.com \
    -record rec.jsonl

# 域名也可以来自文件（支持 # 注释和空行）
tlsdump -domains domains.txt -record rec.jsonl

# tun 模式（管理员 / root）
tlsdump -mode tun -domains example.com -record rec.jsonl

# 调试
tlsdump -v -insecure-skip-verify -body-limit 65536 ...
```

主要参数：

| 参数 | 说明 |
|---|---|
| `-mode` | `proxy`（默认）或 `tun` |
| `-listen` | 代理监听地址，默认 `127.0.0.1:8080` |
| `-domains` | 逗号分隔域名，或域名列表文件路径 |
| `-record` | JSONL 输出文件，默认 stdout |
| `-ca-dir` | 根证书目录，默认 `./ca`（自动创建 ca.crt/ca.key） |
| `-insecure-skip-verify` | 跳过上游 TLS 校验（上游自签/ pinning 场景） |
| `-body-limit` | 每个请求/响应体最多记录的字节数，默认 16384 |
| `-tun-name` / `-tun-mtu` / `-tun-no-route` / `-tun-physical-iface` | tun 模式参数 |
| `-tun-reset` | 清理上次运行残留的路由/网卡地址后退出（见下文注意事项） |
| `-tun-exclude-domains` | 额外豁免的域名（逗号分隔或文件路径），其流量完全不经过 tun |

## CA 安装

首次运行后在 `-ca-dir` 生成根证书 `ca.crt` / `ca.key`。客户端需要信任它：

- **Windows**：双击 `ca.crt` → 安装证书 → 本地计算机 → 受信任的根证书颁发机构（或 `certutil -addstore Root ca.crt`，需管理员）。
- **curl**：`curl -x 127.0.0.1:8080 --cacert ca/ca.crt https://example.com/`
- **系统级**：把 `ca.crt` 导入系统信任库后所有客户端无感。

## 记录格式

每行一个 JSON：

```json
{"time":"2025-01-01T12:00:00Z","client":"127.0.0.1:51000","mode":"mitm","host":"example.com","method":"GET","uri":"/path?x=1","status":200,"req_headers":{...},"resp_headers":{...},"req_body":"...","resp_body":"...","req_body_truncated":false}
```

- `mode`：`mitm`（HTTPS 解密）或 `http`（明文 HTTP）。
- 非 UTF-8 的 body 做 base64 编码存放。
- 超 `-body-limit` 的 body 截断并标记 `*_body_truncated`。

## 注意事项

- **只解密白名单域名**（含子域名，如 `example.com` 匹配 `www.example.com`）；其余流量纯转发，无记录。
- tun 模式需要管理员（Windows）或 root + `ip` 命令（Linux）；默认会添加两条大默认路由（`0.0.0.0/1`、`128.0.0.0/1`）接管全网 IPv4 流量，退出时自动清理。
- **用 Ctrl+C 停止**（不要直接关窗口）。程序异常退出或忘记清理时，用 `-tun-reset` 恢复：

  ```bash
  # 清理残留的路由和网卡地址（需管理员 / root）
  tlsdump -tun-reset
  ```

- **域名豁免（不经过 tun）**：tun 模式可用 `-tun-exclude-domains` 把指定域名的 IP 钉到物理网卡（/32 主机路由，优先于 /1 接管路由），使其流量完全不进 tun。注意：按 IP 豁免，CDN 换 IP 后需重启程序重新解析。

  也可以手动清理，Windows（管理员 cmd）：

  ```bat
  netsh interface ipv4 delete route prefix=0.0.0.0/1 interface=tlsdump
  netsh interface ipv4 delete route prefix=128.0.0.0/1 interface=tlsdump
  netsh interface ipv4 delete address tlsdump 198.19.0.1
  ```

  Linux（root）：

  ```bash
  ip route del 0.0.0.0/1 dev tlsdump
  ip route del 128.0.0.0/1 dev tlsdump
  ip addr del 198.19.0.1/30 dev tlsdump
  ```

  macOS（root，设备名为内核分配的 utunN，可用 `ifconfig | grep utun` 查看）：

  ```bash
  route -n delete -net 0.0.0.0/1 -interface utunN
  route -n delete -net 128.0.0.0/1 -interface utunN
  ```
- **macOS 注意事项**：utun 设备名由内核分配（`utunN`），`-tun-name` 在 macOS 上无效；出口绑定使用 IP_BOUND_IF，如出口异常可用 `-tun-physical-iface` 显式指定物理网卡。
- 上游 TLS 默认严格校验；命中证书 pinning 或上游自签时打开 `-insecure-skip-verify`。
- **不要与其他 TUN/虚拟网卡类工具同时运行**（如 Clash Verge 的 TUN 模式）：它们使用 fake-ip 网段和同样的 /1 接管路由，互相冲突会导致断网。使用前确保相关进程（含残留的 `clash-core-service.exe` 之类系统服务进程）已退出。
- **Windows 下 curl 验证 MITM 需要** `--cacert ca/ca.crt --ssl-no-revoke`（schannel 会对无 CRL 的本地 CA 报吊销状态未知）。
- 解密流量由本地动态签发叶子证书完成（RSA-2048，SAN=dns，缓存复用）。
- HTTP/2：客户端 ALPN=h2 时按 h2 解密转发；其余按 HTTP/1.1 处理。
- UDP（含 DNS）在 tun 模式下按原目的地址双向转发，空闲 2 分钟断开；tun 模式仅接管 IPv4（v6 流量不受影响）。
- 已知限制：Windows 下 IP_UNICAST_IF 字节序按 winsock 文档（网络字节序）处理，个别环境如出口异常可用 `-tun-physical-iface` 显式指定；转发 HTTP 请求时若客户端未带 User-Agent 不会注入默认头；超大 body 只记录前 `-body-limit` 字节。
- 调试：`-v` 输出每 5 秒的收发计数（`tun: stats`）和每条连接的判定日志（`intercept TLS`/`bypass TLS`/`bypass HTTP` 等）。
