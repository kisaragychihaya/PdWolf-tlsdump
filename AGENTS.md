# AGENTS.md

面向 AI 编码代理的项目说明。读完本文应能独立构建、测试并修改本仓库。

## 项目概述

**tlsdump** 是一个 HTTPS 流量解密 + 按域名白名单记录的工具（Go 编写，模块名 `tlsdump`，Go 1.27）。对域名白名单内的请求做 MITM 解密并记录为 JSONL；白名单外的流量纯转发（bypass），不记录、不解密。

两种运行模式：

- **proxy**（默认）：本地 HTTP/CONNECT 代理，监听 `-listen`（默认 `127.0.0.1:8080`），`curl -x` 可用。
- **tun**：创建虚拟网卡（Windows 用 wintun，Linux 用 `/dev/net/tun`，macOS 用内核 utun），配合 gVisor netstack 透明接管全网 IPv4 TCP/UDP 流量。需要管理员 / root 权限。

详细用法、参数表、CA 安装方法、记录格式、注意事项见 `README.md`（中文）。

## 构建与测试

```bash
go build ./...        # 构建全部包
go build -o tlsdump.exe ./cmd/tlsdump   # 产出可执行文件
go test ./...         # 运行测试
```

- 无 Makefile、无 linter 配置；标准 Go 工具链即可。CI 为 GitHub Actions（`.github/workflows/build.yml`）：push 到 main / tag `v*` / 手动触发时交叉编译 windows amd64+arm64、linux amd64+arm64、darwin arm64 并上传 artifact（tag 时自动发 Release）。
- 主要依赖（见 `go.mod`）：`gvisor.dev/gvisor`（用户态 TCP/IP 协议栈，tun 模式核心）、`golang.zx2c4.com/wireguard`（tun 设备抽象）、`golang.org/x/net`（HTTP/2）、`golang.org/x/sys`、`gopkg.in/yaml.v3`（配置文件解析）。
- Windows 下 `internal/tun/wintun_windows.go` 通过 `//go:embed wintun.dll` 内嵌驱动 DLL，构建产物运行时会自动释放到可执行文件旁。**该 DLL 不入库**（已 gitignore）：CI 构建 Windows 目标前会从 wintun.net 官方包按目标架构下载到 `internal/tun/wintun.dll`；本地 Windows 构建需手动放置（见 README「构建」一节）。仓库根目录的 `wintun.dll` 是运行时释放产物，与嵌入的 DLL 是同一份文件。

## 代码组织

```
cmd/tlsdump/main.go        入口：flag 解析、YAML 配置合并（显式 flag > YAML > 默认值）、组装各组件、按 -mode 启动 proxy 或 tun
internal/
  proxy/proxy.go           proxy 模式前端：HTTP/CONNECT 代理，读首个请求后交给 mitm
  tun/tun.go               tun 模式前端：建 tun 设备 + gVisor netstack，接管 TCP/UDP
  tun/route_*.go           平台相关：配置/清理系统路由（Windows netsh / Linux ip / macOS route+ifconfig 命令）
  tun/bind_*.go            平台相关：出口 socket 绑定物理网卡（防路由回路）
  tun/exclude_*.go         平台相关：-tun-exclude-domains 域名豁免（/32 主机路由钉到物理网卡）
  tun/wintun_*.go          平台相关：Windows 释放内嵌 wintun.dll 并固定网卡 GUID；macOS 设备名映射为 utun
  mitm/mitm.go             核心：嗅探首字节 → TLS/明文 HTTP/未知 分类 → 解密转发或 bypass
  certmgr/manager.go       本地根 CA（RSA-2048，./ca/ca.crt + ca.key）与按域名动态签发叶子证书（内存缓存）
  filter/filter.go         域名白名单匹配（后缀匹配，含子域名，大小写不敏感）
  record/record.go         JSONL 记录器：每行一条 Entry；body 超限时截断；非 UTF-8 body 走 base64
  config/config.go         YAML 配置加载/校验 + Diff（可热重载字段 vs 需重启字段）
  config/watch.go          配置文件 mtime 轮询（2s），变化则回调（解析失败沿用旧配置）
```

架构要点：

- 两个前端（`proxy`、`tun`）都把连接交给同一个 `mitm.Handler.HandleConn(ctx, conn, dstAddr, writeEstablished)`，之后的处理路径完全共享。
- `mitm` 通过 `Peek` 嗅探连接首字节：TLS record（`0x16 0x03`）→ 解析 ClientHello 取 SNI；HTTP 方法前缀 → 明文 HTTP；其余 → bypass 双向盲转发。
- 白名单判定优先用 SNI；无 SNI（如 IP 直连）时回退到目标地址的 host。
- 解密后的 ALPN 为 `h2` 时按 HTTP/2 处理（`x/net/http2` 起服务端 + Transport），否则按 HTTP/1.1 逐请求转发。
- 转发前剥离 hop-by-hop 头；客户端未带 User-Agent 时不注入默认头（`Header["User-Agent"] = nil` 抑制 `Request.Write` 的默认注入）。
- tun 模式：netstack 只接管 IPv4；出口连接必须通过 `newBoundDialer` 绑定物理网卡，否则流量会绕回 tun 形成回路；UDP 按原目的地址双向转发，空闲 2 分钟断开。
- 记录通过 `record.Logger`（mutex 串行化写）输出，`-record` 缺省写到 stdout。
- 热重载（`-config`）：`mitm.Handler` 的白名单/记录器/body 上限/上游 TLS 校验存放在 `atomic.Pointer[mitmRuntime]` 中，经 `SetRuntime` 整体原子替换；可重载字段为 `domains`、`record`、`body_limit`、`insecure_skip_verify`、`verbose`，`mode`/`listen`/`ca_dir`/`tun.*` 改动只记 Warn 需重启。切换 `record` 文件时旧文件保持打开到进程退出，避免与在途 `Log` 写竞争。

## 代码风格约定

- 代码注释用英文（包注释说明职责，关键 hack 处写明原因，如 SNI 回退、User-Agent 抑制、防路由回路）；`README.md` 与用户-facing 文档用中文。
- 平台相关代码用 Go build tag 拆分文件：`_windows.go` / `_linux.go` / `_darwin.go` / `_unsupported.go`（`!windows && !linux && !darwin` 提供 no-op 桩），公共逻辑放 `tun.go`。
- 日志统一用 `log/slog`；`-v` 打开 Debug 级。Debug 日志的判定关键词（`intercept TLS` / `bypass TLS` / `bypass HTTP` 等）是排查问题的主要手段，改动时保持这些语义。
- 错误处理：平台路由操作尽量 best-effort（失败记 Warn 不致命），但设备创建、路由配置等关键步骤失败要清理已做的变更（`cleanups` 栈模式，见 `tun.Run`）。
- 公开符号都有 doc 注释；导出函数保持简短、可测试。

## 测试

- 测试很少：`internal/tun` 两个、`internal/config` 一组：
  - `netstack_test.go`：无 build tag，全平台可跑。用 `channel.Endpoint` 构造与 `Run` 相同的 netstack 配置，注入手工构造的 TCP 包完成三次握手并验证双向数据流。**不依赖真实 tun 设备和特权**。
  - `gateway_windows_test.go`（`//go:build windows`）：查询名为 `WLAN` 的网卡网关，依赖真实网络环境，无 WLAN 网卡的机器会失败。
  - `config/config_test.go`：YAML 加载（含未知字段拒绝）、`Validate`、`Diff` 的可重载/需重启分类。
- 其余包（`mitm` / `proxy` / `filter` / `record` / `certmgr`）目前没有测试；改动这些包时如需验证，优先端到端跑一遍：proxy 模式下 `curl -x 127.0.0.1:8080 --cacert ca/ca.crt https://<白名单域名>/`（Windows 的 curl 还需 `--ssl-no-revoke`），检查输出的 JSONL 记录。
- 手动验证 tun 模式需管理员/root，且**不要与其他 TUN 类工具（如 Clash TUN 模式）同时运行**；异常退出后用 `-tun-reset` 清理残留路由。

## 安全注意事项

- `ca/ca.key` 是根 CA 私钥（RSA-2048，权限 0600）：**绝不能提交到公开仓库、不能外发**。已有 `ca/` 目录是运行时产物。
- `-insecure-skip-verify` 会跳过上游 TLS 校验，仅在自签/pinning 上游的调试场景使用。
- 转发时剥离 `Proxy-Authorization` 等 hop-by-hop 头，避免把代理凭据泄漏给上游。
- 本工具会解密并落盘敏感流量：`-record` 文件（JSONL）含请求/响应头和 body 原文，按敏感数据处理。
- 仓库根目录的 `tun.log`、`tun_debug.log`、`tun.pid`、`tlsdump.exe`、`wintun.dll` 均为本机运行/构建产物，不是源码。
