# AGENTS.md

面向 AI 编码代理的项目说明。读完本文应能独立构建、测试并修改本仓库。

## 项目概述

**tlsdump** 是一个 HTTPS 流量解密 + 按域名白名单记录的工具（Go 编写，模块名 `tlsdump`，Go 1.27）。对域名白名单内的请求做 MITM 解密并记录为 JSONL；白名单外的流量纯转发（bypass），不记录、不解密。

两种运行模式：

- **proxy**（默认）：本地代理，监听 `-listen`（默认 `127.0.0.1:8080`），同一端口同时支持 HTTP/CONNECT 与 SOCKS5（按首字节自动识别；SOCKS5 仅 no-auth + CONNECT），`curl -x` 可用。
- **tun**：创建虚拟网卡（Windows 用 wintun，Linux 用 `/dev/net/tun`，macOS 用内核 utun），配合 gVisor netstack 透明接管全网 IPv4 TCP/UDP 流量。需要管理员 / root 权限。

详细用法、参数表、CA 安装方法、记录格式、注意事项见 `README.md`（中文）。

## 构建与测试

```bash
go build ./...        # 构建全部包
go build -o tlsdump.exe ./cmd/tlsdump   # 产出可执行文件
go test ./...         # 运行测试
```

- 无 Makefile、无 linter 配置；标准 Go 工具链即可。CI 为 GitHub Actions（`.github/workflows/build.yml`）：push 到 main / tag `v*` / 手动触发时交叉编译 windows amd64+arm64、linux amd64+arm64、darwin arm64 并上传 artifact（tag 时自动发 Release）。
- 主要依赖（见 `go.mod`）：`gvisor.dev/gvisor`（用户态 TCP/IP 协议栈，tun 模式核心）、`golang.zx2c4.com/wireguard`（tun 设备抽象）、`golang.org/x/net`（HTTP/2）、`golang.org/x/sys`、`gopkg.in/yaml.v3`（配置文件解析）、`github.com/dop251/goja`（纯 Go 的 ES5.1+ 引擎，`internal/script` 用）。
- Windows 下 `internal/tun/wintun_windows.go` 通过 `//go:embed wintun.dll` 内嵌驱动 DLL，构建产物运行时会自动释放到可执行文件旁。**该 DLL 不入库**（已 gitignore）：CI 构建 Windows 目标前会从 wintun.net 官方包按目标架构下载到 `internal/tun/wintun.dll`；本地 Windows 构建需手动放置（见 README「构建」一节）。仓库根目录的 `wintun.dll` 是运行时释放产物，与嵌入的 DLL 是同一份文件。

## 代码组织

```
cmd/tlsdump/main.go        入口：flag 解析、YAML 配置合并（显式 flag > YAML > 默认值）、组装各组件（含 `-script` 引擎）、按 -mode 启动 proxy 或 tun
internal/
  proxy/proxy.go           proxy 模式前端：HTTP/CONNECT 代理，读首个请求后交给 mitm；按首字节 0x05 分流到 SOCKS5
  proxy/socks5.go          SOCKS5 握手（RFC 1928，仅 no-auth + CONNECT），成功回包后交给 mitm
  tun/tun.go               tun 模式前端：建 tun 设备 + gVisor netstack，接管 TCP/UDP
  tun/route_*.go           平台相关：配置/清理系统路由（Windows netsh / Linux ip / macOS route+ifconfig 命令）
  tun/bind_*.go            平台相关：出口 socket 绑定物理网卡（防路由回路）
  tun/exclude_*.go         平台相关：-tun-exclude-domains 域名豁免（/32 主机路由钉到物理网卡）
  tun/wintun_*.go          平台相关：Windows 释放内嵌 wintun.dll 并固定网卡 GUID；macOS 设备名映射为 utun
  mitm/mitm.go             核心：嗅探首字节 → TLS/明文 HTTP/未知 分类 → 解密转发或 bypass；接入脚本改写（rewriteRequest / rewriteResponse）
  mitm/compression.go      响应体的 gzip/deflate 解压与重压（脚本改写前后自动转明文），deflate 兼容 zlib 包装与裸 DEFLATE
  certmgr/manager.go       本地根 CA（RSA-2048，./ca/ca.crt + ca.key）与按域名动态签发叶子证书（内存缓存）；支持外部 CA 两种模式：交叉签名本地根（EnableCrossIssuer，链 叶子→cross-cert→外部中间CA）与外部 CA 私钥直接签叶子（EnableDirectSigner，链 叶子→外部中间CA，兼容 pathlen:0 中间 CA）
  filter/filter.go         域名白名单匹配（后缀匹配，含子域名，大小写不敏感）
  record/record.go         JSONL 记录器：每行一条 Entry；body 超限时截断；非 UTF-8 body 走 base64
  config/config.go         YAML 配置加载/校验 + Diff（可热重载字段 vs 需重启字段）
  config/watch.go          配置文件 mtime 轮询（2s），变化则回调（解析失败沿用旧配置）
  script/engine.go         JS 规则引擎（goja）：加载脚本、预编译 rules 里的正则、按 URL 首匹配执行 rewriteRequest/rewriteResponse，带超时；已被 mitm 接入（`Handler.ScriptEngine`）
  script/convert.go        Go ↔ JS 对象转换：请求/响应、headers、body（非 UTF-8 走 base64）
```

架构要点：

- 两个前端（`proxy`、`tun`）都把连接交给同一个 `mitm.Handler.HandleConn(ctx, conn, dstAddr, writeEstablished)`，之后的处理路径完全共享。
- `mitm` 通过 `Peek` 嗅探连接首字节：TLS record（`0x16 0x03`）→ 解析 ClientHello 取 SNI；HTTP 方法前缀 → 明文 HTTP；其余 → bypass 双向盲转发。
- 白名单判定优先用 SNI；无 SNI（如 IP 直连）时回退到目标地址的 host。
- 解密后的 ALPN 为 `h2` 时按 HTTP/2 处理（`x/net/http2` 起服务端 + Transport），否则按 HTTP/1.1 逐请求转发。
- 转发前剥离 hop-by-hop 头；客户端未带 User-Agent 时不注入默认头（`Header["User-Agent"] = nil` 抑制 `Request.Write` 的默认注入）。
- WebSocket（HTTP/1.1 Upgrade 握手）在 `serveHTTP1` 循环内检测（`isWebSocketUpgrade`）：握手按普通 Entry 记录（字段与普通 HTTP 记录一致），剥离后重新补上 `Connection: Upgrade` / `Upgrade: websocket` 再转发；上游回 101 后升级为双向盲转发（`relayWebSocket`），帧内容不解析不记录（代码内有 TODO）。HTTP/2 的 extended CONNECT（RFC 8441）不支持。
- tun 模式：netstack 只接管 IPv4；出口连接必须通过 `newBoundDialer` 绑定物理网卡，否则流量会绕回 tun 形成回路；UDP 按原目的地址双向转发，空闲 2 分钟断开。
- 记录通过 `record.Logger`（mutex 串行化写）输出，`-record` 缺省写到 stdout。
- 热重载（`-config`）：`mitm.Handler` 的白名单/记录器/body 上限/上游 TLS 校验存放在 `atomic.Pointer[mitmRuntime]` 中，经 `SetRuntime` 整体原子替换；可重载字段为 `domains`、`record`、`body_limit`、`insecure_skip_verify`、`verbose`，`mode`/`listen`/`ca_dir`/`cross_cert`/`cross_key`/`sign_cert`/`sign_key`/`script.*`/`tun.*` 改动只记 Warn 需重启。切换 `record` 文件时旧文件保持打开到进程退出，避免与在途 `Log` 写竞争。
- 脚本改写（`-script` / YAML `script.*`，启动时一次性生效）：`main` 用 `script.NewEngine` 建引擎后交给 `Handler.ScriptEngine`（nil = 关闭）。HTTP/1.1 在 `serveHTTP1` 循环内、WebSocket 分支之后调 `rewriteRequest`；HTTP/2 在 `handleH2Request` 里调同一个辅助函数。响应侧走 `rewriteResponse`：仅当 `Engine.HasResponseHook(res)` 为真时才把上游 body 全部读入内存并可改写（`buffered=true`，重新推导 Content-Length/Transfer-Encoding），否则保持原来的 `TeeReader` 流式记录。hook 报错或超时一律 Warn + 转发原始流量；请求改写后记录的是实际发往上游的 method/URI/headers/body。响应体为 `gzip`/`deflate` 时，`rewriteResponse` 先经 `compression.go` 解压、临时移除 `Content-Encoding` 再交给 hook，改完按原编码重压并恢复该头（`Content-Length` 取压缩后长度）；返回的 `recordBody` 是解压后的明文，供 JSONL 记录，`out.Body` 才是发给客户端的字节。解压失败跳过改写原样转发；`br` 等不支持的编码不做转换。改写只对白名单命中的解密流量生效，WebSocket 握手不改写；出口连接在改写前已确定（CONNECT/tun 目标固定），改 `host` 只影响 Host 头/URL。

## 代码风格约定

- 代码注释用英文（包注释说明职责，关键 hack 处写明原因，如 SNI 回退、User-Agent 抑制、防路由回路）；`README.md` 与用户-facing 文档用中文。
- 平台相关代码用 Go build tag 拆分文件：`_windows.go` / `_linux.go` / `_darwin.go` / `_unsupported.go`（`!windows && !linux && !darwin` 提供 no-op 桩），公共逻辑放 `tun.go`。
- 日志统一用 `log/slog`；`-v` 打开 Debug 级。Debug 日志的判定关键词（`intercept TLS` / `bypass TLS` / `bypass HTTP` 等）是排查问题的主要手段，改动时保持这些语义。
- 错误处理：平台路由操作尽量 best-effort（失败记 Warn 不致命），但设备创建、路由配置等关键步骤失败要清理已做的变更（`cleanups` 栈模式，见 `tun.Run`）。
- 公开符号都有 doc 注释；导出函数保持简短、可测试。

## 测试

- 测试很少：`internal/tun` 两个、`internal/config` 一组、`internal/script` 一个、`internal/mitm` 一个、`internal/certmgr` 一个测试文件：
  - `netstack_test.go`：无 build tag，全平台可跑。用 `channel.Endpoint` 构造与 `Run` 相同的 netstack 配置，注入手工构造的 TCP 包完成三次握手并验证双向数据流。**不依赖真实 tun 设备和特权**。
  - `gateway_windows_test.go`（`//go:build windows`）：查询名为 `WLAN` 的网卡网关，依赖真实网络环境，无 WLAN 网卡的机器会失败。
  - `config/config_test.go`：YAML 加载（含未知字段拒绝）、`Validate`、`Diff` 的可重载/需重启分类。
  - `script/engine_test.go`：脚本加载失败的各种情形（语法错误、顶层异常、rules 缺失/非数组、pattern 缺失或非法、hook 非函数、加载超时）、URL/header/body/base64 body/host/path 改写、无匹配、首匹配优先、hook 返回新对象、JS 异常后仍可继续用、hook 死循环超时（`errors.Is(err, ErrTimeout)`）后引擎仍可用、响应改写、并发调用；`TestRewrittenRequestIsForwardable` 把改写后的请求真正写到 `httptest` 服务端，校验线上帧格式（单个 Content-Length、body 长度一致）。
  - `mitm/compression_test.go`：gzip/deflate（含裸 DEFLATE）解压、重压往返、空 body、大小写、非法数据、不支持的编码，以及 `rewriteResponse` 端到端（解压 → hook → 重压，校验线上 Content-Length 与客户端可解压、解压失败原样回退、无 response hook 时保持流式）。
  - `certmgr/crosssign_test.go`：外部 CA 交叉签名/直接签名的链验证（对照玩具 PKI 用 `x509.Verify` 从外部根验通）、cross-cert 内容（subject/公钥=本地根、issuer/AKID=外部 CA）、pathlen 语义（交叉签名+`pathlen:0` 被拒、直接签名+`pathlen:0` 通过）、链文件附加证书、key 不匹配/非 CA 拒绝、openssl 多 PEM 块私钥（EC PARAMETERS 头）。
- 其余包（`proxy` / `filter` / `record`）目前没有测试；改动这些包时如需验证，优先端到端跑一遍：proxy 模式下 `curl -x 127.0.0.1:8080 --cacert ca/ca.crt https://<白名单域名>/`（Windows 的 curl 还需 `--ssl-no-revoke`），检查输出的 JSONL 记录。外部 CA 签名模式建议用 `openssl s_client -proxy 127.0.0.1:8080 -connect <host>:443 -CAfile <外部根>.crt -verify_return_error` 做端到端链验证。
- 手动验证 tun 模式需管理员/root，且**不要与其他 TUN 类工具（如 Clash TUN 模式）同时运行**；异常退出后用 `-tun-reset` 清理残留路由。

## 安全注意事项

- `ca/ca.key` 是根 CA 私钥（RSA-2048，权限 0600）：**绝不能提交到公开仓库、不能外发**。已有 `ca/` 目录是运行时产物。
- `-insecure-skip-verify` 会跳过上游 TLS 校验，仅在自签/pinning 上游的调试场景使用。
- `-cross-*`/`-sign-*` 外部 CA 签名模式仅用于对**自有或获得书面授权**的设备做安全检查（如审计仍信任已泄露中间 CA 链且不打补丁的运行时）；它同样可作为"客户端是否校验吊销"的检测探针。不要指向第三方流量。
- 转发时剥离 `Proxy-Authorization` 等 hop-by-hop 头，避免把代理凭据泄漏给上游。
- 本工具会解密并落盘敏感流量：`-record` 文件（JSONL）含请求/响应头和 body 原文，按敏感数据处理。
- 仓库根目录的 `tun.log`、`tun_debug.log`、`tun.pid`、`tlsdump.exe`、`wintun.dll` 均为本机运行/构建产物，不是源码。
