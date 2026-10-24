# tlsdump

HTTPS 流量解密 + 按域名白名单记录的工具。对域名列表内的请求做 MITM 解密并记录为 JSONL；列表外的流量纯转发（bypass），不记录。

## 模式

- **proxy**：本地代理，同一端口同时支持 HTTP/CONNECT 和 SOCKS5（仅 no-auth + CONNECT 命令，按首字节自动识别），`curl -x` 可用。
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

## 配置文件

用 `-config` 指定 YAML 配置文件启动：

```bash
tlsdump -config config.yaml
```

```yaml
mode: proxy              # proxy | tun，默认 proxy
listen: 127.0.0.1:8080   # proxy 监听地址
domains:                 # 白名单；每项可以是域名，也可以是域名列表文件路径
  - example.com
  - api.example.com
record: rec.jsonl        # JSONL 输出文件，缺省 stdout
ca_dir: ./ca
# cross_cert: issuer.crt   # 外部 CA 证书链（交叉签名模式，与 cross_key 成对）
# cross_key: issuer.key
# sign_cert: issuer.crt    # 外部 CA 证书链（直接签名模式，与 sign_key 成对）
# sign_key: issuer.key
insecure_skip_verify: false
body_limit: 16384
verbose: false
script:                  # JS 规则引擎（启动时一次性生效）
  enabled: false         # path 非空时自动置为 true
  path: ""               # 脚本文件路径
  timeout: 5s            # 单次执行超时，缺省 5s
tun:                     # tun 模式参数（仅 mode: tun 时生效）
  name: tlsdump
  mtu: 1420
  no_route: false
  physical_iface: ""     # 缺省自动检测
  exclude_domains: []
```

优先级：**显式命令行 flag > YAML > flag 默认值**。

**热重载**：`-config` 模式下程序每 2 秒检查一次文件变化，以下字段改动不重启即生效：

- `domains`（白名单整体替换）
- `record`（切换到新文件，旧文件退出时关闭）
- `body_limit`
- `insecure_skip_verify`
- `verbose`

`mode`、`listen`、`ca_dir`、`cross_cert`、`cross_key`、`sign_cert`、`sign_key`、`script.*`、`tun.*` 是启动时一次性生效的字段，改动会被记录 Warn 日志并忽略，需重启生效。配置文件语法错误时程序记 Error 日志并沿用旧配置，修复后下个周期自动生效。从文件中删除 `body_limit` 字段会保持当前值不变（不会归零）；`domains` 重载为空列表会被拒绝并沿用旧白名单。

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
| `-config` | YAML 配置文件路径；设置后监视文件变化并热重载可重载字段（见上文） |
| `-mode` | `proxy`（默认）或 `tun` |
| `-listen` | 代理监听地址，默认 `127.0.0.1:8080` |
| `-domains` | 逗号分隔域名，或域名列表文件路径 |
| `-record` | JSONL 输出文件，默认 stdout |
| `-ca-dir` | 根证书目录，默认 `./ca`（自动创建 ca.crt/ca.key） |
| `-cross-cert` / `-cross-key` | 外部 CA 证书链 + 私钥（PEM）：交叉签名本地根，使已信任该外部 CA 的客户端无需安装本地根（见下文「外部 CA 签名」） |
| `-sign-cert` / `-sign-key` | 外部 CA 证书链 + 私钥（PEM）：直接用外部 CA 私钥签叶子（外部中间 CA 带 `pathlen` 约束时必须用此模式） |
| `-insecure-skip-verify` | 跳过上游 TLS 校验（上游自签/ pinning 场景） |
| `-body-limit` | 每个请求/响应体最多记录的字节数，默认 16384 |
| `-script` | JS 规则脚本路径（空 = 不启用；脚本错误会让启动失败） |
| `-script-timeout` | 单次脚本执行超时，默认 5s |
| `-tun-name` / `-tun-mtu` / `-tun-no-route` / `-tun-physical-iface` | tun 模式参数 |
| `-tun-reset` | 清理上次运行残留的路由/网卡地址后退出（见下文注意事项） |
| `-tun-exclude-domains` | 额外豁免的域名（逗号分隔或文件路径），其流量完全不经过 tun |

## CA 安装

首次运行后在 `-ca-dir` 生成根证书 `ca.crt` / `ca.key`。客户端需要信任它：

- **Windows**：双击 `ca.crt` → 安装证书 → 本地计算机 → 受信任的根证书颁发机构（或 `certutil -addstore Root ca.crt`，需管理员）。
- **curl**：`curl -x 127.0.0.1:8080 --cacert ca/ca.crt https://example.com/`（HTTP 代理）；SOCKS5 用 `curl -x socks5h://127.0.0.1:8080 --cacert ca/ca.crt https://example.com/`（`socks5h://` 让代理解析域名，白名单才能命中）。
- **系统级**：把 `ca.crt` 导入系统信任库后所有客户端无感。

## 外部 CA 签名（免安装根证书）

针对**无法在信任库安装本地根**的受控审计对象（如老旧/嵌入式/IoT 设备），tlsdump 可以用一个外部 CA 的证书+私钥签发解密链，使已信任该外部 CA 的设备直接接受。两种模式互斥（`cross-*` 与 `sign-*` 只能选一组，证书文件首张 PEM 为签发用中间 CA，其余 PEM 块追加进服务链）：

- **交叉签名模式**（`-cross-cert issuer.crt -cross-key issuer.key`）：外部 CA 私钥给本地根签一张 cross-cert（subject/公钥不变，issuer 换成外部 CA），服务链 `叶子 → cross-cert → 外部中间 CA`。要求外部中间 CA **无 pathlen 约束**。
- **直接签名模式**（`-sign-cert issuer.crt -sign-key issuer.key`）：叶子直接由外部 CA 私钥签发，服务链 `叶子 → 外部中间 CA`。外部中间 CA 带 `pathlen:0`（公共 Web PKI 通行配置）也能通过验证，**带 pathlen 约束的外部 CA 必须用这个模式**。

判定方法：`openssl x509 -in issuer.crt -noout -ext basicConstraints`，看到 `pathlen:0` 就用 `-sign-*`。

典型场景：2026-10 披露的 eMudhra 弱私钥事件中，8 张中间 CA 证书（`EM DV/OV/EV TLS CA - G3B/G3C` 等，私钥为可从公网证书直接重算的 P-384 小整数）已 `cACompromise` 吊销且均为 `pathlen:0`。对**仍信任这些链且不校验吊销/CT 的未打补丁设备进行授权审计**时：

```bash
# issuer.key 为与证书匹配的 SEC1/PKCS#8 PEM 私钥（该事件中私钥即公开小整数 d）
# 中间 CA 证书可从披露站 impacted-intermediates.json / chains.zip 取得（共 16 张）
tlsdump -domains example.com -record rec.jsonl \
    -sign-cert EM-DV-TLS-CA-G3B.crt.pem -sign-key issuer.key
```

每个 EM 私钥对应**两张**中间 CA 证书（emSign Root TLS CA - G3 签发 / Sectigo AAA Certificate Services 交叉签名），同一张叶子两条链都能验过；AAA 根在更老设备上覆盖率更高。一个实例一次只能服务一条链，多链覆盖请开多个实例（不同 `-listen` 端口）分别测试。

授权边界：该功能仅用于**你拥有或获得书面授权**的设备的安全检查；它同时是检测"哪些客户端不校验证书吊销状态"的探针——目标设备接受此类链即证明其信任库/运行时未打补丁。

## 记录格式

每行一个 JSON：

```json
{"time":"2025-01-01T12:00:00Z","client":"127.0.0.1:51000","mode":"mitm","host":"example.com","method":"GET","uri":"/path?x=1","status":200,"req_headers":{...},"resp_headers":{...},"req_body":"...","resp_body":"...","req_body_truncated":false}
```

- `mode`：`mitm`（HTTPS 解密）或 `http`（明文 HTTP）。
- 非 UTF-8 的 body 做 base64 编码存放。
- 超 `-body-limit` 的 body 截断并标记 `*_body_truncated`。

## 脚本改写

`-script <文件>`（或 YAML 的 `script.path`）让白名单域名的请求/响应经过一个 JS 文件改写，引擎为 goja（ES5.1+）：

```js
var rules = [
  {
    pattern: "^https://api\\.example\\.com/",  // Go 正则，匹配完整 URL；首个命中生效
    rewriteRequest: function (req) {
      req.headers["X-Debug"] = "1";
      req.path = req.path.replace("/api/", "/api/v2/");
    },
    rewriteResponse: function (resp) {
      resp.status = 200;
      resp.headers["X-Rewritten"] = "yes";
      resp.body = resp.body.replace("foo", "bar");
    }
  }
];
```

- 请求对象字段：`method`、`url`、`scheme`、`host`、`path`、`headers`、`body`、`bodyEncoding`；响应对象字段：`status`、`statusText`、`headers`、`body`、`bodyEncoding`。改 `url` 优先，否则用 `scheme`/`host`/`path` 重新拼装。
- hook 可原地改对象，也可返回新对象（返回值优先）；两个 hook 都可省略。
- body 是合法 UTF-8 时按文本给出，否则 `body` 为 base64 且 `bodyEncoding: "base64"`。
- 改写后 `Content-Length` / `Transfer-Encoding` 由新 body 重新推导；记录的是改写后实际收发的请求与响应。
- 响应带 `Content-Encoding: gzip` 或 `deflate` 时，body 会先解压再交给 `rewriteResponse`，脚本改完后按原编码重新压缩并恢复该响应头（`Content-Length` 按压缩后长度重算）；记录里存的是解压后的明文 body。解压失败则跳过改写、原样转发。其他编码（如 `br`）不做处理，脚本看到的是原始字节。
- 脚本加载失败（语法错误、顶层异常、`rules` 缺失、正则非法）会让启动直接失败；单个 hook 抛异常或超时只记 Warn 并转发原始流量。
- 只对白名单命中的解密流量生效；WebSocket 握手不改写；`script.*` 启动时一次性生效，改脚本需重启。
- 局限：出口连接在改写前已确定，改 `host` 只影响 Host 头/URL，不会真的换服务器；有 `rewriteResponse` 时整个响应体会读进内存（无该 hook 时仍流式转发）。

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
- 解密流量由本地动态签发叶子证书完成（RSA-2048，SAN=dns，缓存复用）；启用 `-cross-*`/`-sign-*` 时改由外部 CA 签发，服务链相应变化（见「外部 CA 签名」）。
- 外部 CA 签名模式的目标设备必须不校验吊销（OCSP/CRL）与 CT；已打补丁的浏览器/运行时（Go ≥1.27.3、Python certifi ≥2026.10.19、Electron ≥44.9.1、NSS 3.131.1 等）会拒绝此类链。
- HTTP/2：客户端 ALPN=h2 时按 h2 解密转发；其余按 HTTP/1.1 处理。
- UDP（含 DNS）在 tun 模式下按原目的地址双向转发，空闲 2 分钟断开；tun 模式仅接管 IPv4（v6 流量不受影响）。
- 已知限制：Windows 下 IP_UNICAST_IF 字节序按 winsock 文档（网络字节序）处理，个别环境如出口异常可用 `-tun-physical-iface` 显式指定；转发 HTTP 请求时若客户端未带 User-Agent 不会注入默认头；超大 body 只记录前 `-body-limit` 字节。
- 调试：`-v` 输出每 5 秒的收发计数（`tun: stats`）和每条连接的判定日志（`intercept TLS`/`bypass TLS`/`bypass HTTP` 等）。
