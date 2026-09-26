# DNS 优选工具实施计划

## 一、项目定位

构建一款 Go 编写的 DNS 优选工具，参考 `xxnuo/dns-benchmark` 与 `palemoky/dnspick`，但代码完全重写。工具提供两种界面：

- **可视化 CLI**：类似 dnspick 的分类进度面板，使用 TUI 展示测试进度、成功率、延迟。
- **Web 本地回环端**：仿 xxnuo 的网站界面，绑定 `127.0.0.1`，通过 `net/http` 嵌入静态资源，用于查看结果、切换评分公式、导入/导出 JSON。

不提供公网服务、账号系统、远程 API、数据库。所有数据本地处理。

---

## 二、技术栈

| 模块         | 选型                                        |
| ------------ | ------------------------------------------- |
| 语言         | Go                                          |
| CLI 框架     | cobra                                       |
| TUI          | bubbletea + lipgloss                        |
| DNS 库       | `miekg/dns` 处理 UDP/DoT                    |
| DoH          | `net/http` + `miekg/dns` 消息编码           |
| DoH3         | `quic-go/http3`                             |
| Web 服务     | `net/http`                                  |
| 前端         | 纯静态 HTML + 少量 JS + ECharts（按需打包） |
| 静态资源嵌入 | `go:embed`                                  |
| 构建发布     | goreleaser                                  |
| 优先平台     | Windows amd64                               |
| 其他平台     | 量力而行，编译失败则移除支持                |

---

## 三、核心架构

### 3.1 并发模型：仿 xxnuo

采用全局 worker pool + 按 DNS 服务器分片调度：

- 全局并发数 = `runtime.NumCPU() × 3`（默认 3 倍 CPU 线程数，可用 `-c/--concurrency` 覆盖）。
  每个 worker 独占一个 DNS 服务器，因此延迟是「一次往返」而非「排队等待」；
  每线程 3 个 worker 足以把网络等待藏起来，又不会让 CPU 在解析响应时互相抢占。
- 任务粒度：一个 DNS 服务器 + 一种协议作为一个测试单元。
- 每个 worker 一次只处理一个 DNS 服务器，该服务器的域名 × 试探次数查询
  按 `DefaultPerServerConcurrency = 2` 条连接拆分，每条连接由独立 goroutine 独占
  （一个 `Querier` 绝不跨 goroutine 共用）。
- 不同 DNS 服务器并行测试；同一台服务器最多 2 条连接并发，实测（19 台服务器交错对照）
  与全串行的成功率、延迟无差异，却把墙钟时间减半。再往上调会开始丢应答
  （单服务器 ≥16 并发时成功率跌到 88~96%），所以固定为 2。
- 单服务器的失败连击计数（`unreachableFailStreak = 5`）在各连接间共享：判死的是端点，不是某一条 socket。

调度流程：

1. 生成待测 DNS 服务器列表，按协议分组。
2. 所有任务放入全局队列。
3. worker 从队列取任务，执行该 DNS 服务器的完整测试。
4. 测试完成后写回结果，继续取下一个任务。

### 3.2 连接复用与预热：参考 dnspick

- UDP：无连接，直接查询。
- DoT：每条连接维护持久 TCP 连接，预热后复用。
- DoH：每条连接一个独立 `http.Transport`，启用 keep-alive，复用连接。
- DoH3：每条连接一个 HTTP/3 连接，预热后复用。
- 预热查询统一使用 `example.com`，不计入正式结果；连接数即 `DefaultPerServerConcurrency`，
  所以每台服务器预热相应条数，预热失败共享同一份失败连击计数。
- 若连接中断，重建连接，本次查询记为失败。
- 正式计时在预热完成后开始。

### 3.3 数据流式写入

- 原始记录写入临时 JSON Lines 文件，避免内存峰值。
- 汇总数据在内存中聚合。
- 最终导出单个 JSON 文件，结构包含 `meta`、`raw`、`summary`。
- `raw` 流式写入，`summary` 内存聚合。

---

## 四、数据模型

### 4.1 元数据

```json
{
  "meta": {
    "version": "1.0",
    "timestamp": "2026-09-25T12:00:00Z",
    "platform": "windows/amd64",
    "concurrency": 8,
    "warmup_domain": "example.com",
    "domain_groups": ["cn", "intl"],
    "domains": "all",
    "protocols": ["udp", "dot", "doh", "doh3"],
    "combo": "udp+doh",
    "regions": ["CN"],
    "policies": ["native"],
    "ip_version": "ipv6",
    "network": { "ipv4": true, "ipv6": false, "skipped": 10, "forced": false, "label": "…" },
    "dns_servers": [
      {
        "name": "AliDNS 1",
        "address": "223.5.5.5",
        "protocol": "udp",
        "ip": "223.5.5.5",
        "region": "CN",
        "policy": "native",
        "family": "ipv4",
        "is_system": false
      }
    ],
    "system_dns": []
  }
}
```

`combo` / `regions` / `policies` / `domains` / `ip_version` / `network` 仅在对应选项生效或判定存在时出现（见 12.1）。
`ip` 是该服务器**实际访问到的字面地址**（界面用它做标识）；`region` 是地区码，
`policy` 是文档所述的过滤策略（`native` / `security` / `unknown`），
`family` 是**实际使用的地址族**（主机名端点在解析后回填）。
厂商名 `name` 仅作来源信息，界面不再用它做标识。

### 4.2 原始记录

```json
{
  "dns": "8.8.8.8",
  "protocol": "udp",
  "domain": "baidu.com",
  "group": "cn",
  "attempt": 1,
  "success": true,
  "latency_ms": 12.3,
  "ts": 1758801600
}
```

失败统一记为 `success: false`，不区分超时与错误码。

### 4.3 汇总记录

```json
{
  "dns": "8.8.8.8",
  "protocol": "udp",
  "group": "cn",
  "ip": "8.8.8.8",
  "region": "CDN",
  "policy": "native",
  "family": "ipv4",
  "total": 100,
  "success": 98,
  "success_rate": 0.98,
  "avg_ms": 15.2,
  "p95_ms": 28.1,
  "stddev_ms": 4.3,
  "combo": "google|CDN"
}
```

`combo` 只在 `--protocols udp+doh` 时出现，用于把同一服务商的两种传输配对（见 12.1）。

---

## 五、评分公式

自行编写四套公式，Web 端可选择，并展示公式说明与适用场景。公式基于汇总数据计算。

### 公式 1：极速优先

```
Score = 1000 * success_rate / avg_latency_ms
```

适用：对延迟极度敏感，能接受偶尔失败。

### 公式 2：稳定优先

```
Score = 1000 * success_rate² / avg_latency_ms * (1 / (1 + stddev_ms / avg_latency_ms))
```

适用：视频会议、在线游戏、长时间稳定连接。

### 公式 3：综合体验

```
Score = 1000 * success_rate / (0.5 * avg_latency_ms + 0.5 * p95_latency_ms)
```

适用：日常网页浏览、综合场景。

### 公式 4：抗抖动优先

```
Score = 1000 * success_rate / (avg_latency_ms + 2 * stddev_ms)
```

适用：移动网络、Wi-Fi 不稳定、网络波动大。

Web 端切换公式后重新排名，并提示“同一 DNS 在不同公式下排名可能变化”。

---

## 六、CLI 设计

命令示例：

```bash
dns-opti test --domains cn --protocols udp,dot,doh --output result.json
dns-opti web --result result.json
dns-opti test --domains all --web
```

主要参数：

- `--domains cn|intl|all|mixed`：域名范围；`all` 分组统计，`mixed` 合并统计（见 12.1 第 19 项）。
- `--protocols udp,dot,doh,doh3`：选择协议；也接受组合模式 `udp+doh`。
- `--regions cn,hk,tw`：按地区码筛选内置服务器。
- `--policy native|security`：按过滤策略筛选内置服务器。
- `--ip-version ipv4|ipv6|both`：限制地址族。
- `--output result.json`：导出 JSON。
- `--web`：测试完成后启动本地 Web 端。
- `--no-web`：仅 CLI。
- `--timeout`：单次查询超时。
- `--attempts`：重试次数。
- `--system-dns`：检测系统 DNS 并纳入对比。

TUI 面板仿 dnspick：

- 顶部：当前阶段、总进度。
- 中部：按协议分类的进度条。
- 底部：实时成功率、平均延迟、当前测试服务器。
- 主菜单含域名范围 / 协议 / 地址族 / 地区筛选 / 过滤策略 / 公式 / 系统 DNS / 高级选项 /
  **打开 Web 界面**；选项自动持久化（见 12.1 第 20、21 项）。
- 提示：README 与帮助文档中说明“关闭代理”，不在运行时检测。

---

## 七、Web 本地回环端

- 使用 `net/http` 提供服务，绑定 `127.0.0.1`，随机端口。
- 静态资源通过 `go:embed` 嵌入。
- 界面仿 `https://bench.dash.2020818.xyz/`。
- 功能：
  - 展示本次测试结果。
  - 切换四套评分公式。
  - 展示公式差异与适用场景。
  - 导入 JSON 历史结果。
  - 导出 JSON。
  - 图表：排名柱状图、延迟分布、成功率对比。
- 支持导入自身格式 JSON，尽量兼容 xxnuo 的 JSON 字段。

---

## 八、DNS 与域名列表

- 列表硬编码在内置文件中：
  - 国内公共 DNS
  - 国外公共 DNS
  - DoH 服务器
  - 国内域名列表
  - 国外域名列表
- 用户选择：
  - 仅国内域名 / 仅国外域名
  - 国内 + 国外域名（`all`，**分组分别统计**）
  - 国内 + 国外域名（`mixed`，**合并为一个分组**，新增，见 12.1 第 19 项）
- 默认严格区分国内外域名、不混用；合并统计必须是显式选择，因为平均掉两组分数
  恰好会抹平分组模式想暴露的差异（见 12.1 第 19 项）。
- 后续通过代码更新列表，不提供外部动态配置。

---

## 九、系统 DNS 检测

仿 dnspick：

- 读取系统当前 DNS 配置。
- 识别 RFC 1918 / RFC 4193 内网地址。
- 在结果中标记“当前系统 DNS”。
- 避免误导用户切换内网 DNS。

---

## 十、构建与发布

- 使用 goreleaser。
- 优先平台：`windows/amd64`。
- 其他平台量力而行：`darwin/arm64`、`darwin/amd64`、`linux/amd64`。
- 若某平台因 DoH3 或 cgo 编译失败，移除该平台支持或使用 build tags 禁用 DoH3。
- 输出单二进制文件。

---

## 十一、目录结构

```
dns-opti/
  cmd/dns-opti/main.go
  internal/cli/
  internal/engine/
  internal/dnsclient/
  internal/region/          地区码（新增，见 12.1 第 15 项）
  internal/policy/          过滤策略：原生 / 安全 的端点表、分类探测与说明
  internal/settings/        配置持久化（新增，见 12.1 第 20 项）
  internal/scheduler/
  internal/scorer/
  internal/store/
  internal/web/
  internal/config/
  internal/domainlist/
  web/static/
  data/cn_domains.txt
  data/intl_domains.txt
  data/dns_servers.go
  README.md
  go.mod
  .goreleaser.yml
```

> 实际实现把前端放在 `internal/web/static/` 而非 `web/static/`：`go:embed` 只能嵌入
> **当前包目录及其子目录**下的文件，顶层目录无法被 `internal/web` 嵌入。
> 放在包内是既能单二进制分发、又不依赖外部文件的唯一做法（README 亦记录此偏差）。

---

## 十二、开发里程碑

1. 初始化项目，定义数据模型与配置。
2. 实现 DNS 查询引擎：UDP、DoT、DoH、DoH3。
3. 实现连接复用与预热：`example.com`。
4. 实现并发调度器：全局 worker pool，按 DNS 服务器分片。
5. 实现 CLI TUI 进度面板。
6. 实现四套评分公式。
7. 实现流式 JSON 写入与汇总。
8. 实现 Web 本地回环端，嵌入静态资源。
9. 实现系统 DNS 检测。
10. 实现 JSON 导入导出。
11. 配置 goreleaser，优先构建 Windows amd64。
12. 编写 README，参考来源声明放首位。

### 12.1 后续扩展（在原始计划之外追加）

以下扩展在计划落地后追加，均已实现：

13. **IPv6 支持**
    - 内置清单为 UDP 与 DoH 各补齐可直接寻址的 IPv6 端点，IPv6 服务器与 IPv4 同列展示。
    - 新增 `--ip-version ipv4|ipv6|both`：只测指定地址族；**主机名端点按所选地址族解析**（`ipv6` 时只查 AAAA），
      socket 也钉到该地址族（`udp4`/`udp6`、`tcp4`/`tcp6`）。
    - 地址族探测由「能否建 socket」改为「**真实查询是否被应答**」，且每个地址族尝试多个目标。
      仅凭拨号会把「有 IPv6 地址与默认路由、但上游无 IPv6 出口」的网络误判为可用，
      进而为每个 IPv6 服务器白等一次超时；只探测单一目标则会把被屏蔽了 1.1.1.1 的健康 IPv4 主机误判为不可用。
    - 显式 `--ip-version` **覆盖**上述探测：明确指令优先于启发式，宁可如实测出失败也不静默不测。
    - 摘要记录**实际使用的地址族**（主机名端点在解析后回填），因此 IPv6 运行是可验证的，而非只是「配置成了 IPv6」。

14. **UDP + DoH 组合模式**
    - `--protocols udp+doh` 是一个**选择器**：展开为两种传输，并把同一服务商的两种传输配成一对。
    - 两种传输**分别统计**，不合并成一个分数——UDP 是一次往返，DoH 还多付 TLS 与 HTTP 握手，
      平均掉恰好会掩盖该模式要回答的问题。
    - 报告新增「UDP 与 DoH 对比」一节（CLI 表格 + Web 面板）；一个服务商有多个 UDP 端点时该侧聚合展示并标注端点数。
    - 只有两侧都至少成功一次才给出差值：缺失侧的全 0 会被误读成「非常快」。

15. **按地区码筛选（仿 xxnuo/dns-benchmark）**
    - 新增 `internal/region`：地区码为 ISO 3166-1 两位国家码，或 `CDN` / `PRIVATE` / `UNKNOWN` 三个特殊码。
    - 内置清单**逐条手工标注**地区码（权威且离线）；不在清单内的地址由手工核对的网段 / 主机名表推导。
    - **不使用 GeoIP 数据库**：被测服务器绝大多数是任播，GeoIP 给出的是厂商注册地而非实际应答节点所在国，
      对「该选哪个 DNS」没有指导意义；真正有用的「哪些网络只属于一个国家、哪些是全球任播」可以手工标注，
      既不必内置 10MB 数据库，也不必联网。
    - 导入 `xxnuo/dns-benchmark` 文件时优先采用其 `geocode` 字段，并把其中的厂商名（`CLOUDFLARE`、`GOOGLE` 等）归并到 `CDN`。
    - CLI 新增 `--regions`；TUI 新增地区筛选项；Web 端把原来的「按服务器逐个勾选」升级为
      **地区码快捷分组 + 搜索 + 全选/清除/反选 + 带记录数的地区胶囊**，并在明细表新增地区列。
    - 地区名称、快捷分组与 UDP/DoH 配对均由服务端下发（`/api/result` 的 `regions` / `region_groups` / `comparisons`），
      前端不自行推导，保证与 CLI 措辞一致。

16. **地址族判定的深度修复**（针对「本机 IPv6 实测无响应」这一提示）
    - 先确认该提示在报告它的机器上**属实**：`udp6` 拨号成功（有路由与源地址），但真实查询在
      1.5s / 3s / 6s / **10s** 下全部超时，`tcp6:443` 同样超时，而系统解析器能正常返回 AAAA。
      即「有 IPv6 地址与默认路由、但没有 IPv6 出口」。因此修复方向不是让探测改口，而是修掉判定**周围**的缺陷。
    - **同一判定作用于所有服务器**：新增 `dnsclient.NewFamilyFilter`，内置服务器、系统 DNS、
      `--servers` 条目共用一条地址族规则。此前系统 DNS 只受显式 `--ip-version` 影响，
      于是「跳过 8 个内置 IPv6」的同时仍去测 IPv6 系统解析器，白等一整个超时预算换来必然 0% 的行。
    - **判定写入结果文件**：新增 `meta.network`（`ipv4` / `ipv6` / `skipped` / `forced` / `label`），
      报告新增一行「地址族实测」。此前判定只作为一句会消失的控制台提示，文件被分享或稍后重读时
      无法解释自己为什么缺少 IPv6 服务器。
    - **探测只在必要时执行**：新增 `probeWouldMatter`，列表中没有对应字面量、或已显式指定 `--ip-version`
      时完全跳过探测。实测纯 IPv4 列表与纯主机名列表由 ~1.6s 降至 ~0.12s。
    - **首个应答即取消同族其余目标**：探测改为 `ExchangeContext`，任一目标应答后 `cancel()`，
      不再等全部目标超时。此前只要有一个目标被黑洞（真实网络中的常态），每轮都要白等满超时。
    - **提示去重**：`PrintReport` 新增 `AlreadyShown`，一次性 CLI 不再把运行前已打印的同一句话在报告中重复；
      交互式菜单仍用自包含的 `ResultView`（其报告会被另存为文件）。
    - 新增 20 余项测试，包括用桩函数验证取消确实传播、探测跳过条件、判定记录与提示去重。

17. **服务器以 IP 标识**
    - 服务器标识由厂商名改为 **IP 地址**：CLI 报告首列、TUI 报告、Web 明细表首列与图表标签统一为
      「**IP · 协议 · 域名组**」。理由：一个厂商名对应多个端点（AliDNS 在 4 种传输 × 2 个地址族下共 8 个），
      只有地址唯一；且地址正是用户要填进系统设置的东西。
    - `model.Server` / `model.Summary` 新增 `ip` 字段，记录**实际访问到的字面地址**；`Querier` 接口新增
      `ResolvedIP()`，由调度器在传输建好后回填——主机名端点只有在解析之后才知道地址。
      这是**运行期**信息，因此必须由传输层回报，不能靠配置推导。
    - 新增 `model.HostOf`，作为全工具唯一的端点取主机实现（裸 IP / 裸主机名 / 方括号 IPv6 / `host:port` /
      DoH URL）。此前 `region` 与 `dnsclient` 各有一份，容易出现「某一种写法少截一段」的偏差。
    - 加密端点（DoH / DoT）在 IP 之外**保留配置用的端点地址**：证书签发给域名，只给 IP 用户无法配置。
      同理「点击复制」对明文协议复制 IP，对加密协议复制完整端点 URL。
    - 厂商名保留在 `meta.dns_servers[].name` 作为来源信息，界面不再用它做标识。

18. **过滤策略：原生 / 安全**
    - 新增 `internal/policy`，与 `internal/region` **正交**：地区说「在哪里」，策略说「对答案做了什么」。
      114DNS 与 AliDNS 都是 CN，但只有 114DNS 有过滤版本，因此两者必须是独立维度。
    - **策略靠人工核对厂商文档，不靠探测**。探测在两个方向都不可靠：一个已下线的广告域名与「被策略拦截」
      无法区分（假阳性）；解析器名单里恰好没有所探测的那一个域名时，探测成功也证明不了「不过滤」（假阴性）。
      文档是写明策略的，也正是用户选解析器时真正需要的信息。
    - 表按**端点**而非厂商建立：Quad9 的 `9.9.9.9` 拦截、`9.9.9.10` 明确不拦截；AdGuard 的 `94.140.14.14`
      会拦截、`94.140.14.140` 不拦截。按厂商归类对用户最可能手填的地址恰好是错的。
      每条都记录判定所依据的文档原文（`note`）；**查不到依据一律记为 `unknown`，绝不猜测**——
      错误的「安全」标签比诚实的「未知」更糟。内置清单现有 5 条为 `unknown`。
    - **「安全」与「拦截广告」合并为一个类别**。二者在文档层面是不同策略，但在观测层面无法区分：
      只有部分厂商对拦截返回 sinkhole（Cloudflare 返回 `0.0.0.0`），另一些厂商直接让查询超时，
      而「超时的拦截」与「不可达」在客户端完全一致。报一个无法验证的细分等于给猜测贴标签。
      每条 note 仍保留文档所述的**具体**拦截范围，日后若要拆分有据可依。
      旧文件中 `adblock` 的取值仍解析为 `security`，不丢策略信息。
    - CLI 新增 `--policy`，TUI 新增策略循环项，Web 新增「过滤策略」筛选栏；
      策略标签与说明由服务端下发（`/api/result` 的 `policies`），与 CLI 措辞一致。

18b. **内置 DNS 类型检测（仅交互界面手动启动）**
    - 主菜单新增独立入口，**不参与正常测试流程**：它逐个探测**内置清单**（不受当前协议 / 地区 / 策略
      筛选影响），与硬编码表对照并列出所有不一致项。之所以限定手动，是因为它是针对内置数据的维护动作，
      而不是基准测试的一部分。
    - 判定口径：**任一测试域被拦截即判为「安全」**；全部正常应答判为「原生」；
      三者均无可用应答判为「未确认」——**无应答不等于不过滤**。这条区分是核心：
      把「连不上」当成「不过滤」会让每个不可达的解析器都获得一个它未赢得的标签。
    - `Querier` 新增 `Lookup`：探测必须区分「被拒绝」与「没应答」，而 `Query` 把两者都折叠成一个 error，
      因此无法在 `Query` 之上实现。分类（NXDOMAIN / 空应答 / sinkhole → 拦截；SERVFAIL·REFUSED → 无证据）
      放在 `internal/policy` 的纯函数里，可独立测试。
    - **探测域名分两类，这个区分是实测出来的**：厂商自检域（Cloudflare `malware.testcategory.com`、
      `phishing.testcategory.com`、DNSFilter `advertising.filterdns.net`）是官方文档给出的权威方式，
      但**在本机不具区分度**——全量扫描 72 个目标时「安全 0 个」，连已证实会拦截的 AdGuard 都判成原生
      （这些域只上了自己厂商的名单）。因此补入实测可区分的广告域名
      （`googleads.g.doubleclick.net`、`pagead2.googlesyndication.com`、`ad.doubleclick.net`），
      补入后 AdGuard 的 4 个端点全部被正确判为「安全」。
    - 报告以「与内置表不一致」小节开头，因为维护者真正的问题是「表还准不准」；每条同时打印三次探测的
      逐项应答，使结论可审计。注：`phishing.testcategory.com` 并非 Cloudflare 官方公布的测试域
      （官方仅 `malware.` 与 `nudity.`），已在代码与 README 中标注。
    - 结论**只是证据不是定论**：它反映本机网络路径下观测到的行为，换网络可能不同；
      也无法证明「只拦威胁不拦广告」。

19. **国内外域名混合模式**
    - 新增 `--domains mixed`：把国内外域名**合并为单一 `mixed` 分组**统计。
    - 它是**独立模式而非修改 `all`**：`all` 保留分组，因而能回答「国内快、国外慢」；
      混合模式回答「在混合负载下整体如何」。两者都有用，且都不能悄悄替代对方——
      把两组分数平均掉恰好会抹平 `all` 想暴露的差异，所以混合只能是用户显式要求的结果。
    - 两个列表按域名**先去重再合并**：同时出现在两边时只测一次，否则该域名的权重会被悄悄加倍。
    - `model.GroupMixed` 与 `GroupShortLabel`；`meta.domains` 记录本次的域名选择，
      使文件能自己说明它是分组还是混合统计的。

20. **配置持久化**
    - 新增 `internal/settings`：交互界面的选项自动写入**程序所在目录**下的 `dns-opti.settings.json`，
      下次启动自动读取。
    - 放程序目录而不是 `%APPDATA%`：这是绿色便携工具，配置应跟着程序走（U 盘 / 便携目录可带走），
      也便于直接查看、编辑、删除。
    - **原子写入**：临时文件建在**目标同目录**（跨卷重命名会退化为复制+删除，留下不完整文件），
      写入 → `Sync` → `Close` → `Chmod` → 重命名；任一步失败都不留残留文件。
    - 目录不可写（如 `Program Files`）时回退到当前工作目录；无法保存只在状态栏提示，**不中断测试**。
    - 文件损坏或字段非法时**逐项校验并回落到默认值**，绝不让界面停在一个跑不起来的配置上；
      `*bool` 用于区分「未设置」与「显式关闭」。没有 `SettingsPath` 时不写任何文件（测试即靠此保证安全）。

21. **主菜单可直接打开 Web 界面**
    - 主菜单新增「打开 Web 界面」，**无需先跑测试**：没有结果时以空数据集打开，页面显示导入按钮，
      可直接读取已有结果 JSON。此前只能在结果页按 `o`，未测试过就用不上。
    - `startWeb` 接受 nil 结果，不再拒绝启动。

---

## 十三、风险与缓解

| 风险                  | 缓解                                  |
| --------------------- | ------------------------------------- |
| 并发导致单 DNS 被压测 | 单服务器固定 2 条连接（实测安全线内），在飞总数 ≤ 150 |
| DoH3 库兼容性差       | 使用 build tags，失败则禁用           |
| 数据量过大            | 流式写 JSONL，汇总数据内存聚合        |
| 本地 DNS 缓存影响     | 文档说明，预热使用 example.com        |
| 代理干扰结果          | README 纯文档提示关闭代理             |
| 平台编译失败          | 优先 Windows amd64，其他量力而行      |
| 许可证问题            | 代码完全重写，README 首位声明参考来源 |
| 地址族误判（有地址无出口） | 以真实查询而非拨号为准；每族多目标；显式 `--ip-version` 可覆盖 |
| 探测拖慢启动          | 只在结果可能改变筛选时才探测；同族首个应答即取消其余目标 |
| 过滤策略判断错误      | 只依据厂商文档，每条记录原文；无依据记为「未确认」而非猜测 |
| 策略细分无法观测      | 「安全」与「拦截广告」合并：超时的拦截与不可达在客户端无法区分 |
| 类型检测把不可达误判为不过滤 | 「无任何可用应答」判为「未确认」而非「原生」；报告明示结论只代表本机路径 |
| 厂商自检域无区分度    | 实测补充可区分的广告域名；只用自检域时全量扫描「安全 0 个」 |
| 混合模式掩盖组间差异  | 混合是显式 `mixed`，`all` 保持分组；两列表先去重再合并避免权重加倍 |
| 配置文件写入失败      | 原子写入（同目录临时文件 + 重命名）；失败只在状态栏提示，不中断测试 |
| 配置文件损坏导致无法运行 | 逐字段校验，非法值跳过并回落默认值；删文件即恢复出厂设置 |
| 主机名端点无 IP 可显示 | `ip` 由传输层 `ResolvedIP()` 回填；未解析时回落到从端点取出的主机 |
| 厂商名对应多端点导致误标 | 策略表按端点而非厂商建立，覆盖多传输 / 多地址族 |

---

## 十四、参考声明

README 首位声明：

本项目参考了以下开源项目，代码为完全重写：

- `xxnuo/dns-benchmark`
- `palemoky/dnspick`

**不复制源代码**，因此不构成对其代码的再分发。许可证情况：

- `palemoky/dnspick`：MIT 许可。
- `xxnuo/dns-benchmark`：**未声明任何许可证**（GitHub API 的 `license` 字段为 `null`，
  仓库内亦无 LICENSE 文件）。因此仅作设计思路的引用与致谢，**不主张任何许可关系**；
  这一点已在 README 与 NOTICE 中如实说明，不写成"许可证均已遵循"。

---

## 十五、发布准备

| 项目 | 状态 |
| ---- | ---- |
| 许可证 | Apache-2.0（`LICENSE`），另附 `NOTICE` 说明内嵌 ECharts 与依赖许可 |
| 仓库地址 | https://github.com/DHA404/DNS-Finder |
| CI | `.github/workflows/ci.yml`：gofmt / vet / test / test -race（三平台）+ 6 平台交叉编译 + `nodoh3` 标签构建 |
| 发布 | `.goreleaser.yml`，手动执行；产出 draft release、各平台压缩包与 `checksums.txt` |
| `go install` | **不支持**：模块名为 `dns-opti` 而非完整仓库路径，README 已显式说明 |
| 忽略项 | `.gitignore` 覆盖 `dist/`、结果 JSON、`dns-opti.settings.json`、参考项目 `.example/` |

发布流程：

```bash
goreleaser check                        # 校验配置
goreleaser release --snapshot --clean   # 本地试打包，输出到 dist/
git tag -a v1.0.0 -m "v1.0.0" && git push origin v1.0.0
goreleaser release --clean              # 需要 GITHUB_TOKEN，产出 draft release
```