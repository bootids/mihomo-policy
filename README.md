# mihomo-policy

用 Go 开发的 Mihomo 服务分类规则管理与访问分析工具。

以 **10.10.10.1 为唯一分析来源**，生成两台设备共用的规则。支持任意数量的服务分类，每个分类有独立策略组与优先级，默认 AI 优先于 Google。规则建议需人工确认，不会自动覆盖高优先级服务策略。

## 当前实现

- 分类配置、严格校验、确定性排序、域名/CIDR 规则重叠报告。
- 编译带 SHA-256 清单的不可变规则包；合成保留本地设置的 Mihomo 配置。
- 域名分类查询与预期路由案例校验。
- 导入现有 clash-monitor JSONL，重复导入去重，单个文件事务提交。
- 从 Mihomo `/connections` 增量统计流量，从 `/logs` 提取失败类型。
- 通过两个指定 HTTP 代理入口并发进行 DIRECT / PROXY 配对探测。
- SQLite 持久化、跨时间窗口证据分析、JSON / Markdown 报告。
- 常驻调度、任务成功时间持久化、同数据源采集租约、历史数据清理。
- Go 内嵌交互式看板：支持按**一级域名 / 二级域名 / 完整域名**聚合统计流量，提供即时 **Direct 直连测试**、**忽略域名**（仍计入统计但不再作为待测项）、测试通过后**一键加入 `policy/rules/direct.list`**、**本地仓库 Commit & Push**，以及通过 SSH/SFTP 将 `config.yaml` 同步并热重载到 `admin@10.10.10.1` 与 `admin@10.10.8.1`。支持独立登录凭据，无需额外前端运行时。
- 统一维护 `config.template.yaml`：通过 `proxy-providers` URL（环境变量 `${MIHOMO_SUB_URL}` 注入，不入库）订阅节点组，并通过 `rule-providers` 引用本仓库 `policy/rules/*.list` 的 GitHub Raw 链接。
- GitHub CI、容器构建文件、systemd 服务示例。

## 本机构建和离线演示

需要 Go 1.26 或更高版本。SQLite 使用不依赖 CGO 的 `modernc.org/sqlite`。

```sh
make build
./bin/mihomo-policy validate --cases tests/routing-cases.yaml
./bin/mihomo-policy match --host gemini.google.com
```

Gemini 应命中 `ai / AI`，普通 `www.google.com` 应命中 `google / GOOGLE`。查询仅计算域名规则，不进行 DNS 解析，也不等同于目标设备的原生路由验证。

离线导入和报告不需要 API 密钥，不会访问路由器：

```sh
./bin/mihomo-policy import --config examples/demo.yaml tests/fixtures/legacy.jsonl
./bin/mihomo-policy import --config examples/demo.yaml tests/fixtures/legacy.jsonl
./bin/mihomo-policy report --config examples/demo.yaml --since 87600h --format markdown --out data/demo-report.md
```

第一次导入应新增 2 行，第二次新增 0 行。测试数据是合成记录。没有主动探测证据时，报告保留 `observe`，不会凭流量大小判定应直连。

## 维护服务分类与优先级

编辑 `policy/policy.yaml`：

```yaml
version: 1
fallback: 默认策略
categories:
  - name: ai
    priority: 1000
    policy: AI
    files: [rules/ai.list]
  - name: google
    priority: 800
    policy: GOOGLE
    files: [rules/google.list]
```

- 优先级数值越大越先匹配；启用分类的优先级必须唯一。
- 分类数量不限。`policy` 可以是策略组、节点或 DIRECT / REJECT 等出口。
- `enabled: false` 可停用分类；`rules:` 可直接写少量内联规则。
- 文件路径相对 `policy.yaml`，不可通过 `..` 或符号链接逃出该目录。
- 规则采用 classical text：每行 `TYPE,value`，不附加出口。
- 当前支持 DOMAIN、DOMAIN-SUFFIX、DOMAIN-KEYWORD、IP-CIDR、IP-CIDR6；IP 规则可附 `no-resolve`。
- 规则文件可写空行和整行 `#` 注释。示例是起始分类，不是完整的 Google/AI 服务域名库。

`gemini.google.com` 精确匹配 AI，同时也被 Google 的 `google.com` 后缀覆盖；因 AI 优先级高，最终策略是 AI。重叠报告区分较低规则完全被覆盖、部分交集。当前重叠检测覆盖 DOMAIN/DOMAIN-SUFFIX 和 CIDR；不声称穷举 keyword 的全部交集。

分析生成的 DIRECT 建议会保留当前分类和 `priority_review: true`。它不是已生效的直连规则，不会自动绕过 AI 分类。

## 构建规则包和设备配置

```sh
./bin/mihomo-policy build --out dist/example
./bin/mihomo-policy render \
  --base examples/base.yaml \
  --bundle-path ./policy/releases/example \
  --out local/config.generated.yaml
```

规则包包含：

```text
manifest.json      # 语义版本和文件校验值
policy.json        # 标准化分类与覆盖关系
fragment.yaml      # rules 与 file 类型 rule-providers
rules/*.list
```

版本由标准化规则、优先级、出口和兜底策略共同计算，不受构建时间或注释影响。已存在的输出目录不会被覆盖。

`render` 以本地基础配置为输入，完整替换 `rules` 与 `rule-providers`，保留订阅、密钥、TUN、DNS、接口和策略组等其他字段。它会检查所有分类引用的出口是否存在，但不会猜测应该如何创建你的节点和策略组。输出会重新序列化 YAML，不保留原注释。

`--bundle-path` 是 **Mihomo 容器内** 的规则包目录，不是本机源码目录。必须将同一个版本包完整放到该路径。`fragment.yaml` 是片段，不能单独当作完整运行配置。

`examples/base.yaml` 中策略组使用 DIRECT 只是为了离线展示结构；接入生产前请在 `local/` 配置真实节点、策略组及密钥。当前没有自动部署步骤。

## 采集 10.10.10.1

```sh
mkdir -p local
cp examples/runtime.yaml local/runtime.yaml
read -r -s MIHOMO_SECRET
export MIHOMO_SECRET
./bin/mihomo-policy collect --config local/runtime.yaml
```

使用看板所对应的 API Secret。可按 Ctrl-C 停止。`collect` 只采集；`serve` 还会执行探测、报告和清理任务。

只在 `controller` 配置 10.10.10.1，不需要配置 10.10.8.1。`source: home` 是数据分区名，分析时不会混入其他 source。

采集规则：

- 首次连接、请求失败后恢复时先建立计数器基线，不将连接历史累计量算作新增流量。
- 正常采样按 connection ID 计算字节增量；计数器重置时跳过该次差值。
- 每秒轮询可能漏掉短连接；`sample_rows` 是采样行数，不是请求次数。
- `/logs` 只保存失败分类和可可靠提取的目标域名，不保存可能含凭据的原文。
- 同一 SQLite 数据库中，同一 source 只允许一个采集进程；不要让两个独立数据库同时采集后再直接相加。
- 调度状态在重启后保留，错过的任务会在下次循环补做一次，不制造历史探测样本。

10.10.10.1 当前的新 Mihomo 仍是并行试运行；在接管实际流量之前，采集到的只是主动使用该实例的请求。

## 探测及建议

将 `examples/probe-listeners.yaml` 合入**独立探测实例**的完整配置，在 10.10.10.1 所在出口网络运行。`PROBE_PROXY` 必须只包含真实代理节点；确认 DIRECT 出站不被 RouterOS 策略路由再次送入代理。探测服务与 localhost 监听器应在同一网络命名空间；跨容器访问应调整监听地址和访问限制。

`direct_proxy` / `proxy_proxy` 必须分别是强制 DIRECT / PROXY 入口。不能把普通 `7890` mixed 端口当作强制代理入口。程序不会在入口不可用时退回本机直连，也不使用环境代理。

```sh
./bin/mihomo-policy probe --config local/runtime.yaml
./bin/mihomo-policy analyze --config local/runtime.yaml --format markdown --out data/report.md
./bin/mihomo-policy serve --config local/runtime.yaml
```

目标必须显式配置测试 URL、期望状态码，可选内容标记。请求不自动跟随重定向，响应内容检查限制在前 64 KiB；响应体不入库。不自动重放用户请求，不推断未知 URL 的业务成功条件。

每次对一个目标同时执行两条线路，保存为一个配对；不完整配对不计入证据。访问统计和探测证据采用独立周期：页面的 24 小时 / 7 天 / 30 天控制访问统计，探测默认始终回看 7 天。证据默认要求至少 20 组、3 个四小时时间窗口、跨度 24 小时，最近有效配对距今不超过 12 小时（默认取探测周期的两倍）。

- `route_verdict: direct_candidate`：两路样本成功率均 >=95%，最近 5 组两路均成功；两路都成功的配对中，直连不慢于代理的比例在整个周期和近期均 >=50%，配对耗时差中位数 <=0，直连成功样本 P95 不高于代理。
- `route_verdict: proxy_candidate`：代理样本成功率 >=95%，最近 5 组代理均成功；整个周期和近期均有 >=80% 的直连样本出现可归因的 TLS 传输失败。
- 出现 HTTP 拒绝、证书异常、DNS/代理隧道异常、入口故障等未归因错误，或证据不足、过期、同域名测试目标结论冲突时，保持 `observe`。
- P50/P95 仅统计成功样本，耗时包含连接建立和最多 64 KiB 响应读取。没有成功样本时为 JSON `null`，页面显示“无成功样本”。样本成功率是经验统计，不代表置信保证。

线路评估与规则变更分开：本地草案已为 DIRECT 且观测没有出口冲突时标记 `keep`，不计入待复核建议；仅主动探测、没有所选周期访问或失败事件的域名只保留线路评估。已有策略组的代理可用结论用于诊断该组与探测出口是否一致，不推断应更换规则。REJECT / PASS 等显式意图不会被可达性结果转换为放行建议。

`direct_candidate` / `proxy_candidate` 变更建议附带精确 `DOMAIN` 的复核范围和本周期观测流量；代理策略组、所属分类与插入优先级仍须人工选择，不自动生成整个后缀的例外。

这些阈值可在 `analysis` 中调整。`evidence_lookback` 控制独立证据周期，`max_age` 控制有效期，`recent_pairs` 控制近期检查组数，`min_direct_win_rate` 控制直连不劣比例。测量的是指定 HTTP(S) 端点，不能据此保证整个服务、IPv6、UDP/QUIC 或所有地区限制都适用。入口线路标签仍依赖部署时验证，程序尚未自动证明出口 IP 和实际节点。

新探测保存目标 URL、成功条件、入口、超时、控制器及 `probe_environment` 的配置指纹；只分析当前仍启用且指纹一致的目标，包括尚未获得样本的目标，避免遗漏端点被误认为结论一致。指纹不保存 URL 或内容标记原文。相同入口背后的节点、DNS 或出口网络变化后，应更新 `probe_environment`，重新积累证据；指纹本身不证明出口身份。

首次启动会在事务中把 SQLite v1 升级为 v2，保留已有流量、失败和探测数据。升级前应停止旧进程并备份数据库；旧程序不兼容扩展后的表。没有配置指纹的历史探测保留在库中，但不作为当前变更依据；详情显示证据周期内被排除的样本数。历史访问缺少的客户端、协议和地址族信息显示为未知，不推测补齐。

当前代理入口故障与目标在 CONNECT 阶段的失败可能无法区分，因此采用保守结论。未来可关联结构化错误日志与实际节点补全归因。

## 运行与验证

看板离线预览：

```sh
./bin/mihomo-policy dashboard --config examples/dashboard-demo.yaml
```

打开 `http://127.0.0.1:18091/`。此命令只读取已有数据；要同时采集和调度，请使用 `serve` 并设置：

```yaml
web:
  listen: 0.0.0.0:8080
  username: admin
  password_env: MIHOMO_DASHBOARD_PASSWORD
```

非回环监听地址要求独立看板用户名和密码环境变量。Mihomo API Secret、订阅 URL 与 SSH 私钥不会发送给浏览器，也不会写入 Git 提交。所有写接口均校验登录凭据与 `X-Requested-With: mihomo-policy` 请求头：

- `GET /api/state?level=l1|l2|host`：按一级域名、二级域名或完整域名聚合统计流量与直连状态。
- `POST /api/direct-test`：对指定一级/二级/完整域名（及观测到的高流量子域名）执行直连连通性测试并持久化结果。
- `POST /api/rules/ignore`：写入或移除 `policy/ignore.list`（忽略域名仍保留流量统计，但不再进入待测列表）。
- `POST /api/rules/direct`：将直连测试通过的域名以 `DOMAIN-SUFFIX` / `DOMAIN` 写入或移出 `policy/rules/direct.list`，并在写盘后校验 `policy/policy.yaml`。
- `POST /api/git/push`：仅暂存 `policy/` 与 `config.template.yaml`，拦截任何订阅链接泄露后执行 Commit & Push。
- `POST /api/routers/deploy`：按设备渲染 `config.template.yaml`（注入 `${MIHOMO_SUB_URL}` 及各设备独立 API Secret），通过 SFTP 上传至 `admin@10.10.10.1` 与 `admin@10.10.8.1`，备份旧配置并调用 Mihomo API 热重载与刷新远程规则集，失败自动回滚。

`compose.yaml` 默认只把看板发布到宿主机 `127.0.0.1:18091`。需要内网访问时，可将 `DASHBOARD_BIND` 设置为宿主机 LAN 地址。配置 `local/runtime.yaml`，通过 `.env` 或宿主机环境提供 `MIHOMO_SECRET` 和 `MIHOMO_DASHBOARD_PASSWORD`；SQLite 使用持久化卷。数据库 bind mount 时，数据目录需对容器 UID 10001 可写。

看板按全量数据汇总流量、分类、证据与变更计数，明细每页 50 项，搜索、筛选、排序覆盖所有域名。导出保留当前访问统计周期，包含未分页的完整报告。访问域名只计有用户流量采样的域名，另列仅失败、仅主动探测的域名；流量总量仅包含可归属域名的采样字节，短连接、连接尾部与未知目标可能漏计。

域名详情展示实际线路 / 节点 / 命中规则的流量分布、客户端和协议维度、失败类型、最近配对、按窗口成功数与精确域名变更范围。失败日志事件没有请求总数，也未可靠关联实际线路，不作为失败率。

看板明确区分本地规则草案、已观测线路和探测证据；没有全网接管或真实探测数据时，不会填充虚构结果。连接空闲时 Mihomo 返回的 `connections: null` 被视为有效空采样。

资源紧张的远端可以使用 `Dockerfile.prebuilt`，把预先编译的 Linux 静态程序和公开 CA 证书包放到构建上下文，再构建 scratch 镜像，无需下载 Go 编译镜像。

```sh
make check
make test
make release
# 可选：安装 Node.js 后，Go 测试也会运行前端脚本回归。也可单独执行：
node --test internal/dashboard/app_test.cjs
```

`make release` 构建无 CGO 的 Linux amd64 / arm64 程序。RouterOS 需在 Linux 容器中运行它，不能作为 RouterOS 原生命令执行。

`examples/mihomo-policy.service` 可作为 Linux 服务模板，须预先创建对应用户和目录。`Dockerfile` 提供容器打包方式；挂载 `local/` 与可写 `data/`，通过环境变量注入密钥。CI 只校验和构建，不访问内网、不发布路由器配置。

## 后续演进

1. 接管现有 GEOSITE/GEOIP、第三方 YAML/MRS 规则及固定版本的上游同步；当前编译器遇到不支持的规则会直接报错。
2. 入口健康和实际出口证明、实际出口变化自动识别、失败事件与线路和探测关联、更完整的协议探测。

协议参考：[Mihomo API](https://wiki.metacubex.one/api/)、[规则优先级](https://wiki.metacubex.one/config/rules/)、[规则集格式](https://wiki.metacubex.one/config/rule-providers/content/)、[强制监听器出口](https://wiki.metacubex.one/config/inbound/listeners/)。
