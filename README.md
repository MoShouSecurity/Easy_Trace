# Easy Trace

**离线采集事实，用本地规则生成调查线索，把结论落成可复核的报告。**

Easy Trace 是使用 Go 开发的 Windows 主机离线调查命令行工具。它先采集并保存主机事实快照，再用本地 YAML 规则筛查线索，最后导出可独立打开的报告与事件调查包。适合现场排查、应急响应和离线复核。

工具不联网、不执行外部命令、不做自动处置，也不把规则命中表述为对主机、进程、文件或网络端点的确定性结论。

[快速开始](#快速开始) · [核心命令](#核心命令) · [采集模块](#采集模块) · [数据与能力边界](#数据与能力边界)

> 本仓库只包含构建所需的源码，不含本地开发文档与测试文件。
> 当前产品形态是 CLI，不包含 GUI、常驻服务、在线 IOC 查询或自动提权。

## 能做什么

| 能力 | 当前功能 |
| --- | --- |
| 事实采集 | 采集主机、进程、网络、自启动项、服务、计划任务、用户、已加载驱动等事实，写入 SQLite 快照。 |
| 扩展采集 | 按需采集落地文件、指定注册表键、白名单事件日志、Prefetch 文件头与执行痕迹（UserAssist / BAM / DAM / RecentDocs / PowerShell 历史 / LNK）。 |
| 本地规则 | 使用内嵌 YAML 规则筛查进程、自启动、服务、计划任务、网络、文件、注册表与事件线索，规则随 exe 分发，也可用外部规则目录覆盖。 |
| 调查线索 | 输出结构化 Finding，包含规则、实体、证据、严重度与处置建议；严重度只表示核查优先级。 |
| 关联传导 | 可选地把直接命中沿 `spawn` / `launch` / `network_connect` 关系扩散 1~N 跳，生成带来源路径的传导提示，严重度衰减一级。 |
| 白名单 | 把人工确认属正常业务的命中标记为已知，只在报告展示层抑制，并保留抑制理由与审计记录。 |
| 痕迹留存 | 显式执行 `catch`，把命中项指向的文件只读复制到新证据目录，生成 SHA256 清单，绝不覆盖源文件。 |
| 报告导出 | 生成自包含 `report.html`、`findings.json`、`summary.txt`，以及可选的 Incident 事件调查包（SQLite、CSV、时间线、哈希清单、证据与 EVTX）。 |
| 自身可信 | `verify` 校验 exe 与规则清单并扫描成品高危字串；`audit` 记录每次命令的操作留痕。 |

## 快速开始

要求：Windows + Go 1.26.5 或更高版本。

```powershell
# 一条命令完成格式化、构建、自校验、vet 与测试
powershell -ExecutionPolicy Bypass -File .\build.ps1

# 或只构建
go build -o Easy_Trace.exe ./cmd/easytrace-agent
```

**运行要求：** 除 `help` / `version` / `verify` 外，所有命令都必须在已提权的管理员会话中运行。未提权时会给出中文提示并以退出码 **3** 结束，不采集、不建库、不写文件；工具不会自动弹 UAC 或重启自身。

```powershell
# 采集事实并建立快照（真实主机操作，请先确认授权）
.\Easy_Trace.exe collect --db easytrace.db

# 分析已有快照
.\Easy_Trace.exe analyze --db easytrace.db

# 查看单条线索
.\Easy_Trace.exe investigate --db easytrace.db -id <finding_id>

# 导出报告目录
.\Easy_Trace.exe report --db easytrace.db -o report-20261103

# 生成事件调查包
.\Easy_Trace.exe report --db easytrace.db -o report-20261103 -zip

# 查看全部命令
.\Easy_Trace.exe help
```

`collect` 默认采集 `--module all`；未指定 `--db` 时使用当前目录的 `easytrace.db`。单模块采集默认只把 JSONL 写到 stdout，不建库，只有显式传入 `--db` 才导入快照。规则默认编入 exe，单文件即可运行；现场需要临时规则时用 `-r <dir>` 覆盖。

## 核心命令

```powershell
# 采集与快照
Easy_Trace.exe collect --db easytrace.db
Easy_Trace.exe collect --module event --db easytrace.db
Easy_Trace.exe collect --module prefetch --db easytrace.db
Easy_Trace.exe collect --module execution --mode deep --db easytrace.db

# 规则与白名单
Easy_Trace.exe rules list -r rules
Easy_Trace.exe rules validate --rules rules
Easy_Trace.exe whitelist add --rule <rule_id> --entity <entity_id> --reason "已确认的正常业务" --db easytrace.db
Easy_Trace.exe whitelist list --db easytrace.db

# 分析与报告
Easy_Trace.exe analyze --db easytrace.db
Easy_Trace.exe analyze --db easytrace.db -jsonl -o findings.jsonl
Easy_Trace.exe report --db easytrace.db -o report-20261103
Easy_Trace.exe report --db easytrace.db -o report-20261103 -zip

# 关联传导（默认关闭）
Easy_Trace.exe analyze --db easytrace.db --propagate 2

# 痕迹留存（会第二次接触主机，需显式执行）
Easy_Trace.exe catch --db easytrace.db --out evidence-20261103
Easy_Trace.exe report --db easytrace.db -o report-20261103 -zip --evidence evidence-20261103

# 快照管理
Easy_Trace.exe snapshot import --db easytrace.db result.jsonl
Easy_Trace.exe snapshot list --db easytrace.db
Easy_Trace.exe snapshot show --db easytrace.db <snapshot_id>
Easy_Trace.exe snapshot diff --db easytrace.db --from <from_id> --to <to_id>

# 自校验与操作留痕
Easy_Trace.exe verify
Easy_Trace.exe verify --write-manifest
Easy_Trace.exe audit -n 20
```

## 采集模块

`collect --module all` 包含 host / process / network / persistence / service / task / driver / user。以下模块需要显式参数或更高权限，不会自动进入 `all`：

| 模块 | 触发方式 | 说明 |
| --- | --- | --- |
| `file` | `--path <dir>` + `--mode deep` 或 `forensic` | 只枚举显式指定目录，按最近修改优先，单文件哈希上限 64 MiB。 |
| `registry` | `--key <key>`（可重复） | 只读取显式指定的注册表键，可配 `--depth`。 |
| `event` | `--module event` | 按固定通道与事件 ID 白名单解析事件日志，生成带事件时刻的 `event` 实体。 |
| `prefetch` | `--module prefetch` | 只读解析 `%SystemRoot%\Prefetch\*.pf` 文件头；不解压压缩段，不提供运行次数。 |
| `execution` | `--module execution` | Basic 采 UserAssist / BAM / DAM / RecentDocs；Deep 追加 PowerShell 历史与 Recent LNK。 |

Deep 模式对固定解释器 / LOLBin 名单与用户目录进程读取命令行，但不额外读取 PE、哈希或验签。真实 Deep、Forensic 与管理员操作应单独获得授权。

## 报告与事件调查包

`report` 生成自包含 HTML，内嵌样式、无外部资源、无 JavaScript，可在隔离网络中直接打开或打印；同一快照重复导出得到相同内容。

`report -zip` 额外生成 `Incident_<YYYYMMDD>_01.zip`，包含：

- `report.html` / `findings.json` / `summary.txt`
- 只含目标快照的 `database.db`
- 各模块 CSV、`relations.csv`、`entity_scores.csv`、`timeline.csv`
- `hashes.txt`
- 可选的 `events/*.evtx` 与 `evidence/*`（需显式指定目录）

报告会包含主机名、用户名、文件路径、进程命令行与网络事实。请按内部证据保管流程处理导出物。

## 数据与能力边界

- **离线、不自动处置。** 没有自动封禁、删除、隔离、注册表修改、远端查询、IOC 下载或规则热更新。
- **采集器只采集事实，分析器只读快照与本地规则。** 检测逻辑不放入采集器，分析阶段不访问主机。
- **管理员门禁不等于自动提权。** 应用清单保持 `asInvoker`，未提权时直接退出 3，不会弹 UAC。
- **规则命中是调查线索，不是入侵结论。** 应结合原始证据、采集范围、缺失字段和人工核查判断。
- **采集范围受权限与系统策略影响。** Prefetch、事件日志、BAM/DAM 等可能因权限或策略不可用；工具会如实报告缺失或不完整。
- **Deep / Forensic 不会自动运行。** `inspect -pid` 的补证需要人工确认。
- **网络能力限于本机事实。** 不做实时抓包、流量解析、TLS 解密或在线情报查询。
- **证据留存有上限。** `catch` 默认只处理 HIGH/MEDIUM，单文件 64 MiB、合计 512 MiB，可用参数覆盖；超限会显式记录为未留存。
- **导出目标必须是新的。** 不覆盖已有文件或目录，重新导出请使用新名称。
- **构建产物未做代码签名。** 首次运行可能出现 SmartScreen「未知发布者」提示；需要来源认证时应按组织流程签名。

## 开发与构建

```text
cmd/easytrace-agent    CLI 入口、命令解析、管理员门禁
internal/collector     各模块采集器与采集流水线
internal/analyzer      规则加载、匹配、传导与实体评分
internal/storage       SQLite 快照、实体、线索与差异
internal/model         协议数据结构
internal/output        JSONL 输出
internal/evidence      证据留存与校验
internal/platform      权限检测等平台能力
rules/                 内嵌 YAML 规则（//go:embed，构建必需）
```

开发检查：

```powershell
gofmt -l .
go vet ./...
go build -o Easy_Trace.exe ./cmd/easytrace-agent
```

`build.ps1` 会生成并立即自校验 `Easy_Trace.manifest.sha256`，并扫描成品 exe 是否含可能触发杀软启发式的高危连续字串。

## 开发规则

1. 采集器只采集事实。
2. 分析器产生调查线索。
3. 输出与存储层之外的模块不得直接写入导出文件。
4. 结构化数据必须符合协议约束。
5. 不引入自动处置、自动网络查询或外部命令执行。
6. 不将检测逻辑放入采集器。
7. 真实主机行为与 fixture 验证必须明确区分。
