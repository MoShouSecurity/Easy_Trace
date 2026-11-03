package model

// 本文件定义 Entity/Relation 的强类型 Data 结构（协议 v0.2 §3）。
// 原则：采集器写入的每个字段必须在此定义；禁止裸 map / 动态字段。
// 后续采集模块扩展 Data 时：先更新 docs/protocol-spec-v0.2.md §3，再实现。
// 例外：协议**已冻结**的类型若未给出 data 形状（如 file），形状以
// docs/实现状态.md「实体类型补充」为准，不改动冻结规范本身。

// HostData 主机信息（Task 1 Host Collector）。
type HostData struct {
	Hostname     string `json:"hostname"`
	OSVersion    string `json:"os_version"`
	OSBuild      string `json:"os_build"`
	Architecture string `json:"architecture"`
	Username     string `json:"username"`
	CurrentTime  string `json:"current_time"`
	BootTime     string `json:"boot_time,omitempty"`
}

// ProcessData 进程信息（Task 2 Process Collector；Step 1/1.5 起两级采集）。
// creation_time 为基础字段；collection_level 标记本实体为 basic（默认）或 deep。
// signature_state 为轻量检测结果（present/missing/unknown），不调用 WinVerifyTrust；
// signed/publisher 由深度签名验证（enrichment）填充。
type ProcessData struct {
	PID             uint32 `json:"pid"`
	Name            string `json:"name"`
	Path            string `json:"path"`
	ParentPID       uint32 `json:"parent_pid"`
	CommandLine     string `json:"command_line"`
	Username        string `json:"username"`
	Session         uint32 `json:"session"`
	Windowed        bool   `json:"windowed"`
	Signed          bool   `json:"signed"`
	SignatureState  string `json:"signature_state,omitempty"`
	HashSHA256      string `json:"hash_sha256,omitempty"`
	CreationTime    string `json:"creation_time,omitempty"`
	CollectionLevel string `json:"collection_level,omitempty"`
}

// ProcessEnrichmentData 进程深度采集补充数据（Step 1/1.5/1.6，经 entity_update 输出，
// ProcessData 的子集）。last_write_time 为 PE Inspect 阶段获取的文件最近修改时间。
type ProcessEnrichmentData struct {
	CommandLine       string `json:"command_line,omitempty"`
	HashSHA256        string `json:"hash_sha256,omitempty"`
	ParentCommandLine string `json:"parent_command_line,omitempty"`
	SignatureState    string `json:"signature_state,omitempty"`
	// nil 表示未验签；显式 false/空 publisher 撤销旧成功值，wire 类型保持 bool/string。
	SignatureValid  *bool   `json:"signature_valid,omitempty"`
	Publisher       *string `json:"publisher,omitempty"`
	LastWriteTime   string  `json:"last_write_time,omitempty"`
	CollectionLevel string  `json:"collection_level"`
}

// NetworkData 网络连接（Task 3 Network Collector）。
type NetworkData struct {
	Protocol   string `json:"protocol"`
	LocalIP    string `json:"local_ip"`
	LocalPort  uint16 `json:"local_port"`
	RemoteIP   string `json:"remote_ip"`
	RemotePort uint16 `json:"remote_port"`
	State      string `json:"state"`
	PID        uint32 `json:"pid"`
}

// PersistenceData 持久化项（Task 4 Persistence Collector）。
type PersistenceData struct {
	Type     string `json:"type"`
	Location string `json:"location"`
	Name     string `json:"name"`
	Command  string `json:"command"`
	Path     string `json:"path"`
	User     string `json:"user"`
	// KeyLastWriteTime 是**注册表键**的 LastWriteTime（UTC/RFC3339）——"这个键最后一次被改动"。
	//
	// 注意语义边界（2026-10-14 本机实测）：它**不是**"这个启动项被人加上去的时刻"——系统自身
	// 在开机、更新、安装时也会改写这类键（实测 Winlogon Shell/Userinit 的键时间 = 开机后 12 秒）。
	// 因此它只能当**线索**："可疑键在什么时候变了"，不能当结论。
	// 只对注册表来源的项有值；启动文件夹等文件来源留空（文件时间见深采的 last_write_time，
	// 两者语义不同，不混用）。形状记录见 docs/实现状态.md「实体类型补充」。
	KeyLastWriteTime string `json:"key_last_write_time,omitempty"`
}

// ServiceData 服务（Task 5 Service Collector）。
type ServiceData struct {
	ServiceName string `json:"service_name"`
	DisplayName string `json:"display_name"`
	BinaryPath  string `json:"binary_path"`
	StartType   string `json:"start_type"`
	Status      string `json:"status"`
	Account     string `json:"account"`
}

// TaskData 计划任务（Task 6 Scheduled Task Collector）。
type TaskData struct {
	TaskName string `json:"task_name"`
	Path     string `json:"path"`
	Author   string `json:"author"`
	Command  string `json:"command"`
	Trigger  string `json:"trigger"`
	Enabled  bool   `json:"enabled"`
}

// UserData 用户（Task 7 User Collector）。
type UserData struct {
	Username  string   `json:"username"`
	SID       string   `json:"sid"`
	Groups    []string `json:"groups"`
	Enabled   bool     `json:"enabled"`
	LastLogin string   `json:"last_login,omitempty"`
}

// FileData 是 file 实体的 data 形状（P1-9：协议白名单已声明 file 类型与 ID 规则
// file_<sha256前12>_<seq> / file_na_<seq>，但 v0.2 未给出字段形状）。
//
// 字段全部沿用协议中已有的同名语义，未引入新概念：
//   - path / size / last_write_time：文件事实（last_write_time 与 ProcessEnrichmentData 同名）
//   - extension：按最后一个扩展名规范化的小写形式（便于规则匹配）
//   - hash_sha256：深采阶段计算的 SHA256（基础采集为空 → entity_id 走 file_na_<seq>）
//   - collection_level：basic / deep / forensic
//
// 尚未填充（后续复用 process 的 PE/验签能力后再补，不在本阶段声称支持）：
// signature_state / signed / publisher。
type FileData struct {
	Path            string `json:"path"`
	Size            int64  `json:"size"`
	LastWriteTime   string `json:"last_write_time,omitempty"`
	Extension       string `json:"extension,omitempty"`
	HashSHA256      string `json:"hash_sha256,omitempty"`
	CollectionLevel string `json:"collection_level"`
}

// RegistryData 是 registry 实体的 data 形状（P1-9：协议白名单已声明 registry 类型与
// ID 规则 registry_<sha1(path)>，但 v0.2 未给出字段形状；形状记录见
// docs/实现状态.md「实体类型补充」）。
//
// 一条 registry 实体表示**一个注册表值**（path = <key>\<value name>）；当目标键
// 没有任何值时，输出一条代表该键自身的记录（value_type="(key)"），避免把
// "键存在但没有值"丢成"什么都没采到"。
type RegistryData struct {
	Path            string `json:"path"`
	Key             string `json:"key"`
	Name            string `json:"name"`
	ValueType       string `json:"value_type"`
	ValueData       string `json:"value_data,omitempty"`
	Truncated       bool   `json:"truncated,omitempty"`
	CollectionLevel string `json:"collection_level"`
}

// DriverData 是 driver 实体的 data 形状（P1-9：协议白名单已声明 driver 类型与
// ID 规则 driver_<name>，但 v0.2 未给出字段形状）。
//
// 来源：EnumDeviceDrivers + GetDeviceDriverBaseNameW/FileNameW（**已加载**的内核驱动
// 模块，只读枚举）。base_address 是本次启动的加载基址（随 ASLR 变化），仅作为事实记录。
// 尚未填充：签名态 / 发布者（需先抽共享 PE-WinVerifyTrust 能力，不在本阶段声称支持）。
type DriverData struct {
	Name            string `json:"name"`
	Path            string `json:"path,omitempty"`
	BaseAddress     string `json:"base_address,omitempty"`
	CollectionLevel string `json:"collection_level"`
}

// EventData 是 event 实体的 data 形状（日志采集阶段 B：协议白名单新增 entity_type=event，
// 但 v0.2 未给出字段形状；形状记录见 docs/实现状态.md「实体类型补充」）。
//
// 语义提醒：
//   - `time_created` 是**事件自身的时间**（UTC / RFC3339 秒精度），不是采集时刻；
//     采集时刻由 snapshot.collected_at 单独标注，两者不可混用。
//   - 关键字段按事件 ID 选填（omitempty），只来自**通道 + 事件 ID 白名单**内的事件。
//   - **不放完整原始 XML**：体积大，且会把 XML 解析负担推给 Analyzer；
//     完整原件在 `collect --evtx` 导出的 `events/*.evtx` 里。
type EventData struct {
	// 通用字段（每条事件都有）
	Channel     string `json:"channel"`
	EventID     uint32 `json:"event_id"`
	Level       string `json:"level,omitempty"`
	Provider    string `json:"provider,omitempty"`
	RecordID    uint64 `json:"record_id"`
	TimeCreated string `json:"time_created"` // UTC / RFC3339 秒精度
	Computer    string `json:"computer,omitempty"`
	Summary     string `json:"summary"`

	// 关键字段（按事件 ID 选填）—— 这些正是排查横向移动、口令爆破、Kerberoasting、
	// RDP 登录、服务安装的依据；空值一律不写，绝不用占位值（"-"）充数。
	LogonType            uint32 `json:"logon_type,omitempty"`
	TargetUser           string `json:"target_user,omitempty"`
	TargetSid            string `json:"target_sid,omitempty"`
	SubjectUser          string `json:"subject_user,omitempty"`
	IPAddress            string `json:"ip_address,omitempty"`
	LogonProcess         string `json:"logon_process,omitempty"`
	ShareName            string `json:"share_name,omitempty"`
	TicketEncryptionType string `json:"ticket_encryption_type,omitempty"`
	ServiceName          string `json:"service_name,omitempty"`
	ProcessName          string `json:"process_name,omitempty"`
	// ImagePath 归一 7045 的 ImagePath / 4697 的 ServiceFileName；
	// ParentProcessName 来自 4688。两者都可能包含参数/较长路径，统一裁剪。
	ImagePath         string `json:"image_path,omitempty"`
	ParentProcessName string `json:"parent_process_name,omitempty"`
	CommandLine       string `json:"command_line,omitempty"`
	ScriptBlockText   string `json:"script_block_text,omitempty"`
}

// PrefetchData 是 prefetch 实体的 data 形状（2026-10-30 协议白名单新增
// entity_type=prefetch，v0.2 未给出字段形状；形状记录见 docs/实现状态.md
// 「实体类型补充」）。
//
// 来源：只读解析 %SystemRoot%\Prefetch\*.pf 的**固定文件头**（版本 / "SCCA" 签名 /
// 可执行文件名 / prefetch hash）。压缩块（文件列表、卷信息、metrics）不解压。
//
// 语义提醒：
//   - `executable_name` 是 .pf 头里的可执行文件名（如 NOTEPAD.EXE），不是完整路径；
//     同一镜像可能因路径不同产生多个 .pf 文件。
//   - `last_write_time` 是 **.pf 文件自身的最后写入时间**（UTC/RFC3339）。Windows 在
//     程序再次运行时重写该文件，所以它是"最近一次运行"的**实用近似**，不是保证；
//     报告/规则不得把它当作确凿的执行时间。
//   - 不提供运行次数：该数值需解压 metrics 段，未实现，绝不用 0 占位。
type PrefetchData struct {
	ExecutableName  string `json:"executable_name"`
	PrefetchHash    string `json:"prefetch_hash,omitempty"`
	SourceVersion   uint32 `json:"source_version,omitempty"`
	Path            string `json:"path"`
	FileSize        int64  `json:"file_size"`
	LastWriteTime   string `json:"last_write_time,omitempty"`
	CollectionLevel string `json:"collection_level"`
}

// ExecutionData 是 execution 实体的 data 形状（2026-10-30 批准新增 entity_type=execution）。
//
// 一个 execution 实体代表一条**执行痕迹**，source 区分来源：
// userassist / bam / dam / recentdocs / pshistory / lnk。
//
// 语义提醒（字段随来源选填，不得互相冒充）：
//   - `last_run_time` 只在来源能解释"何时运行"时填写：UserAssist、BAM/DAM。
//     RecentDocs、PowerShell 历史、LNK **不填** last_run_time——它们没有可靠的
//     执行时间，绝不拿文件写入时间顶替。
//   - `last_write_time` 是来源文件（.lnk / PowerShell 历史文件）自身的写入时间，
//     只在文件类来源填写；它同样不是执行时间。
//   - `run_count` 只有 UserAssist 提供；BAM/DAM 没有次数，留空而不是填 0。
//   - `command` 是 PowerShell 历史中的一行；其它来源留空。
//   - PowerShell 历史按行去重，`occurrences` 记录同一行出现的次数。
type ExecutionData struct {
	Source          string  `json:"source"`                    // userassist / bam / dam / recentdocs / pshistory / lnk
	User            string  `json:"user,omitempty"`            // 用户名或 SID
	Name            string  `json:"name,omitempty"`            // 显示名 / 文件名
	Path            string  `json:"path,omitempty"`            // 可执行文件、目标文件或历史文件路径
	Command         string  `json:"command,omitempty"`         // PowerShell 历史行
	RunCount        *uint32 `json:"run_count,omitempty"`       // UserAssist 运行次数；其它来源为 nil（不填 0）
	LastRunTime     string  `json:"last_run_time,omitempty"`   // UTC/RFC3339；仅可信来源
	LastWriteTime   string  `json:"last_write_time,omitempty"` // 来源文件写入时间；不是执行时间
	Occurrences     *uint32 `json:"occurrences,omitempty"`     // PowerShell 历史去重后的出现次数；其它来源为 nil
	CollectionLevel string  `json:"collection_level"`
}

// PersistenceEnrichmentData 是 persistence 实体的**深采补充数据**（经 entity_update 输出，
// 与 ProcessEnrichmentData 同一模式）。
//
// 字段来自启动项目标文件的只读元数据（internal/filemeta）：
// hash_sha256（超过哈希上限时留空）、signature_state（PE 安全目录存在/缺失/不可读）、
// last_write_time。形状记录见 docs/实现状态.md「实体类型补充」。
// 语义提醒：signature_state=missing 只表示 PE 安全目录不存在，**不等于**"确认未签名"。
type PersistenceEnrichmentData struct {
	HashSHA256      string `json:"hash_sha256,omitempty"`
	SignatureState  string `json:"signature_state,omitempty"`
	LastWriteTime   string `json:"last_write_time,omitempty"`
	CollectionLevel string `json:"collection_level"`
}
