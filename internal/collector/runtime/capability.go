package runtime

// Capability 描述采集运行时被授予的行为能力（deny by default：
// Collector 只能使用被授予的能力，不能自行决定；未知能力一律拒绝）。
//
// 每个字段对应一类可能触发安全软件行为监控的系统操作。
// Step 2.2 冻结：覆盖当前全部 Collector（Process/Network/Persistence/Service/Task/User）。
type Capability struct {
	// ReadProcessMemory 读取其他进程内存（PEB / 命令行等）。[Process]
	ReadProcessMemory bool
	// ReadFile 读取文件内容或元数据（PE 头、修改时间等）。[Process]
	ReadFile bool
	// HashFile 计算文件 SHA256。[Process]
	HashFile bool
	// VerifySignature 调用 WinVerifyTrust 验证文件签名。[Process]
	VerifySignature bool
	// NetworkQuery 枚举网络连接表（GetExtendedTcpTable/UdpTable，离线查询）。[Network]
	NetworkQuery bool
	// RegistryQuery 查询注册表（启动项/配置等）。[Persistence]
	RegistryQuery bool
	// ServiceQuery 枚举服务（OpenSCManager/EnumServicesStatusEx，只读）。[Service]
	ServiceQuery bool
	// TaskQuery 枚举计划任务（schtasks /query 只读）。[Task]
	TaskQuery bool
	// DriverQuery 枚举**已加载的内核驱动模块**（EnumDeviceDrivers +
	// GetDeviceDriverBaseNameW/FileNameW，只读枚举，不加载/不卸载/不读驱动内存）。
	// [Driver] 2026-10-13 随 Driver Collector 加入能力集：仍属只读系统枚举，
	// 与 ServiceQuery/TaskQuery 同级，因此 Basic 模式也授予。
	DriverQuery bool
	// ExternalCommand 执行外部程序（任意外部命令；schtasks 只读查询走 TaskQuery，
	// 不消耗本能力）。[Task]
	ExternalCommand bool
	// UserQuery 枚举用户与本地组（NetUserEnum 等，只读）。[User]
	UserQuery bool
	// EventQuery 只读查询事件日志（wevtapi EvtQuery/EvtNext/EvtRender：按
	// **通道 + 事件 ID 白名单**取事件，不导出、不清除、不改通道配置，也不执行
	// wevtutil.exe）。[Event] 2026-10-15 随 Event Collector（日志阶段 B）加入能力集：
	// 属只读系统查询，与 ServiceQuery/TaskQuery 同级，因此 Basic 模式也授予。
	EventQuery bool
	// PrefetchQuery 只读枚举并解析 %SystemRoot%\Prefetch\*.pf 的**固定文件头**
	// （版本 / "SCCA" 签名 / 可执行文件名 / prefetch hash）。[Prefetch] 2026-10-30
	// 随 Prefetch Collector 加入能力集：路径固定、不遍历其它目录、不解压、不执行，
	// 与 DriverQuery/EventQuery 同为只读系统枚举，因此 Basic 模式也授予。
	PrefetchQuery bool
}

// modeCapabilities 定义各模式授予的能力集合。
//
// Basic 对齐 process Step 1.6 验证过的低暴露面：只保留只读枚举/查询能力，
// 一切文件/内存触碰（ReadProcessMemory/ReadFile/HashFile/VerifySignature）与
// 任意外部命令（ExternalCommand）全部拒绝。
// Deep 在 Basic 基础上授予补充证据能力。
// Forensic 授予全部能力（当前与 Deep 一致，后续扩展）。
var modeCapabilities = map[CollectionMode]Capability{
	Basic: {
		NetworkQuery:  true,
		DriverQuery:   true,
		RegistryQuery: true,
		ServiceQuery:  true,
		TaskQuery:     true,
		UserQuery:     true,
		EventQuery:    true,
		PrefetchQuery: true,
	},
	Deep: {
		ReadProcessMemory: true,
		ReadFile:          true,
		HashFile:          true,
		VerifySignature:   true,
		NetworkQuery:      true,
		RegistryQuery:     true,
		ServiceQuery:      true,
		TaskQuery:         true,
		DriverQuery:       true,
		UserQuery:         true,
		EventQuery:        true,
		PrefetchQuery:     true,
	},
	Forensic: {
		ReadProcessMemory: true,
		ReadFile:          true,
		HashFile:          true,
		VerifySignature:   true,
		NetworkQuery:      true,
		RegistryQuery:     true,
		ServiceQuery:      true,
		TaskQuery:         true,
		ExternalCommand:   true,
		DriverQuery:       true,
		UserQuery:         true,
		EventQuery:        true,
		PrefetchQuery:     true,
	},
}

// Capabilities 返回模式 m 授予的能力集合；未注册模式按 Basic 处理（安全默认）。
func Capabilities(m CollectionMode) Capability {
	if c, ok := modeCapabilities[m]; ok {
		return c
	}
	return modeCapabilities[Basic]
}
