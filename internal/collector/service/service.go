// Package service 实现 Service Collector（Task 5）。
//
// 枚举 Windows 服务（Windows Service API），输出 service 实体与
// service --launch--> process 关系。只采集事实，不修改服务状态。
package service

import (
	"fmt"
	"os"
	goruntime "runtime"
	"sort"
	"syscall"
	"unsafe"

	"easytrace/internal/collector"
	"easytrace/internal/collector/runtime"
	"easytrace/internal/model"
)

// ---- Windows API 句柄（懒加载，零外部依赖） ----
var (
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	procOpenSCManagerW        = advapi32.NewProc("OpenSCManagerW")
	procEnumServicesStatusExW = advapi32.NewProc("EnumServicesStatusExW")
	procOpenServiceW          = advapi32.NewProc("OpenServiceW")
	procQueryServiceConfigW   = advapi32.NewProc("QueryServiceConfigW")
	procCloseServiceHandle    = advapi32.NewProc("CloseServiceHandle")
)

// 常量
const (
	scManagerConnect          = 0x0001 // SC_MANAGER_CONNECT
	scManagerEnumerateService = 0x0004 // SC_MANAGER_ENUMERATE_SERVICE
	scEnumProcessInfo         = 0      // SC_ENUM_PROCESS_INFO
	serviceWin32              = 0x30   // SERVICE_WIN32
	serviceStateAll           = 3      // SERVICE_STATE_ALL
	serviceQueryConfig        = 0x0001 // SERVICE_QUERY_CONFIG
)

// startType / status 映射
var startTypeNames = map[uint32]string{
	0: "boot", 1: "system", 2: "auto", 3: "demand", 4: "disabled",
}

var statusNames = map[uint32]string{
	1: "stopped", 2: "start_pending", 3: "stop_pending", 4: "running",
	5: "continue_pending", 6: "pause_pending", 7: "paused",
}

// serviceEntry 是单个服务的中间结构（内部结构，供测试注入）。
type serviceEntry struct {
	name        string
	displayName string
	binaryPath  string
	startType   string
	status      string
	account     string
	pid         uint32
}

// serviceStatusProcess 对应 SERVICE_STATUS_PROCESS。
type serviceStatusProcess struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
	ProcessID               uint32
	ServiceFlags            uint32
}

// enumServiceStatusProcess 对应 ENUM_SERVICE_STATUS_PROCESSW。
type enumServiceStatusProcess struct {
	ServiceName          *uint16
	DisplayName          *uint16
	ServiceStatusProcess serviceStatusProcess
}

// queryServiceConfig 对应 QUERY_SERVICE_CONFIGW（64 位下字符串字段存相对偏移）。
type queryServiceConfig struct {
	ServiceType      uint32
	StartType        uint32
	ErrorControl     uint32
	_                uint32 // padding
	BinaryPathName   uintptr
	LoadOrderGroup   uintptr
	TagID            uint32
	_                uint32
	Dependencies     uintptr
	ServiceStartName uintptr
	DisplayName      uintptr
}

// Collector 实现 service 采集。getEntries 可注入以便测试；nil 时使用真实 Windows API。
type Collector struct {
	getEntries func() ([]serviceEntry, error)
	rt         *runtime.Runtime
}

// New 创建使用真实 Windows API 的 Service Collector，绑定调用方注入的 Runtime。
// Collector 不在内部创建 Runtime（架构收口，Step 2.2）；rt 必传，nil 视为编程错误。
func New(rt *runtime.Runtime) *Collector {
	if rt == nil {
		panic("service: New 必须传入 runtime.Runtime（禁止 Collector 内部创建）")
	}
	return &Collector{rt: rt}
}

// NewWithEntries 创建使用自定义数据源的 Service Collector（用于测试）。
func NewWithEntries(rt *runtime.Runtime, f func() ([]serviceEntry, error)) *Collector {
	c := New(rt)
	c.getEntries = f
	return c
}

// Runtime 返回绑定的行为控制 Runtime（供注入一致性校验）。
func (c *Collector) Runtime() *runtime.Runtime { return c.rt }

// Name 实现 collector.Collector 接口。
func (c *Collector) Name() string { return "service" }

// Collect 实现 collector.Collector 接口：返回 service 实体 + launch 关系。
//
// Step 5.1 行为门卫：先经 rt.Allow("service","ServiceQuery") 检查——被拒则
// 不执行任何 Service API，返回空结果并记录 deny 行为事件（不视为错误）。
// 容错遵循"能采多少采多少"：单服务配置查询失败已降级留空；枚举整体失败时
// 已采项照常保留，但返回聚合错误，让 CLI/Pipeline 计入失败而不是把空结果当成功。
// 服务有 PID 时生成 service --launch--> process_<pid> 关系。
func (c *Collector) Collect() (*collector.Result, error) {
	if !c.rt.Allow("service", "ServiceQuery", "services") {
		debugf("service_query_denied mode=%s", c.rt.Mode())
		return &collector.Result{}, nil
	}
	getEntries := c.getEntries
	if getEntries == nil {
		getEntries = collectServices
	}
	entries, err := getEntries()
	if err != nil {
		// 部分失败：记录内部错误（含 collector/capability/operation/error），保留已采集项。
		debugf("collection_error collector=service capability=ServiceQuery operation=collectServices error=%v", err)
	}

	// 输出顺序决定事件流的字节级可复现性：Windows 枚举顺序并不保证稳定。
	// 实体 ID 仍是 service_<name>（协议字段语义不变），但稳定顺序让同一批服务
	// 在任何枚举顺序下都产出相同的实体/关系序列。
	sort.SliceStable(entries, func(i, j int) bool {
		return serviceEntryLess(entries[i], entries[j])
	})

	res := &collector.Result{}
	for _, se := range entries {
		id := "service_" + se.name
		e := model.NewEntity("service", id, model.ServiceData{
			ServiceName: se.name,
			DisplayName: se.displayName,
			BinaryPath:  se.binaryPath,
			StartType:   se.startType,
			Status:      se.status,
			Account:     se.account,
		})
		res.Entities = append(res.Entities, e)

		if se.pid != 0 {
			rel := model.NewRelation(
				fmt.Sprintf("rel_%s", se.name),
				id,
				fmt.Sprintf("process_%d", se.pid),
				"launch",
				map[string]string{"status": se.status},
			)
			res.Relations = append(res.Relations, rel)
		}
	}
	if err != nil {
		return res, fmt.Errorf("service 采集不完整: %w", err)
	}
	return res, nil
}

// serviceEntryLess 是全字段稳定排序键：name → displayName → binaryPath →
// startType → status → account → pid。所有字段都参与比较，保证同一批服务
// 在任意枚举顺序下都得到相同输出序列。
func serviceEntryLess(a, b serviceEntry) bool {
	if a.name != b.name {
		return a.name < b.name
	}
	if a.displayName != b.displayName {
		return a.displayName < b.displayName
	}
	if a.binaryPath != b.binaryPath {
		return a.binaryPath < b.binaryPath
	}
	if a.startType != b.startType {
		return a.startType < b.startType
	}
	if a.status != b.status {
		return a.status < b.status
	}
	if a.account != b.account {
		return a.account < b.account
	}
	return a.pid < b.pid
}

// debugf 输出采集阶段/内部错误日志到 stderr（不污染 stdout 的 JSONL 流）。
func debugf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[service] "+format+"\n", args...)
}

// collectServices 通过 Windows Service API 枚举服务（含状态与配置）。
func collectServices() ([]serviceEntry, error) {
	hSCM, _, _ := procOpenSCManagerW.Call(0, 0, scManagerConnect|scManagerEnumerateService)
	if hSCM == 0 {
		return nil, fmt.Errorf("OpenSCManagerW 失败（无权限枚举服务）")
	}
	defer procCloseServiceHandle.Call(hSCM)

	// 用初始 buffer 直接枚举；不足时按需扩大（EnumServicesStatusExW 返回 BOOL，非 0=成功）
	size := uint32(128 * 1024)
	buf := make([]byte, size)
	var bytesNeeded, servicesReturned, resumeHandle uint32
	ret, _, _ := procEnumServicesStatusExW.Call(hSCM, scEnumProcessInfo, serviceWin32,
		serviceStateAll, uintptr(unsafe.Pointer(&buf[0])), uintptr(size),
		uintptr(unsafe.Pointer(&bytesNeeded)),
		uintptr(unsafe.Pointer(&servicesReturned)), uintptr(unsafe.Pointer(&resumeHandle)), 0)
	goruntime.KeepAlive(buf)
	if ret == 0 && bytesNeeded > 0 {
		// buffer 不足（GetLastError=ERROR_INSUFFICIENT_BUFFER），扩大重试
		buf = make([]byte, bytesNeeded)
		resumeHandle = 0
		ret, _, _ = procEnumServicesStatusExW.Call(hSCM, scEnumProcessInfo, serviceWin32,
			serviceStateAll, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)),
			uintptr(unsafe.Pointer(&bytesNeeded)),
			uintptr(unsafe.Pointer(&servicesReturned)), uintptr(unsafe.Pointer(&resumeHandle)), 0)
		goruntime.KeepAlive(buf)
	}
	if ret == 0 {
		return nil, fmt.Errorf("EnumServicesStatusExW 失败")
	}

	entries := make([]serviceEntry, 0, servicesReturned)
	items := unsafe.Slice((*enumServiceStatusProcess)(unsafe.Pointer(&buf[0])), servicesReturned)
	for i := range items {
		item := &items[i]
		name := utf16PtrToString(item.ServiceName)
		display := utf16PtrToString(item.DisplayName)
		status := statusNames[item.ServiceStatusProcess.CurrentState]
		pid := item.ServiceStatusProcess.ProcessID

		// 查询服务配置（权限不足时优雅降级：字段留空）
		cfg := queryServiceConfigEntry(hSCM, name)
		entries = append(entries, serviceEntry{
			name:        name,
			displayName: display,
			binaryPath:  cfg.binaryPath,
			startType:   cfg.startType,
			status:      status,
			account:     cfg.account,
			pid:         pid,
		})
	}
	return entries, nil
}

// serviceConfig 是查询结果。
type serviceConfig struct {
	binaryPath string
	startType  string
	account    string
}

// queryServiceConfigEntry 查询单个服务的配置（权限不足/失败时返回空配置，不中断整体）。
func queryServiceConfigEntry(hSCM uintptr, name string) serviceConfig {
	var out serviceConfig
	if name == "" {
		return out
	}
	hSvc, _, _ := procOpenServiceW.Call(hSCM,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(name))), serviceQueryConfig)
	if hSvc == 0 {
		return out // 权限不足 / 服务不可访问：优雅降级
	}
	defer procCloseServiceHandle.Call(hSvc)

	var bytesNeeded uint32
	ret, _, _ := procQueryServiceConfigW.Call(hSvc, 0, 0, uintptr(unsafe.Pointer(&bytesNeeded)))
	if ret == 0 && bytesNeeded == 0 {
		return out
	}
	buf := make([]byte, bytesNeeded)
	ret, _, _ = procQueryServiceConfigW.Call(hSvc,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&bytesNeeded)))
	goruntime.KeepAlive(buf)
	if ret == 0 { // QueryServiceConfigW 返回 BOOL，非 0=成功
		return out
	}
	cfg := (*queryServiceConfig)(unsafe.Pointer(&buf[0]))
	out.startType = startTypeNames[cfg.StartType]
	out.binaryPath = strFromBuffer(buf, uintptr(cfg.BinaryPathName))
	out.account = strFromBuffer(buf, uintptr(cfg.ServiceStartName))
	return out
}

// utf16PtrToString 从 *uint16 指针读取字符串（直到 NUL，带防御上限）。
func utf16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	var chars []uint16
	for i := 0; i < 4096; i++ {
		c := *(*uint16)(unsafe.Add(unsafe.Pointer(p), uintptr(i)*2))
		if c == 0 {
			break
		}
		chars = append(chars, c)
	}
	return syscall.UTF16ToString(chars)
}

// strFromBuffer 将 QUERY_SERVICE_CONFIGW 返回的字符串字段转为字符串。
// 兼容两种形式：绝对指针（指向 buffer 内）与相对偏移。
func strFromBuffer(buf []byte, field uintptr) string {
	if field == 0 {
		return ""
	}
	base := uintptr(unsafe.Pointer(&buf[0]))
	// 情况1：绝对指针且指向 buffer 内
	if field >= base && field < base+uintptr(len(buf)) {
		off := field - base
		return utf16PtrToString((*uint16)(unsafe.Add(unsafe.Pointer(&buf[0]), off)))
	}
	// 情况2：相对偏移（64 位下部分系统返回偏移量）
	if field < uintptr(len(buf)) {
		return utf16PtrToString((*uint16)(unsafe.Add(unsafe.Pointer(&buf[0]), field)))
	}
	return ""
}
