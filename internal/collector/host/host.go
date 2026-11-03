// Package host 实现 Host Collector（Task 1）。
//
// 采集 Windows 主机基础信息，输出 entity_type=host 的 Entity。
// 只采集事实，不输出 Finding；数据符合协议 v0.2 的 HostData 结构。
package host

import (
	"fmt"
	"syscall"
	"time"
	"unsafe"

	"easytrace/internal/collector"
	"easytrace/internal/collector/runtime"
	"easytrace/internal/model"
)

// Windows API 句柄（懒加载，保持零外部依赖）。
var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")
	ntdll    = syscall.NewLazyDLL("ntdll.dll")

	procGetComputerNameW = kernel32.NewProc("GetComputerNameW")
	procGetTickCount64   = kernel32.NewProc("GetTickCount64")
	procGetNativeSystem  = kernel32.NewProc("GetNativeSystemInfo")
	procGetUserNameW     = advapi32.NewProc("GetUserNameW")
	procRegOpenKeyExW    = advapi32.NewProc("RegOpenKeyExW")
	procRegQueryValueExW = advapi32.NewProc("RegQueryValueExW")
	procRegCloseKey      = advapi32.NewProc("RegCloseKey")
	procRtlGetVersion    = ntdll.NewProc("RtlGetVersion")
)

// rtlOSVersionInfoEx 对应 RTL_OSVERSIONINFOEXW（**完整**字段，见下方 systemInfo 的教训）。
type rtlOSVersionInfoEx struct {
	OSVersionInfoSize uint32
	MajorVersion      uint32
	MinorVersion      uint32
	BuildNumber       uint32
	PlatformID        uint32
	CSDVersion        [128]uint16
	ServicePackMajor  uint16
	ServicePackMinor  uint16
	SuiteMask         uint16
	ProductType       uint8
	Reserved          uint8
}

// systemInfo 对应 Win32 SYSTEM_INFO（**完整**字段，不是"只用前几个字段"）。
//
// 教训（2026-10-15，真实事故）：此前这里只声明了前 3 个字段（8 字节），而
// GetNativeSystemInfo 会把**整个结构体**写满（x64 上 48 字节）——API 因此越界写掉
// 40 字节**栈内存**，踩坏同一栈帧里的其它局部变量（切片头 / 接口值等），最终在完全
// 无关的 encoding/json 里以 `reflect: Field index out of range` 偶发崩溃：随机、
// 与 GC/堆状态强相关、`GOGC=1` 下必现、排查了整整一轮才定位到。
//
// 规则：**交给 API 填写的结构体必须与 Win32 定义逐字段对齐**，不能用"只取需要的字段"
// 的写法。host 包有尺寸断言测试（TestWin32StructLayouts）兜住这一类回归。
type systemInfo struct {
	ProcessorArchitecture     uint16
	Reserved                  uint16
	PageSize                  uint32
	MinimumApplicationAddress uintptr
	MaximumApplicationAddress uintptr
	ActiveProcessorMask       uintptr
	NumberOfProcessors        uint32
	ProcessorType             uint32
	AllocationGranularity     uint32
	ProcessorLevel            uint16
	ProcessorRevision         uint16
}

const (
	hkeyLocalMachine      = 0x80000002
	keyRead               = 0x00020019
	regSz                 = 1
	ntdllVersionKey       = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	ntdllVersionValueName = "ProductName"
)

// Collector 采集主机信息。getData 可注入以便单元测试；nil 时使用真实 Windows API。
type Collector struct {
	getData func() (*model.HostData, error)
	rt      *runtime.Runtime
}

// New 创建使用真实 Windows API 的 Host Collector，绑定调用方注入的 Runtime。
// Collector 不在内部创建 Runtime（架构收口，Step 2.2）；rt 必传，nil 视为编程错误。
func New(rt *runtime.Runtime) *Collector {
	if rt == nil {
		panic("host: New 必须传入 runtime.Runtime（禁止 Collector 内部创建）")
	}
	return &Collector{rt: rt}
}

// NewWithDataFunc 创建使用自定义数据源的 Host Collector（用于测试）。
func NewWithDataFunc(rt *runtime.Runtime, f func() (*model.HostData, error)) *Collector {
	c := New(rt)
	c.getData = f
	return c
}

// Runtime 返回绑定的行为控制 Runtime（供注入一致性校验）。
func (c *Collector) Runtime() *runtime.Runtime { return c.rt }

// Name 实现 collector.Collector 接口。
func (c *Collector) Name() string { return "host" }

// Collect 实现 collector.Collector 接口，返回 host 实体。
func (c *Collector) Collect() (*collector.Result, error) {
	getData := c.getData
	if getData == nil {
		getData = collectHostData
	}
	data, err := getData()
	if err != nil {
		return nil, err
	}
	e := model.NewEntity("host", "host_"+data.Hostname, *data)
	return &collector.Result{Entities: []*model.Entity{e}}, nil
}

// collectHostData 通过 Windows API 采集主机信息。
func collectHostData() (*model.HostData, error) {
	hostname, err := getComputerName()
	if err != nil {
		return nil, fmt.Errorf("GetComputerNameW: %w", err)
	}

	username, err := getUserName()
	if err != nil {
		return nil, fmt.Errorf("GetUserNameW: %w", err)
	}

	arch := getArchitecture()
	major, minor, build := getOSVersion()
	// Windows 11 的注册表 ProductName 至今仍写 "Windows 10 ..."（兼容性遗留），
	// 因此必须结合 build 号修正，否则会把 Windows 11 报成 Windows 10。
	osVersion := normalizeProductName(getProductName(), build)
	if osVersion == "" {
		osVersion = fmt.Sprintf("Windows %d.%d", major, minor)
	}
	osBuild := fmt.Sprintf("%d", build)

	now := time.Now().UTC()
	bootTime := getBootTime(now)

	return &model.HostData{
		Hostname:     hostname,
		OSVersion:    osVersion,
		OSBuild:      osBuild,
		Architecture: arch,
		Username:     username,
		CurrentTime:  now.Format(time.RFC3339),
		BootTime:     bootTime,
	}, nil
}

// getComputerName 获取主机名。
func getComputerName() (string, error) {
	var buf [256]uint16
	n := uint32(len(buf))
	ret, _, err := procGetComputerNameW.Call(
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)))
	if ret == 0 {
		return "", err
	}
	return syscall.UTF16ToString(buf[:n]), nil
}

// getUserName 获取当前用户名。
func getUserName() (string, error) {
	var buf [256]uint16
	n := uint32(len(buf))
	ret, _, err := procGetUserNameW.Call(
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)))
	if ret == 0 {
		return "", err
	}
	return syscall.UTF16ToString(buf[:n]), nil
}

// getArchitecture 获取处理器架构（x64/arm64/x86）。
func getArchitecture() string {
	var si systemInfo
	procGetNativeSystem.Call(uintptr(unsafe.Pointer(&si)))
	switch si.ProcessorArchitecture {
	case 9: // PROCESSOR_ARCHITECTURE_AMD64
		return "x64"
	case 12: // PROCESSOR_ARCHITECTURE_ARM64
		return "arm64"
	case 0: // PROCESSOR_ARCHITECTURE_INTEL
		return "x86"
	default:
		return fmt.Sprintf("unknown(%d)", si.ProcessorArchitecture)
	}
}

// getOSVersion 通过 RtlGetVersion 获取系统版本（Win8.1+ 可靠，不受 GetVersionEx 兼容性影响）。
func getOSVersion() (major, minor, build uint32) {
	info := &rtlOSVersionInfoEx{}
	info.OSVersionInfoSize = uint32(unsafe.Sizeof(*info))
	ret, _, _ := procRtlGetVersion.Call(uintptr(unsafe.Pointer(info)))
	if ret != 0 { // STATUS_SUCCESS
		return 0, 0, 0
	}
	return info.MajorVersion, info.MinorVersion, info.BuildNumber
}

// normalizeProductName 修正 Windows 11 的注册表遗留问题。
//
// Windows 11 的 HKLM\...\CurrentVersion\ProductName 至今仍写 "Windows 10 Pro"，
// 只读注册表必然把 Windows 11 报成 Windows 10。build >= 22000 即 Windows 11，
// 此时把 "Windows 10" 前缀替换为 "Windows 11"，保留版本后缀（Pro/Home/...）。
func normalizeProductName(name string, build uint32) string {
	if build < 22000 {
		return name
	}
	if name == "" {
		return fmt.Sprintf("Windows 11 (build %d)", build)
	}
	const p10 = "Windows 10"
	if len(name) >= len(p10) && name[:len(p10)] == p10 {
		return "Windows 11" + name[len(p10):]
	}
	return name
}

// getProductName 从注册表读取系统产品名（如 "Windows 11 Pro"）。
func getProductName() string {
	var hkey uintptr
	ret, _, _ := procRegOpenKeyExW.Call(
		hkeyLocalMachine,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(ntdllVersionKey))),
		0, keyRead, uintptr(unsafe.Pointer(&hkey)))
	if ret != 0 || hkey == 0 {
		return ""
	}
	defer procRegCloseKey.Call(hkey)

	var buf [256]uint16
	// RegQueryValueExW 的 lpcbData 是**字节数**，不是字符数：这里 buf 是 512 字节，
	// 传 len(buf) 会告诉 API 只有 256 字节（值稍长就 ERROR_MORE_DATA 读不到）。
	var size uint32 = uint32(len(buf) * 2)
	var typ uint32
	ret, _, _ = procRegQueryValueExW.Call(
		hkey,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(ntdllVersionValueName))),
		0, uintptr(unsafe.Pointer(&typ)),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if ret != 0 || typ != regSz || size == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf[:size/2])
}

// getBootTime 用 GetTickCount64（开机时长毫秒）推算启动时间；失败返回空串。
func getBootTime(now time.Time) string {
	uptimeMs, _, _ := procGetTickCount64.Call()
	if uptimeMs == 0 {
		return ""
	}
	return now.Add(-time.Duration(uptimeMs) * time.Millisecond).Format(time.RFC3339)
}
