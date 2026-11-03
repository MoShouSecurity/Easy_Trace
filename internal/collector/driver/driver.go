// Package driver 实现 Driver Collector（协议白名单 entity_type=driver，P1-9）。
//
// 只读枚举**已加载的内核驱动模块**：NtQuerySystemInformation(SystemModuleInformation)
// 一次调用取回模块表（模块基址 + 模块路径）。
//
// 为什么不用 EnumDeviceDrivers：实测在加固/受限环境下该 API 会"成功但把内核地址清零"
// （GetDeviceDriverBaseNameW(0) 随之失败，等于拿不到任何模块名）；而
// SystemModuleInformation 在同一环境下正常返回完整模块表。两者都是只读系统查询，
// 不加载、不卸载、不读驱动内存、不调用外部命令。
//
// 权限门卫（Step 2.2 能力集）：DriverQuery（只读系统枚举，与 ServiceQuery/TaskQuery
// 同级，Basic 模式也授予）。被拒时返回空结果并记录 deny 事件，不伪造任何条目。
package driver

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	goruntime "runtime"
	"sort"
	"strings"
	"syscall"
	"unsafe"

	"easytrace/internal/collector"
	"easytrace/internal/collector/runtime"
	"easytrace/internal/model"
)

// DefaultMaxDrivers 单次枚举的实体上限（正常主机数百条；上限是失控保护）。
const DefaultMaxDrivers = 2000

const (
	// systemModuleInformation 是 SystemModuleInformation 信息类编号。
	systemModuleInformation = 11
	// statusInfoLengthMismatch 是探测长度时的预期返回（STATUS_INFO_LENGTH_MISMATCH）。
	statusInfoLengthMismatch = 0xC0000004
	// moduleInfoHeaderBytes 是 SYSTEM_MODULE_INFORMATION 中 Count 之后模块数组的偏移
	// （x64 下因指针对齐为 8 字节）。
	moduleInfoHeaderBytes = 8
)

// moduleNameFieldOffset 是 SYSTEM_MODULE 内 Name 字段的偏移（x64 = 40），
// 用 unsafe.Offsetof 取，避免手写魔数。
var moduleNameFieldOffset = int(unsafe.Offsetof(systemProcessModule{}.Name))

// systemProcessModule 是 SystemModuleInformation 的模块条目。
//
// x64 固定布局，合计 296 字节（与 SDK 的 SYSTEM_MODULE 一致）：
//
//	0..23   Reserved1 / Reserved2 / ImageBaseAddress
//	24..31  ImageSize / Flags (ULONG)
//	32..39  Id / Rank / LoadCount / NameOffset (WORD)
//	40..295 Name[256]（ANSI；NameOffset 指向**该字符串内基名**的起始，例如`\SystemRoot\system32\` 为 21）
type systemProcessModule struct {
	Reserved1  uintptr
	Reserved2  uintptr
	ImageBase  uintptr
	ImageSize  uint32
	Flags      uint32
	Index      uint16
	Rank       uint16
	LoadCount  uint16
	NameOffset uint16
	Name       [256]byte
}

var (
	ntdll                        = syscall.NewLazyDLL("ntdll.dll")
	procNtQuerySystemInformation = ntdll.NewProc("NtQuerySystemInformation")
)

// item 是单个驱动模块的中间结构（内部结构，便于测试注入）。
type item struct {
	Name string // 基名（如 ntfs.sys）
	Path string // 模块路径（NT 形式已尽量归一）
	Base string // 本次启动的加载基址（hex 字符串）
}

// Collector 实现 driver 采集；getDrivers 可注入以便测试。
type Collector struct {
	rt         *runtime.Runtime
	getDrivers func() ([]item, error)
	maxDrivers int
}

// New 创建 Driver Collector，绑定调用方注入的 Runtime（Collector 不在内部创建 Runtime）。
func New(rt *runtime.Runtime) *Collector {
	if rt == nil {
		panic("driver: New 必须传入 runtime.Runtime（禁止 Collector 内部创建）")
	}
	return &Collector{rt: rt, maxDrivers: DefaultMaxDrivers}
}

// NewWithDrivers 创建使用自定义数据源的 Driver Collector（用于测试）。
func NewWithDrivers(rt *runtime.Runtime, f func() ([]item, error)) *Collector {
	c := New(rt)
	c.getDrivers = f
	return c
}

// WithMaxDrivers 设置实体数量上限（<=0 时保持默认）。
func (c *Collector) WithMaxDrivers(n int) *Collector {
	if n > 0 {
		c.maxDrivers = n
	}
	return c
}

// Runtime 返回绑定的行为控制 Runtime（供注入一致性校验）。
func (c *Collector) Runtime() *runtime.Runtime { return c.rt }

// Name 实现 collector.Collector 接口。
func (c *Collector) Name() string { return "driver" }

// Collect 实现 collector.Collector 接口：输出 driver 实体。
//
// 顺序固定（按实体 ID 升序），同名模块只保留第一条；空名称条目跳过并如实记录。
// 任何"少采"（上限截断、跳过条目、枚举失败）都放进返回错误里，不静默。
func (c *Collector) Collect() (*collector.Result, error) {
	if !c.rt.Allow("driver", "DriverQuery", "loaded_kernel_modules") {
		debugf("driver_query_denied mode=%s", c.rt.Mode())
		return &collector.Result{}, nil
	}
	get := c.getDrivers
	if get == nil {
		get = enumerateDrivers
	}
	items, err := get()
	var notes []string
	if err != nil {
		notes = append(notes, fmt.Sprintf("驱动枚举失败: %v", err))
	}

	seen := map[string]bool{}
	var kept []item
	skipped := 0
	for _, it := range items {
		name := strings.TrimSpace(it.Name)
		if name == "" {
			skipped++
			continue
		}
		id := driverID(name)
		if seen[id] {
			skipped++
			continue
		}
		seen[id] = true
		it.Name = name
		// 归一 NT 路径（\SystemRoot\… / \??\…）；注入的 data source 同样受益。
		it.Path = normalizeDriverPath(it.Path)
		kept = append(kept, it)
	}
	if skipped > 0 {
		notes = append(notes, fmt.Sprintf("%d 条驱动条目被跳过（空名称或同名重复）", skipped))
	}
	sort.Slice(kept, func(i, j int) bool { return driverID(kept[i].Name) < driverID(kept[j].Name) })
	if len(kept) > c.maxDrivers {
		notes = append(notes, fmt.Sprintf("驱动数 %d 超过上限 %d，只保留前 %d 条（结果不完整）", len(kept), c.maxDrivers, c.maxDrivers))
		kept = kept[:c.maxDrivers]
	}
	debugf("driver_query loaded=%d", len(kept))

	res := &collector.Result{}
	for _, it := range kept {
		res.Entities = append(res.Entities, model.NewEntity("driver", driverID(it.Name), model.DriverData{
			Name:            it.Name,
			Path:            it.Path,
			BaseAddress:     it.Base,
			CollectionLevel: string(c.rt.Mode()),
		}))
	}
	if len(notes) > 0 {
		return res, fmt.Errorf("driver 采集不完整（已保留可核对的事实）：%s", strings.Join(notes, "；"))
	}
	return res, nil
}

// driverID 按协议 ID 规则生成 driver 实体 ID：driver_<name>，其中 name 的
// 非 [A-Za-z0-9_-] 字符替换为下划线（协议示例 driver_abc_sys 即 abc.sys 的归一形式）。
func driverID(name string) string {
	var b strings.Builder
	b.WriteString("driver_")
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// enumerateDrivers 只读枚举已加载的内核驱动模块（两遍调用取所需长度）。
func enumerateDrivers() ([]item, error) {
	var needed uint32
	st, _, _ := procNtQuerySystemInformation.Call(
		systemModuleInformation, 0, 0, uintptr(unsafe.Pointer(&needed)))
	if needed == 0 {
		return nil, fmt.Errorf("NtQuerySystemInformation(SystemModuleInformation) 未返回所需长度: status=0x%X", uint32(st))
	}
	if st != statusInfoLengthMismatch && st != 0 {
		return nil, fmt.Errorf("NtQuerySystemInformation(SystemModuleInformation) 失败: status=0x%X", uint32(st))
	}

	buf := make([]byte, needed)
	st, _, _ = procNtQuerySystemInformation.Call(
		systemModuleInformation, uintptr(unsafe.Pointer(&buf[0])), uintptr(needed), uintptr(unsafe.Pointer(&needed)))
	goruntime.KeepAlive(buf)
	if st != 0 {
		return nil, fmt.Errorf("NtQuerySystemInformation(SystemModuleInformation) 二次调用失败: status=0x%X", uint32(st))
	}
	if len(buf) < moduleInfoHeaderBytes {
		return nil, fmt.Errorf("模块表缓冲区异常: %d 字节", len(buf))
	}

	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	modSize := int(unsafe.Sizeof(systemProcessModule{}))
	var (
		items  []item
		failed int
	)
	for i := 0; i < int(count); i++ {
		off := moduleInfoHeaderBytes + i*modSize
		if off+modSize > len(buf) {
			failed++
			break
		}
		m := (*systemProcessModule)(unsafe.Pointer(&buf[off]))
		path, base := readModuleName(buf, off, m)
		if base == "" || path == "" {
			failed++
			continue
		}
		baseAddr := ""
		if m.ImageBase != 0 {
			// 加固/受限环境可能把内核地址清零；清零时留空，不记录无意义的 0。
			baseAddr = fmt.Sprintf("0x%016X", uint64(m.ImageBase))
		}
		items = append(items, item{Name: base, Path: path, Base: baseAddr})
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("模块表返回 %d 条但无可用模块名（读取失败 %d 条）", count, failed)
	}
	if failed > 0 {
		debugf("driver_query partial count=%d failed=%d", count, failed)
	}
	return items, nil
}

// readModuleName 从模块表缓冲区读取模块条目里的 Name 字段（ANSI、NUL 结尾），
// 返回 (完整路径, 基名)。NameOffset 指向**该字符串内部**基名的起始位置；
// 越界或为 0 时回退到按最后一段路径取基名（不猜测）。
func readModuleName(buf []byte, modOffset int, m *systemProcessModule) (string, string) {
	modSize := int(unsafe.Sizeof(systemProcessModule{}))
	start := modOffset + moduleNameFieldOffset
	end := modOffset + modSize
	if start < modOffset || start >= end || end > len(buf) {
		return "", ""
	}
	raw := buf[start:end]
	if idx := bytes.IndexByte(raw, 0); idx >= 0 {
		raw = raw[:idx]
	}
	full := strings.TrimSpace(string(raw))
	if full == "" {
		return "", ""
	}
	base := ""
	if off := int(m.NameOffset); off > 0 && off < len(full) {
		base = strings.TrimSpace(full[off:])
	}
	if base == "" {
		base = baseName(full)
	}
	return full, base
}

// baseName 取模块路径的文件名（模块表路径用反斜杠分隔）。
func baseName(path string) string {
	return filepath.Base(strings.ReplaceAll(path, `\`, `/`))
}

// normalizeDriverPath 把 NT 形式的驱动路径尽量归一为可读路径：
//
//	\SystemRoot\System32\drivers\x.sys → <SystemRoot>\System32\drivers\x.sys
//	\??\C:\path\x.sys                → C:\path\x.sys
//
// 无法识别的形式原样保留（不做猜测）。
func normalizeDriverPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if strings.HasPrefix(p, `\??\`) {
		return p[len(`\??\`):]
	}
	const prefix = `\SystemRoot\`
	if len(p) >= len(prefix) && strings.EqualFold(p[:len(prefix)], prefix) {
		if root := strings.TrimSpace(os.Getenv("SystemRoot")); root != "" {
			return filepath.Join(root, filepath.FromSlash(p[len(prefix):]))
		}
	}
	return p
}

// debugf 输出采集阶段/内部错误日志到 stderr（不污染 stdout 的 JSONL 流）。
func debugf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[driver] "+format+"\n", args...)
}
