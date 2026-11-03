// Package registry 实现 Registry Collector（协议白名单 entity_type=registry，P1-9）。
//
// 只读枚举**显式指定**的注册表键下的值（可递归指定层数）：RegOpenKeyExW +
// RegEnumValueW + RegEnumKeyExW + RegCloseKey，零外部命令、零第三方依赖。
// 不写入、不删除、不修改任何键值；不读取安全描述符/不打开写权限（只申请 KEY_READ）。
//
// 权限门卫（Step 2.2 能力集）：RegistryQuery（只读查询，Basic 模式已授予，与
// Persistence Collector 同级）。被拒时返回空结果并记录 deny 事件，不伪造条目。
//
// 不提供默认键：不指定 --key 直接报错，避免自作主张扩大采集范围。
package registry

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"os"
	goruntime "runtime"
	"sort"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"easytrace/internal/collector"
	"easytrace/internal/collector/runtime"
	"easytrace/internal/model"
)

const (
	// DefaultMaxValues 单次采集的实体上限（失控保护）。
	DefaultMaxValues = 5000
	// maxValueBytes 单个值数据的读取上限；超出只保留前 N 字节并标记 truncated。
	maxValueBytes = 4096
)

// Windows 注册表常量（advapi32）。
const (
	keyRead           = 0x20019
	errorSuccess      = 0
	errorMoreData     = 234
	errorNoMoreItems  = 259
	valueNameMaxChars = 1024
	valueNameMaxBytes = valueNameMaxChars * 2
)

var (
	advapi32         = syscall.NewLazyDLL("advapi32.dll")
	procRegOpenKeyEx = advapi32.NewProc("RegOpenKeyExW")
	procRegEnumValue = advapi32.NewProc("RegEnumValueW")
	procRegEnumKeyEx = advapi32.NewProc("RegEnumKeyExW")
	procRegCloseKey  = advapi32.NewProc("RegCloseKey")
)

// rootKeys 是预定义根键句柄（HKEY_* 常量值）。
var rootKeys = map[string]uintptr{
	"HKEY_CLASSES_ROOT":   0x80000000,
	"HKEY_CURRENT_USER":   0x80000001,
	"HKEY_LOCAL_MACHINE":  0x80000002,
	"HKEY_USERS":          0x80000003,
	"HKEY_CURRENT_CONFIG": 0x80000005,
}

// rootAliases 是常见简写 → 全名（实体 ID 一律用全名，保证同一值 ID 稳定）。
var rootAliases = map[string]string{
	"HKCR": "HKEY_CLASSES_ROOT",
	"HKCU": "HKEY_CURRENT_USER",
	"HKLM": "HKEY_LOCAL_MACHINE",
	"HKU":  "HKEY_USERS",
	"HKCC": "HKEY_CURRENT_CONFIG",
}

// defaultValueName 是注册表默认值的显示名（真实名字为空串）。
const defaultValueName = "(Default)"

// keyPlaceholder 表示"该键没有任何值"时输出的一条占位记录（避免把"键存在"丢成"没采到"）。
const keyPlaceholder = "(key)"

// item 是单个注册表值的中间结构（内部结构，便于测试注入）。
type item struct {
	Key       string // 规范化键路径（HKEY_* 全名 + 子键）
	Name      string // 值名；defaultValueName = 默认值；keyPlaceholder = 键自身占位
	ValueType string // REG_SZ / REG_DWORD / ... ；（key）占位时为 "(key)"
	ValueData string
	Truncated bool
}

// Collector 实现 registry 采集；getItems 可注入以便测试。
type Collector struct {
	rt        *runtime.Runtime
	keys      []string
	depth     int
	maxValues int
	getItems  func() ([]item, error)
}

// New 创建 Registry Collector，绑定调用方注入的 Runtime（Collector 不在内部创建 Runtime）。
func New(rt *runtime.Runtime) *Collector {
	if rt == nil {
		panic("registry: New 必须传入 runtime.Runtime（禁止 Collector 内部创建）")
	}
	return &Collector{rt: rt, maxValues: DefaultMaxValues}
}

// NewWithItems 创建使用自定义数据源的 Registry Collector（用于测试）。
func NewWithItems(rt *runtime.Runtime, f func() ([]item, error)) *Collector {
	c := New(rt)
	c.getItems = f
	return c
}

// WithKeys 设置要枚举的注册表键（可为 HKLM\... 或全名 HKEY_LOCAL_MACHINE\...）。
func (c *Collector) WithKeys(keys ...string) *Collector {
	c.keys = append([]string(nil), keys...)
	return c
}

// WithDepth 设置子键递归层数（0 = 只采指定键本身）。
func (c *Collector) WithDepth(d int) *Collector {
	if d > 0 {
		c.depth = d
	}
	return c
}

// WithMaxValues 设置实体数量上限（<=0 时保持默认）。
func (c *Collector) WithMaxValues(n int) *Collector {
	if n > 0 {
		c.maxValues = n
	}
	return c
}

// Runtime 返回绑定的行为控制 Runtime（供注入一致性校验）。
func (c *Collector) Runtime() *runtime.Runtime { return c.rt }

// Name 实现 collector.Collector 接口。
func (c *Collector) Name() string { return "registry" }

// Collect 实现 collector.Collector 接口：输出 registry 实体（一个值一条）。
//
// 顺序固定（按实体 ID 升序）；超出上限、键不可读、值读取失败都保留其它事实并
// 在返回错误里说明"不完整"，不静默。
func (c *Collector) Collect() (*collector.Result, error) {
	if len(c.keys) == 0 {
		return nil, fmt.Errorf("registry 采集必须至少指定一个 --key <HKEY_*\\...>（不提供默认键，避免扩大采集范围）")
	}
	if !c.rt.Allow("registry", "RegistryQuery", "keys:"+strings.Join(c.keys, ";")) {
		debugf("registry_query_denied mode=%s keys=%d", c.rt.Mode(), len(c.keys))
		return &collector.Result{}, nil
	}

	get := c.getItems
	if get == nil {
		get = func() ([]item, error) { return c.enumerate() }
	}
	items, err := get()
	var notes []string
	if err != nil {
		notes = append(notes, fmt.Sprintf("注册表枚举不完整: %v", err))
	}

	seen := map[string]bool{}
	var kept []item
	skipped := 0
	for _, it := range items {
		if strings.TrimSpace(it.Key) == "" {
			skipped++
			continue
		}
		if seen[valuePath(it)] {
			skipped++
			continue
		}
		seen[valuePath(it)] = true
		kept = append(kept, it)
	}
	if skipped > 0 {
		// 重复/缺路径属内部去重，不是数据缺失：只记内部日志，不当作"采集不完整"。
		debugf("registry_skipped n=%d", skipped)
	}
	sort.Slice(kept, func(i, j int) bool { return valueID(kept[i]) < valueID(kept[j]) })
	if len(kept) > c.maxValues {
		notes = append(notes, fmt.Sprintf("值数 %d 超过上限 %d，只保留前 %d 条（结果不完整）", len(kept), c.maxValues, c.maxValues))
		kept = kept[:c.maxValues]
	}
	debugf("registry_query values=%d", len(kept))

	res := &collector.Result{}
	for _, it := range kept {
		res.Entities = append(res.Entities, model.NewEntity("registry", valueID(it), model.RegistryData{
			Path:            valuePath(it),
			Key:             it.Key,
			Name:            it.Name,
			ValueType:       it.ValueType,
			ValueData:       it.ValueData,
			Truncated:       it.Truncated,
			CollectionLevel: string(c.rt.Mode()),
		}))
	}
	if len(notes) > 0 {
		return res, fmt.Errorf("registry 采集不完整（已保留可核对的事实）：%s", strings.Join(notes, "；"))
	}
	return res, nil
}

// valuePath 返回值的完整路径（键 + \ + 值名）；键自身占位记录只到键。
func valuePath(it item) string {
	if it.Name == keyPlaceholder {
		return it.Key
	}
	return it.Key + `\` + it.Name
}

// valueID 按协议 ID 规则生成：registry_<sha1(path)>（取前 16 个十六进制字符，
// 与 task 采集器的 hashPath 同一风格；path 用全名根键保证稳定）。
func valueID(it item) string {
	sum := sha1.Sum([]byte(strings.ToUpper(valuePath(it))))
	return "registry_" + fmt.Sprintf("%x", sum[:8])
}

// enumerate 打开并枚举全部指定键（只读）。
//
// 错误模型对齐 Task 采集器：**显式请求的键打不开**才算失败（都打不开时报错）；
// 递归过程中个别子键/值读不到只记内部日志并继续（否则系统键的深度递归必然"整体失败"）。
func (c *Collector) enumerate() ([]item, error) {
	var (
		items []item
		fatal []string
	)
	for _, raw := range c.keys {
		rootName, subKey, err := splitKeyPath(raw)
		if err != nil {
			fatal = append(fatal, err.Error())
			continue
		}
		root, ok := rootKeys[rootName]
		if !ok {
			fatal = append(fatal, fmt.Sprintf("不支持的根键 %q（可用 HKCR/HKCU/HKLM/HKU/HKCC）", rootName))
			continue
		}
		items = c.enumerateKey(root, rootName, subKey, 0, items, &fatal)
	}
	if len(items) == 0 && len(fatal) > 0 {
		return nil, fmt.Errorf("%s", strings.Join(fatal, "；"))
	}
	if len(fatal) > 0 {
		return items, fmt.Errorf("%s", strings.Join(fatal, "；"))
	}
	return items, nil
}

// enumerateKey 递归枚举一个键（深度用尽即停）。
// depth == 0 表示这是**显式请求**的键：打不开算失败；更深层子键打不开只记内部日志。
func (c *Collector) enumerateKey(root uintptr, rootName, subKey string, depth int, items []item, fatal *[]string) []item {
	full := rootName
	if subKey != "" {
		full += `\` + subKey
	}
	handle, err := openKey(root, subKey)
	if err != nil {
		if depth == 0 {
			*fatal = append(*fatal, fmt.Sprintf("键不可读 %s: %v", full, err))
		} else {
			debugf("subkey_open_failed key=%s error=%v", full, err)
		}
		return items
	}
	subKeys, values := enumKeyContents(handle, full)
	closeKey(handle)

	if len(values) == 0 {
		// 键存在但没有值：保留一条占位记录，别把"存在"丢成"没采到"。
		items = append(items, item{Key: full, Name: keyPlaceholder, ValueType: keyPlaceholder})
	} else {
		items = append(items, values...)
	}
	if depth >= c.depth {
		return items
	}
	for _, name := range subKeys {
		child := name
		if subKey != "" {
			child = subKey + `\` + name
		}
		items = c.enumerateKey(root, rootName, child, depth+1, items, fatal)
	}
	return items
}

// enumKeyContents 读取一个已打开键的直接子键名与全部值。
// 单个子键/值的读取失败只记内部日志，保留其余事实。
func enumKeyContents(handle uintptr, fullKey string) ([]string, []item) {
	var (
		subKeys []string
		values  []item
	)
	for i := uint32(0); ; i++ {
		name, status := enumSubKeyName(handle, i)
		if status == errorNoMoreItems {
			break
		}
		if status != errorSuccess {
			debugf("subkey_enum_failed key=%s index=%d status=%d", fullKey, i, status)
			break
		}
		subKeys = append(subKeys, name)
	}

	for i := uint32(0); ; i++ {
		it, status := enumValue(handle, fullKey, i)
		if status == errorNoMoreItems {
			break
		}
		if status != errorSuccess {
			debugf("value_enum_failed key=%s index=%d status=%d", fullKey, i, status)
			break
		}
		values = append(values, it)
	}
	sort.Strings(subKeys)
	return subKeys, values
}

// openKey 只读打开子键（KEY_READ）。
func openKey(root uintptr, subKey string) (uintptr, error) {
	var handle uintptr
	sub, err := syscall.UTF16PtrFromString(subKey)
	if err != nil {
		return 0, fmt.Errorf("子键路径非法: %w", err)
	}
	ret, _, _ := procRegOpenKeyEx.Call(root, uintptr(unsafe.Pointer(sub)), 0, keyRead,
		uintptr(unsafe.Pointer(&handle)))
	if ret != errorSuccess || handle == 0 {
		return 0, fmt.Errorf("RegOpenKeyExW status=%d", ret)
	}
	return handle, nil
}

func closeKey(handle uintptr) {
	if handle != 0 {
		procRegCloseKey.Call(handle)
	}
}

// nameSliceLen 把 API 回填的名称长度收敛到缓冲区范围内。
//
// RegEnum*W 在名称放不下时返回 ERROR_MORE_DATA，并把长度写成**需要**的字符数；
// 直接 buf[:n] 会越界 panic（值名最长 16383 字符，远超默认 1024 的缓冲）。
func nameSliceLen(nameLen uint32, bufLen int) (int, bool) {
	if bufLen <= 0 || nameLen == 0 {
		return 0, false
	}
	if int64(nameLen) > int64(bufLen) {
		return bufLen, true
	}
	return int(nameLen), false
}

// enumSubKeyName 取第 index 个子键名。
func enumSubKeyName(handle uintptr, index uint32) (string, uintptr) {
	buf := make([]uint16, valueNameMaxChars)
	size := uint32(len(buf))
	ret, _, _ := procRegEnumKeyEx.Call(handle, uintptr(index),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, 0, 0, 0)
	goruntime.KeepAlive(buf)
	if ret != errorSuccess {
		return "", ret
	}
	n, _ := nameSliceLen(size, len(buf))
	return syscall.UTF16ToString(buf[:n]), errorSuccess
}

// enumValueRetryNameLimit 是值名重试缓冲的上限（注册表值名最长 16383 字符 + NUL）。
const enumValueRetryNameLimit = 16384

// regEnumValue 调用一次 RegEnumValueW，并把长度参数初始化为缓冲区大小。
func regEnumValue(handle uintptr, index uint32, nameBuf []uint16, nameLen *uint32,
	valueType *uint32, data []byte, dataLen *uint32) uintptr {
	*nameLen = uint32(len(nameBuf))
	*dataLen = uint32(len(data))
	ret, _, _ := procRegEnumValue.Call(handle, uintptr(index),
		uintptr(unsafe.Pointer(&nameBuf[0])), uintptr(unsafe.Pointer(nameLen)), 0,
		uintptr(unsafe.Pointer(valueType)), uintptr(unsafe.Pointer(&data[0])), uintptr(unsafe.Pointer(dataLen)))
	goruntime.KeepAlive(data)
	goruntime.KeepAlive(nameBuf)
	return ret
}

// enumValue 取第 index 个值（**单次调用**：固定数据缓冲一次取回名字/类型/数据）。
//
// 注意：不要把 lpData 传 NULL 去"探测长度"——那样 RegEnumValueW 会以 SUCCESS 返回
// 且不回填所需长度，结果所有值都读成空数据。数据超过缓冲时返回 ERROR_MORE_DATA，
// 此时保留已读到的部分并标记 truncated。
//
// 值名超出 1024 字符缓冲同样返回 ERROR_MORE_DATA 并把 nameLen 写成所需长度；
// 此时按需要扩大名缓冲重试一次，任何情况下切片前都用 nameSliceLen 收敛长度。
func enumValue(handle uintptr, fullKey string, index uint32) (item, uintptr) {
	nameBuf := make([]uint16, valueNameMaxChars)
	data := make([]byte, maxValueBytes)
	var (
		nameLen   uint32
		dataLen   uint32
		valueType uint32
	)

	ret := regEnumValue(handle, index, nameBuf, &nameLen, &valueType, data, &dataLen)
	if ret == errorMoreData && int64(nameLen) > int64(len(nameBuf)) {
		want := int(nameLen)
		if want > enumValueRetryNameLimit {
			want = enumValueRetryNameLimit
		}
		nameBuf = make([]uint16, want)
		data = make([]byte, maxValueBytes)
		ret = regEnumValue(handle, index, nameBuf, &nameLen, &valueType, data, &dataLen)
	}
	if ret == errorNoMoreItems {
		return item{}, errorNoMoreItems
	}
	if ret != errorSuccess && ret != errorMoreData {
		return item{}, ret
	}

	n, nameTruncated := nameSliceLen(nameLen, len(nameBuf))
	if nameTruncated {
		debugf("value_name_too_long key=%s index=%d required=%d used=%d", fullKey, index, nameLen, n)
	}
	name := syscall.UTF16ToString(nameBuf[:n])
	if name == "" {
		name = defaultValueName
	}
	it := item{Key: fullKey, Name: name, ValueType: typeName(valueType)}
	if ret == errorMoreData {
		it.Truncated = true // 数据超过 maxValueBytes，只保留前 maxValueBytes 字节
	} else if int(dataLen) < len(data) {
		data = data[:dataLen]
	}
	it.ValueData = formatValue(valueType, data)
	return it, errorSuccess
}

// typeName 把 REG_* 类型号转成可读名（未知类型保留原始号，不猜测）。
func typeName(t uint32) string {
	switch t {
	case 0:
		return "REG_NONE"
	case 1:
		return "REG_SZ"
	case 2:
		return "REG_EXPAND_SZ"
	case 3:
		return "REG_BINARY"
	case 4:
		return "REG_DWORD"
	case 5:
		return "REG_DWORD_BIG_ENDIAN"
	case 6:
		return "REG_LINK"
	case 7:
		return "REG_MULTI_SZ"
	case 8:
		return "REG_RESOURCE_LIST"
	case 9:
		return "REG_FULL_RESOURCE_DESCRIPTOR"
	case 10:
		return "REG_RESOURCE_REQUIREMENTS_LIST"
	case 11:
		return "REG_QWORD"
	}
	return fmt.Sprintf("REG_UNKNOWN(%d)", t)
}

// formatValue 按类型把原始字节渲染为可读文本（二进制转 hex；未知类型转 hex）。
func formatValue(t uint32, data []byte) string {
	switch t {
	case 1, 2, 6: // REG_SZ / REG_EXPAND_SZ / REG_LINK（UTF-16LE，去结尾 NUL）
		return utf16ToString(data)
	case 4: // REG_DWORD
		if len(data) >= 4 {
			return fmt.Sprintf("%d", binary.LittleEndian.Uint32(data[:4]))
		}
	case 5: // REG_DWORD_BIG_ENDIAN
		if len(data) >= 4 {
			return fmt.Sprintf("%d", binary.BigEndian.Uint32(data[:4]))
		}
	case 11: // REG_QWORD
		if len(data) >= 8 {
			return fmt.Sprintf("%d", binary.LittleEndian.Uint64(data[:8]))
		}
	case 7: // REG_MULTI_SZ：多项用 " | " 连接
		parts := strings.Split(utf16ToString(data), "\x00")
		var kept []string
		for _, p := range parts {
			if p != "" {
				kept = append(kept, p)
			}
		}
		return strings.Join(kept, " | ")
	}
	return fmt.Sprintf("%x", data)
}

// utf16ToString 把 UTF-16LE 字节串转成 Go 字符串（容错奇数字节，去结尾 NUL）。
func utf16ToString(data []byte) string {
	if len(data)%2 == 1 {
		data = data[:len(data)-1]
	}
	u16 := make([]uint16, len(data)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(data[i*2:])
	}
	s := string(utf16.Decode(u16))
	return strings.TrimRight(s, "\x00")
}

// splitKeyPath 拆分为规范根键名与子键路径（不修改输入大小写，只规范化根键全名）。
func splitKeyPath(raw string) (rootName, subKey string, err error) {
	raw = strings.TrimSpace(strings.Trim(raw, `\`))
	if raw == "" {
		return "", "", fmt.Errorf("空键路径")
	}
	parts := strings.SplitN(raw, `\`, 2)
	root := strings.ToUpper(parts[0])
	if full, ok := rootAliases[root]; ok {
		root = full
	}
	if _, ok := rootKeys[root]; !ok {
		return "", "", fmt.Errorf("不支持的根键 %q（可用 HKCR/HKCU/HKLM/HKU/HKCC）", parts[0])
	}
	if len(parts) == 2 {
		subKey = parts[1]
	}
	return root, subKey, nil
}

// debugf 输出采集阶段/内部错误日志到 stderr（不污染 stdout 的 JSONL 流）。
func debugf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[registry] "+format+"\n", args...)
}
