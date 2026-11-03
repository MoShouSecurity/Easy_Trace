// Package persistence 实现 Persistence Collector（Task 4）。
//
// 采集的持久化位置（2026-10-14 扩展，覆盖银狐/远控常用点）：
//  1. 注册表 Run / RunOnce 键（HKLM + HKCU，含 WOW6432Node）
//  2. 启动文件夹（用户 + 公共 Startup）
//  3. 策略作用域 Run 键（Policies\Explorer\Run，HKLM + HKCU）
//  4. Active Setup\Installed Components（逐子键读 StubPath，含 WOW6432Node）
//  5. Winlogon Shell / Userinit（含 WOW6432Node）
//  6. BootExecute（Session Manager，REG_MULTI_SZ）
//
// 只采集事实（不删除启动项、不修复注册表、不判断恶意）；无法解析目标文件时只输出实体。
package persistence

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	goruntime "runtime"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"easytrace/internal/cmdline"
	"easytrace/internal/collector"
	"easytrace/internal/collector/runtime"
	"easytrace/internal/filemeta"
	"easytrace/internal/model"
)

// ---- Windows API 句柄（懒加载，零外部依赖） ----
var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	procRegOpenKeyExW        = advapi32.NewProc("RegOpenKeyExW")
	procRegEnumValueW        = advapi32.NewProc("RegEnumValueW")
	procRegQueryValueExW     = advapi32.NewProc("RegQueryValueExW")
	procRegEnumKeyExW        = advapi32.NewProc("RegEnumKeyExW")
	procRegCloseKey          = advapi32.NewProc("RegCloseKey")
	procRegQueryInfoKeyW     = advapi32.NewProc("RegQueryInfoKeyW")
	procExpandEnvironmentStr = kernel32.NewProc("ExpandEnvironmentStringsW")
	procFindFirstFileW       = kernel32.NewProc("FindFirstFileW")
	procFindNextFileW        = kernel32.NewProc("FindNextFileW")
	procFindClose            = kernel32.NewProc("FindClose")
	procGetUserNameW         = advapi32.NewProc("GetUserNameW")
)

const (
	hkeyLocalMachine = 0x80000002
	hkeyCurrentUser  = 0x80000001
	keyRead          = 0x00020019
	regSz            = 1
	regExpandSz      = 2
	regMultiSz       = 7
	errorNoMoreItems = 259 // ERROR_NO_MORE_ITEMS
	errorMoreData    = 234 // ERROR_MORE_DATA

	// Step 11.5 注册表超长值动态扩容：
	initValueNameChars = 512       // 值名初始缓冲区（UTF-16 字符）
	maxValueNameChars  = 32 * 1024 // 值名上限（UTF-16 字符 = 64KB；Windows 实际上限 16K 字符）
	initValueDataBytes = 256       // 值数据初始缓冲区（字节）
	maxValueDataBytes  = 64 * 1024 // 值数据上限（字节，64KB）

	maxPath = 260

	// maxExpandEnvChars 展开环境变量结果的最大长度（UTF-16 字符数，64KB）。
	// 恶意/异常环境变量不能导致越界或无限分配。
	maxExpandEnvChars = 64 * 1024
)

// registryRunKeys 是采集的注册表 Run 键位置（type 标记用于 PersistenceData.Type）。
var registryRunKeys = []struct {
	hive uintptr
	path string
	typ  string
	user string
}{
	{hkeyLocalMachine, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, "registry_run", "ALL USERS"},
	{hkeyLocalMachine, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, "registry_runonce", "ALL USERS"},
	{hkeyCurrentUser, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, "registry_run", ""}, // user 运行时填当前用户名
	{hkeyCurrentUser, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, "registry_runonce", ""},
	{hkeyLocalMachine, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`, "registry_run", "ALL USERS"},
	{hkeyLocalMachine, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`, "registry_runonce", "ALL USERS"},
	{hkeyCurrentUser, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`, "registry_run", ""},
	{hkeyCurrentUser, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`, "registry_runonce", ""},
	// 策略作用域 Run 键（2026-10-14 增补；与普通 Run 同族语义 → type 仍用 registry_run）：
	// 银狐等远控常用它做持久化，且不会被普通 Run 键清单覆盖。
	{hkeyLocalMachine, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`, "registry_run", "ALL USERS"},
	{hkeyCurrentUser, `Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`, "registry_run", ""},
}

// activeSetupKeys 是 Active Setup\Installed Components（逐子键读 StubPath，2026-10-14 增补）。
var activeSetupKeys = []string{
	`SOFTWARE\Microsoft\Active Setup\Installed Components`,
	`SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components`,
}

// singleValueKeys 是"单值加载点"：Winlogon Shell/Userinit 与 BootExecute（2026-10-14 增补）。
var singleValueKeys = []struct {
	hive      uintptr
	path      string
	valueName string
	typ       string
	user      string
}{
	{hkeyLocalMachine, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, "Shell", "winlogon", "ALL USERS"},
	{hkeyLocalMachine, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, "Userinit", "winlogon", "ALL USERS"},
	{hkeyLocalMachine, `SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon`, "Shell", "winlogon", "ALL USERS"},
	{hkeyLocalMachine, `SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon`, "Userinit", "winlogon", "ALL USERS"},
	{hkeyLocalMachine, `SYSTEM\CurrentControlSet\Control\Session Manager`, "BootExecute", "boot_execute", "ALL USERS"},
}

// persistItem 是单个持久化项的中间结构（内部结构，供测试注入）。
type persistItem struct {
	Type     string
	Location string
	Name     string
	Command  string
	Path     string
	User     string
	// KeyLastWriteTime 是注册表键的 LastWriteTime（UTC/RFC3339）——"这个启动项是什么时候
	// 被加上去的"。只对注册表来源的项有值；启动文件夹等文件来源留空。
	KeyLastWriteTime string
}

// 深采补目标文件元数据的上限（失控保护）。
const (
	maxEnrichFiles     = 200
	maxEnrichHashBytes = 64 * 1024 * 1024
)

// fileMeta 是启动项目标文件的只读元数据（内部结构，便于测试注入）。
type fileMeta struct {
	HashSHA256     string
	SignatureState string
	LastWriteTime  string
}

// Collector 实现 persistence 采集。getItems / readMeta 可注入以便测试；
// nil 时分别使用真实 Windows API 与 filemeta 只读实现。
type Collector struct {
	getItems func() ([]persistItem, error)
	readMeta func(path string, withHash bool) (fileMeta, error)
	rt       *runtime.Runtime
	maxFiles int
}

// New 创建使用真实 Windows API 的 Persistence Collector，绑定调用方注入的 Runtime。
// Collector 不在内部创建 Runtime（架构收口，Step 2.2）；rt 必传，nil 视为编程错误。
func New(rt *runtime.Runtime) *Collector {
	if rt == nil {
		panic("persistence: New 必须传入 runtime.Runtime（禁止 Collector 内部创建）")
	}
	return &Collector{rt: rt, readMeta: readFileMeta, maxFiles: maxEnrichFiles}
}

// NewWithItems 创建使用自定义数据源的 Persistence Collector（用于测试）。
func NewWithItems(rt *runtime.Runtime, f func() ([]persistItem, error)) *Collector {
	c := New(rt)
	c.getItems = f
	return c
}

// WithReadMeta 注入目标文件元数据读取实现（测试用；生产走 filemeta 只读实现）。
func (c *Collector) WithReadMeta(f func(path string, withHash bool) (fileMeta, error)) *Collector {
	if f != nil {
		c.readMeta = f
	}
	return c
}

// WithMaxEnrichFiles 设置深采补充的文件数上限（<=0 时保持默认）。
func (c *Collector) WithMaxEnrichFiles(n int) *Collector {
	if n > 0 {
		c.maxFiles = n
	}
	return c
}

// Runtime 返回绑定的行为控制 Runtime（供注入一致性校验）。
func (c *Collector) Runtime() *runtime.Runtime { return c.rt }

// Name 实现 collector.Collector 接口。
func (c *Collector) Name() string { return "persistence" }

// Collect 实现 collector.Collector 接口：输出 persistence 实体。
//
// Step 4 行为门卫：先经 rt.Allow("persistence","RegistryQuery") 检查——被拒则
// 不执行任何注册表/文件系统枚举，返回空结果并记录 deny 行为事件（不导致 Pipeline
// 失败）。容错遵循"能采多少采多少"：单个 Run 键 / Startup 文件夹失败不影响其它项；
// 存在失败时已采项照常输出，但返回聚合错误，让 CLI/Pipeline 计入失败。
//
// 说明：execute 关系到 Task 8 Pipeline（拿到 process 列表后按命令路径匹配）再生成；
// 本阶段只采集事实实体。
func (c *Collector) Collect() (*collector.Result, error) {
	if !c.rt.Allow("persistence", "RegistryQuery", "registry_run+startup_folder") {
		debugf("registry_query_denied mode=%s", c.rt.Mode())
		return &collector.Result{}, nil
	}
	getItems := c.getItems
	if getItems == nil {
		getItems = collectItems
	}
	items, err := getItems()
	if err != nil {
		// 部分失败：记录内部错误（含 collector/capability/operation/error），保留已采集项。
		debugf("collection_error collector=persistence capability=RegistryQuery operation=collectItems error=%v", err)
	}
	// 实体 ID 是索引型（persistence_%03d），必须先按内容稳定排序再编号，
	// 否则注册表/目录枚举顺序变化会让同一批启动项得到不同 ID。
	// enrich 复用同一份排序切片，保证 entity_update 的 ID 与实体一一对应。
	sort.SliceStable(items, func(i, j int) bool {
		return persistItemLess(items[i], items[j])
	})

	res := &collector.Result{}
	for i, it := range items {
		id := fmt.Sprintf("persistence_%03d", i+1)
		e := model.NewEntity("persistence", id, model.PersistenceData{
			Type:     it.Type,
			Location: it.Location,
			Name:     it.Name,
			Command:  it.Command,
			Path:     it.Path,
			User:     it.User,

			KeyLastWriteTime: it.KeyLastWriteTime,
		})
		res.Entities = append(res.Entities, e)
	}
	// 深采：为启动项目标文件补充只读元数据（Basic 下门卫直接拒绝，不读任何文件）。
	c.enrich(res, items)
	if err != nil {
		return res, fmt.Errorf("persistence 采集不完整: %w", err)
	}
	return res, nil
}

// persistItemLess 是持久化项的稳定排序键：type → location → name，
// 并列时依次用 command / path / user / key_last_write_time 打破平局。
func persistItemLess(a, b persistItem) bool {
	if a.Type != b.Type {
		return a.Type < b.Type
	}
	if a.Location != b.Location {
		return a.Location < b.Location
	}
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	if a.Command != b.Command {
		return a.Command < b.Command
	}
	if a.Path != b.Path {
		return a.Path < b.Path
	}
	if a.User != b.User {
		return a.User < b.User
	}
	return a.KeyLastWriteTime < b.KeyLastWriteTime
}

// enrich 在深采模式为启动项目标文件补充只读元数据（经 entity_update 输出，id 与实体一致）。
//
// 门卫：文件元数据属 ReadFile 能力（Basic 被拒 → 不读任何文件）；哈希另需 HashFile。
// 单条失败（文件不存在/不可读）只记内部日志并跳过——**不写占位值**，避免"字段存在但
// 内容不可信"；因此依赖 signature_state 的规则在 basic 快照上不会命中（由规则守卫兜住）。
func (c *Collector) enrich(res *collector.Result, items []persistItem) {
	if len(items) == 0 {
		return
	}
	if !c.rt.Allow("persistence", "ReadFile", "startup_target_files") {
		debugf("enrichment_denied mode=%s capability=ReadFile", c.rt.Mode())
		return
	}
	withHash := c.rt.Allow("persistence", "HashFile", "startup_target_files")
	limit := c.maxFiles
	if limit <= 0 {
		limit = maxEnrichFiles
	}
	readMeta := c.readMeta
	if readMeta == nil {
		readMeta = readFileMeta
	}

	enriched := 0
	for i, it := range items {
		if enriched >= limit {
			debugf("enrichment_limit items=%d limit=%d", len(items), limit)
			break
		}
		path := targetPath(it)
		if path == "" {
			continue
		}
		enriched++
		meta, err := readMeta(path, withHash)
		if err != nil {
			debugf("enrichment_failed path=%s error=%v", path, err)
			continue
		}
		if meta.HashSHA256 == "" && meta.SignatureState == "" && meta.LastWriteTime == "" {
			continue
		}
		res.EntityUpdates = append(res.EntityUpdates, model.NewEntityUpdate(
			fmt.Sprintf("persistence_%03d", i+1),
			model.PersistenceEnrichmentData{
				HashSHA256:     meta.HashSHA256,
				SignatureState: meta.SignatureState,
				LastWriteTime:  meta.LastWriteTime,
				// 深采补证固定标 deep：它表示“这条证据由深采能力读取”，
				// 不是快照整体模式。Forensic 同样包含深采能力；若写 forensic，
				// 规则侧 `collection_level equals deep` 的守卫会让规则静默零命中。
				// 与 process 深采保持一致（process_enrichment.go）。
				CollectionLevel: "deep",
			}))
	}
	debugf("enrichment_done enriched=%d items=%d", enriched, len(items))
}

// readFileMeta 用 filemeta 只读读取目标文件元数据。
// 哈希超上限时**不给哈希**（部分文件的哈希会误导调查），只记内部日志。
func readFileMeta(path string, withHash bool) (fileMeta, error) {
	var m fileMeta
	mt, err := filemeta.ModTime(path)
	if err != nil {
		return fileMeta{}, err
	}
	m.LastWriteTime = mt.UTC().Format(time.RFC3339)
	m.SignatureState = filemeta.SignatureState(path)
	if withHash {
		h, _, truncated, err := filemeta.HashSHA256(path, maxEnrichHashBytes)
		if err != nil {
			return m, err
		}
		if truncated {
			debugf("hash_truncated path=%s limit=%d", path, maxEnrichHashBytes)
		} else {
			m.HashSHA256 = h
		}
	}
	return m, nil
}

// targetPath 解析启动项目标文件路径：优先用采集阶段已解析的 Path，其次从 Command 解析，
// 再展开环境变量。解析不出来时返回空串（该条只输出实体，不补文件元数据）。
func targetPath(it persistItem) string {
	p := strings.TrimSpace(it.Path)
	if p == "" {
		p = parseCommandPath(it.Command)
	}
	if p == "" {
		return ""
	}
	if ex := expandEnv(p); ex != "" {
		p = ex
	}
	return strings.Trim(strings.TrimSpace(p), `"`)
}

// collectItems 采集注册表 Run 键 + 启动文件夹。
// 单键/单目录失败跳过并聚合错误，不影响其它项（"能采多少采多少"）。
func collectItems() ([]persistItem, error) {
	var items []persistItem
	var errs []string

	currentUser := currentUserName()

	// 1. 注册表 Run / RunOnce 键
	for _, k := range registryRunKeys {
		user := k.user
		if user == "" {
			user = currentUser
		}
		rows, err := readRegistryRun(k.hive, k.path, k.typ, user)
		if err != nil {
			errs = append(errs, fmt.Sprintf("readRegistryRun(%s\\%s): %v", hiveDisplay(k.hive), k.path, err))
			continue // 键不存在/无权限：跳过该键，不中断
		}
		items = append(items, rows...)
	}

	// 2. 启动文件夹
	if items2, err := scanStartupFolder(startupFolderPath(true), currentUser); err == nil {
		items = append(items, items2...)
	} else {
		errs = append(errs, fmt.Sprintf("scanStartupFolder(user): %v", err))
	}
	if items2, err := scanStartupFolder(startupFolderPath(false), "ALL USERS"); err == nil {
		items = append(items, items2...)
	} else {
		errs = append(errs, fmt.Sprintf("scanStartupFolder(common): %v", err))
	}

	// 3. Active Setup\Installed Components（逐子键读 StubPath）
	for _, base := range activeSetupKeys {
		rows, err := readActiveSetup(hkeyLocalMachine, base)
		if err != nil {
			errs = append(errs, fmt.Sprintf("readActiveSetup(%s): %v", base, err))
			continue
		}
		items = append(items, rows...)
	}

	// 4. 单值加载点：Winlogon Shell/Userinit + BootExecute
	for _, k := range singleValueKeys {
		rows, err := readSingleValueKey(k.hive, k.path, k.valueName, k.typ, k.user)
		if err != nil {
			errs = append(errs, fmt.Sprintf("readSingleValueKey(%s\\%s): %v", hiveDisplay(k.hive), k.path, err))
			continue
		}
		items = append(items, rows...)
	}

	if len(errs) > 0 {
		return items, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return items, nil
}

// openKeyForCollect 打开注册表键：**键不存在不算失败**（很多机器没有 WOW/策略键），
// 其它错误（拒绝访问等）如实返回，由调用方聚合为"采集不完整"。
func openKeyForCollect(hive uintptr, keyPath string) (uintptr, bool, error) {
	var hkey uintptr
	ret, _ := regOpenKeyOnce(hive, keyPath, &hkey)
	if ret == 0 && hkey != 0 {
		return hkey, true, nil
	}
	if isNotFoundStatus(ret) {
		return 0, false, nil
	}
	return 0, false, fmt.Errorf("RegOpenKeyExW(%s): ret=%d", keyPath, ret)
}

// isNotFoundStatus 判断注册表返回码是否为 ERROR_FILE_NOT_FOUND / ERROR_PATH_NOT_FOUND。
func isNotFoundStatus(ret uintptr) bool { return ret == 2 || ret == 3 }

// readSingleValueKey 读取单个"加载点"值（Winlogon Shell/Userinit、BootExecute）。
func readSingleValueKey(hive uintptr, keyPath, valueName, typ, user string) ([]persistItem, error) {
	hkey, ok, err := openKeyForCollect(hive, keyPath)
	if err != nil || !ok {
		return nil, err
	}
	defer procRegCloseKey.Call(hkey)

	cmd := readRegValue(hkey, valueName)
	if cmd == "" {
		return nil, nil
	}
	return []persistItem{{
		Type:             typ,
		Location:         hiveDisplay(hive) + `\` + keyPath,
		Name:             valueName,
		Command:          cmd,
		Path:             parseCommandPath(cmd),
		User:             user,
		KeyLastWriteTime: queryKeyLastWrite(hkey),
	}}, nil
}

// readActiveSetup 枚举 Active Setup 组件的 StubPath（每个子键一条）。
func readActiveSetup(hive uintptr, basePath string) ([]persistItem, error) {
	base, ok, err := openKeyForCollect(hive, basePath)
	if err != nil || !ok {
		return nil, err
	}
	defer procRegCloseKey.Call(base)

	var items []persistItem
	index := uint32(0)
	for {
		sub, err := enumSubKeyName(base, index)
		if err == errNoMoreItems {
			break
		}
		if err != nil {
			debugf("reg_enum_key_failed base=%s index=%d error=%v", basePath, index, err)
			index++
			continue
		}
		index++

		full := basePath + `\` + sub
		hkey, ok, err := openKeyForCollect(hive, full)
		if err != nil || !ok {
			debugf("active_setup_open_failed key=%s ret_error=%v", full, err)
			continue
		}
		cmd := readRegValue(hkey, "StubPath")
		kwt := queryKeyLastWrite(hkey)
		procRegCloseKey.Call(hkey)
		if cmd == "" {
			continue
		}
		items = append(items, persistItem{
			Type:             "active_setup",
			Location:         hiveDisplay(hive) + `\` + full,
			Name:             sub,
			Command:          cmd,
			Path:             parseCommandPath(cmd),
			User:             "ALL USERS",
			KeyLastWriteTime: kwt,
		})
	}
	return items, nil
}

// debugf 输出采集阶段/内部错误日志到 stderr（不污染 stdout 的 JSONL 流）。
func debugf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[persistence] "+format+"\n", args...)
}

// queryKeyLastWrite 取注册表键的 LastWriteTime（UTC/RFC3339 秒精度）。
//
// 这是持久化排查里最有用的一个时间："这个启动项**什么时候**被加上去的"。只读、1 次调用/键，
// 因此 Basic 即采。失败时返回空串——**不写占位值**，避免"字段存在但内容不可信"。
// 启动文件夹等文件来源没有"键时间"，同样留空（文件时间由深采的 last_write_time 表达，
// 两者语义完全不同，不能混用）。
func queryKeyLastWrite(hkey uintptr) string {
	var ft syscall.Filetime
	ret, _ := regQueryInfoKeyOnce(hkey, &ft)
	if ret != 0 {
		return ""
	}
	// FILETIME 全 0：注册表没有给出该键的写入时间。
	//
	// 注意**不能**先调 ft.Nanoseconds()：它在全 0 输入上会整数溢出
	//（0-116444736000000000 再乘 100 超出 int64），结果反而变成正数、算出个 2185 年。
	// 这里先在无符号空间做 1601→1970 的换算，再拼出秒与纳秒。
	if ft.LowDateTime == 0 && ft.HighDateTime == 0 {
		return ""
	}
	const (
		ticksPerSecond  = 10000000    // FILETIME 是 100 纳秒一格
		epochDiffSecond = 11644473600 // 1601-01-01 → 1970-01-01 的秒数
	)
	ticks := uint64(ft.HighDateTime)<<32 | uint64(ft.LowDateTime)
	sec := int64(ticks/ticksPerSecond) - epochDiffSecond
	nsec := int64(ticks%ticksPerSecond) * 100
	return time.Unix(sec, nsec).UTC().Format(time.RFC3339)
}

// regQueryInfoKeyOnce 单次 RegQueryInfoKeyW 调用（可注入，测试注入假时间/假失败）。
//
// 12 个参数里只用到 hKey 与 lpftLastWriteTime，其余按 API 约定传 NULL
// （lpReserved 必须为 NULL）：这样调用只读元数据，不枚举、不分配、不写任何东西。
var regQueryInfoKeyOnce = func(hkey uintptr, lastWrite *syscall.Filetime) (uintptr, error) {
	ret, _, err := procRegQueryInfoKeyW.Call(
		hkey,
		0,                                  // lpClass
		0,                                  // lpcchClass
		0,                                  // lpReserved（必须为 NULL）
		0,                                  // lpcSubKeys
		0,                                  // lpcbMaxSubKeyLen
		0,                                  // lpcbMaxClassLen
		0,                                  // lpcValues
		0,                                  // lpcbMaxValueNameLen
		0,                                  // lpcbMaxValueLen
		0,                                  // lpcbSecurityDescriptor
		uintptr(unsafe.Pointer(lastWrite)), // lpftLastWriteTime
	)
	return ret, err
}

// regOpenKeyOnce 单次 RegOpenKeyExW 调用（可注入，测试注入假键句柄）。
var regOpenKeyOnce = func(hive uintptr, keyPath string, hkey *uintptr) (uintptr, error) {
	ret, _, err := procRegOpenKeyExW.Call(hive,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(keyPath))), 0, keyRead,
		uintptr(unsafe.Pointer(hkey)))
	return ret, err
}

// readRegistryRun 枚举一个注册表 Run 键下的所有值。
//
// Step 11.5：RegEnumValueW 遇 ERROR_MORE_DATA（超长 value name）动态扩容重试，
// 上限 maxValueNameChars；单值失败记录内部错误并继续（能采多少采多少），
// 不静默跳过、不静默忽略。
func readRegistryRun(hive uintptr, keyPath, typ, user string) ([]persistItem, error) {
	hkey, ok, err := openKeyForCollect(hive, keyPath)
	if err != nil || !ok {
		return nil, err
	}
	defer procRegCloseKey.Call(hkey)

	// 键级时间：同一键下的所有值共享同一个 LastWriteTime（值为 1 次调用/键，只读）。
	kwt := queryKeyLastWrite(hkey)

	var items []persistItem
	index := uint32(0)
	for {
		name, err := enumValueName(hkey, index)
		if err == errNoMoreItems {
			break
		}
		if err != nil {
			// 单值失败（含超限）：明确记录，继续枚举其它值
			debugf("reg_enum_value_failed index=%d error=%v", index, err)
			index++
			continue
		}
		index++

		if cmd := readRegValue(hkey, name); cmd != "" {
			items = append(items, persistItem{
				Type:             typ,
				Location:         hiveDisplay(hive) + `\` + keyPath,
				Name:             name,
				Command:          cmd,
				Path:             parseCommandPath(cmd),
				User:             user,
				KeyLastWriteTime: kwt,
			})
		}
	}
	return items, nil
}

// errNoMoreItems 表示枚举结束（ERROR_NO_MORE_ITEMS）。
var errNoMoreItems = errors.New("ERROR_NO_MORE_ITEMS")

// regEnumValueOnce 单次 RegEnumValueW 调用（可注入，测试模拟 ERROR_MORE_DATA/超限）。
// 返回 Windows 返回码；成功时 *nameLen 为实际字符数（不含结尾 NUL）。
var regEnumValueOnce = func(hkey uintptr, index uint32, buf *uint16, nameLen *uint32) (uintptr, error) {
	ret, _, err := procRegEnumValueW.Call(hkey, uintptr(index),
		uintptr(unsafe.Pointer(buf)), uintptr(unsafe.Pointer(nameLen)),
		0, 0, 0, 0)
	return ret, err
}

// enumValueName 动态扩容读取第 index 个值名（Step 11.5：ERROR_MORE_DATA 重试，
// 支持超长 value name，上限 maxValueNameChars；超过明确记录，不静默跳过）。
func enumValueName(hkey uintptr, index uint32) (string, error) {
	buf := make([]uint16, initValueNameChars)
	nameLen := uint32(len(buf))
	for retries := 0; retries < 8; retries++ {
		ret, err := regEnumValueOnce(hkey, index, &buf[0], &nameLen)
		if ret == errorNoMoreItems {
			return "", errNoMoreItems
		}
		if ret == 0 {
			return syscall.UTF16ToString(buf[:nameLen]), nil
		}
		if ret != errorMoreData {
			return "", fmt.Errorf("RegEnumValueW(index=%d): ret=%d (%v)", index, ret, err)
		}
		// ERROR_MORE_DATA：nameLen 含结尾 NUL 的所需字符数，按需扩容
		if nameLen > maxValueNameChars {
			return "", fmt.Errorf("reg value name exceeds read limit index=%d chars=%d limit=%d", index, nameLen, maxValueNameChars)
		}
		buf = make([]uint16, nameLen)
		nameLen = uint32(len(buf))
	}
	return "", fmt.Errorf("RegEnumValueW(index=%d): 扩容重试次数超限", index)
}

// regQueryValueOnce 单次 RegQueryValueExW 调用（可注入，测试模拟 ERROR_MORE_DATA/超限）。
// 成功时 *size 为实际字节数（含 REG_SZ 结尾 NUL）；ERROR_MORE_DATA 时 *size 为所需字节数。
var regQueryValueOnce = func(hkey uintptr, name string, typ *uint32, buf *byte, size *uint32) (uintptr, error) {
	ret, _, err := procRegQueryValueExW.Call(hkey,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(name))), 0,
		uintptr(unsafe.Pointer(typ)),
		uintptr(unsafe.Pointer(buf)), uintptr(unsafe.Pointer(size)))
	return ret, err
}

// readRegValueData 动态扩容读取注册表值数据（Step 11.5：ERROR_MORE_DATA 重试，
// 支持超长 value data，上限 maxValueDataBytes；超过明确记录，不静默截断/忽略）。
func readRegValueData(hkey uintptr, name string) (uint32, []byte, error) {
	var typ uint32
	buf := make([]byte, initValueDataBytes)
	for retries := 0; retries < 8; retries++ {
		size := uint32(len(buf))
		ret, err := regQueryValueOnce(hkey, name, &typ, &buf[0], &size)
		if ret == 0 {
			return typ, buf[:size], nil
		}
		if ret != errorMoreData {
			return 0, nil, fmt.Errorf("RegQueryValueExW(%s): ret=%d (%v)", name, ret, err)
		}
		if size > maxValueDataBytes {
			return 0, nil, fmt.Errorf("reg value data exceeds read limit name=%q size=%d limit=%d", name, size, maxValueDataBytes)
		}
		if size <= uint32(len(buf)) {
			return 0, nil, fmt.Errorf("RegQueryValueExW(%s): ERROR_MORE_DATA 但所需大小未增长（size=%d）", name, size)
		}
		buf = make([]byte, size)
	}
	return 0, nil, fmt.Errorf("RegQueryValueExW(%s): 扩容重试次数超限", name)
}

// readRegValue 读取注册表字符串值（REG_SZ / REG_EXPAND_SZ）。
// Step 11.5：读取失败/超限时明确记录内部错误（不静默忽略）。
func readRegValue(hkey uintptr, name string) string {
	typ, data, err := readRegValueData(hkey, name)
	if err != nil {
		debugf("reg_value_read_failed name=%q error=%v", name, err)
		return ""
	}
	val := ""
	if len(data) >= 2 {
		val = syscall.UTF16ToString(unsafe.Slice((*uint16)(unsafe.Pointer(&data[0])), len(data)/2))
	}
	if typ == regMultiSz {
		return multiSzToString(data)
	}
	if typ == regExpandSz {
		if expanded := expandEnv(val); expanded != "" {
			return expanded
		}
	}
	return val
}

// multiSzToString 把 REG_MULTI_SZ 的 UTF-16 数据渲染为 "a | b"（跳过空项）。
//
// 注意：不能先转成 Go 字符串再按 NUL 切分——UTF16ToString 遇到第一个 NUL 就停，
// 会把第二个及之后的项全部丢掉。这里直接遍历 UTF-16 码元、以 0 作为分隔。
func multiSzToString(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	u16 := unsafe.Slice((*uint16)(unsafe.Pointer(&data[0])), len(data)/2)
	var (
		parts []string
		cur   []uint16
	)
	flush := func() {
		if len(cur) == 0 {
			return
		}
		if s := strings.TrimSpace(string(utf16.Decode(cur))); s != "" {
			parts = append(parts, s)
		}
		cur = cur[:0]
	}
	for _, u := range u16 {
		if u == 0 {
			flush()
			continue
		}
		cur = append(cur, u)
	}
	flush()
	return strings.Join(parts, " | ")
}

// regEnumKeyOnce 单次 RegEnumKeyExW 调用（可注入，测试模拟 ERROR_MORE_DATA/超限）。
var regEnumKeyOnce = func(hkey uintptr, index uint32, buf *uint16, nameLen *uint32) (uintptr, error) {
	ret, _, err := procRegEnumKeyExW.Call(hkey, uintptr(index),
		uintptr(unsafe.Pointer(buf)), uintptr(unsafe.Pointer(nameLen)), 0, 0, 0, 0)
	return ret, err
}

// enumSubKeyName 动态扩容读取第 index 个子键名（与 enumValueName 同策略）。
func enumSubKeyName(hkey uintptr, index uint32) (string, error) {
	buf := make([]uint16, initValueNameChars)
	nameLen := uint32(len(buf))
	for retries := 0; retries < 8; retries++ {
		ret, err := regEnumKeyOnce(hkey, index, &buf[0], &nameLen)
		if ret == errorNoMoreItems {
			return "", errNoMoreItems
		}
		if ret == 0 {
			return syscall.UTF16ToString(buf[:nameLen]), nil
		}
		if ret != errorMoreData {
			return "", fmt.Errorf("RegEnumKeyExW(index=%d): ret=%d (%v)", index, ret, err)
		}
		if nameLen > maxValueNameChars {
			return "", fmt.Errorf("reg subkey name exceeds read limit index=%d chars=%d limit=%d", index, nameLen, maxValueNameChars)
		}
		buf = make([]uint16, nameLen)
		nameLen = uint32(len(buf))
	}
	return "", fmt.Errorf("RegEnumKeyExW(index=%d): 扩容重试次数超限", index)
}

// expandEnv 展开环境变量（%SystemRoot% 等）；失败时返回空（调用方降级用原始值，
// 不 panic、不影响其它采集项）。底层实现可注入（测试模拟超长/API 失败）。
func expandEnv(s string) string {
	v, err := expandEnvCall(s)
	if err != nil {
		debugf("expand_env_failed input=%q error=%v", s, err)
		return ""
	}
	return v
}

// expandEnvCall 是可注入的底层展开实现（默认 expandEnvImpl）。
var expandEnvCall = expandEnvImpl

// expandEnvImpl 展开环境变量（ExpandEnvironmentStringsW），两次调用模式：
//   - 第一次：nSize=0 获取所需长度（含结尾 NUL；超上限直接失败，不做超大分配）
//   - 第二次：按所需长度动态分配 buffer 并取结果
//
// 返回值按 API 实际写入长度截取并剥离结尾 NUL；对返回值与文档两种语义
// （含/不含结尾 NUL）都做了防御，绝不越界。API 失败返回错误，不 panic。
func expandEnvImpl(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	// 第一次调用：获取所需长度（含结尾 NUL）
	ret, _, _ := procExpandEnvironmentStr.Call(
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(s))), 0, 0)
	if ret == 0 {
		return "", fmt.Errorf("ExpandEnvironmentStringsW(size) 失败")
	}
	if ret > maxExpandEnvChars+1 {
		return "", fmt.Errorf("展开结果超过限制 %d 字符（实际 %d）", maxExpandEnvChars, ret-1)
	}
	// 第二次调用：动态分配 buffer 取结果
	buf := make([]uint16, ret)
	ret2, _, _ := procExpandEnvironmentStr.Call(
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(s))),
		uintptr(unsafe.Pointer(&buf[0])), ret)
	goruntime.KeepAlive(buf)
	if ret2 == 0 {
		return "", fmt.Errorf("ExpandEnvironmentStringsW(result) 失败")
	}
	n := int(ret2)
	if n > len(buf) {
		n = len(buf) // 防御：API 返回异常长度，按实际 buffer 截断
	}
	if n > 0 && buf[n-1] == 0 {
		n-- // 剥离结尾 NUL（API 文档两种语义均兼容）
	}
	return syscall.UTF16ToString(buf[:n]), nil
}

// parseCommandPath 从命令行提取**目标可执行文件**路径并展开环境变量。
//
// 只取可执行文件部分，绝不把整条命令行（含参数）当成路径：参数里的
// `"C:\Users\Public\evil.dll",Start` 不是启动项指向的文件，把它当 path 会让
// 规则在错误的目标上命中（并附上错误的哈希/签名证据）。
func parseCommandPath(cmd string) string {
	exe, _ := cmdline.Split(cmd)
	if exe == "" {
		return ""
	}
	if strings.Contains(exe, `%`) {
		if expanded := expandEnv(exe); expanded != "" {
			return expanded
		}
	}
	return exe
}

// scanStartupFolder 枚举启动文件夹中的文件（.lnk/.exe/.bat 等）。
func scanStartupFolder(folder, user string) ([]persistItem, error) {
	if folder == "" {
		return nil, fmt.Errorf("启动文件夹路径为空")
	}
	pattern := filepath.Join(folder, "*")
	var findData win32FindData
	h, _, err := procFindFirstFileW.Call(
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(pattern))),
		uintptr(unsafe.Pointer(&findData)))
	if h == uintptr(syscall.InvalidHandle) {
		// 启动文件夹不存在是常态（用户级目录常被系统省略），不是采集失败。
		// 权限等其它错误继续上抛，由调用方聚合为"采集不完整"。
		if errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) || errors.Is(err, syscall.ERROR_PATH_NOT_FOUND) {
			return nil, nil
		}
		return nil, err
	}
	defer procFindClose.Call(h)

	var items []persistItem
	for {
		name := syscall.UTF16ToString(findData.FileName[:])
		if name != "." && name != ".." {
			fullPath := filepath.Join(folder, name)
			items = append(items, persistItem{
				Type:     "startup_folder",
				Location: folder,
				Name:     name,
				Command:  fullPath,
				Path:     fullPath,
				User:     user,
			})
		}
		ret, _, _ := procFindNextFileW.Call(h, uintptr(unsafe.Pointer(&findData)))
		if ret == 0 {
			break
		}
	}
	return items, nil
}

// win32FindData 对应 WIN32_FIND_DATAW（仅使用 FileName 字段）。
type win32FindData struct {
	FileAttributes uint32
	CreationTime   [2]uint32
	LastAccessTime [2]uint32
	LastWriteTime  [2]uint32
	FileSizeHigh   uint32
	FileSizeLow    uint32
	Reserved0      uint32
	Reserved1      uint32
	FileName       [maxPath]uint16
	AlternateName  [14]uint16
}

// startupFolderPath 返回启动文件夹路径（userFolder=true 用户级，否则公共级）。
func startupFolderPath(userFolder bool) string {
	if userFolder {
		// %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
		appdata := os.Getenv("APPDATA")
		if appdata == "" {
			return ""
		}
		return filepath.Join(appdata, `Microsoft\Windows\Start Menu\Programs\Startup`)
	}
	// %PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup
	progdata := os.Getenv("PROGRAMDATA")
	if progdata == "" {
		return ""
	}
	return filepath.Join(progdata, `Microsoft\Windows\Start Menu\Programs\Startup`)
}

// hiveDisplay 返回注册表根键的展示名。
func hiveDisplay(hive uintptr) string {
	if hive == hkeyLocalMachine {
		return "HKLM"
	}
	return "HKCU"
}

// currentUserName 获取当前用户名（HKCU 键的归属者）。
func currentUserName() string {
	var buf [256]uint16
	n := uint32(len(buf))
	ret, _, _ := procGetUserNameW.Call(
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)))
	if ret == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf[:n])
}
