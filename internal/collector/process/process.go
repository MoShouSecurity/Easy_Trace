package process

import (
	"errors"
	"fmt"
	"os"
	goruntime "runtime"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"easytrace/internal/collector"
	"easytrace/internal/collector/runtime"
	"easytrace/internal/filemeta"
	"easytrace/internal/model"
)

// Collector 实现 process 采集（Step 1 两级采集 + Step 2 行为门卫）。
//
// Basic/Deep/Forensic 三种模式（Step 2.2 冻结）：
//   - Basic：只做基础事实采集（pid/ppid/name/path/session/creation_time/username/
//     windowed），全程不调用 ReadProcessMemory / NtQueryInformationProcess / PEB 读取，
//     避免触发安全软件对"读取其他进程内存"的拦截。
//   - Deep/Forensic：对 Collection Policy 命中（或 --pid 指定）的进程执行深度采集
//     （commandline / sha256 / parent commandline），结果经 entity_update 输出。
//
// 深采是否执行由 runtime.Mode 与 runtime.Allow 决定——Collector 不自行决定能力、
// 不持有私有深度参数，一切行为由 Runtime 统一控制。
type Collector struct {
	getEntries func() ([]procEntry, error)
	pidFilter  uint32
	rt         *runtime.Runtime
	expected   *model.ProcessData
}

// New 创建 Process Collector，绑定由调用方注入的行为控制 Runtime。
// Collector 不在内部创建 Runtime（架构收口，Step 2.2）；rt 必传，nil 视为编程错误。
func New(rt *runtime.Runtime) *Collector {
	if rt == nil {
		panic("process: New 必须传入 runtime.Runtime（禁止 Collector 内部创建）")
	}
	return &Collector{rt: rt}
}

// NewWithPID 创建仅采集指定 PID 的 Process Collector（定向排查 / 低干扰测试）。
func NewWithPID(rt *runtime.Runtime, pid uint32) *Collector {
	c := New(rt)
	c.pidFilter = pid
	return c
}

// WithPID 设置定向 PID（保留已绑定的 runtime）。
func (c *Collector) WithPID(pid uint32) *Collector { c.pidFilter = pid; return c }

// NewWithEntries 创建使用自定义数据源的 Process Collector（用于测试）。
func NewWithEntries(rt *runtime.Runtime, f func() ([]procEntry, error)) *Collector {
	c := New(rt)
	c.getEntries = f
	return c
}

// WithEntries 设置自定义数据源（保留已绑定的 runtime）。
func (c *Collector) WithEntries(f func() ([]procEntry, error)) *Collector {
	c.getEntries = f
	return c
}

// Runtime 返回绑定的行为控制 Runtime（供注入一致性校验）。
func (c *Collector) Runtime() *runtime.Runtime { return c.rt }

// 基础采集元数据查询注入点（Step 11.5：测试注入失败分类）。
var (
	queryProcessPathFn  = queryProcessPath
	querySessionIDFn    = querySessionID
	queryCreationTimeFn = queryCreationTime
	queryUsernameFn     = queryProcessUsername
)

// deepMode 返回当前模式是否允许深度采集（Deep/Forensic）。
func (c *Collector) deepMode() bool {
	return c.rt.Mode() == runtime.Deep || c.rt.Mode() == runtime.Forensic
}

// Name 实现 collector.Collector 接口。
func (c *Collector) Name() string { return "process" }

// debugf 输出采集阶段日志到 stderr（不污染 stdout 的 JSONL 流）。
// 调试定位用（Process Collector 调试定位任务），后续可保留或降级。
func debugf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[process] "+format+"\n", args...)
}

// Collect 实现 collector.Collector 接口：
// 返回进程基础实体 + 深采 entity_update（Deep/Forensic 模式）+ 父子 spawn 关系。
func (c *Collector) Collect() (*collector.Result, error) {
	debugf("basic_start mode=%s pidFilter=%d", c.rt.Mode(), c.pidFilter)
	getEntries := c.getEntries
	if getEntries == nil {
		getEntries = collectProcessesBasic
	}
	entries, err := getEntries()
	if err != nil {
		return nil, err
	}
	debugf("snapshot_complete entries=%d", len(entries))
	if c.pidFilter != 0 {
		filtered := entries[:0]
		for _, pe := range entries {
			if pe.pid == c.pidFilter {
				filtered = append(filtered, pe)
			}
		}
		entries = filtered
		debugf("pid_filter applied=%d", len(entries))
	}

	if c.expected != nil {
		if !c.deepMode() || c.pidFilter == 0 || c.expected.PID != c.pidFilter {
			return nil, fmt.Errorf("身份门卫必须绑定同一 PID 的定向深采")
		}
		if err := ValidateInspectIdentity(*c.expected); err != nil {
			return nil, err
		}
		for _, pe := range entries {
			if err := MatchInspectIdentity(*c.expected, model.ProcessData{
				PID: pe.pid, Path: pe.path, CreationTime: pe.creationTime,
			}); err != nil {
				return nil, err
			}
		}
	}

	// 深度采集：Deep/Forensic 模式且 runtime 授予 ReadProcessMemory 时，
	// 按 CollectionPlan 对进程补充证据（Step 2 行为门卫：Collector 不自决能力）。
	var updates []*model.EntityUpdate
	if c.deepMode() && len(entries) > 0 {
		if !c.rt.Allow("process", "ReadProcessMemory", "") {
			debugf("enrichment_skip capability=ReadProcessMemory denied mode=%s", c.rt.Mode())
		} else {
			debugf("policy_check start")
			parentNames := make(map[uint32]string, len(entries))
			for i := range entries {
				parentNames[entries[i].pid] = entries[i].name
			}
			plans := make(map[int]CollectionPlan, len(entries))
			targets := make([]int, 0, len(entries))
			for i := range entries {
				plan := planCollection(entries[i], parentNames[entries[i].ppid])
				if c.pidFilter != 0 {
					// --pid+--deep：定向深采，强制全部深采动作（系统进程保护仍生效）
					if plan.NeedCommandLine || !protectedProcessNames[strings.ToLower(entries[i].name)] {
						// Step 12.3 Follow-up：强制 plan 含 NeedPEInspect——
						// 定向深采也必须填充 PE 头级 signature_state
						// （present/missing/unknown），否则验签结果无法在
						// 证据展示中体现（会误显示为 Unavailable）。
						plan = CollectionPlan{NeedPEInspect: true, NeedSignatureVerify: true, NeedHash: true, NeedCommandLine: true}
					}
				}
				plans[i] = plan
				if plan.NeedsWork() {
					debugf("policy_hit pid=%d name=%s plan=%+v", entries[i].pid, entries[i].name, plan)
					targets = append(targets, i)
				} else {
					debugf("policy_skip pid=%d name=%s", entries[i].pid, entries[i].name)
				}
			}
			debugf("enrichment_start targets=%d", len(targets))
			if c.expected != nil && len(targets) > 0 {
				if err := c.checkLiveIdentity(); err != nil {
					return nil, err // 未核验身份，不能开始读取深采证据
				}
			}
			enrichEntries(entries, targets, plans, c.rt.AllowFn("process"))
			if c.expected != nil && len(targets) > 0 {
				if err := c.checkLiveIdentity(); err != nil {
					return nil, err // 采集中身份改变，整批补证丢弃
				}
			}
			for _, i := range targets {
				if data, ok := enrichmentData(entries[i]); ok {
					updates = append(updates, model.NewEntityUpdate(
						fmt.Sprintf("process_%d", entries[i].pid), data))
				}
			}
		}
	} else {
		debugf("enrichment_skip mode=%s entries=%d", c.rt.Mode(), len(entries))
	}

	res := &collector.Result{}
	ids := make(map[uint32]bool, len(entries))
	// signature_state 基础阶段恒为 unknown（不读取进程文件，Step 1.6 §一）；
	// signed/hash 也仅深采后填充。
	for _, pe := range entries {
		ids[pe.pid] = true
		sigState := string(pe.signatureState)
		if sigState == "" {
			sigState = "unknown"
		}
		e := model.NewEntity("process", fmt.Sprintf("process_%d", pe.pid), model.ProcessData{
			PID:             pe.pid,
			Name:            pe.name,
			Path:            pe.path,
			ParentPID:       pe.ppid,
			Username:        pe.username,
			Session:         pe.session,
			Windowed:        pe.windowed,
			Signed:          pe.signatureValid,
			SignatureState:  sigState,
			HashSHA256:      pe.hashSHA256,
			CreationTime:    pe.creationTime,
			CollectionLevel: "basic",
		})
		res.Entities = append(res.Entities, e)
	}
	res.EntityUpdates = updates
	res.Relations = buildRelations(entries, ids)
	// Step 11.5：汇总各进程的深采/元数据失败分类（非协议数据，仅供 CLI 输出精确原因）。
	for i := range entries {
		res.DeepFailures = append(res.DeepFailures, entries[i].failures...)
	}
	return res, nil
}

// collectProcessesBasic 基础采集：快照枚举 + path/session/creation_time/username/windowed。
// 禁止读取进程文件（不读 PE 头、不验签、不计算哈希）、禁止 queryCommandLine——
// 文件相关采集全部推迟到深采阶段的 PE Inspect（Step 1.6 §一）。
func collectProcessesBasic() ([]procEntry, error) {
	debugf("snapshot begin")
	visiblePids := collectVisibleWindowPids()

	snap, _, err := procCreateToolhelp32Snapshot.Call(th32csSnapProcess, 0)
	if snap == 0 || snap == uintptr(syscall.InvalidHandle) {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer procCloseHandle.Call(snap)

	var pe processEntry32W
	pe.Size = uint32(unsafe.Sizeof(pe))
	ret, _, _ := procProcess32FirstW.Call(snap, uintptr(unsafe.Pointer(&pe)))
	if ret == 0 {
		return nil, fmt.Errorf("Process32FirstW 无进程")
	}

	var entries []procEntry
	for {
		pid, ppid := pe.ProcessID, pe.ParentProcessID
		name := syscall.UTF16ToString(pe.ExeFile[:])

		entry := procEntry{pid: pid, ppid: ppid, name: name}
		// Step 11.5：元数据查询失败按原因分类记录（access_denied / process_exited /
		// api_failed），供 inspect 输出精确失败原因，绝不静默忽略。
		fillBasicMetadata(&entry, pid)
		if entry.path == "" {
			// 绝不把进程名当路径：拿不到完整路径时留空，深采据此跳过文件读取。
			// 旧行为把 name 写进 path，Deep 会按**当前工作目录**打开同名文件，
			// 把无关文件的哈希/签名错误归因到该进程（例如 cwd 下的 chrome.exe）。
			debugf("path_unavailable pid=%d name=%s", pid, name)
		}
		debugf("path_query pid=%d name=%s path=%s", pid, name, entry.path)
		entry.windowed = visiblePids[pid]

		// signature_state 基础阶段恒为 unknown（不读取进程文件，Step 1.6）

		entries = append(entries, entry)

		ret, _, _ = procProcess32NextW.Call(snap, uintptr(unsafe.Pointer(&pe)))
		if ret == 0 {
			break
		}
	}

	// 稳定排序（pid），保证输出顺序确定
	sort.Slice(entries, func(i, j int) bool { return entries[i].pid < entries[j].pid })
	debugf("collect_finish entries=%d", len(entries))
	return entries, nil
}

// queryProcessPath 获取进程可执行文件完整路径（失败时返回空 + 失败原因）。
// 只使用 PROCESS_QUERY_LIMITED_INFORMATION，不申请读内存权限。
func queryProcessPath(pid uint32) (string, string) {
	h, err := openProcessQuery(pid)
	if err != nil {
		return "", classifyOpenErrno(err)
	}
	defer procCloseHandle.Call(h)

	var buf [syscall.MAX_PATH]uint16
	size := uint32(len(buf))
	ret, _, _ := procQueryFullProcessImageName.Call(h, 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if ret == 0 || size == 0 {
		return "", collector.ReasonAPIFailed
	}
	return syscall.UTF16ToString(buf[:size]), ""
}

// fillBasicMetadata 采集单进程基础元数据（path/session/creation_time/username），
// 查询失败按原因分类记录到 entry.failures（Step 11.5：绝不静默忽略）。
func fillBasicMetadata(pe *procEntry, pid uint32) {
	var pathReason string
	pe.path, pathReason = queryProcessPathFn(pid)
	if pe.path == "" && pathReason != "" {
		pe.recordMetaFailure(pathReason, fmt.Sprintf("QueryFullProcessImageNameW(pid=%d)", pid))
	}
	if sess, ok := querySessionIDFn(pid); ok {
		pe.session = sess
	} else {
		pe.recordMetaFailure(collector.ReasonAPIFailed, fmt.Sprintf("ProcessIdToSessionId(pid=%d)", pid))
	}
	var ctReason, userReason string
	pe.creationTime, ctReason = queryCreationTimeFn(pid)
	if ctReason != "" {
		pe.recordMetaFailure(ctReason, fmt.Sprintf("GetProcessTimes(pid=%d)", pid))
	}
	pe.username, userReason = queryUsernameFn(pid)
	if userReason != "" {
		pe.recordMetaFailure(userReason, fmt.Sprintf("OpenProcessToken/LookupAccountSid(pid=%d)", pid))
	}
}

// classifyOpenErrno 将 OpenProcess 失败错误码分类为失败原因
// （5=ERROR_ACCESS_DENIED→access_denied；87=ERROR_INVALID_PARAMETER→进程已退出；
// 其它→api_failed）。Step 11.5：错误分类必须精确，绝不笼统。
func classifyOpenErrno(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case 5: // ERROR_ACCESS_DENIED
			return collector.ReasonAccessDenied
		case 87: // ERROR_INVALID_PARAMETER（进程已退出，PID 失效）
			return collector.ReasonProcessExited
		}
	}
	return collector.ReasonAPIFailed
}

// openProcessQuery 以 PROCESS_QUERY_LIMITED_INFORMATION 打开进程句柄（基础采集专用，
// 不含 VM_READ，不会触发"读取其他进程内存"类安全拦截）。失败返回原始错误码。
func openProcessQuery(pid uint32) (uintptr, error) {
	h, _, err := procOpenProcess.Call(processQueryLimitedInformation, 0, uintptr(pid))
	if h == 0 {
		return 0, err
	}
	return h, nil
}

// querySessionID 获取进程所在会话（失败返回 0）。
func querySessionID(pid uint32) (uint32, bool) {
	var session uint32
	ret, _, _ := procProcessIdToSessionId.Call(uintptr(pid), uintptr(unsafe.Pointer(&session)))
	return session, ret != 0
}

// queryProcessUsername 通过进程令牌 + LookupAccountSid 获取进程用户名
// （失败返回空 + 失败原因）。
func queryProcessUsername(pid uint32) (string, string) {
	h, err := openProcessQuery(pid)
	if err != nil {
		return "", classifyOpenErrno(err)
	}
	defer procCloseHandle.Call(h)

	var hToken uintptr
	ret, _, _ := procOpenProcessToken.Call(h, tokenQuery, uintptr(unsafe.Pointer(&hToken)))
	if ret == 0 || hToken == 0 {
		return "", collector.ReasonAPIFailed
	}
	defer procCloseHandle.Call(hToken)

	buf := make([]byte, tokenUserSidLen)
	var retLen uint32
	ret, _, _ = procGetTokenInformation.Call(hToken, tokenUser,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&retLen)))
	goruntime.KeepAlive(buf)
	if ret == 0 || retLen < 8 {
		return "", collector.ReasonAPIFailed
	}
	// TOKEN_USER 首字段是 SID 指针
	sidPtr := *(*uintptr)(unsafe.Pointer(&buf[0]))
	if sidPtr == 0 {
		return "", collector.ReasonAPIFailed
	}

	var nameBuf [256]uint16
	var domainBuf [256]uint16
	nameLen := uint32(len(nameBuf))
	domainLen := uint32(len(domainBuf))
	var sidUse uint32
	ret, _, _ = procLookupAccountSidW.Call(0, sidPtr,
		uintptr(unsafe.Pointer(&nameBuf[0])), uintptr(unsafe.Pointer(&nameLen)),
		uintptr(unsafe.Pointer(&domainBuf[0])), uintptr(unsafe.Pointer(&domainLen)),
		uintptr(unsafe.Pointer(&sidUse)))
	goruntime.KeepAlive(buf)
	if ret == 0 || nameLen == 0 {
		return "", collector.ReasonAPIFailed
	}
	return syscall.UTF16ToString(nameBuf[:nameLen]), ""
}

// queryCreationTime 通过 GetProcessTimes 获取进程创建时间（ISO8601 UTC；
// 失败返回空 + 失败原因）。只使用有限查询句柄，不涉及内存读取。
func queryCreationTime(pid uint32) (string, string) {
	h, err := openProcessQuery(pid)
	if err != nil {
		return "", classifyOpenErrno(err)
	}
	defer procCloseHandle.Call(h)

	var creation, exit, kernel, user fileTime
	ret, _, _ := procGetProcessTimes.Call(h,
		uintptr(unsafe.Pointer(&creation)), uintptr(unsafe.Pointer(&exit)),
		uintptr(unsafe.Pointer(&kernel)), uintptr(unsafe.Pointer(&user)))
	if ret == 0 || creation == 0 {
		return "", collector.ReasonAPIFailed
	}
	return filetimeToString(int64(creation)), ""
}

// fileTime 对应 FILETIME。
type fileTime uint64

// filetimeToString 将 FILETIME（100ns since 1601）转为 ISO8601 UTC；近零返回空。
func filetimeToString(ft int64) string {
	if ft == 0 {
		return ""
	}
	const epochDiff = 116444736000000000 // 1601-01-01 -> 1970-01-01 (100ns)
	if ft < epochDiff {
		return ""
	}
	ticks := ft - epochDiff
	t := time.Unix(ticks/10_000_000, (ticks%10_000_000)*100).UTC()
	// 固定保留七位小数，整秒时刻也不能与旧版截断时间混淆。
	return t.Format("2006-01-02T15:04:05.0000000Z")
}

// collectVisibleWindowPids 返回所有拥有可见顶层窗口的进程 PID 集合。
func collectVisibleWindowPids() map[uint32]bool {
	pids := make(map[uint32]bool)
	cb := syscall.NewCallback(func(hwnd uintptr, lparam uintptr) uintptr {
		var pid uint32
		procGetWindowThreadPid.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
		if pid != 0 {
			vis, _, _ := procIsWindowVisible.Call(hwnd)
			if vis != 0 {
				pids[pid] = true
			}
		}
		return 1 // TRUE: 继续枚举
	})
	procEnumWindows.Call(cb, 0)
	return pids
}

// verifyFileSigned 委托 filemeta 的唯一验签实现（true = 签名链有效）。
func verifyFileSigned(path string) bool {
	info, _ := filemeta.VerifySignature(path)
	return info.Valid
}
