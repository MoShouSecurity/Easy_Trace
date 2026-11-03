// 本文件承载 Process Collector 使用的 Windows API 声明与常量，以及进程实体/关系的
// 公共结构（procEntry、buildRelations、失败分类辅助）。
//
// 历史说明：本文件原名 process_old.go，容易让人以为整份都是遗留代码；实际上只有
// 一个未被任何代码引用的 collectProcessesLegacy 是真正的遗留实现，已于 2026-10-12
// 删除，文件更名为 winapi.go——名字与实际内容一致，避免后来者误删仍在使用的
// API 声明（processCommandLineInformation、进程/令牌/窗口相关等）。
// 签名相关的声明与实现已迁到 internal/filemeta（2026-10-14，process 只留薄封装）。
//
// 采集分两级：
//   - 基础采集（process.go）：快照枚举 + path/user/session/signature/creation_time
//   - 深度采集（process_enrichment.go + collection_policy.go）：commandline / hash /
//     parent commandline，经 entity_update 输出
//
// 只采集事实（不判断恶意、不加入 IOC、不评分）；单个进程采集失败不影响整体。
package process

import (
	"fmt"
	"syscall"
	"time"

	"easytrace/internal/collector"
	"easytrace/internal/model"
)

// ---- Windows API 句柄（懒加载，零外部依赖） ----
var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")
	ntdll    = syscall.NewLazyDLL("ntdll.dll")
	user32   = syscall.NewLazyDLL("user32.dll")

	procCreateToolhelp32Snapshot  = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW           = kernel32.NewProc("Process32FirstW")
	procProcess32NextW            = kernel32.NewProc("Process32NextW")
	procOpenProcess               = kernel32.NewProc("OpenProcess")
	procQueryFullProcessImageName = kernel32.NewProc("QueryFullProcessImageNameW")
	// 刻意不声明 ReadProcessMemory：命令行改用 ProcessCommandLineInformation，
	// 由内核把命令行拷进**调用方**缓冲，因此不需要 PROCESS_VM_READ，也不再读取
	// 其它进程的内存——这是为缩小安全软件触发面而做的决定。**不要加回来。**
	procProcessIdToSessionId = kernel32.NewProc("ProcessIdToSessionId")
	procCloseHandle          = kernel32.NewProc("CloseHandle")
	procGetProcessTimes      = kernel32.NewProc("GetProcessTimes")

	procNtQueryInformationProcess = ntdll.NewProc("NtQueryInformationProcess")

	procOpenProcessToken    = advapi32.NewProc("OpenProcessToken")
	procGetTokenInformation = advapi32.NewProc("GetTokenInformation")
	procLookupAccountSidW   = advapi32.NewProc("LookupAccountSidW")

	procEnumWindows        = user32.NewProc("EnumWindows")
	procGetWindowThreadPid = user32.NewProc("GetWindowThreadProcessId")
	procIsWindowVisible    = user32.NewProc("IsWindowVisible")
)

const (
	th32csSnapProcess = 0x00000002

	processQueryLimitedInformation = 0x1000
	processQueryInformation        = 0x0400

	// PROCESSINFOCLASS：ProcessCommandLineInformation = 60（Win8.1+）。
	// 注意 1 是 ProcessQuotaLimits，曾被误用；用错类别会把配额结构当成
	// UNICODE_STRING 解析，导致命令行读取失败甚至按无意义的地址调用 ReadProcessMemory。
	processCommandLineInformation = 0x3C

	// maxCommandLineBytes 是命令行读取的缓冲上限。Windows 命令行上限为
	// 32767 字符，64 KiB 足够容纳，同时防止异常长度导致的大块分配。
	maxCommandLineBytes = 64 * 1024

	tokenQuery      = 0x0008
	tokenUser       = 1 // TokenUser
	tokenUserSidLen = 1024
)

// processEntry32W 对应 PROCESSENTRY32W。
type processEntry32W struct {
	Size              uint32
	CntUsage          uint32
	ProcessID         uint32
	DefaultHeapID     uintptr
	ModuleID          uint32
	CntThreads        uint32
	ParentProcessID   uint32
	PriorityClassBase int32
	Flags             uint32
	ExeFile           [syscall.MAX_PATH]uint16
}

// unicodeString 对应 UNICODE_STRING（用于读取进程命令行）。
type unicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        uintptr
}

// procEntry 是单个进程的中间采集结果（内部结构）。
type procEntry struct {
	pid               uint32
	ppid              uint32
	name              string
	path              string
	commandLine       string
	parentCommandLine string
	username          string
	session           uint32
	windowed          bool
	signed            bool
	hashSHA256        string
	creationTime      string
	signatureState    signatureState
	signatureValid    bool
	sigAttempted      bool // 与 false 区分：未调用验签时不得覆盖已有签名证据
	publisher         string
	lastWriteTime     string // 文件最近修改时间（PE Inspect 阶段填充）
	// failures 深采/元数据失败分类（Step 11.5：inspect 错误原因准确分类）。
	// 非协议数据，不落库；仅供 CLI 层输出精确失败原因。
	failures []collector.DeepFailure
}

// recordFailure 记录深采动作失败（同字段后写覆盖；reason 为空忽略）。
func (pe *procEntry) recordFailure(field, reason, detail string) {
	if reason == "" {
		return
	}
	f := collector.DeepFailure{
		EntityID: fmt.Sprintf("process_%d", pe.pid),
		Field:    field,
		Reason:   reason,
		Detail:   detail,
	}
	for i := range pe.failures {
		if pe.failures[i].Field == field {
			pe.failures[i] = f
			return
		}
	}
	pe.failures = append(pe.failures, f)
}

// metaFailurePriority 元数据失败原因优先级（高优先=更精确）。
func metaFailurePriority(reason string) int {
	switch reason {
	case collector.ReasonAccessDenied:
		return 3
	case collector.ReasonProcessExited:
		return 2
	case collector.ReasonAPIFailed:
		return 1
	}
	return 0
}

// recordMetaFailure 记录进程元数据查询失败（同字段保留优先级最高的原因）。
func (pe *procEntry) recordMetaFailure(reason, detail string) {
	if reason == "" {
		return
	}
	if len(pe.failures) > 0 && pe.failures[0].Field == "process_metadata" {
		if metaFailurePriority(reason) > metaFailurePriority(pe.failures[0].Reason) {
			pe.failures[0] = collector.DeepFailure{
				EntityID: fmt.Sprintf("process_%d", pe.pid),
				Field:    "process_metadata",
				Reason:   reason,
				Detail:   detail,
			}
		}
		return
	}
	pe.failures = append(pe.failures, collector.DeepFailure{
		EntityID: fmt.Sprintf("process_%d", pe.pid),
		Field:    "process_metadata",
		Reason:   reason,
		Detail:   detail,
	})
}

// buildRelations 根据 pid/ppid 生成 spawn 关系（纯函数，可单测）。
// 仅当父进程也出现在本次采集集合中时生成关系。
//
// PID 复用防护：ppid 只是“当时的父进程 ID”，父进程退出后该 ID 可能被另一个
// 新进程复用。如果双方创建时间都已知、且“父进程”比子进程还晚创建，这条边
// 在时间上不可能成立，直接跳过（否则报告会把两个无关进程画成父子）。
// 创建时间缺失时无法判断，保留关系——宁可多一条待核实的边，也不丢证据。
func buildRelations(entries []procEntry, ids map[uint32]bool) []*model.Relation {
	created := make(map[uint32]time.Time, len(entries))
	for _, pe := range entries {
		if t, err := time.Parse(time.RFC3339, pe.creationTime); err == nil {
			created[pe.pid] = t
		}
	}

	var rels []*model.Relation
	seq := 0
	for _, pe := range entries {
		if pe.ppid == 0 || pe.ppid == pe.pid {
			continue
		}
		if !ids[pe.ppid] {
			continue
		}
		if parentAt, ok := created[pe.ppid]; ok {
			if childAt, ok := created[pe.pid]; ok && childAt.Before(parentAt) {
				debugf("spawn_relation_skipped_pid_reuse child=%d parent=%d", pe.pid, pe.ppid)
				continue
			}
		}
		seq++
		rel := model.NewRelation(
			fmt.Sprintf("rel_%04d", seq),
			fmt.Sprintf("process_%d", pe.ppid),
			fmt.Sprintf("process_%d", pe.pid),
			"spawn",
			map[string]string{"command": pe.commandLine},
		)
		rels = append(rels, rel)
	}
	return rels
}
