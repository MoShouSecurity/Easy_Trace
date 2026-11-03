package process

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	goruntime "runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"easytrace/internal/collector"
	"easytrace/internal/model"
	"easytrace/internal/safepath"
)

// 本文件实现深度证据采集（Step 1）：
//   - queryCommandLine：NtQueryInformationProcess(ProcessCommandLineInformation) 读命令行
//   - hashFile：文件 SHA256
//   - enrichEntries：对目标进程批量深采，并补父进程命令行
//
// 深度采集只读取进程**文件**（哈希、PE 头、签名）与命令行查询 API，
// 不读取其它进程的内存。仍只应在 --deep 且 Collection Policy 命中时调用，
// 绝不在基础模式调用。

// 函数注入点（测试用）：真实实现 queryCommandLine / hashFileCached /
// verifyFileSignatureCached / peInspectCached / fileMTime。
// 深采函数默认均为带生命周期缓存的版本（Step 12.3：同一路径只执行一次
// 敏感操作；测试注入 fake 时覆盖注入点即绕过缓存）。
var (
	queryCommandLineFn = queryCommandLine
	hashFileFn         = hashFileCached
	verifySignatureFn  = verifyFileSignatureCached
	peInspectFn        = peInspectCached
	fileMTimeFn        = fileMTime
)

// peInspect 读取 PE 头签名状态与文件最近修改时间（深采 Stage 2，会读取文件）。
func peInspect(path string) (signatureState, string) {
	if path == "" {
		return sigUnknown, ""
	}
	state := signatureStateOf(path)
	mtime := fileMTime(path)
	return state, mtime
}

// fileMTime 返回文件最近修改时间（ISO8601 UTC；失败返回空）。
func fileMTime(path string) string {
	st, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return st.ModTime().UTC().Format(time.RFC3339)
}

// enrichEntries 按 plans 对 targets 指定的 entries 执行深采（两阶段，Step 1.6）：
//
//	Stage 1 已完成（planCollection）；此处按序执行：
//	PE Inspect（读 PE 头 + 文件 mtime）→ 二次评估（missing→验签；recent_file→hash/cmdline）
//	→ Signature Verify → Hash → CommandLine → 父命令行回填。
//
// allow 是行为门卫（Step 2）：为 nil 视为全部允许（旧调用/白盒测试兼容）；
// 传入时每个深采动作先经 runtime.Allow 判定，被拒则跳过该动作（deny by default）。
func enrichEntries(entries []procEntry, targets []int, plans map[int]CollectionPlan, allow func(action, target string) bool) {
	if len(targets) == 0 {
		return
	}
	allowAll := func(action, target string) bool { return true }
	if allow == nil {
		allow = allowAll
	}
	cmdByPID := make(map[uint32]string, len(targets))
	for _, i := range targets {
		pe := &entries[i]
		plan := plans[i]

		// 文件类深采前先确认映像路径是本地普通文件（非 UNC/映射盘/链接/重解析点）。
		// 进程映像是主数据源里最容易被忽略的读取入口：镜像完全可能来自网络路径。
		safePath := pe.path
		var pathErr error
		unsafePath := false
		if plan.NeedPEInspect || plan.NeedSignatureVerify || plan.NeedHash {
			if pe.path == "" {
				pathErr = fmt.Errorf("process path unavailable")
			} else {
				safePath, pathErr = safepath.ValidateLocalFilePath(pe.path, "进程映像路径")
				unsafePath = pathErr != nil
			}
		}

		// Stage 2：PE Inspect（读 PE 头 + 文件修改时间）
		if plan.NeedPEInspect && allow("ReadFile", pe.path) {
			if pathErr != nil {
				pe.recordFailure("signature_state", pathFailureReason(unsafePath), pathErr.Error())
			} else {
				state, mtime := peInspectFn(safePath)
				pe.signatureState = state
				pe.lastWriteTime = mtime
				if state == sigMissing {
					plan.NeedSignatureVerify = true
					plan.Reasons = append(plan.Reasons, "unsigned")
				}
				if isRecentFile(mtime) {
					plan.NeedHash = true
					plan.NeedCommandLine = true
					plan.Reasons = append(plan.Reasons, "recent_file")
				}
				plans[i] = plan
			}
		}

		if plan.NeedSignatureVerify && allow("VerifySignature", pe.path) {
			if pathErr != nil {
				pe.recordFailure("signature_state", pathFailureReason(unsafePath), pathErr.Error())
			} else {
				// Step 11.5：签名失败按原因分类记录（不静默忽略）。
				// Step 12.3 Follow-up：Detail 附带原始返回码（0x%08X），不丢失。
				info, reason := verifySignatureFn(safePath)
				pe.sigAttempted = true
				pe.signatureValid = reason == "" && info.status == SigStatusSigned && info.valid
				pe.publisher = ""
				if pe.signatureValid {
					pe.publisher = info.publisher
				}
				if reason != "" {
					pe.recordFailure("signature_state", reason, fmt.Sprintf("WinVerifyTrust(%s) ret=0x%08X", safePath, info.retCode))
				}
			}
		}
		if plan.NeedHash && allow("HashFile", pe.path) {
			if pathErr != nil {
				pe.recordFailure("hash_sha256", pathFailureReason(unsafePath), pathErr.Error())
			} else {
				hash, reason := hashFileFn(safePath)
				if reason == "" {
					pe.hashSHA256 = hash
				} else {
					pe.recordFailure("hash_sha256", reason, fmt.Sprintf("SHA256(%s)", safePath))
				}
			}
		}
		if plan.NeedCommandLine && allow("ReadProcessMemory", fmt.Sprintf("pid:%d", pe.pid)) {
			cmd, reason := queryCommandLineFn(pe.pid)
			if reason != "" {
				pe.recordFailure("command_line", reason, fmt.Sprintf("NtQueryInformationProcess(pid=%d)", pe.pid))
			} else {
				pe.commandLine = cmd
				cmdByPID[pe.pid] = cmd
			}
		}
	}
	for _, i := range targets {
		pe := &entries[i]
		if pc, ok := cmdByPID[pe.ppid]; ok && pc != "" {
			pe.parentCommandLine = pc
		}
	}
}

// enrichmentData 仅输出实际得到的字段；显式 false/空 publisher 也属于有效更新。
// 查询失败的空命令行省略，不能覆盖上次已保存的历史证据。
func enrichmentData(pe procEntry) (model.ProcessEnrichmentData, bool) {
	data := model.ProcessEnrichmentData{
		CommandLine: pe.commandLine, HashSHA256: pe.hashSHA256,
		ParentCommandLine: pe.parentCommandLine, CollectionLevel: "deep",
		LastWriteTime: pe.lastWriteTime,
	}
	if pe.signatureState == sigPresent || pe.signatureState == sigMissing {
		data.SignatureState = string(pe.signatureState)
	}
	if pe.sigAttempted {
		data.SignatureValid = &pe.signatureValid
		data.Publisher = &pe.publisher
	}
	hasEvidence := data.CommandLine != "" || data.HashSHA256 != "" || data.ParentCommandLine != "" ||
		data.LastWriteTime != "" || pe.signatureState == sigPresent || pe.signatureState == sigMissing
	return data, hasEvidence || pe.sigAttempted
}

// pathFailureReason 区分“路径不可用/为空”和“路径不安全（UNC/映射盘/链接）”。
func pathFailureReason(unsafe bool) string {
	if unsafe {
		return collector.ReasonUnsafePath
	}
	return collector.ReasonQueryFailed
}

// classifyNTStatus 将 NtQueryInformationProcess / ReadProcessMemory 的 NTSTATUS
// 分类为失败原因（0xC0000022=STATUS_ACCESS_DENIED→access_denied；其它→query_failed）。
func classifyNTStatus(status uintptr) string {
	if status == 0xC0000022 {
		return collector.ReasonAccessDenied
	}
	return collector.ReasonQueryFailed
}

// queryCommandLine 读取目标进程命令行（深采专用）。
//
// 使用 PROCESSINFOCLASS = ProcessCommandLineInformation（60，Win8.1+）。
// 该类别只需 PROCESS_QUERY_LIMITED_INFORMATION：内核把命令行拷进**调用方**缓冲，
// 因此这里不申请 PROCESS_VM_READ、也不调用 ReadProcessMemory——
// 不再出现"读取其它进程内存"的行为（这是 Deep 触发安全软件的主要来源）。
//
// 调用约定（已在本机用自身进程验证）：
//  1. 先用 sizeof(UNICODE_STRING) 探测：内核返回 STATUS_INFO_LENGTH_MISMATCH，
//     并在 ReturnLength 给出所需总字节数。
//  2. 再传一块所需字节数的缓冲：内核在开头写 UNICODE_STRING，命令行字符串紧随其后。
func queryCommandLine(pid uint32) (string, string) {
	h, err := openProcessQuery(pid)
	if err != nil {
		return "", classifyOpenErrno(err)
	}
	defer procCloseHandle.Call(h)

	// 第一步：探测所需长度
	var probe unicodeString
	var need uint32
	ret, _, _ := procNtQueryInformationProcess.Call(h, processCommandLineInformation,
		uintptr(unsafe.Pointer(&probe)), uintptr(unsafe.Sizeof(probe)), uintptr(unsafe.Pointer(&need)))
	if need == 0 || need > maxCommandLineBytes {
		return "", classifyNTStatus(ret)
	}

	// 第二步：单块缓冲，前部是 UNICODE_STRING，其后是命令行字符串
	raw := make([]byte, need)
	var retLen uint32
	ret, _, _ = procNtQueryInformationProcess.Call(h, processCommandLineInformation,
		uintptr(unsafe.Pointer(&raw[0])), uintptr(len(raw)), uintptr(unsafe.Pointer(&retLen)))
	goruntime.KeepAlive(raw)
	if ret != 0 {
		return "", classifyNTStatus(ret)
	}
	us := (*unicodeString)(unsafe.Pointer(&raw[0]))
	sizeofUS := uintptr(unsafe.Sizeof(probe))
	if us.Length == 0 || us.Length%2 != 0 ||
		sizeofUS+uintptr(us.Length) > uintptr(len(raw)) {
		return "", collector.ReasonAPIFailed
	}
	// 只在本进程缓冲范围内定位字符串；绝不按内核返回的指针直接解引用，
	// 也不对它调用 ReadProcessMemory。
	off := sizeofUS
	if base := uintptr(unsafe.Pointer(&raw[0])); us.Buffer >= base && us.Buffer < base+uintptr(len(raw)) {
		off = us.Buffer - base
	}
	if off%2 != 0 || off+uintptr(us.Length) > uintptr(len(raw)) {
		return "", collector.ReasonAPIFailed
	}
	text := syscall.UTF16ToString(unsafe.Slice((*uint16)(unsafe.Pointer(&raw[off])), us.Length/2))
	return strings.TrimSpace(text), ""
}

// classifyFileErr 将文件访问错误分类为失败原因
// （IsNotExist→file_not_found；IsPermission→access_denied；其它→query_failed）。
func classifyFileErr(err error) string {
	if os.IsNotExist(err) {
		return collector.ReasonFileNotFound
	}
	if os.IsPermission(err) {
		return collector.ReasonAccessDenied
	}
	return collector.ReasonQueryFailed
}

// hashFile 计算文件 SHA256（深采专用）。失败返回空 + 分类原因
// （File not found / Access denied / Hash failed）。
// maxProcessHashBytes 是进程镜像哈希上限，与 file / persistence 的 64 MiB
// 口径一致。超过上限不计算哈希：只对前缀做哈希会得到误导性的“完整哈希”。
const maxProcessHashBytes int64 = 64 * 1024 * 1024

func hashFile(path string) (string, string) {
	return hashFileLimit(path, maxProcessHashBytes)
}

func hashFileLimit(path string, maxBytes int64) (string, string) {
	if _, err := safepath.ValidateLocalFilePath(path, "进程映像路径"); err != nil {
		return "", collector.ReasonUnsafePath
	}
	f, err := os.Open(path)
	if err != nil {
		return "", classifyFileErr(err)
	}
	defer f.Close()
	h := sha256.New()
	// 多读 1 字节用于判断是否超限，避免只对前缀计算哈希。
	limit := maxBytes + 1
	if limit <= 0 { // 防御 maxBytes 溢出
		limit = maxBytes
	}
	n, err := io.Copy(h, io.LimitReader(f, limit))
	if err != nil {
		return "", collector.ReasonHashFailed
	}
	if n > maxBytes {
		return "", collector.ReasonFileTooLarge
	}
	return fmt.Sprintf("%x", h.Sum(nil)), ""
}
