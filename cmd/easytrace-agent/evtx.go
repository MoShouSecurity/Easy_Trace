package main

// evtx.go 实现事件日志（EVTX）原始导出（阶段 A）。
//
// 设计依据：docs/设计-日志采集.md
//   - 只用系统自带的 wevtapi.dll，不调用 wevtutil.exe、不执行外部程序
//   - 只导出白名单通道，导出为**原始 .evtx 副本**：不解析、不建模
//   - 不触碰协议 v0.2、SQLite schema、Collector 与 Analyzer
//
// 阶段 B（把事件解析为 event 实体）需要协议扩展，未实施。

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"easytrace/internal/integrity"
)

var (
	wevtapi                 = syscall.NewLazyDLL("wevtapi.dll")
	procEvtExportLog        = wevtapi.NewProc("EvtExportLog")
	procEvtExtStatus        = wevtapi.NewProc("EvtGetExtendedStatus")
	evtExportLogChannelPath = 1 // EVT_EXPORTLOG_FLAGS: 第 2 个参数是通道名
)

// 资源上限（docs/设计-日志采集.md §2.4）。
// 声明为 var 以便测试用极小上限验证"超限即明确失败"，不写 256MB 的假文件。
var (
	maxEvtxChannelBytes int64 = 256 << 20 // 单通道 256 MB
	maxEvtxTotalBytes   int64 = 512 << 20 // 全部 512 MB
)

// evtxExportTimeout 是单通道导出的墙钟上限。EvtExportLog 是同步 win32 调用，
// 无法真正中断：超时只放弃等待并按失败记录，事件日志服务卡住时不能让整次
// collect 永久挂起。声明为 var 便于测试用极小值验证。
var evtxExportTimeout = 5 * time.Minute

// evtxPreflightSize 预估单通道导出后的量级：直接 stat 系统事件日志目录里
// 同名文件的当前大小（EvtExportLog 输出是该通道的一致性副本，量级一致）。
//
// ok=false 表示无法判断（文件不存在、无权限），此时不预判、照常导出，交由
// 导出后的大小检查兜底——预判只用于避免白写一个数 GB 的临时文件，绝不能
// 因为读不到元数据就把通道判失败。声明为 var 便于测试注入。
var evtxPreflightSize = func(fileName string) (int64, bool) {
	root := strings.TrimSpace(os.Getenv("SystemRoot"))
	if root == "" {
		return 0, false
	}
	info, err := os.Stat(filepath.Join(root, "System32", "winevt", "Logs", fileName))
	if err != nil || !info.Mode().IsRegular() {
		return 0, false
	}
	return info.Size(), true
}

// evtxChannels 是默认通道白名单（docs/设计-日志采集.md §2.1）。
var evtxChannels = []string{
	"Security",
	"System",
	"Application",
	"Microsoft-Windows-PowerShell/Operational",
	"Microsoft-Windows-TaskScheduler/Operational",
}

// evtxEntry 记录单个通道的导出结果。
type evtxEntry struct {
	channel string
	file    string
	bytes   int64
	sha256  string
	status  string // ok / access_denied / too_large / failed
	reason  string // 失败原因原文（成功时为空）
}

// evtxFileName 把通道名映射为文件名。
//
// 通道名中的 "/" 是事件日志的合法分隔符但不能作文件名，按 Windows 自身惯例
// 替换为 "%4"（与 System32\winevt\Logs 下的实际文件名一致）。
func evtxFileName(channel string) string {
	return strings.ReplaceAll(channel, "/", "%4") + ".evtx"
}

// exportChannelFn 是导出注入点（测试用 fake 覆盖，不触碰真实事件日志）。
var exportChannelFn = evtxExportChannel

// exportChannelBounded 给单通道导出加墙钟上限。
//
// EvtExportLog 无法取消，超时后这个 goroutine 可能仍在写临时区；这是刻意
// 取舍：宁可留下一个（由 staging 清理兜底的）半成品，也不让一次 collect
// 因为事件日志服务无响应而永远挂着。超时按 failed 记录，与其它通道互不影响。
func exportChannelBounded(channel, dest string, timeout time.Duration) error {
	if timeout <= 0 {
		return exportChannelFn(channel, dest)
	}
	done := make(chan error, 1)
	go func() { done <- exportChannelFn(channel, dest) }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		return fmt.Errorf("导出超时：单通道超过 %s 上限（已放弃等待，后台导出可能仍在写临时区）", timeout)
	}
}

// evtxExportChannel 用 EvtExportLog 把单个通道导出为 .evtx 原始副本。
// 目标文件必须此前不存在（排他创建由调用方保证）。
func evtxExportChannel(channel, dest string) error {
	ch, err := syscall.UTF16PtrFromString(channel)
	if err != nil {
		return err
	}
	dp, err := syscall.UTF16PtrFromString(dest)
	if err != nil {
		return err
	}
	// EvtExportLog(Session, Path, Query, TargetFilePath, Flags)
	// EvtExportLog 返回 BOOL：**非 0 表示成功**（这里曾经写反，导致每次成功都被
	// 当成失败并删除刚导出的文件）。失败时真正的错误码在 GetLastError 里，
	// 返回值本身没有错误码含义。
	ret, _, lastErr := procEvtExportLog.Call(0, uintptr(unsafe.Pointer(ch)), 0,
		uintptr(unsafe.Pointer(dp)), uintptr(evtExportLogChannelPath))
	if ret != 0 {
		return nil
	}
	errno, _ := lastErr.(syscall.Errno)
	return fmt.Errorf("EvtExportLog 失败 (win32=%d)%s", uintptr(errno), evtxExtendedStatus())
}

// evtxExtendedStatus 取 EvtGetExtendedStatus 的补充诊断（尽力而为）。
func evtxExtendedStatus() string {
	var buf [512]uint16
	var used uint32
	ret, _, _ := procEvtExtStatus.Call(uintptr(len(buf)),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&used)))
	if ret != 0 || used == 0 {
		return ""
	}
	return ": " + syscall.UTF16ToString(buf[:used])
}

// classifyEvtxErr 把导出错误归类到 manifest 状态。
//
// too_large 只由大小检查直接赋值，绝不靠错误文本推断：导出失败原因里出现
// “超过”之类字样时把通道记成“超限”，会让清单给出错误的处置依据。
func classifyEvtxErr(err error) string {
	if err == nil {
		return "ok"
	}
	if strings.Contains(err.Error(), "win32=5") {
		return "access_denied"
	}
	return "failed"
}

// runEvtxExport 导出白名单通道到 dir（必须是此前不存在的新目录）。
//
// 返回每个通道的结果与错误。单通道失败不中断其它通道；只要存在失败通道，
// 最终返回错误（"采集不完整"必须显式暴露，不静默缺失）。
func runEvtxExport(dir string) ([]evtxEntry, error) {
	outDir, err := ensureNewOutputDir(dir)
	if err != nil {
		return nil, err
	}
	// outDir 是本次新建的目录，events 必须由本函数以 O_EXCL 语义创建。
	// 用 Mkdir（不是 MkdirAll）：已存在的 events 可能是竞态植入的 junction，
	// 直接复用会把后续写入重定向到链接目标。
	evDir := filepath.Join(outDir, "events")
	if err := os.Mkdir(evDir, 0o755); err != nil {
		return nil, fmt.Errorf("创建 events 目录失败（拒绝复用已存在条目）: %w", err)
	}

	// EvtExportLog 只能按路径写文件，无法传入带 O_EXCL 的句柄。先把所有
	// 导出结果写到隔离的随机临时目录，校验普通文件/大小/哈希后，再通过
	// createNewOutputFile（父链检查 + O_EXCL）复制到最终位置。这样即使
	// 最终路径被竞态替换，也不会写到链接目标或覆盖已有文件。
	staging, err := os.MkdirTemp("", "easytrace-evtx-staging-")
	if err != nil {
		return nil, fmt.Errorf("创建 EVTX 临时目录失败: %w", err)
	}
	defer os.RemoveAll(staging)

	channels := append([]string(nil), evtxChannels...)
	sort.Strings(channels)

	var results []evtxEntry
	var total int64       // 已验收（最终目录）字节数，写入 manifest
	var stagedTotal int64 // 已导出到临时区的累计字节数，用于约束总写入量
	failed := 0
	for _, ch := range channels {
		e := evtxEntry{channel: ch, file: evtxFileName(ch)}
		if stagedTotal >= maxEvtxTotalBytes {
			e.status = "too_large"
			e.reason = fmt.Sprintf("本次导出累计写入已达上限 %d 字节，未再导出", maxEvtxTotalBytes)
			failed++
			results = append(results, e)
			continue
		}
		// 导出前预估：超过上限就直接拒绝，避免先写出一个数 GB 的临时文件再删除。
		if size, ok := evtxPreflightSize(e.file); ok &&
			(size > maxEvtxChannelBytes || stagedTotal+size > maxEvtxTotalBytes) {
			e.status = "too_large"
			e.reason = fmt.Sprintf("导出前预估超过上限：单通道 %d 字节 / 合计 %d 字节（原始日志约 %d 字节），未导出",
				maxEvtxChannelBytes, maxEvtxTotalBytes, size)
			failed++
			results = append(results, e)
			continue
		}
		staged := filepath.Join(staging, e.file)
		expErr := exportChannelBounded(ch, staged, evtxExportTimeout)
		e.status = classifyEvtxErr(expErr)
		if expErr != nil {
			failed++
			e.reason = expErr.Error()
			discardStaged(staged)
			results = append(results, e)
			continue
		}
		info, statErr := os.Lstat(staged)
		if statErr != nil {
			e.status = "failed"
			e.reason = fmt.Sprintf("读取临时导出文件失败: %v", statErr)
			failed++
			discardStaged(staged)
			results = append(results, e)
			continue
		}
		if !info.Mode().IsRegular() {
			e.status = "failed"
			e.reason = "导出结果不是普通文件（拒绝链接/重解析点）"
			failed++
			discardStaged(staged)
			results = append(results, e)
			continue
		}
		// 所有导出产物（含即将被拒绝的）都计入累计写入量：否则连续多个超大
		// 通道会各自重新写一遍临时文件，把系统盘写满。
		stagedTotal += info.Size()
		if info.Size() > maxEvtxChannelBytes || total+info.Size() > maxEvtxTotalBytes {
			// 明确失败，不静默截断：最终目录中不会出现超限产物，临时区里的
			// 半成品立即删除，不等整个导出结束。
			e.status = "too_large"
			e.reason = fmt.Sprintf("超过上限：单通道 %d 字节 / 合计 %d 字节，实际 %d 字节",
				maxEvtxChannelBytes, maxEvtxTotalBytes, info.Size())
			failed++
			discardStaged(staged)
			results = append(results, e)
			continue
		}
		sum, hashErr := fileSHA256(staged)
		if hashErr != nil {
			e.status = "failed"
			e.reason = fmt.Sprintf("计算临时文件哈希失败: %v", hashErr)
			failed++
			discardStaged(staged)
			results = append(results, e)
			continue
		}
		dest := filepath.Join(evDir, e.file)
		if copyErr := copyToNewOutputFile(dest, staged, 0o644); copyErr != nil {
			e.status = "failed"
			e.reason = copyErr.Error()
			failed++
			discardStaged(staged)
			results = append(results, e)
			continue
		}
		// 复制完成后立即释放临时区，峰值磁盘只多一个通道的量。
		discardStaged(staged)
		finalInfo, statErr := os.Stat(dest)
		if statErr != nil || finalInfo.Size() != info.Size() {
			_ = os.Remove(dest)
			e.status = "failed"
			e.reason = "最终文件大小校验失败（未保留）"
			failed++
			results = append(results, e)
			continue
		}
		finalSum, hashErr := fileSHA256(dest)
		if hashErr != nil || finalSum != sum {
			_ = os.Remove(dest)
			e.status = "failed"
			e.reason = "最终文件哈希校验失败（未保留）"
			failed++
			results = append(results, e)
			continue
		}
		e.bytes = finalInfo.Size()
		e.sha256 = finalSum
		total += finalInfo.Size()
		results = append(results, e)
	}

	// manifest.txt 放在 events/ 内（设计文档 §2.3）：这样 collect --evtx 的产物
	// 可以直接整体交给 report -zip --events，通道映射不会在打包时丢失。
	manifest := buildEvtxManifest(results, total)
	if err := integrity.VerifyManifestHash([]byte(manifest)); err != nil {
		return results, fmt.Errorf("EVTX 清单自校验失败: %w", err)
	}
	if err := writeNewOutputFile(filepath.Join(evDir, "manifest.txt"), []byte(manifest), 0o644); err != nil {
		return results, fmt.Errorf("写入 manifest.txt 失败: %w", err)
	}
	if failed > 0 {
		return results, fmt.Errorf("事件日志导出不完整: %d/%d 个通道失败（已成功的通道与 manifest 保留）",
			failed, len(channels))
	}
	return results, nil
}

// discardStaged 立即删除临时导出产物。
//
// 被拒绝（超限/哈希失败/复制失败）的文件如果不在这里删掉，会一直留在临时区
// 直到整个导出结束；多个大通道叠加足以写满系统盘。删除失败通常只发生在
// “超时后的后台导出仍持有句柄”时（Windows 拒绝删除已打开的文件），由
// staging 目录的统一清理兜底。
func discardStaged(path string) {
	_ = os.Remove(path)
}

// fileSHA256 计算文件 SHA256（小写十六进制）。
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// buildEvtxManifest 生成 manifest.txt：文件名 ↔ 原始通道名 ↔ 大小 ↔ 哈希 ↔ 状态。
//
// 通道名不能直接作文件名（"/" 会被替换为 "%4"），所以必须把映射写下来，
// 否则证据包里的文件名无法还原回原始通道。清单末尾带自校验行，打包时重新
// 校验每个 ok 通道的哈希/字节数，并拒绝清单外的文件。
func buildEvtxManifest(results []evtxEntry, total int64) string {
	var sb strings.Builder
	sb.WriteString("# Easy_Trace EVTX 导出清单（阶段 A：原始副本，未解析）\n")
	sb.WriteString("# 列：<文件名>\t<原始通道名>\t<字节数>\t<sha256>\t<状态>\t<失败原因>\n")
	for _, e := range results {
		sum := e.sha256
		if sum == "" {
			sum = "-"
		}
		sb.WriteString(evtxManifestField(e.file) + "\t" + evtxManifestField(e.channel) + "\t" +
			fmt.Sprintf("%d", e.bytes) + "\t" + evtxManifestField(sum) + "\t" +
			evtxManifestField(e.status) + "\t" + evtxManifestField(e.reason) + "\n")
	}
	sb.WriteString("# 合计字节数\t" + fmt.Sprintf("%d", total) + "\n")
	return integrity.AppendManifestHash(sb.String())
}

// evtxManifestField 防止失败原因里的制表符/换行改变清单结构。
func evtxManifestField(s string) string {
	return strings.NewReplacer("\t", " ", "\r", " ", "\n", " ").Replace(s)
}

// verifyEvtxPackage 校验 events 目录的内存视图（文件名 → 内容）。
// 只接受本次导出格式的清单：必须有自校验行且每个 ok 条目都能对上实际文件；
// 清单外的任何文件都拒绝，避免事件包混入未记录内容。
func verifyEvtxPackage(files map[string][]byte) error {
	manifest, ok := files["manifest.txt"]
	if !ok {
		return fmt.Errorf("缺少 events/manifest.txt")
	}
	if err := integrity.VerifyManifestHash(manifest); err != nil {
		return fmt.Errorf("events/manifest.txt 校验失败: %w", err)
	}

	listed := map[string]bool{}
	for i, line := range strings.Split(string(manifest), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 6 {
			return fmt.Errorf("events/manifest.txt 第 %d 行列数非法（应为 6 列）", i+1)
		}
		name, channel := fields[0], fields[1]
		if channel == "" {
			return fmt.Errorf("events/manifest.txt 第 %d 行缺少通道名", i+1)
		}
		switch status := fields[4]; status {
		case "ok":
			if err := validateEvtxFileName(name); err != nil {
				return fmt.Errorf("events/manifest.txt 第 %d 行: %w", i+1, err)
			}
			if listed[name] {
				return fmt.Errorf("events/manifest.txt 重复登记文件: %s", name)
			}
			data, ok := files[name]
			if !ok {
				return fmt.Errorf("清单记录的事件日志不存在: %s", name)
			}
			wantHash := strings.ToLower(strings.TrimSpace(fields[3]))
			if len(wantHash) != 64 {
				return fmt.Errorf("events/manifest.txt 第 %d 行哈希长度非法", i+1)
			}
			if _, err := hex.DecodeString(wantHash); err != nil {
				return fmt.Errorf("events/manifest.txt 第 %d 行哈希非法: %v", i+1, err)
			}
			sum := sha256.Sum256(data)
			if got := hex.EncodeToString(sum[:]); got != wantHash {
				return fmt.Errorf("事件日志哈希与清单不一致: %s（清单 %s，实际 %s）", name, wantHash, got)
			}
			wantBytes, err := strconv.ParseInt(fields[2], 10, 64)
			if err != nil || wantBytes != int64(len(data)) {
				return fmt.Errorf("事件日志字节数与清单不一致: %s（清单 %s，实际 %d）", name, fields[2], len(data))
			}
			listed[name] = true
		case "access_denied", "too_large", "failed":
			// 未成功条目不应留下文件（导出失败时会删除半成品）。
			if name != "" {
				if _, exists := files[name]; exists {
					return fmt.Errorf("未成功条目声称的文件却存在: %s（%s）", name, status)
				}
			}
		default:
			return fmt.Errorf("events/manifest.txt 第 %d 行状态未知: %q", i+1, status)
		}
	}

	for name := range files {
		if name == "manifest.txt" {
			continue
		}
		if !listed[name] {
			return fmt.Errorf("events 目录包含清单未记录的文件: %s", name)
		}
	}
	return nil
}

// validateEvtxFileName 只接受 events/ 下的单个 .evtx 文件名，拒绝目录穿越、
// NTFS 备用数据流与 Windows 非法字符。
func validateEvtxFileName(name string) error {
	if !strings.HasSuffix(strings.ToLower(name), ".evtx") ||
		name == "" || name == "." || name == ".." ||
		filepath.Base(name) != name || strings.ContainsAny(name, `\/:*?"<>|`) {
		return fmt.Errorf("非法事件日志文件名: %q", name)
	}
	for _, r := range name {
		if r < 0x20 {
			return fmt.Errorf("非法事件日志文件名（控制字符）: %q", name)
		}
	}
	return nil
}

// reportEvtxExport 执行事件日志导出并把逐通道结果写到 stderr。
// stdout 只承载协议 JSONL，进度与结果一律走 stderr。
//
// 单通道失败（典型：非管理员读不到 Security）只警告，不把整次 collect 判成
// 失败：调用方已先完成快照采集，事件日志不完整不应抹掉已成功的采集结果。
// 只有“一个通道都没成功”或导出目录无法建立才返回错误（后者没有 results）。
func reportEvtxExport(dir string) error {
	results, err := runEvtxExport(dir)
	if len(results) == 0 {
		// 尚未开始导出就失败（例如目标目录已存在）：不打印空标题，直接报错。
		return err
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Event log export (EVTX, phase A):")
	ok := 0
	for _, e := range results {
		if e.status == "ok" {
			ok++
		}
		line := fmt.Sprintf("  %-56s %-14s %d bytes", e.file, e.status, e.bytes)
		if e.reason != "" {
			line += "  " + e.reason
		}
		fmt.Fprintln(os.Stderr, line)
	}
	if err == nil {
		return nil
	}
	if ok == 0 {
		return err
	}
	fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
	fmt.Fprintln(os.Stderr, "Warning: 事件日志不完整不影响已创建的采集结果；失败通道已记录在 events/manifest.txt。")
	return nil
}
