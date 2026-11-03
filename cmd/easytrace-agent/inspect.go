package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"easytrace/internal/analyzer"
	"easytrace/internal/collector"
	"easytrace/internal/collector/pipeline"
	"easytrace/internal/collector/process"
	"easytrace/internal/collector/runtime"
	"easytrace/internal/model"
	"easytrace/internal/platform/privilege"
	"easytrace/internal/protocol"
	"easytrace/internal/storage"
)

// runInspect 处理 inspect 子命令（Step 10，替代 GUI Deep 流程）：
//
//	easytrace inspect -pid <pid> [--db <path>] [--snapshot <id>] [-r|--rules <dir>]
//
// 流程：用户确认 → 核验历史/实时身份 → Deep Collector（仅目标 PID）→ EntityUpdate
// 整批追加快照 → 整份快照重新分析 → 输出目标实体最新线索与补充证据。
// 禁止自动 Deep：未输入 y 一律不执行任何采集。
func runInspect(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	dbPath := fs.String("db", "easytrace.db", "SQLite 数据库路径")
	snapshotID := fs.String("snapshot", "", "目标快照 snapshot_id（默认最新快照）")
	pid := fs.Uint("pid", 0, "目标进程 PID（必填）")
	rulesDir := fs.String("r", "", "规则目录；留空使用**内嵌规则包**（单 exe 即可用），指定则覆盖")
	fs.StringVar(rulesDir, "rules", "", "规则目录别名（-r 同义；留空用内嵌规则包）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pid == 0 || *pid > uint(^uint32(0)) {
		return fmt.Errorf("用法: inspect -pid <pid> [--db <path>] [--snapshot <id>] [-r <rules_dir>]")
	}

	// inspect 会向数据库追加补证（EntityUpdate），需要读写句柄；但绝不能创建
	// 新库：--db 拼错时必须在任何提示、任何主机采集之前失败。
	db, err := storage.OpenExisting(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := storage.CheckSchema(db); err != nil {
		return err
	}
	if *snapshotID == "" {
		snaps, err := storage.ListSnapshots(db)
		if err != nil {
			return err
		}
		if len(snaps) == 0 {
			return fmt.Errorf("数据库中没有快照，请先执行 collect 或 snapshot import")
		}
		*snapshotID = snaps[0].SnapshotID
	} else {
		// 显式 --snapshot 也要在提示与深采之前确认存在，避免“先采集、后报错”。
		meta, err := storage.GetSnapshot(db, *snapshotID)
		if err != nil {
			return err
		}
		if meta == nil {
			return fmt.Errorf("快照 %s 不存在（可用 snapshot list 查看）；未执行深采", *snapshotID)
		}
	}

	// 权限提示（Step 10.1）：采集命令启动时输出，仅提示不阻止
	printPrivilegeBanner(os.Stderr, privilege.Detect())

	// 确认机制：明确列出将读取的证据与行为暴露
	fmt.Fprintln(os.Stderr, "Deep inspection will collect:")
	fmt.Fprintln(os.Stderr, "[x] command line")
	fmt.Fprintln(os.Stderr, "[x] file hash")
	fmt.Fprintln(os.Stderr, "[x] signature")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "该操作可能触发安全软件的行为监控或告警。")
	fmt.Fprintln(os.Stderr, "Continue? (y/N)")
	if !confirmInspect(os.Stdin) {
		fmt.Fprintln(os.Stderr, "已取消，未执行任何深采。")
		return nil
	}

	// 目标级深采：仅 process 模块 + PID 过滤（runtime.Deep 授权）
	entityID := fmt.Sprintf("process_%d", *pid)
	rt := runtime.New(runtime.Deep)
	newCollector := func(history model.ProcessData) collector.Collector {
		return process.New(rt).WithPID(uint32(*pid)).WithExpectedIdentity(history)
	}
	if _, err := inspectProcess(db, *snapshotID, entityID, uint32(*pid), newCollector, *rulesDir); err != nil {
		return err
	}
	// Step 11.5：未采集到证据时，失败原因分类已在 inspectProcess 内输出，
	// 不再笼统报错"目标进程可能已退出"。
	return nil
}

// confirmInspect 读取 stdin 一行，仅 y/Y 返回 true（默认拒绝）。
func confirmInspect(r io.Reader) bool {
	reader := bufio.NewReader(r)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	return line == "y" || line == "Y"
}

// inspectProcess 执行目标级深采并重新分析：
//
//	Deep Collector（仅目标 PID）→ EntityUpdate 追加快照 → 整份快照重新分析
//	→ 展示目标实体最新线索 + 已获得/未获得证据。
//
// 返回 executed 表示是否采集到补充证据。Collector 可注入（测试用 fake）。
//
// Step 11.5/12.2：三种情况明确区分并输出 Status，绝不笼统报"目标进程可能已退出"：
//   - 情况 1：目标不存在（进程已退出/PID 已失效）→ 明确错误 + 既有线索引导
//   - 情况 2：目标存在但深采动作全部失败/被拒 → 精确分类（Access denied /
//     File not found / WinVerifyTrust failed / ...）+ 引导
//   - 情况 3：目标成功采集 → Status: succeeded + [✓] 已获得证据
//
// runPipelineSafely 给 inspect 的 pipeline 调用加 P3 保护。
//
// inspect 不经过 collectSteps，此前 pipeline.Run() 直接执行：采集器 panic 会终止
// 整个进程，卡死也没有超时。这里与 collect 的 runStep 保持同一语义：panic/超时都
// 转成显式错误，并丢弃无法安全中断的结果。
func runPipelineSafely(p *pipeline.Pipeline, timeout time.Duration) (*pipeline.Result, bool, error) {
	if p == nil {
		return nil, false, fmt.Errorf("pipeline 为空")
	}
	type outcome struct {
		res *pipeline.Result
		ok  bool
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				done <- outcome{err: fmt.Errorf("采集 panic 已被拦截: %v", rec)}
			}
		}()
		res, ok := p.Run()
		done <- outcome{res: res, ok: ok}
	}()
	select {
	case o := <-done:
		return o.res, o.ok, o.err
	case <-time.After(timeout):
		return nil, false, fmt.Errorf("超过采集超时上限 %s，结果丢弃", timeout)
	}
}

func inspectProcess(db *storage.DB, snapshotID, entityID string, pid uint32, newCollector func(model.ProcessData) collector.Collector, rulesDir string) (bool, error) {
	history, err := inspectHistory(db, snapshotID, entityID, pid)
	if err != nil {
		return false, err
	}
	if newCollector == nil {
		return false, fmt.Errorf("未配置目标采集器")
	}
	c := newCollector(history)
	if c == nil {
		return false, fmt.Errorf("目标采集器为空")
	}
	res, _, runErr := runPipelineSafely(pipeline.New(c), stepTimeout)
	if runErr != nil {
		return false, fmt.Errorf("目标采集未完成（未保存补证）: %w", runErr)
	}
	if res == nil {
		return false, fmt.Errorf("目标采集返回空结果（未保存补证）")
	}
	for _, st := range res.Stats {
		if st.Err != nil {
			return false, fmt.Errorf("目标采集失败（未保存补证）: %s: %w", st.Name, st.Err)
		}
	}
	actual, err := processInResult(&res.Result, entityID)
	if err != nil {
		return false, err
	}
	if err := process.MatchInspectIdentity(history, actual); err != nil {
		return false, err
	}

	// 全部目标更新先校验/编码，再在短事务内追加，不能留下半批补证。
	added := map[string]string{}
	var rows []*storage.EntityUpdateRow
	newEvidenceUpdates := 0
	clearedSignature := false
	for _, u := range res.EntityUpdates {
		if u == nil {
			return false, fmt.Errorf("目标补证为空（未保存补证）")
		}
		if u.EntityID != entityID {
			continue
		}
		if err := protocol.ValidateEntityUpdate(u); err != nil {
			return false, err
		}
		data, err := marshalUpdateData(u.Data)
		if err != nil {
			return false, fmt.Errorf("补证编码失败（未保存补证）: %w", err)
		}
		rows = append(rows, &storage.EntityUpdateRow{
			SnapshotID: snapshotID, EntityID: u.EntityID, UpdateType: u.UpdateType,
			SchemaVersion: u.SchemaVersion, DataJSON: data,
			Timestamp: u.Timestamp.UTC().Format(time.RFC3339Nano),
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
		})
		observed := map[string]string{}
		collectAddedEvidence(observed, u.Data)
		if d, ok := u.Data.(model.ProcessEnrichmentData); ok && d.SignatureValid != nil {
			clearedSignature = clearedSignature || !*d.SignatureValid
			if !*d.SignatureValid && !inspectFieldFailed(res.DeepFailures, entityID, "signature_state") {
				observed["signature_state"] = "verification completed (not confirmed trusted)"
			}
		}
		if len(observed) > 0 {
			newEvidenceUpdates++
		}
		for k, v := range observed {
			added[k] = v
		}
	}
	if err := saveInspectUpdates(db, rows); err != nil {
		return false, err
	}
	if len(added) == 0 {
		fmt.Fprintln(os.Stdout, "Status: target found, no new evidence")
		fmt.Fprintln(os.Stdout, "目标进程存在，但未获得新的可用证据（动作失败、被拒或未执行）：")
		printInspectFailures(res.DeepFailures, entityID)
		if clearedSignature {
			fmt.Fprintln(os.Stdout, "已记录未确认的签名状态，不再沿用旧验签成功标记；这不代表深采成功。")
		}
		fmt.Fprintln(os.Stdout, "已获得的证据仍然有效（作为历史记录保留）；可运行 \"easytrace analyze\" 查看，确认权限后重试。")
		return false, nil
	}

	// 整份快照重新分析（Analyzer 合并视图）
	rules, _, err := loadRules(rulesDir)
	if err != nil {
		return true, fmt.Errorf("补充证据已保存，但规则加载失败: %w", err)
	}
	an, err := analyzer.NewAnalyzer(db, snapshotID, rules)
	if err != nil {
		return true, fmt.Errorf("补充证据已保存，但分析器初始化失败: %w", err)
	}
	results, err := an.AnalyzeWithContext()
	if err != nil {
		return true, fmt.Errorf("补充证据已保存，但重新分析失败: %w", err)
	}

	// 输出结果：目标实体最新线索 + 证据状态
	fmt.Fprintln(os.Stdout, "Deep inspection completed")
	fmt.Fprintln(os.Stdout)
	fmt.Fprintf(os.Stdout, "Target: %s (PID %d)\n", entityID, pid)
	fmt.Fprintln(os.Stdout, "Status: target found, deep collection succeeded")
	fmt.Fprintln(os.Stdout)
	fmt.Fprintf(os.Stdout, "Added evidence: %d item(s)\n\n", newEvidenceUpdates)
	for _, f := range deepEvidenceFields {
		if added[f.key] != "" {
			if f.key == "signature_state" {
				fmt.Fprintf(os.Stdout, "[✓] %s: %s\n", f.label, added[f.key])
			} else {
				fmt.Fprintf(os.Stdout, "[✓] %s\n", f.label)
			}
		}
	}
	if inspectFieldFailed(res.DeepFailures, entityID, "") || anyCriticalMissing(added) {
		fmt.Fprintln(os.Stdout)
		fmt.Fprintln(os.Stdout, "部分深采动作失败（已获得的证据仍然有效）：")
		printInspectFailures(res.DeepFailures, entityID)
	}
	fmt.Fprintln(os.Stdout)

	targetFound := false
	for _, r := range results {
		if r.Finding.EntityID == entityID {
			targetFound = true
			fmt.Fprintf(os.Stdout, "[%s]\n\n", severityLabel(r.Finding.Severity))
			fmt.Fprintln(os.Stdout, findingDetailText(r))
			fmt.Fprintln(os.Stdout, "-----------------")
			fmt.Fprintln(os.Stdout)
		}
	}
	if !targetFound {
		fmt.Fprintln(os.Stdout, "目标进程深采后未命中任何规则（补充证据已保存，可重新执行 analyze 查看全量线索）。")
	}
	return true, nil
}

// printInspectFailures 输出目标进程深采/元数据失败分类明细（Step 11.5：
// 替代笼统的"目标进程可能已退出"，精确到字段 + 原因）。
func printInspectFailures(failures []collector.DeepFailure, entityID string) {
	for _, f := range failures {
		if f.EntityID != entityID {
			continue
		}
		fmt.Fprintf(os.Stdout, "  [!] %s: %s", deepFieldLabel(f.Field), deepReasonLabel(f.Reason))
		if f.Detail != "" {
			fmt.Fprintf(os.Stdout, " (%s)", f.Detail)
		}
		fmt.Fprintln(os.Stdout)
	}
}

// deepFieldLabel 深采失败字段的人类可读标签。
func deepFieldLabel(field string) string {
	switch field {
	case "command_line":
		return "command line"
	case "hash_sha256":
		return "file hash"
	case "signature_state":
		return "signature"
	case "process_metadata":
		return "process metadata"
	}
	return field
}

// deepReasonLabel 深采失败原因的人类可读标签（Step 11.5：精确分类）。
func deepReasonLabel(reason string) string {
	switch reason {
	case collector.ReasonAccessDenied:
		return "Access denied"
	case collector.ReasonProcessExited:
		return "Process exited"
	case collector.ReasonQueryFailed:
		return "Query failed"
	case collector.ReasonFileNotFound:
		return "File not found"
	case collector.ReasonHashFailed:
		return "Hash failed"
	case collector.ReasonFileTooLarge:
		return "File too large (hash skipped)"
	case collector.ReasonWinVerifyTrustFail:
		return "WinVerifyTrust failed"
	case collector.ReasonAPIFailed:
		return "API failed"
	case collector.ReasonUnsafePath:
		return "Unsafe path (not a local regular file)"
	}
	return reason
}

// deepEvidenceFields 可展示的深采事实；前三项为关键字段，其余仍计入实际新增证据。
var deepEvidenceFields = []struct{ key, label string }{
	{"command_line", "command line"},
	{"hash_sha256", "file hash"},
	{"signature_state", "signature evidence"},
	{"parent_command_line", "parent command line"},
	{"last_write_time", "file last write time"},
}

var deepCriticalFields = deepEvidenceFields[:3]

// anyCriticalMissing 判断是否有深采关键字段未获得。
func anyCriticalMissing(added map[string]string) bool {
	for _, f := range deepCriticalFields {
		if added[f.key] == "" {
			return true
		}
	}
	return false
}

// marshalUpdateData 将 entity_update 的 Data 序列化为 JSON（与协议一致）。
func marshalUpdateData(data any) (string, error) {
	b, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil || fields == nil {
		return "", fmt.Errorf("补证 data 必须为非 null 对象")
	}
	return string(b), nil
}

// collectAddedEvidence 提取实际可用的补证（含非关键事实），不把状态清除计为成功。
// ProcessEnrichmentData 是唯一数据源（protocol 冻结，无动态字段）。
func collectAddedEvidence(added map[string]string, data any) {
	if d, ok := data.(model.ProcessEnrichmentData); ok {
		for _, f := range deepEvidenceFields {
			if s := enrichmentField(d, f.key); s != "" {
				added[f.key] = s
			}
		}
	}
}

// enrichmentField 从 ProcessEnrichmentData 提取指定 json 字段的字符串值。
func enrichmentField(d model.ProcessEnrichmentData, field string) string {
	switch field {
	case "command_line":
		return d.CommandLine
	case "hash_sha256":
		return d.HashSHA256
	case "parent_command_line":
		return d.ParentCommandLine
	case "last_write_time":
		return d.LastWriteTime
	case "signature_state":
		if d.SignatureValid != nil && *d.SignatureValid {
			return "trust verification passed"
		}
		if d.SignatureState == "present" || d.SignatureState == "missing" {
			return "PE signature directory " + d.SignatureState + " (not a trust verdict)"
		}
	}
	return ""
}
