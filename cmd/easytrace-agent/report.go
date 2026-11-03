package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"easytrace/internal/analyzer"
	"easytrace/internal/model"
	"easytrace/internal/storage"
	"easytrace/internal/timeline"
	"easytrace/internal/whitelist"
)

// runReport 处理 report 子命令（Step 10，替代 GUI 报告导出）：
//
//	easytrace report [--db <path>] [--snapshot <id>] [-r|--rules <dir>] [-o|--output <dir>] [-zip]
//
// 在输出目录（默认 report/）生成三个文件：
//   - report.html   人类可读 HTML 报告（纯模板，无 GUI）
//   - findings.json 机器可读线索数据（SIEM/归档）
//   - summary.txt   终端可读摘要
//
// 加 -zip 时另行生成 Incident_<YYYYMMDD>_<seq>.zip 事件调查包（一期）：
// 只含本快照范围的数据，见 incident.go。
//
// 内容：Host（hostname/OS/user/采集时间）、Collection（模块/实体/关系统计）、
// Findings 统计（HIGH/MEDIUM/LOW）与每条线索 Detail。措辞统一"调查线索"，
// 不使用"感染/木马/恶意程序"等定性词汇。Analyzer 只读，报告生成不采集。
func runReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	dbPath := fs.String("db", "easytrace.db", "SQLite 数据库路径")
	snapshotID := fs.String("snapshot", "", "要报告的快照 snapshot_id（默认最新快照）")
	rulesDir := fs.String("r", "", "规则目录；留空使用**内嵌规则包**（单 exe 即可用），指定则覆盖")
	fs.StringVar(rulesDir, "rules", "", "规则目录别名（-r 同义；留空用内嵌规则包）")
	outDir := fs.String("o", "report", "新建输出目录（已有目录会拒绝）")
	fs.StringVar(outDir, "output", "report", "新建输出目录别名（-o 同义，已有目录会拒绝）")
	zipFlag := fs.Bool("zip", false, "同时生成 Incident_<YYYYMMDD>_<seq>.zip 事件调查包")
	eventsDir := fs.String("events", "", "把该目录下的文件打包进事件包的 events/（配合 collect --evtx 生成的 events 目录；需同时使用 -zip）")
	evidenceDir := fs.String("evidence", "", "把该目录下的文件打包进事件包的 evidence/（配合 catch 生成的证据目录；需同时使用 -zip）")
	propagate := fs.Int("propagate", 0, "关联传导: 沿 spawn/launch/network_connect 最多扩散 N 跳（0=关闭）；传导项 rule_id 以 derived. 开头，不是独立检测")
	whitelistFile := fs.String("w", "", "白名单文件（默认与 --db 同目录的 "+whitelist.FileName+"）")
	fs.StringVar(whitelistFile, "whitelist", "", "-w 同义")
	noWhitelist := fs.Bool("no-whitelist", false, "忽略白名单（审计/复核用：把所有命中都报出来）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *eventsDir != "" && !*zipFlag {
		return fmt.Errorf("-events 需要同时使用 -zip：事件日志只能打包进事件包，不会单独输出")
	}
	if *evidenceDir != "" && !*zipFlag {
		return fmt.Errorf("-evidence 需要同时使用 -zip：痕迹留存产物只能打包进事件包，不会单独输出")
	}

	rules, rulesSource, err := loadRules(*rulesDir)
	if err != nil {
		return err
	}

	// 只读打开：report 只读取快照，不能建表、不能写 journal。
	db, err := storage.OpenReadOnly(*dbPath)
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
	}

	// Step 11.8：生成报告前提示敏感信息（stderr，不污染 stdout 的 JSON/文本输出）。
	// 仅提示不阻止；报告可能包含主机名/用户名/文件路径/进程信息，按内部安全流程保存。
	printReportNotice(os.Stderr)

	// 1) 分析（Analyzer 只读快照 + 规则）
	an, err := analyzer.NewAnalyzer(db, *snapshotID, rules)
	if err != nil {
		return err
	}
	results, err := an.AnalyzeWithContext()
	if err != nil {
		return err
	}
	// V0.3 关联传导（可选，默认关闭）：叠加 derived.* 提示；报告里以 rule_id 前缀区分。
	if *propagate > 0 {
		results, err = an.PropagateFindings(results, analyzer.PropagateOptions{Hops: *propagate})
		if err != nil {
			return err
		}
	}

	// 2) 收集报告数据
	meta, err := storage.GetSnapshot(db, *snapshotID)
	if err != nil {
		return err
	}
	if meta == nil {
		return fmt.Errorf("快照 %s 不存在", *snapshotID)
	}
	// 采集来源只读数据库旁的 sidecar；没有记录就显示“未记录”，绝不读取
	// 报告进程当前 Token 冒充采集时权限。sidecar 存在但非法/不匹配 → 显式失败。
	prov, err := loadCollectionProvenance(*dbPath, meta)
	if err != nil {
		return err
	}
	entities, err := storage.GetEntities(db, *snapshotID)
	if err != nil {
		return err
	}
	relations, err := storage.GetRelations(db, *snapshotID)
	if err != nil {
		return err
	}

	labels := entityLabels(entities)
	updatesByEntity, err := entityUpdatesByID(db, *snapshotID)
	if err != nil {
		return err
	}

	host := hostInfo(meta, entities)
	collection := collectionStats(entities, relations)
	findings := make([]reportFinding, 0, len(results))
	for _, r := range results {
		findings = append(findings, reportFinding{
			FindingID:   r.Finding.FindingID,
			RuleID:      r.Finding.RuleID,
			Severity:    severityLabel(r.Finding.Severity),
			Title:       r.Finding.Title,
			Description: r.Finding.Description,
			EntityID:    r.Finding.EntityID,
			Evidence:    r.Finding.Evidence,
			Context:     contextBrief(r.Context),
			Advice:      r.Finding.Advice,
		})
	}
	sort.Slice(findings, func(i, j int) bool {
		return sevRank(findings[i].Severity) < sevRank(findings[j].Severity)
	})
	allHigh, allMed, allLow := countSeverity(results)

	// 证据融合：用同一份快照里**已有的其它证据**把线索说得更直观（服务→运行进程、
	// 持久化→目标文件签名态/哈希）。查不到就什么都不加，绝不编造。
	fuseEvidence(findings, relations, updatesByEntity, labels, entityTypes(entities))

	// 白名单抑制（V1.0 设计项，见 docs/设计-白名单.md）：只影响**报告展示层**。
	// 被抑制的线索仍留在 findings.json 与快照里；人类可读摘要会单独说明抑制数量，
	// 且总数/严重度统计只按可见项计算，绝不把被抑制项混进正文计数。
	sup := suppressionStats{}
	if !*noWhitelist {
		wl, err := whitelist.Load(resolveWhitelistPath(*whitelistFile, *dbPath))
		if err != nil {
			return err
		}
		snapshotHost := strings.TrimSpace(meta.Hostname)
		if snapshotHost == "" {
			snapshotHost = strings.TrimSpace(host["hostname"])
		}
		byEntity := make(map[string]storage.EntityRow, len(entities))
		for _, e := range entities {
			byEntity[e.EntityID] = e
		}
		for i := range findings {
			var entityType, identity, evidenceHash string
			if row, ok := byEntity[findings[i].EntityID]; ok {
				entityType = row.EntityType
				identity, _ = whitelist.EntityIdentity(row.EntityType, row.DataJSON)
				evidenceHash = whitelist.EvidenceHashOf(row.DataJSON)
			}
			// 带主机/实体指纹的新条目必须与当前快照一致才抑制；旧条目
			// （这些字段为空）保持原语义。无法计算指纹时不会匹配带指纹的条目。
			if e, ok := wl.LookupScoped(findings[i].RuleID, findings[i].EntityID,
				entityType, snapshotHost, identity, evidenceHash); ok {
				findings[i].Suppressed = true
				findings[i].SuppressReason = e.Reason
				sup.add(findings[i].Severity)
			}
		}
	}
	// visible：报告正文/索引/摘要只列这些；findings 全集仍写进 findings.json。
	visible := make([]reportFinding, 0, len(findings))
	for _, f := range findings {
		if !f.Suppressed {
			visible = append(visible, f)
		}
	}
	high, med, low := countReportSeverity(visible)

	// 3) 输出三文件。报告目录必须是本次新建的目录，避免覆写已有报告。
	outputDir, err := ensureNewOutputDir(*outDir)
	if err != nil {
		return err
	}

	// 采集环境：只展示**采集时**写入 sidecar 的来源记录（非协议实体、非安全发现）。
	env := prov.environment()

	// 3a) findings.json
	fj := reportJSON{
		Snapshot:        meta.SnapshotID,
		CollectedAt:     meta.Timestamp,
		TimestampSource: prov.timeSourceEN(),
		Host:            host,
		Collection:      collection,
		Severity:        severityStats{High: allHigh, Medium: allMed, Low: allLow},
		Findings:        findings,
		Environment:     env,
	}
	jb, err := json.MarshalIndent(fj, "", "  ")
	if err != nil {
		return err
	}
	if err := writeNewOutputFile(filepath.Join(outputDir, "findings.json"), jb, 0o644); err != nil {
		return fmt.Errorf("写入 findings.json 失败: %w", err)
	}

	// 3b) summary.txt
	sum := buildSummaryText(meta, host, collection, high, med, low, visible, sup, rulesSource, prov)
	if err := writeNewOutputFile(filepath.Join(outputDir, "summary.txt"), []byte(sum), 0o644); err != nil {
		return fmt.Errorf("写入 summary.txt 失败: %w", err)
	}

	// 3c) report.html
	scores := entityScores(results, rules, labels, entityTypes(entities))

	// 时间线（V0.3，设计见 docs/设计-时间线.md）：**只随事件包（-zip）构建**，
	// 因此普通 report 的三文件保持逐字节不变。
	var tl *timeline.Result
	if *zipFlag {
		built, err := buildTimeline(db, meta, entities, updatesByEntity, prov)
		if err != nil {
			return fmt.Errorf("构建时间线失败: %w", err)
		}
		tl = &built
	}
	page := buildReportHTML(meta, host, collection, high, med, low, visible, prov, relations, labels, scores, tl, pidProcessNames(entities), sup)
	if err := writeNewOutputFile(filepath.Join(outputDir, "report.html"), []byte(page), 0o644); err != nil {
		return fmt.Errorf("写入 report.html 失败: %w", err)
	}

	// 3d) Incident 事件调查包（仅 -zip 时生成）
	var zipName string
	var zipEntries int
	if *zipFlag {
		entries, err := buildIncidentEntries(db, meta, page, string(jb), sum, *eventsDir, *evidenceDir, scores, *tl)
		if err != nil {
			return fmt.Errorf("生成事件调查包失败: %w", err)
		}
		zipName = incidentZipName(meta)
		if err := writeIncidentZip(filepath.Join(outputDir, zipName), entries, incidentModTime(meta)); err != nil {
			return fmt.Errorf("写入 %s 失败: %w", zipName, err)
		}
		zipEntries = len(entries)
	}

	fmt.Fprintln(os.Stdout, "Report generated:")
	fmt.Fprintln(os.Stdout)
	fmt.Fprintf(os.Stdout, "%s\n", *outDir)
	fmt.Fprintln(os.Stdout)
	fmt.Fprintf(os.Stdout, "  %-20s %d findings\n", "report.html", len(visible))
	fmt.Fprintf(os.Stdout, "  %-20s %d findings\n", "findings.json", len(findings))
	fmt.Fprintf(os.Stdout, "  %-20s %d lines\n", "summary.txt", strings.Count(sum, "\n"))
	fmt.Fprintf(os.Stdout, "  %-20s %s\n", "rules", rulesSource)
	if d := countDerived(results); d > 0 {
		fmt.Fprintf(os.Stdout, "  %-20s %d (derived, 非独立检测)\n", "propagated", d)
	}
	if zipName != "" {
		fmt.Fprintf(os.Stdout, "  %-20s %d rows\n", "timeline.csv", tl.Total)
		fmt.Fprintf(os.Stdout, "  %-20s %d entries\n", zipName, zipEntries)
	}
	return nil
}

// printReportNotice 输出报告敏感信息提示（Step 11.8）。
// 始终写 stderr：报告可能包含主机名/用户名/文件路径/进程信息，
// 提示用户按内部安全流程保存，不阻止生成。
func printReportNotice(w io.Writer) {
	fmt.Fprintln(w, "Notice:")
	fmt.Fprintln(w, "Report may contain sensitive host information,")
	fmt.Fprintln(w, "including process names, paths and user data.")
	fmt.Fprintln(w, "Handle exported reports appropriately.")
}

// reportFinding 报告中的单条线索（规则/实体/证据/上下文/建议）。
type reportFinding struct {
	FindingID   string              `json:"finding_id"`
	RuleID      string              `json:"rule_id"`
	Severity    string              `json:"severity"`
	Title       string              `json:"title"`
	Description string              `json:"description"`
	EntityID    string              `json:"entity_id"`
	Evidence    []string            `json:"evidence,omitempty"`
	Context     map[string][]string `json:"context,omitempty"`
	Advice      []string            `json:"advice,omitempty"`

	// Fused 是**由同一份快照的其它证据融合而来**的补充事实（见 fuseEvidence）。
	// 单独一个字段而不是塞进 Evidence：来源不同（Evidence 是规则命中时的原始证据），
	// 机器可读输出（findings.json）里也要能区分。
	Fused []string `json:"fused_evidence,omitempty"`

	// Suppressed 表示这条命中已被白名单抑制（V1.0 设计项，见 docs/设计-白名单.md）。
	// **被抑制不等于被删除**：条目仍留在 findings.json 与快照里，只是不再出现在报告正文与索引中。
	Suppressed     bool   `json:"suppressed,omitempty"`
	SuppressReason string `json:"suppress_reason,omitempty"`
}

// reportJSON findings.json 结构。
type reportJSON struct {
	Snapshot string `json:"snapshot"`
	// CollectedAt 保留既有键名以兼容机器消费者；它代表 snapshots.timestamp，
	// 不保证是采集时刻——必须同时看 timestamp_source。
	CollectedAt     string                `json:"collected_at"`
	TimestampSource string                `json:"timestamp_source"`
	Host            map[string]string     `json:"host"`
	Collection      map[string]int        `json:"collection"`
	Severity        severityStats         `json:"severity"`
	Findings        []reportFinding       `json:"findings"`
	Environment     collectionEnvironment `json:"environment,omitempty"`
}

type severityStats struct {
	High   int `json:"high"`
	Medium int `json:"medium"`
	Low    int `json:"low"`
}

// hostInfo 提取报告用主机信息（snapshot meta + host entity 数据）。
func hostInfo(meta *storage.SnapshotMeta, entities []storage.EntityRow) map[string]string {
	out := map[string]string{
		"hostname":  meta.Hostname,
		"os":        meta.OSVersion,
		"os_build":  "",
		"arch":      meta.Architecture,
		"user":      "",
		"collected": meta.Timestamp,
	}
	for _, e := range entities {
		if e.EntityType != "host" {
			continue
		}
		var d model.HostData
		if json.Unmarshal([]byte(e.DataJSON), &d) == nil {
			if d.OSBuild != "" {
				out["os_build"] = d.OSBuild
			}
			if d.Username != "" {
				out["user"] = d.Username
			}
		}
		break
	}
	if b := out["os_build"]; b != "" {
		out["os"] = out["os"] + " (Build " + b + ")"
	}
	return out
}

// collectionStats 统计采集范围（按实体类型计数 + 关系总数）。
func collectionStats(entities []storage.EntityRow, relations []storage.RelationRow) map[string]int {
	out := map[string]int{}
	for _, e := range entities {
		out[e.EntityType]++
	}
	out["relations"] = len(relations)
	return out
}

// contextBrief 从 FindingContext 提取报告摘要字段（避免原始 map 膨胀）。
func contextBrief(ctx *analyzer.FindingContext) map[string][]string {
	if ctx == nil {
		return nil
	}
	out := map[string][]string{}
	if ctx.Process != nil {
		var parts []string
		for _, k := range []string{"name", "pid", "path", "command_line"} {
			if v := ctx.Process[k]; v != "" {
				parts = append(parts, k+": "+v)
			}
		}
		if len(parts) > 0 {
			out["process"] = parts
		}
	}
	if ctx.Network != nil {
		parts := []string{
			"protocol: " + avail(ctx.Network, "protocol"),
			"local: " + endpointLabel(ctx.Network["local_ip"], ctx.Network["local_port"]),
			"state: " + avail(ctx.Network, "state"),
			"pid: " + avail(ctx.Network, "pid"),
		}
		if !strings.EqualFold(ctx.Network["state"], "LISTENING") &&
			(ctx.Network["remote_ip"] != "" || ctx.Network["remote_port"] != "") {
			parts = append(parts, "remote: "+endpointLabel(ctx.Network["remote_ip"], ctx.Network["remote_port"]))
		}
		out["network"] = parts
	}
	if ctx.EntityData != nil {
		keys := make([]string, 0, len(ctx.EntityData))
		for k := range ctx.EntityData {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, k+": "+ctx.EntityData[k])
		}
		if len(parts) > 0 {
			out["entity"] = parts
		}
	}
	if ctx.ParentProcess != nil && ctx.ParentProcess["name"] != "" {
		out["parent"] = []string{ctx.ParentProcess["name"]}
	}
	for _, c := range ctx.ChildProcesses {
		if c["name"] != "" {
			out["child"] = append(out["child"], c["name"]+" (PID "+c["pid"]+")")
		}
	}
	for _, n := range ctx.NetworkConns {
		out["network"] = append(out["network"], n["remote_ip"]+":"+n["remote_port"])
	}
	for _, p := range ctx.PersistenceRefs {
		out["persistence"] = append(out["persistence"], p["type"]+" — "+p["location"])
	}
	if len(ctx.MissingEvidence) > 0 {
		out["missing"] = ctx.MissingEvidence
	}
	return out
}

// reportEvidence 返回 report.html 的人工可读证据。findings.json 始终保留
// 原始 Evidence；监听网络实体的远端零值只是不适用于监听的 API 占位，不能在
// HTML 中被展示成实际远程连接。
func reportEvidence(f reportFinding) []string {
	if !isListeningNetworkTarget(f.Context) {
		return f.Evidence
	}

	out := make([]string, 0, len(f.Evidence))
	for _, line := range f.Evidence {
		if strings.HasPrefix(line, "network.remote_ip=") || strings.HasPrefix(line, "network.remote_port=") {
			continue
		}
		out = append(out, line)
	}
	return out
}

func isListeningNetworkTarget(ctx map[string][]string) bool {
	for _, line := range ctx["network"] {
		if strings.EqualFold(strings.TrimSpace(line), "state: LISTENING") {
			return true
		}
	}
	return false
}

// sevRank 严重程度排序权重（越小越靠前）。
func sevRank(s string) int {
	switch s {
	case "CRITICAL", "HIGH":
		return 1
	case "MEDIUM":
		return 2
	}
	return 3
}

// 实体风险评分（协议 v0.1 §3「实体中心风险评分模型」）。
//
//   - 不评"事件"评"实体"：分数挂在 finding 的主挂载实体上
//   - 同一实体多条 finding **累加**，但同一规则只算一次（去重）
//   - 单条分值取规则的 score；未声明时按 severity 推导默认分
//   - 等级与判定按协议 §3.3 阈值
//
// 只读派生：分数不落库、不进协议（SQLite schema 与协议 v0.2 均冻结）。
// 关联传导（子进程高分按 0.5 传导给父进程）属 V0.3，未实现。

// maxEntityScores 是"实体风险概览"最多渲染的实体数（按分数降序）。
//
// 2026-10-14 可读性复盘：真实采集有 48 个实体带分数，全渲染 12KB，属于"数据附录"
// 而非正文。表格只保留头部，完整分数见事件包 entity_scores.csv。
const maxEntityScores = 20

// severityDefaultScore 是规则未声明 score 时的默认分值。
// 取值使协议 §3.3 的阈值有意义：一条 low→低、一条 medium→中、
// 一条 high→高（≥20）、三条 high→严重（≥50）。
func severityDefaultScore(sev string) int {
	switch strings.ToUpper(sev) {
	case "CRITICAL", "HIGH":
		return 20
	case "MEDIUM":
		return 10
	case "LOW":
		return 1
	}
	return 0
}

// scoreLevel 按协议 §3.3 把分数映射为等级。
func scoreLevel(score int) string {
	switch {
	case score >= 50:
		return "严重"
	case score >= 20:
		return "高"
	case score >= 5:
		return "中"
	}
	return "低"
}

// scoreVerdict 按协议 §3.3：≥50 malicious、≥20 suspicious、否则 unknown。
func scoreVerdict(score int) string {
	switch {
	case score >= 50:
		return "malicious"
	case score >= 20:
		return "suspicious"
	}
	return "unknown"
}

// entityScore 是单个实体的聚合风险分。
type entityScore struct {
	EntityID     string
	EntityType   string
	Label        string
	Score        int
	Level        string
	Verdict      string
	FindingCount int
	Rules        []string
}

// entityScores 聚合实体风险分。结果按分数降序、同分按 entity_id 升序（保证确定性）。
func entityScores(results []*analyzer.AnalysisResult, rules []*analyzer.Rule, labels, types map[string]string) []entityScore {
	ruleScore := make(map[string]int, len(rules))
	for _, rl := range rules {
		s := rl.Score
		if s == 0 {
			s = severityDefaultScore(rl.Severity)
		}
		ruleScore[rl.RuleID] = s
	}
	type agg struct {
		score int
		count int
		seen  map[string]bool
		rules []string
	}
	byEntity := map[string]*agg{}
	for _, res := range results {
		if res.Finding == nil || res.Finding.EntityID == "" {
			continue
		}
		eid := res.Finding.EntityID
		a := byEntity[eid]
		if a == nil {
			a = &agg{seen: map[string]bool{}}
			byEntity[eid] = a
		}
		a.count++
		if a.seen[res.Finding.RuleID] {
			continue // 同一规则只算一次
		}
		a.seen[res.Finding.RuleID] = true
		a.rules = append(a.rules, res.Finding.RuleID)
		score, known := ruleScore[res.Finding.RuleID]
		if !known && strings.HasPrefix(res.Finding.RuleID, analyzer.DerivedRulePrefix) {
			// 传导提示没有对应规则：按其（已衰减一级的）严重度计分；rule_id 仍保留 derived.*
			// 前缀，报告与 entity_scores.csv 里可以一眼区分"直接命中"与"传导推断"。
			score = severityDefaultScore(res.Finding.Severity)
		}
		a.score += score
	}
	out := make([]entityScore, 0, len(byEntity))
	for eid, a := range byEntity {
		sort.Strings(a.rules)
		out = append(out, entityScore{
			EntityID: eid, EntityType: types[eid], Label: labels[eid],
			Score: a.score, Level: scoreLevel(a.score), Verdict: scoreVerdict(a.score),
			FindingCount: a.count, Rules: a.rules,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].EntityID < out[j].EntityID
	})
	return out
}

// entityTypes 生成 entity_id → entity_type 的映射。
func entityTypes(entities []storage.EntityRow) map[string]string {
	out := make(map[string]string, len(entities))
	for _, e := range entities {
		out[e.EntityID] = e.EntityType
	}
	return out
}

// maxSummaryFindings 是摘要区块里"先看这几条"最多列出的线索数。
const maxSummaryFindings = 10

// suppressionStats 是被白名单抑制的线索数量（按严重度拆分）。
// 人类可读摘要按**可见项**计数；抑制项只在这个独立统计里出现。
type suppressionStats struct {
	Total int
	High  int
	Med   int
	Low   int
}

func (s *suppressionStats) add(severity string) {
	s.Total++
	switch severity {
	case "CRITICAL", "HIGH":
		s.High++
	case "MEDIUM":
		s.Med++
	default:
		s.Low++
	}
}

// countReportSeverity 统计 reportFinding 的严重度（可见项计数用）。
func countReportSeverity(findings []reportFinding) (high, med, low int) {
	for _, f := range findings {
		switch f.Severity {
		case "CRITICAL", "HIGH":
			high++
		case "MEDIUM":
			med++
		default:
			low++
		}
	}
	return
}

// writeSummarySection 输出「摘要」——**给第一次读这份报告的人**。
//
// 由来（2026-10-15 反馈："这个 report 第一次发给别人，别人能看懂吗？"）：原报告一上来是
// 工具名 + 一串快照 ID + 四个数字，读者不知道"这是什么、机器有没有事、我该做什么、
// 能不能当结论用"。本区块用自然语言把这四件事说完，正文再给证据。
// 顺序刻意如此：**先给结论与边界，再给数字与明细**。
func writeSummarySection(sb *strings.Builder, host map[string]string,
	groups []findingGroup, high, med, low int, hasTimeline bool, sup suppressionStats,
	prov *collectionProvenance) {

	total := 0
	for _, g := range groups {
		total += len(g.Members)
	}
	hostname := host["hostname"]
	if hostname == "" {
		hostname = "（未采到主机名）"
	}

	type picked struct {
		anchor int
		g      findingGroup
	}
	var urgent []picked
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM"} {
		for i, g := range groups {
			if g.Severity == sev {
				urgent = append(urgent, picked{i + 1, g})
			}
		}
	}

	sb.WriteString("<section class=\"panel\">\n<h2>摘要 <span class=\"en\">Summary</span></h2>\n")

	// 摘要正文：**一整段**。
	//
	// 使用反馈（2026-10-15）：拆成"说明 + 要不要处理结论框 + 边界小字"三段显得零碎，
	// 要求连成一段、并去掉结论框。于是结论句与判断边界都并入同一段。
	urgentCount := 0
	for _, u := range urgent {
		urgentCount += len(u.g.Members)
	}
	var prose strings.Builder
	prose.WriteString("本次在主机 <b>" + html.EscapeString(hostname) + "</b>")
	if osName := host["os"]; osName != "" {
		prose.WriteString("（" + html.EscapeString(osName) + "）")
	}
	prose.WriteString(" 上做了一次<b>只读</b>采集，" + html.EscapeString(prov.timeSentence()) +
		"。共命中 " + fmt.Sprintf("%d", total) + " 条调查线索：高 " + fmt.Sprintf("%d", high) +
		" / 中 " + fmt.Sprintf("%d", med) + " / 低 " + fmt.Sprintf("%d", low) + "——")
	if urgentCount == 0 {
		prose.WriteString("<b>没有高/中优先级线索，本次没有需要立即处置的项目</b>；低优先级 " +
			fmt.Sprintf("%d", total) + " 条来自 " + fmt.Sprintf("%d", len(groups)) +
			" 条规则，属于\"值得核对\"的事实（例如对外监听的端口、从用户目录启动的进程），" +
			"<b>不代表主机已被入侵</b>。")
	} else {
		prose.WriteString("<b>其中 " + fmt.Sprintf("%d", urgentCount) + " 条为高/中优先级，建议优先核对</b>（见下方列表）。")
	}
	if sup.Total > 0 {
		// 抑制必须可见：读者要知道“报告正文之外还有几条、为什么少”。
		// 注意：正文的 total/high/med/low 都是可见项计数，因此这里用“另有”，
		// 不能写成“其中”（否则数字对不上）。
		prose.WriteString("<b>另有 " + fmt.Sprintf("%d", sup.Total) +
			" 条已按白名单抑制</b>（高 " + fmt.Sprintf("%d", sup.High) +
			" / 中 " + fmt.Sprintf("%d", sup.Med) + " / 低 " + fmt.Sprintf("%d", sup.Low) +
			"；已人工确认属正常业务，理由见白名单文件）；这些条目仍完整保留在 findings.json 与快照里。")
	}
	prose.WriteString("本报告只列出本地规则在本次采集数据上命中的事实，不做定性；" +
		"规则未命中不等于没有问题，请结合现场情况与其它证据判断。")
	sb.WriteString("<p class=\"prose\">" + prose.String() + "</p>\n")

	// 有高/中优先级线索时，摘要里给出可点跳转的清单（最多 maxSummaryFindings 条）。
	if len(urgent) > 0 {
		shown := urgent
		if len(shown) > maxSummaryFindings {
			shown = shown[:maxSummaryFindings]
		}
		sb.WriteString("<ol class=\"prio\">\n")
		for _, u := range shown {
			sb.WriteString("<li><span class=\"badge badge-" + severityClass(u.g.Severity) + "\">" +
				html.EscapeString(strings.ToLower(u.g.Severity)) + "</span> " +
				"<a href=\"#f-" + fmt.Sprintf("%d", u.anchor) + "\">" + html.EscapeString(u.g.Title) + "</a>")
			if len(u.g.Members) > 1 {
				sb.WriteString(" <span class=\"en\">" + fmt.Sprintf("%d 处", len(u.g.Members)) + "</span>")
			}
			sb.WriteString("</li>\n")
		}
		sb.WriteString("</ol>\n")
		if len(urgent) > len(shown) {
			sb.WriteString("<p class=\"note\">另有 " + fmt.Sprintf("%d", len(urgent)-len(shown)) +
				" 条规则的高/中优先级线索见下方「调查线索」。</p>\n")
		}
	}
	sb.WriteString("</section>\n")
}

// writeCollectionAppendix 输出附录「采集范围与环境」。
//
// 这两块是**给分析员核对采集完整性**用的（"driver 294 条"对普通读者是噪音），
// 因此从正文移到这里，并在标题上写明是附录。
func writeCollectionAppendix(sb *strings.Builder, meta *storage.SnapshotMeta,
	collection map[string]int, prov *collectionProvenance) {

	writeSectionOpen(sb, "sec-collection", "附录：采集范围与环境", "Collection Environment", false)
	sb.WriteString("<p class=\"note\">本区块供分析员核对采集完整性，普通读者可略过。" +
		"采集是<b>只读</b>的：不修改系统、不联网、不执行外部程序。</p>\n")

	sb.WriteString("<span class=\"block-label\">本次采到的实体数 <span class=\"en\">Entities by type</span></span>\n<ul class=\"chips\">\n")
	var types []string
	for t := range collection {
		types = append(types, t)
	}
	sort.Strings(types)
	for _, t := range types {
		name := collectionLabels[t]
		if name == "" {
			name = t
		}
		sb.WriteString("<li><span>" + html.EscapeString(name) + "</span>")
		if name != t {
			sb.WriteString("<span class=\"en\">" + html.EscapeString(t) + "</span>")
		}
		sb.WriteString("<span class=\"n\">" + fmt.Sprintf("%d", collection[t]) + "</span></li>\n")
	}
	sb.WriteString("</ul>\n")

	sb.WriteString("<dl class=\"kv\">\n")
	sb.WriteString("<div><dt>快照 ID <span class=\"en\">Snapshot:</span></dt><dd><code>" +
		html.EscapeString(meta.SnapshotID) + "</code></dd></div>\n")
	sb.WriteString("<div><dt>" + html.EscapeString(prov.timeLabel()) +
		" <span class=\"en\">Snapshot timestamp:</span></dt><dd>" +
		html.EscapeString(prov.timestamp()) + "（UTC；" + html.EscapeString(prov.timeNote()) +
		"）</dd></div>\n")
	sb.WriteString("<div><dt>时间来源 <span class=\"en\">Timestamp source:</span></dt><dd><code>" +
		html.EscapeString(prov.timeSourceEN()) + "</code></dd></div>\n")
	if v := prov.collectionStartedAt(); v != "" {
		sb.WriteString("<div><dt>采集开始 <span class=\"en\">Collection started:</span></dt><dd>" +
			html.EscapeString(v) + "</dd></div>\n")
	}
	if v := prov.collectionFinishedAt(); v != "" {
		sb.WriteString("<div><dt>采集结束 <span class=\"en\">Collection finished:</span></dt><dd>" +
			html.EscapeString(v) + "</dd></div>\n")
	}
	sb.WriteString("<div><dt>运行权限 <span class=\"en\">Run privilege:</span></dt><dd>管理员权限：<b>" +
		prov.privilegeZh() + "</b> <span class=\"en\">Administrator elevated: " +
		prov.privilegeEN() + "</span></dd></div>\n")
	sb.WriteString("<div><dt>权限来源 <span class=\"en\">Privilege source:</span></dt><dd><code>" +
		html.EscapeString(prov.Privilege.Source) + "</code></dd></div>\n")
	sb.WriteString("</dl>\n")
	if !prov.privilegeKnown() {
		sb.WriteString("<p class=\"note\"><b>采集权限未记录</b>：本快照没有采集时写入的权限记录" +
			"（旧版本产物或外部导入）。报告<b>不会</b>用生成报告时的进程权限代替采集时权限；" +
			"如需据此判断采集完整性，请补充采集时的 sidecar 或用相同权限重新采集。</p>\n")
	} else if !prov.elevated() {
		sb.WriteString("<p class=\"note\"><b>非管理员采集的影响</b>：计划任务、服务细节、" +
			"受保护进程信息可能采不全（采集器会如实标注失败，不会伪造空结果）。" +
			"应急响应场景建议以管理员身份重新采集。</p>\n")
	}
	sb.WriteString("<p class=\"note\"><b>术语</b>：<b>快照</b>＝某一时刻采集到的主机状态记录；" +
		"<b>实体</b>＝被观察的对象（进程／服务／启动项／网络连接／文件／注册表值等）；" +
		"<b>线索</b>＝一条规则在某个实体上命中的事实组合；" +
		"<b>severity</b>＝规则声明的严重程度（高／中／低）。<b>时间一律用 UTC</b>（比北京时间晚 8 小时）。</p>\n")
	writeSectionClose(sb)
}

// writeSectionOpen / writeSectionClose 输出**可折叠**区块（原生 `<details>`）。
//
// 为什么用 <details>：项目约束是"单文件、无 JavaScript"，而 <details> 是浏览器原生折叠，
// 键盘可用、零脚本依赖。默认开合由调用方决定：正文（主机/线索）默认展开，
// 数据附录（风险分 / 关系 / 时间线 / 采集范围）默认折叠。
// 打印注意：closed 的 <details> 内容默认不打印，reportCSS 里已用 @media print 强制展开。
func writeSectionOpen(sb *strings.Builder, id, zh, en string, open bool) {
	sb.WriteString("<details class=\"panel\" id=\"" + id + "\"")
	if open {
		sb.WriteString(" open")
	}
	sb.WriteString(">\n<summary><h2>" + html.EscapeString(zh) +
		" <span class=\"en\">" + html.EscapeString(en) + "</span></h2></summary>\n<div class=\"sec-body\">\n")
}

func writeSectionClose(sb *strings.Builder) { sb.WriteString("</div>\n</details>\n") }

// writeEntityScoreSection 输出"实体风险概览"区块（纯模板、无 JavaScript）。
func writeEntityScoreSection(sb *strings.Builder, scores []entityScore) {
	if len(scores) == 0 {
		return
	}
	writeSectionOpen(sb, "sec-scores", "实体风险概览", "Entity risk", false)
	sb.WriteString("<p class=\"prose\">共 " + fmt.Sprintf("%d", len(scores)) +
		" 个实体有风险分（同一规则只计一次，多条线索累加）</p>\n")
	// 显式列宽：table-layout:fixed 下若不给列宽，7 列会被**平均分配**，
	// 结果"实体/规则"这种长内容列被挤窄（规则名折成 process.user_pa th.executable），
	// 而"分数/等级"空得太大——看起来就是没对齐（2026-10-15 反馈）。
	sb.WriteString("<table class=\"scores\">\n" +
		"<colgroup><col style=\"width:19%\"><col style=\"width:12%\"><col style=\"width:6%\">" +
		"<col style=\"width:6%\"><col style=\"width:12%\"><col style=\"width:6%\">" +
		"<col style=\"width:39%\"></colgroup>\n" +
		"<thead><tr><th>实体</th><th>类型</th><th class=\"num\">分数</th><th>等级</th>" +
		"<th>判定</th><th class=\"num\">线索</th><th>规则</th></tr></thead>\n<tbody>\n")
	shown := scores
	if len(shown) > maxEntityScores {
		shown = shown[:maxEntityScores]
	}
	for _, s := range shown {
		sb.WriteString("<tr><td><b>" + html.EscapeString(s.Label) + "</b><br><code>" +
			html.EscapeString(s.EntityID) + "</code></td>")
		sb.WriteString("<td>" + html.EscapeString(s.EntityType) + "</td>")
		sb.WriteString("<td class=\"num\">" + fmt.Sprintf("%d", s.Score) + "</td>")
		sb.WriteString("<td><span class=\"badge badge-" + scoreLevelClass(s.Level) + "\">" +
			html.EscapeString(s.Level) + "</span></td>")
		sb.WriteString("<td>" + html.EscapeString(s.Verdict) + "</td>")
		sb.WriteString("<td class=\"num\">" + fmt.Sprintf("%d", s.FindingCount) + "</td>")
		sb.WriteString("<td><code>" + html.EscapeString(strings.Join(s.Rules, " ")) + "</code></td></tr>\n")
	}
	sb.WriteString("</tbody></table>\n")
	if len(scores) > len(shown) {
		sb.WriteString("<p class=\"note\">仅显示分数最高的前 " + fmt.Sprintf("%d", len(shown)) +
			" 个实体（共 " + fmt.Sprintf("%d", len(scores)) + " 个）。</p>\n")
	}
	sb.WriteString("<p class=\"note\">分值为规则声明的 <code>score</code>；未声明时按严重程度默认（low=1 / medium=10 / high=20）。" +
		"等级与判定按协议 v0.1 §3.3；关联传导属 V0.3，未实现。</p>\n")
	writeSectionClose(sb)
}

// scoreLevelClass 把中文等级映射为已有徽章配色令牌（白名单映射，不拼接原始文本）。
func scoreLevelClass(level string) string {
	switch level {
	case "严重":
		return "critical"
	case "高":
		return "high"
	case "中":
		return "medium"
	}
	return "low"
}

// maxRelationRows 是报告里**每类**关系最多渲染的条数。
//
// 2026-10-14 可读性复盘：实测本机 797 条关系（spawn 341 / network_connect 375 / launch 161），
// 按 200/类 渲染出来是 **63KB、559 条 <li>，占整页 32%** —— 这是"报告东西太多"的最大来源。
// HTML 是给人看的摘要，不是数据导出：每类只留头部 30 条，完整数据见事件包 relations.csv 或快照数据库。
const maxRelationRows = 30

// relationTypeLabel 是关系类型的中文名。
var relationTypeLabel = map[string]string{
	"spawn":           "父子进程",
	"launch":          "服务启动进程",
	"network_connect": "网络连接",
	"parent_child":    "父子关系",
}

// entityLabels 生成 entity_id → 简短可读标签的映射，供攻击链渲染使用。
// 解析失败或字段为空时退回 entity_id——不伪造名称，也不留空标签。
func entityLabels(entities []storage.EntityRow) map[string]string {
	labels := make(map[string]string, len(entities))
	for _, e := range entities {
		labels[e.EntityID] = entityLabel(e)
	}
	return labels
}

// formatAddr 把地址与端口拼成 "host:port"，IPv6 地址加方括号。
//
// 不加方括号时 IPv6 会被拼成 ":::135"（"::" + ":" + 端口），既难读、又会与上下文里
// 规范写法 "[::]:135" 不一致，导致"标签里已显示"的判重失效、同一件事在表里出现两列
// （2026-10-15 实测：IPv6 监听行多出一个「本地」列）。
func formatAddr(ip string, port uint16) string {
	if strings.Contains(ip, ":") {
		return "[" + ip + "]:" + fmt.Sprintf("%d", port)
	}
	return ip + ":" + fmt.Sprintf("%d", port)
}

// entityLabel 为单个实体生成简短标签。
func entityLabel(e storage.EntityRow) string {
	switch e.EntityType {
	case "process":
		var d model.ProcessData
		if json.Unmarshal([]byte(e.DataJSON), &d) == nil && d.Name != "" {
			return fmt.Sprintf("%s (%d)", d.Name, d.PID)
		}
	case "service":
		var d model.ServiceData
		if json.Unmarshal([]byte(e.DataJSON), &d) == nil && d.ServiceName != "" {
			return d.ServiceName
		}
	case "persistence":
		var d model.PersistenceData
		if json.Unmarshal([]byte(e.DataJSON), &d) == nil && d.Name != "" {
			return d.Name
		}
	case "task":
		var d model.TaskData
		if json.Unmarshal([]byte(e.DataJSON), &d) == nil && d.TaskName != "" {
			return d.TaskName
		}
	case "network":
		var d model.NetworkData
		if json.Unmarshal([]byte(e.DataJSON), &d) == nil {
			return fmt.Sprintf("%s %s → %s", d.Protocol,
				formatAddr(d.LocalIP, d.LocalPort), formatAddr(d.RemoteIP, d.RemotePort))
		}
	case "user":
		var d model.UserData
		if json.Unmarshal([]byte(e.DataJSON), &d) == nil && d.Username != "" {
			return d.Username
		}
	case "host":
		var d model.HostData
		if json.Unmarshal([]byte(e.DataJSON), &d) == nil && d.Hostname != "" {
			return d.Hostname
		}
	case "file":
		// 文件实体没有天然短名，用文件名；否则标签会退化成 file_<hash>_<seq> 这种无意义 ID。
		var d model.FileData
		if json.Unmarshal([]byte(e.DataJSON), &d) == nil && d.Path != "" {
			if base := filepath.Base(filepath.FromSlash(strings.ReplaceAll(d.Path, `\`, "/"))); base != "" && base != "." {
				return base
			}
			return d.Path
		}
	case "prefetch":
		// .pf 头里的可执行文件名就是最能说明"这是什么程序"的短标签。
		var d model.PrefetchData
		if json.Unmarshal([]byte(e.DataJSON), &d) == nil && d.ExecutableName != "" {
			return d.ExecutableName
		}
	case "execution":
		// 标签只放最能说明"这是什么"的一项：文件名 > 路径文件名 > 命令前 80 字符。
		var d model.ExecutionData
		if json.Unmarshal([]byte(e.DataJSON), &d) == nil {
			if d.Name != "" {
				return d.Name
			}
			if d.Path != "" {
				if base := filepath.Base(filepath.FromSlash(strings.ReplaceAll(d.Path, `\`, "/"))); base != "" && base != "." {
					return base
				}
			}
			if d.Command != "" {
				return clipRunes(d.Command, 80)
			}
		}
	}
	return e.EntityID
}

// relationCommand 从 relation 的 attrs_json 取 spawn 关系的子进程命令行（取不到返回空）。
func relationCommand(attrsJSON string) string {
	if attrsJSON == "" {
		return ""
	}
	var attrs map[string]any
	if json.Unmarshal([]byte(attrsJSON), &attrs) != nil {
		return ""
	}
	if v, ok := attrs["command"].(string); ok {
		return v
	}
	return ""
}

// writeRelationsSection 输出"关系与攻击链"区块（纯模板、无 JavaScript）。
//
// 每类关系按 relation_id 排序后最多渲染 maxRelationRows 条，超出时注明截断，
// 并指向事件包内的 relations.csv 以获取完整数据。
func writeRelationsSection(sb *strings.Builder, relations []storage.RelationRow, labels map[string]string) {
	if len(relations) == 0 {
		return
	}
	grouped := map[string][]storage.RelationRow{}
	for _, rel := range relations {
		grouped[rel.RelationType] = append(grouped[rel.RelationType], rel)
	}
	types := make([]string, 0, len(grouped))
	for t := range grouped {
		types = append(types, t)
	}
	sort.Strings(types)

	writeSectionOpen(sb, "sec-relations", "关系与攻击链", "Relations", false)
	sb.WriteString("<p class=\"lede\">共 " + fmt.Sprintf("%d", len(relations)) + " 条关系")
	for _, t := range types {
		sb.WriteString("<span class=\"pill\">" + html.EscapeString(relationDisplayName(t)) + " " +
			fmt.Sprintf("%d", len(grouped[t])) + "</span>")
	}
	sb.WriteString("</p>\n")

	for _, t := range types {
		rows := grouped[t]
		sort.Slice(rows, func(i, j int) bool { return rows[i].RelationID < rows[j].RelationID })
		shown := rows
		if len(shown) > maxRelationRows {
			shown = shown[:maxRelationRows]
		}
		sb.WriteString("<div class=\"block\">\n<span class=\"block-label\">" + html.EscapeString(relationDisplayName(t)) +
			" <span class=\"en\">" + html.EscapeString(t) + "</span></span>\n<ul class=\"chain\">\n")
		for _, rel := range shown {
			src := labels[rel.SourceID]
			if src == "" {
				src = rel.SourceID
			}
			dst := labels[rel.TargetID]
			if dst == "" {
				dst = rel.TargetID
			}
			sb.WriteString("<li><span class=\"chain-edge\"><code>" + html.EscapeString(src) +
				"</code> → <code>" + html.EscapeString(dst) + "</code></span>")
			if cmd := relationCommand(rel.AttrsJSON); cmd != "" {
				sb.WriteString("<span class=\"chain-cmd\">" + html.EscapeString(cmd) + "</span>")
			}
			sb.WriteString("</li>\n")
		}
		sb.WriteString("</ul>\n")
		if len(rows) > len(shown) {
			sb.WriteString("<p class=\"note\">仅显示前 " + fmt.Sprintf("%d", len(shown)) + " 条（共 " +
				fmt.Sprintf("%d", len(rows)) + " 条）；完整关系见事件包内的 relations.csv，或快照数据库的 relations 表。</p>\n")
		}
		sb.WriteString("</div>\n")
	}
	writeSectionClose(sb)
}

// relationDisplayName 返回关系类型的中文显示名（未登记时退回原始类型名）。
func relationDisplayName(t string) string {
	if name := relationTypeLabel[t]; name != "" {
		return name
	}
	return t
}

// buildSummaryText 生成 summary.txt（终端可读）。
func buildSummaryText(meta *storage.SnapshotMeta, host map[string]string, collection map[string]int, high, med, low int, findings []reportFinding, sup suppressionStats, rulesSource string, prov *collectionProvenance) string {
	var sb strings.Builder
	sb.WriteString("Easy_Trace Report\n")
	sb.WriteString("Easy_Trace 应急响应报告\n")
	sb.WriteString("================\n\n")
	sb.WriteString("主机信息 Host:\n")
	for _, k := range []string{"hostname", "os", "os_build", "arch", "user", "collected"} {
		if host[k] != "" {
			label := hostLabels[k]
			if k == "collected" {
				// 快照时间戳不一定是采集时刻：必须按真实来源命名。
				label = prov.timeLabel()
			} else if label == "" {
				label = k
			}
			sb.WriteString("  " + label + " " + k + ": " + host[k] + "\n")
		}
	}
	sb.WriteString("  时间来源 timestamp_source: " + prov.timeSourceEN() + "\n")
	sb.WriteString("\n采集范围 Collection:\n")
	var types []string
	for t := range collection {
		types = append(types, t)
	}
	sort.Strings(types)
	for _, t := range types {
		name := collectionLabels[t]
		if name == "" {
			name = t
		}
		sb.WriteString(fmt.Sprintf("  %-24s %d\n", name+" "+t, collection[t]))
	}
	sb.WriteString("\n规则来源 Rules source: " + rulesSource + "\n")
	writeEnvironmentText(&sb, prov)
	sb.WriteString("调查线索 Findings: " + fmt.Sprintf("%d", len(findings)) + "\n")
	sb.WriteString("严重程度 Severity:\n")
	sb.WriteString(fmt.Sprintf("  高 HIGH:     %d\n", high))
	sb.WriteString(fmt.Sprintf("  中 MEDIUM:   %d\n", med))
	sb.WriteString(fmt.Sprintf("  低 LOW:      %d\n", low))
	if sup.Total > 0 {
		sb.WriteString(fmt.Sprintf("已抑制 Suppressed: %d（高 %d / 中 %d / 低 %d；仍保留在 findings.json 与快照）\n",
			sup.Total, sup.High, sup.Med, sup.Low))
	}
	sb.WriteString("\n")
	for _, f := range findings {
		sb.WriteString("[" + f.Severity + "] " + f.Title + "\n")
		sb.WriteString("  规则 rule:      " + f.RuleID + "\n")
		sb.WriteString("  实体 entity:    " + f.EntityID + "\n")
		if f.Description != "" {
			sb.WriteString("  描述 desc:      " + f.Description + "\n")
		}
		if len(f.Advice) > 0 {
			sb.WriteString("  建议 advice:    " + strings.Join(f.Advice, "；") + "\n")
		}
		sb.WriteString("\n")
	}
	if len(findings) == 0 {
		if sup.Total > 0 {
			sb.WriteString("报告正文没有未抑制的线索；被抑制条目仍保留在 findings.json 与快照里。\n")
		} else {
			sb.WriteString("未发现需要进一步调查的线索。\n")
		}
	}
	return sb.String()
}

// reportCSS 是 report.html 的内嵌样式表。
//
// 报告必须完全离线可用：不引用外部字体、脚本或 CDN，也不使用任何运行时 JavaScript。
// 打印（@media print）时保持可读，并避免线索卡片跨页断裂。
// reportTimelineCSS 是「时间线」区块的样式。
//
// 刻意**不并入** reportCSS：普通 report（非 -zip）不渲染时间线区块，样式也不该跟着进去——
// 否则同一份报告会因为加了个用不到的样式而字节变化，"普通报告保持不变"就成了空话。
const reportTimelineCSS = `
/* table-layout:fixed + 单元格强制换行：时间线里有大量**无空格**的长注册表路径，
   不固定布局就会被撑出卡片边界（2026-10-14 实测：摘要列整段溢出面板）。 */
.tl{width:100%;table-layout:fixed;border-collapse:collapse;font-size:13px}
.tl th,.tl td{border-bottom:1px solid var(--line-soft);padding:6px 9px;text-align:left;vertical-align:top;
  overflow-wrap:anywhere;word-break:break-word}
.tl th{background:#f7f9fb;font-size:11.5px;letter-spacing:.06em;text-transform:uppercase;color:var(--soft)}
.tl td.t{white-space:nowrap;font-family:"Cascadia Mono",Consolas,ui-monospace,"Courier New",monospace;font-size:12px}
`

const reportCSS = `
:root{
  --bg:#f4f6f8; --panel:#ffffff; --ink:#151a21; --soft:#5c6673;
  --line:#e2e6ec; --line-soft:#eef1f5;
  --brand:#0f3d5c; --brand-soft:#eaf2f8; --brand-line:#cfe0ee;
  --high:#b3261e; --high-bg:#fdeceb; --high-line:#e9b3ae;
  --med:#8a5200;  --med-bg:#fff5e5;  --med-line:#f0cf9a;
  --low:#3c5566;  --low-bg:#eef2f6;  --low-line:#c3d0da;
}
*{box-sizing:border-box}
body{
  margin:0; background:var(--bg); color:var(--ink);
  font-family:"Segoe UI","Microsoft YaHei","PingFang SC",system-ui,-apple-system,sans-serif;
  font-size:15px; line-height:1.65; -webkit-font-smoothing:antialiased;
}
code,pre{font-family:"Cascadia Mono",Consolas,ui-monospace,"Courier New",monospace}
.en{font-size:.82em;letter-spacing:.06em;text-transform:uppercase;color:#93a3b1;font-weight:500}
.panel>h2 .en{font-size:.85em;margin-left:7px}
.block-label .en{margin-left:5px}
.stat-label .en{margin-left:4px}
.kv dt .en{font-size:.88em;margin-left:4px}
.chips .en{color:#93a3b1}

/* 关系 / 攻击链 */
.scores{width:100%;border-collapse:collapse;font-size:13.5px;table-layout:fixed}
.scores th,.scores td{border-bottom:1px solid var(--line-soft);padding:7px 10px;text-align:left;vertical-align:top;
  overflow-wrap:anywhere;word-break:break-word}
.scores th{background:#f7f9fb;font-size:11.5px;letter-spacing:.06em;text-transform:uppercase;color:var(--soft)}
.scores td.num{text-align:right;font-variant-numeric:tabular-nums;font-weight:600}
.scores th.num{text-align:right}
.scores code{background:#f4f6f8;border:1px solid var(--line);border-radius:4px;padding:0 4px;font-size:12px}
/* 页头溯源行 */
.provenance{margin:6px 0 0;font-size:12.5px;color:#b9c6d2}
.provenance code{background:none;border:1px solid #48607a;border-radius:4px;padding:0 4px;font-size:12px}

/* 优先处理（首页索引） */
.prio{margin:8px 0 0;padding-left:22px}
.prio li{margin:3px 0}
.prio code{background:#f4f6f8;border:1px solid var(--line);border-radius:4px;padding:0 4px;font-size:12px}

.chain{list-style:none;padding-left:0;margin:0}
.chain li{margin:0;padding:5px 0;border-bottom:1px dashed var(--line-soft)}
.chain li:last-child{border-bottom:none}
.chain-edge{display:block}
.chain-cmd{display:block;margin-top:2px;color:var(--soft);font-size:12.5px;word-break:break-all}

/* 顶部横幅 */
.masthead{background:linear-gradient(135deg,#0d3350,#12496f 55%,#1a5f8a);color:#fff}
.mast-inner{max-width:1040px;margin:0 auto;padding:36px 28px 48px}
.eyebrow{margin:0 0 8px;font-size:11.5px;letter-spacing:.14em;text-transform:uppercase;color:#a9cde4}
.title{margin:0;font-size:30px;font-weight:650}
.subtitle{margin:12px 0 0;color:#cfe3f0;font-size:13.5px}
.subtitle code{background:rgba(255,255,255,.14);color:#fff;padding:2px 7px;border-radius:4px}

.wrap{max-width:1040px;margin:0 auto;padding:0 28px 8px}

/* 统计卡片 */
.summary{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:0 0 24px}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:15px 18px;
  box-shadow:0 1px 2px rgba(15,61,92,.07)}
.stat-label{display:block;font-size:11.5px;letter-spacing:.1em;text-transform:uppercase;color:var(--soft)}
.stat-value{display:block;margin-top:3px;font-size:28px;font-weight:650;line-height:1.15;
  font-variant-numeric:tabular-nums}
.stat-high{border-color:var(--high-line);background:var(--high-bg)}
.stat-high .stat-value{color:var(--high)}
.stat-medium{border-color:var(--med-line);background:var(--med-bg)}
.stat-medium .stat-value{color:var(--med)}
.stat-low{border-color:var(--low-line);background:var(--low-bg)}
.stat-low .stat-value{color:var(--low)}

/* 分区面板 */
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;
  padding:20px 24px 22px;margin:0 0 20px;box-shadow:0 1px 2px rgba(15,61,92,.05)}
.panel>h2{margin:0 0 16px;padding-bottom:10px;border-bottom:1px solid var(--line);
  font-size:14px;letter-spacing:.07em;text-transform:uppercase;color:var(--brand)}


/* 可折叠区块：原生 <details>，零 JavaScript，键盘可用 */
details.panel>summary{cursor:pointer;list-style:none;display:flex;align-items:center;gap:8px;
  margin:0 0 16px;padding-bottom:10px;border-bottom:1px solid var(--line)}
details.panel>summary::-webkit-details-marker{display:none}
details.panel>summary::before{content:"▸";color:var(--brand);font-size:12px;flex:0 0 12px}
details.panel[open]>summary::before{content:"▾"}
details.panel>summary h2{margin:0;padding:0;border-bottom:none;font-size:14px;letter-spacing:.07em;
  text-transform:uppercase;color:var(--brand)}
details.panel>summary h2 .en{font-size:.85em;margin-left:7px}
details.panel:not([open])>summary{margin-bottom:0;padding-bottom:0;border-bottom:none}
details.panel:not([open])>summary::after{content:"（点击展开）";color:#93a3b1;font-size:12px;
  letter-spacing:0;text-transform:none;font-weight:400}

/* 键值列表 */
.kv{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:0 26px;margin:0}
.kv>div{display:flex;gap:10px;padding:6px 0;border-bottom:1px dashed var(--line-soft)}
.kv dt{min-width:116px;color:var(--soft);font-size:13px}
.kv dd{margin:0;word-break:break-all}

/* 采集模块 */
.chips{display:flex;flex-wrap:wrap;gap:8px;margin:0;padding:0;list-style:none}
.chips li{display:inline-flex;align-items:center;gap:8px;background:#f3f6f9;border:1px solid var(--line);
  border-radius:999px;padding:4px 12px;font-size:13.5px}
.chips .n{color:var(--soft);font-variant-numeric:tabular-nums}

.note{margin:14px 0 0;padding:10px 14px;background:#f7f9fb;border:1px solid var(--line);
  border-radius:6px;font-size:13px;color:var(--soft)}
.boundary{margin:12px 0 0;font-size:12.5px;color:#6b7785}

/* 线索索引 */
.toc{margin:0 0 18px;padding:14px 18px;background:#f7f9fb;border:1px solid var(--line);border-radius:8px}
.toc-title{display:block;font-size:11.5px;letter-spacing:.1em;text-transform:uppercase;
  color:var(--soft);margin-bottom:8px}
.toc ol{margin:0;padding-left:20px}
.toc li{margin:4px 0}
.toc a{color:var(--brand);text-decoration:none}
.toc a:hover{text-decoration:underline}

.lede{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin:0 0 16px;
  color:var(--soft);font-size:13.5px}
/* 叙述段落：**不能用 .lede**（它是 flex，行内 <b> 会变成独立 flex 项，
   把一句话折得七零八落 —— 2026-10-15 渲染复核实测） */
.prose{margin:0 0 14px;color:var(--ink);font-size:14.5px;line-height:1.75}
.prose b{color:var(--brand)}
.pill{border-radius:999px;padding:2px 10px;font-size:12px;font-weight:650;border:1px solid transparent}
.pill-high{background:var(--high-bg);color:var(--high);border-color:var(--high-line)}
.pill-medium{background:var(--med-bg);color:var(--med);border-color:var(--med-line)}
.pill-low{background:var(--low-bg);color:var(--low);border-color:var(--low-line)}

/* 线索卡片 */
.finding{border:1px solid var(--line);border-left:4px solid var(--soft);border-radius:8px;
  padding:16px 20px 18px;margin:0 0 14px;background:#fff}
.finding.sev-critical,.finding.sev-high{border-left-color:var(--high)}
.finding.sev-medium{border-left-color:var(--med)}
.finding.sev-low{border-left-color:var(--low)}
.finding-head{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap}
.finding-head h3{margin:0;font-size:17px;font-weight:620;line-height:1.45}

.badge{display:inline-block;border-radius:5px;padding:2px 8px;font-size:11.5px;font-weight:700;
  letter-spacing:.06em;white-space:nowrap;
  font-family:"Cascadia Mono",Consolas,ui-monospace,monospace}
.badge-critical,.badge-high{background:var(--high-bg);color:var(--high);border:1px solid var(--high-line)}
.badge-medium{background:var(--med-bg);color:var(--med);border:1px solid var(--med-line)}
.badge-low{background:var(--low-bg);color:var(--low);border:1px solid var(--low-line)}
.badge-unknown{background:#f1f3f5;color:var(--soft);border:1px solid var(--line)}

.ids{display:flex;flex-wrap:wrap;gap:6px 18px;margin:10px 0 0;font-size:12.5px;color:var(--soft)}
.ids code{background:#f4f6f8;border:1px solid var(--line);border-radius:4px;padding:1px 6px;
  font-size:12.5px;color:var(--ink)}
.desc{margin:12px 0 0;color:#333b45}

.block{margin:14px 0 0}
.block-label{display:block;font-size:11.5px;letter-spacing:.1em;text-transform:uppercase;
  color:var(--soft);margin-bottom:5px}
.block ul{margin:0;padding-left:20px}
.block li{margin:3px 0;word-break:break-all}
.block code{background:#f4f6f8;border:1px solid var(--line);border-radius:4px;padding:1px 6px;font-size:12.5px}
.ev{list-style:none;padding-left:0}

/* 「回到顶端」：纯 CSS 固定定位的锚点（无 JavaScript；始终可见，不做滚动显隐） */
.to-top{position:fixed;right:22px;bottom:22px;z-index:20;padding:8px 14px;border-radius:999px;
  background:var(--brand);color:#fff;font-size:13px;font-weight:600;text-decoration:none;
  box-shadow:0 2px 10px rgba(15,61,92,.28)}
.to-top:hover{background:#0b2f47;color:#fff}
/* 用百分比而不是 px：打印页比屏幕窄得多，px 会把后面的列挤死（2026-10-15 实测）。 */
.hits col.c-id{width:14%}
.hits col.c-label{width:22%}
.hits tr:not(.facts-detail) td:first-child{white-space:nowrap}
/* 明细行是整行跨列的单格，**必须显式允许换行**：上面的 nowrap 选择器若不加
   :not(.facts-detail) 限定，会把明细行也一起 nowrap —— 命令行就会戳出卡片（2026-10-15 实测）。
   视觉上做成"挂在实体行下面的明细块"：左侧色条 + 浅底色，避免十几个实体混成一片文字墙。 */
.hits tr.facts-detail td{background:#f6f8fb;color:var(--ink);font-size:12.5px;
  padding:6px 10px 7px 14px;border-left:3px solid var(--brand-line);
  white-space:normal;overflow-wrap:anywhere;word-break:break-word}
.hits tr.facts-detail .fact{display:block}
/* 标签定宽：路径/命令行/父进程/子进程/进程镜像 宽度不一，值会左参差；
   定宽后所有值左对齐成一列（2026-10-15 渲染复核）。 */
.hits tr.facts-detail .fact b{display:inline-block;min-width:4.7em}
/* 原始数据（路径 / 命令行 / 哈希）用等宽小字，和叙述文字区分开 */
.hits tr.facts-detail .val{font-family:"Cascadia Mono",Consolas,ui-monospace,"Courier New",monospace;
  font-size:11.5px;color:#2c3947;word-break:break-word}
/* 命令行按参数断行：每个 " --" 前起新行，扫参数比随机折行清楚得多 */
.hits tr.facts-detail .val.cmd-args{display:inline}
.hits tr.facts-detail .arg-break{display:block}
.hits tr.facts-detail .clip-hint{color:#93a3b1;font-size:11.5px;font-family:inherit}
.hits tr.facts-detail .fact b{color:var(--soft);font-weight:600;margin-right:4px;white-space:nowrap}

/* 聚合卡片里的"共同事实"行与逐条事实 */
.fact{display:inline-block;word-break:break-word}/* 聚合卡片里的"共同事实"行 */
.common{margin:10px 0 2px;font-size:13px;color:var(--soft)}

/* 按规则聚合后的命中实体表 */
.hits{width:100%;border-collapse:collapse;font-size:13px;margin-top:2px;table-layout:fixed}
.hits th,.hits td{border-bottom:1px solid var(--line-soft);padding:5px 8px;text-align:left;vertical-align:top;
  overflow-wrap:anywhere;word-break:break-word}
.hits th{background:#f7f9fb;font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--soft);font-weight:600}
.hits code{background:#f4f6f8;border:1px solid var(--line);border-radius:4px;padding:0 4px;font-size:12px}

.advice{margin:16px 0 0;padding:12px 14px;background:var(--brand-soft);
  border:1px solid var(--brand-line);border-radius:6px}
.advice .block-label{color:var(--brand);margin-bottom:6px}
.advice ul{margin:0;padding-left:20px}

.empty{margin:0;padding:24px;text-align:center;color:var(--soft);
  background:#f7f9fb;border:1px dashed var(--line);border-radius:8px}

.foot{max-width:1040px;margin:0 auto;padding:6px 28px 44px;color:var(--soft);font-size:12.5px}
.foot p{margin:4px 0}

@media (max-width:780px){
  .summary{grid-template-columns:repeat(2,1fr)}
  .mast-inner,.wrap,.foot{padding-left:16px;padding-right:16px}
}

@media print{
  body{background:#fff;font-size:11pt;line-height:1.5}
  /* 折叠区块在打印时必须展开（closed 的 <details> 内容默认不打印） */
.to-top{display:none}
  /* 打印页比屏幕窄：表格用小字，避免短列被折成 netwo rk / unknown 两行 */
  .scores{font-size:9.5pt}
  .hits{font-size:9pt}
  details.panel:not([open])>*:not(summary){display:block !important}
  details.panel::details-content{content-visibility:visible !important}
  details.panel>summary::before{content:""}
  details.panel:not([open])>summary::after{content:""}
  .masthead{background:#fff;color:#000;border-bottom:2px solid #000}
  .eyebrow,.subtitle{color:#444}
  .subtitle code{background:none;color:#000}
  .summary{grid-template-columns:repeat(4,1fr);margin:14px 0 18px}
  .stat,.panel,.finding,.toc,.advice,.note{box-shadow:none}
  .panel,.finding,.advice,.note{break-inside:avoid}
  .toc{display:none}
  a{color:#000;text-decoration:none}
}
`

// severityClass 把严重程度映射为固定的 CSS 令牌。
// 使用白名单映射而不是拼接原始文本，严重程度不会作为类名注入到标记中。
func severityClass(sev string) string {
	switch sev {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	}
	return "unknown"
}

// contextLabels 是 Finding context 分组的展示名与固定顺序。
// 中文为主标签；英文保留协议术语，便于与规则、协议文档和 findings.json 对照。
var contextLabels = []struct {
	Key string
	Zh  string
	En  string
}{
	{"process", "进程", "Process"},
	{"parent", "父进程", "Parent"},
	{"child", "子进程", "Child"},
	{"network", "网络", "Network"},
	{"persistence", "持久化", "Persistence"},
	{"entity", "实体事实", "Entity facts"},
	{"missing", "缺失字段", "Missing"},
}

// hostLabels 是 Host 区块的中文标签。原始字段名同时以英文小字标注，
// 保证报告与 findings.json 的键一一对应。
var hostLabels = map[string]string{
	"hostname":  "主机名",
	"os":        "操作系统",
	"os_build":  "系统版本",
	"arch":      "架构",
	"user":      "用户",
	"collected": "采集时间",
}

// collectionLabels 是采集模块的中文名；未登记的类型回退为原始类型名。
var collectionLabels = map[string]string{
	"host": "主机", "process": "进程", "network": "网络", "persistence": "持久化",
	"service": "服务", "task": "计划任务", "user": "用户", "relations": "关系",
}

// writeStatCard 输出统计卡片（Findings / HIGH / MEDIUM / LOW）。
func writeStatCard(sb *strings.Builder, class, zh, en string, value int) {
	sb.WriteString("<div class=\"stat " + class + "\">")
	sb.WriteString("<span class=\"stat-label\">" + zh + " <span class=\"en\">" + en + "</span></span>")
	sb.WriteString("<span class=\"stat-value\">" + fmt.Sprintf("%d", value) + "</span>")
	sb.WriteString("</div>\n")
}

// writeFindingCard 输出单条线索卡片。所有动态文本都经 html.EscapeString 转义。
// findingGroup 把"同一条规则命中的多条线索"聚合为一张卡片。
//
// 背景（2026-10-14 本机实测）：一次真实采集产生 50 条线索，却只来自 **3 条规则**
// （network.public_listener 32 条、process.user_path.executable 15 条、user_path.network 3 条）。
// 逐条渲染 = 50 张卡片、91KB、占整页 46%，同一段描述与处置建议重复三十多遍 ——
// 这是"报告东西太多、可读性差"的主要来源。聚合后同一规则只讲一次，
// 命中实体列成紧凑表格，**信息不丢**（每条线索的实体与关键事实仍在表里，
// 逐条原始证据仍在 findings.json）。
type findingGroup struct {
	Severity    string
	RuleID      string
	Title       string
	Description string
	Advice      []string
	Members     []reportFinding
}

// groupFindings 按 (severity, rule_id, title) 聚合，保持首次出现顺序（输出稳定、可复现）。
func groupFindings(findings []reportFinding) []findingGroup {
	var groups []findingGroup
	index := map[string]int{}
	for _, f := range findings {
		key := f.Severity + "\x00" + f.RuleID + "\x00" + f.Title
		if at, ok := index[key]; ok {
			groups[at].Members = append(groups[at].Members, f)
			continue
		}
		index[key] = len(groups)
		groups = append(groups, findingGroup{
			Severity:    f.Severity,
			RuleID:      f.RuleID,
			Title:       f.Title,
			Description: f.Description,
			Advice:      f.Advice,
			Members:     []reportFinding{f},
		})
	}
	return groups
}

// maxFactColumns 是聚合卡片里"事实列"的最大数量，超出的键折进「其它」列。
const maxFactColumns = 6

// factColumnLabels 把事实键映射为列头（协议术语保留原文，常见字段给中文）。
var factColumnLabels = map[string]string{
	"path": "路径", "command_line": "命令行", "name": "名称", "pid": "PID",
	"protocol": "协议", "local": "本地", "remote": "远端", "state": "状态",
	"username": "用户", "hash_sha256": "哈希", "signature_state": "签名态",
}

// keyedFact 是一条"带键的事实"，用于跨整行展示的长事实。
type keyedFact struct{ key, value string }

// longFactRunes：取值超过这个长度的事实不再放进窄列，改为跨整行展示。
const longFactRunes = 40

// maxColRunes 是"这个键能否当列"的门槛：**只有组内最长取值也在预算内**才拆列。
//
// 为什么不按平均/最短判（2026-10-15 渲染复核实测）：只要某键有一条长取值，
// 放进窄列就必然被折成碎片——`signature_stat` + `e`、`WeChatAppEx.` + `exe`，
// 甚至把明细行的标签"命令行"折成"命令 / 行"。列里塞长文本无解，
// 而"短键进列 + 其余跨整行明细"在屏幕与打印（页面更窄）两种宽度下都稳。
const maxColRunes = 30

// longFactMaxRunes 是跨行明细的安全上限（正常不会碰到；防止异常长的命令行把报告撑爆）。
const longFactMaxRunes = 400

// normalizeFactKey 从事实行里取出"用于分列"的键：去掉 evidence 形式的类型前缀
// （process.path → path），无键（理论上前缀化已兜住）返回空串。
func normalizeFactKey(s string) string {
	key := strings.TrimSpace(factKey(s))
	if key == "" {
		return ""
	}
	key = strings.ToLower(key)
	if i := strings.LastIndex(key, "."); i >= 0 {
		key = key[i+1:]
	}
	return key
}

// factColumnLabel 把规范化后的键映射为列头；映射表里没有就原样显示键。
func factColumnLabel(key string) string {
	if zh, ok := factColumnLabels[key]; ok {
		return zh
	}
	return key
}

// breakCommandArgs 在命令行里每个 " --" 前插入换行，便于逐参数扫读。
//
// 为什么（2026-10-15 渲染复核）：命令行常达数百字符，整段折行后像一堵墙；
// 按参数断行后可以逐行看参数（`--type=renderer`、`--lang=zh-CN`…），排查时快得多。
// 输入是**已转义**的 HTML 文本，所以只做纯文本切分。
func breakCommandArgs(escaped string) string {
	// 已转义的文本里空格仍是普通空格；把 " --" 换成 "<br>--"（HTML 里就是换行）。
	return strings.ReplaceAll(escaped, " --", "<span class=\"arg-break\"></span>--")
}

// maxHitsPerGroup 是一张聚合卡片最多列出的命中实体数。
const maxHitsPerGroup = 50

// entityUpdatesByID 取本快照的全部 entity_update 并按实体分组。
//
// 深采补充的证据（启动项目标文件的 signature_state / hash_sha256、进程的 hash_sha256 等）
// 都落在这里；报告的时间线与"证据融合"都要用它，因此取一次、共用。
func entityUpdatesByID(db *storage.DB, snapshotID string) (map[string][]storage.EntityUpdateRow, error) {
	updates, err := storage.GetEntityUpdatesAll(db, snapshotID)
	if err != nil {
		return nil, err
	}
	byEntity := make(map[string][]storage.EntityUpdateRow)
	for _, u := range updates {
		byEntity[u.EntityID] = append(byEntity[u.EntityID], u)
	}
	return byEntity, nil
}

// fuseEvidence 用**同一份快照里已有的其它证据**给线索补充更直观的事实。
//
// 原则（项目所有者 2026-10-15）："既然是报告，那就尽量融合已有的证据，让报告更直观。"
// 目前做两件事，都只在证据**确实存在**时补，查不到就什么都不加（绝不编造）：
//   - 服务线索 → 该服务当前对应的**运行进程**（来自 launch 关系：服务→进程），
//     省去读者自己翻「关系与攻击链」去找；
//   - 持久化线索 → 启动项**目标文件**的 signature_state / sha256（来自深采 entity_update；
//     Basic 采集本来就没有这些字段，自然不补）。
func fuseEvidence(findings []reportFinding, relations []storage.RelationRow,
	updatesByEntity map[string][]storage.EntityUpdateRow, labels, types map[string]string) {

	// 服务实体 → 运行进程标签（"svchost.exe (1234)"）。一个服务只取第一条 launch。
	svcProc := map[string]string{}
	for _, rel := range relations {
		if rel.RelationType != "launch" {
			continue
		}
		if _, ok := svcProc[rel.SourceID]; ok {
			continue
		}
		if name := labels[rel.TargetID]; name != "" {
			svcProc[rel.SourceID] = name
		}
	}

	for i := range findings {
		f := &findings[i]
		var extra []string
		if name, ok := svcProc[f.EntityID]; ok {
			extra = append(extra, "运行进程: "+name)
		}
		// 深采补充里已有"文件签名态 / 哈希"时补上：持久化看启动项**目标文件**，
		// 进程看进程**自身镜像**（两者字段名相同，语义不同，因此分别取）。
		switch types[f.EntityID] {
		case "persistence":
			if meta := persistenceTargetFileMeta(updatesByEntity[f.EntityID]); meta != "" {
				extra = append(extra, "目标文件: "+meta)
			}
		case "process":
			if meta := processImageMeta(updatesByEntity[f.EntityID]); meta != "" {
				extra = append(extra, "进程镜像: "+meta)
			}
		}
		f.Fused = extra
	}
}

// persistenceTargetFileMeta 从深采 entity_update 里取出启动项**目标文件**的签名态 / 哈希。
func persistenceTargetFileMeta(ups []storage.EntityUpdateRow) string {
	for _, u := range ups {
		var d model.PersistenceEnrichmentData
		if json.Unmarshal([]byte(u.DataJSON), &d) != nil {
			continue
		}
		if s := fileMetaText(d.SignatureState, d.HashSHA256); s != "" {
			return s
		}
	}
	return ""
}

// processImageMeta 从深采 entity_update 里取出进程**自身镜像**的签名态 / 哈希。
func processImageMeta(ups []storage.EntityUpdateRow) string {
	for _, u := range ups {
		var d model.ProcessEnrichmentData
		if json.Unmarshal([]byte(u.DataJSON), &d) != nil {
			continue
		}
		if s := fileMetaText(d.SignatureState, d.HashSHA256); s != "" {
			return s
		}
	}
	return ""
}

// fileMetaText 把签名态 / 哈希拼成一行；两者都没有时返回空串（不编造）。
func fileMetaText(sig, hash string) string {
	var parts []string
	if sig != "" {
		parts = append(parts, "signature_state="+sig)
	}
	if hash != "" {
		parts = append(parts, "sha256="+hash)
	}
	return strings.Join(parts, "；")
}

// pidProcessNames 从本快照的 process 实体建 pid → 进程名映射。
//
// 为什么值得做（2026-10-15 反馈："既然是报告，那就尽量融合已有的证据，让报告更直观"）：
// 网络类线索的关键事实原来只有 "pid: 1964"，读者还得自己回快照里查这是哪个进程；
// 而 process 实体就在同一份快照里，直接补成 "pid: 1964（svchost.exe）" 才有用。
// 同一 PID 多次出现时以先出现的非空名字为准（一份快照内 PID 唯一，正常不冲突）。
func pidProcessNames(entities []storage.EntityRow) map[uint32]string {
	out := make(map[uint32]string)
	for _, e := range entities {
		if e.EntityType != "process" {
			continue
		}
		var d model.ProcessData
		if json.Unmarshal([]byte(e.DataJSON), &d) != nil || d.Name == "" {
			continue
		}
		if _, ok := out[d.PID]; !ok {
			out[d.PID] = d.Name
		}
	}
	return out
}

// factKey 取 "key: value" / "key=value" 的键部分（无分隔符时返回空串）。
func factKey(s string) string {
	if i := strings.Index(s, ": "); i >= 0 {
		return s[:i]
	}
	if i := strings.Index(s, "="); i >= 0 {
		return s[:i]
	}
	return ""
}

// factPID 从 "pid: 1964" / "network.pid=1964" 这类事实行里取出 PID。
// 只在键名以 pid 结尾时才算，避免把端口/句柄当成 PID。
func factPID(s string) (uint32, bool) {
	key := strings.ToLower(strings.TrimSpace(factKey(s)))
	if key != "pid" && !strings.HasSuffix(key, ".pid") && !strings.HasSuffix(key, "_pid") {
		return 0, false
	}
	n, err := strconv.ParseUint(strings.TrimSpace(factValue(s)), 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(n), true
}

// enrichPID 给事实行里的 PID 补上进程名（融合快照里已有的 process 证据）。
func enrichPID(s string, pidNames map[uint32]string) string {
	pid, ok := factPID(s)
	if !ok {
		return s
	}
	if name := pidNames[pid]; name != "" {
		return s + "（" + name + "）"
	}
	return s
}

// enrichFacts 对一组事实行逐条做证据融合（未提供映射时原样返回）。
func enrichFacts(lines []string, pidNames map[uint32]string) []string {
	if len(pidNames) == 0 {
		return lines
	}
	out := make([]string, 0, len(lines))
	for _, s := range lines {
		out = append(out, enrichPID(s, pidNames))
	}
	return out
}

// bareValueContextGroups 是"取值本身是裸值、必须带组名前缀才看得懂"的上下文分组。
//
// 为什么需要（2026-10-15 实测）：context 里 parent / child 的取值就是进程名（如
// "WeChatAppEx.exe"），missing 的取值就是字段名（如 "hash_sha256"）——分行展示后
// 变成一行光秃秃的字，读者不知道那是什么，甚至像渲染坏了。
// 而 process / network / persistence 的取值本身已形如 "name: X" / "local: ..."，
// 自带键名，直接逐行展示即可（加了前缀反而啰嗦）。
var bareValueContextGroups = map[string]string{
	"parent":  "父进程",
	"child":   "子进程",
	"missing": "缺失字段",
}

// findingFacts 取一条线索用于展示的事实行：优先人类可读的 context，退回证据列表。
func findingFacts(f reportFinding) []string {
	var parts []string
	for _, c := range contextLabels {
		vs := f.Context[c.Key]
		if len(vs) == 0 {
			continue
		}
		if label, ok := bareValueContextGroups[c.Key]; ok {
			parts = append(parts, label+": "+strings.Join(vs, "、"))
			continue
		}
		parts = append(parts, vs...)
	}
	if len(parts) == 0 {
		parts = reportEvidence(f)
	}
	// 融合事实排在最后：先看规则自己命中的证据，再看"同一快照里还能补什么"。
	return append(parts, f.Fused...)
}

// hitSummary 给聚合表格里的一行"关键事实"（无公共事实可提取时的兜底展示）。
func hitSummary(f reportFinding) string {
	return clipRunes(strings.Join(findingFacts(f), "；"), 120)
}

// groupCommonFacts 返回在**所有**命中里都出现的事实行（保持首条里的顺序）。
//
// 为什么需要（2026-10-15 反馈）：network.public_listener 命中 32 处，表格里每一行都写
// "protocol: tcp; local: …; state: LISTENING; pid: …" —— 前两项 32 行完全一样，
// 唯一有差异的只是端口与 PID。把公共部分提到表格上方讲一次，表格只留"本条差异"。
func groupCommonFacts(members []reportFinding) []string {
	if len(members) < 2 {
		return nil
	}
	count := map[string]int{}
	for _, m := range members {
		seen := map[string]bool{}
		for _, s := range findingFacts(m) {
			if !seen[s] {
				seen[s] = true
				count[s]++
			}
		}
	}
	var out []string
	seen := map[string]bool{}
	for _, s := range findingFacts(members[0]) {
		if count[s] == len(members) && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// rowFacts 计算聚合表格里某一行要显示的事实：先去掉公共行，再去掉**标签列里已经能看到**
// 的行（例如标签已是 "tcp 0.0.0.0:135 → …"，就不必再写 "local: 0.0.0.0:135"）。
// 若过滤后什么都不剩，则退回"只去掉公共行"的结果，避免整列空掉。
func rowFacts(f reportFinding, common []string, label string) []string {
	var rest []string
	for _, s := range findingFacts(f) {
		if !containsString(common, s) {
			rest = append(rest, s)
		}
	}
	var out []string
	for _, s := range rest {
		// 只对**标签列真正展示的那几个字段**去重（见 labelCoveredKeys），且要求值足够长：
		//  - 短值会误判：`pid: 4` 的值 "4" 命中标签里的端口 "445"（2026-10-15 实测）；
		//  - 不限键会误伤：`父进程: WeChatAppEx.exe` 与子进程同名，被判成"标签里已有"而删掉，
		//    但那明明是**另一个进程**（不同 PID）——现在只对 protocol/local/remote/name 这类
		//    确实等同于标签的字段去重。
		if !labelCoveredKeys[normalizeFactKey(s)] {
			out = append(out, s)
			continue
		}
		if v := factValue(s); label != "" && len(v) >= 4 && strings.Contains(label, v) {
			continue
		}
		out = append(out, s)
	}
	return out
}

// labelCoveredKeys 是"取值已经体现在标签列里"的事实键：这类键在表格里可以省略，
// 避免同一件事写两遍（例如标签已是 "tcp 0.0.0.0:135 → 0.0.0.0:0"，
// 就不必再写 "local: 0.0.0.0:135"）。**不要**把父进程/子进程/缺失字段这类键放进来。
var labelCoveredKeys = map[string]bool{
	"protocol": true, "local": true, "remote": true, "pid": true,
	"name": true, "service_name": true, "task_name": true, "username": true,
}

// factValue 取 "key: value" / "key=value" 里的值部分（无分隔符时返回原串）。
func factValue(s string) string {
	if i := strings.Index(s, ": "); i >= 0 {
		return strings.TrimSpace(s[i+2:])
	}
	if i := strings.Index(s, "="); i >= 0 {
		return strings.TrimSpace(s[i+1:])
	}
	return s
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// clipRunes 按字符（而非字节）截断，避免截出半个汉字。
func clipRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// writeFindingGroupCard 渲染一张线索卡片。
//
// 单条命中 → 与逐条渲染完全一致（保留完整证据列表）；
// 多处命中 → 规则级信息（描述/处置建议）只讲一次，命中实体列为紧凑表格。
func writeFindingGroupCard(sb *strings.Builder, n int, g findingGroup, labels map[string]string, pidNames map[uint32]string) {
	if len(g.Members) == 1 {
		writeFindingCard(sb, n, g.Members[0], pidNames)
		return
	}
	sev := severityClass(g.Severity)
	sb.WriteString("<article class=\"finding sev-" + sev + "\" id=\"f-" + fmt.Sprintf("%d", n) + "\">\n")
	sb.WriteString("<header class=\"finding-head\">\n")
	sb.WriteString("<span class=\"badge badge-" + sev + "\">[" + html.EscapeString(g.Severity) + "]</span>\n")
	sb.WriteString("<h3>" + html.EscapeString(g.Title) + "</h3>\n")
	sb.WriteString("<span class=\"pill\">" + fmt.Sprintf("%d 处命中", len(g.Members)) + "</span>\n")
	sb.WriteString("</header>\n")
	sb.WriteString("<p class=\"ids\">")
	sb.WriteString("<span><b>规则</b> <span class=\"en\">Rule</span> <code>" + html.EscapeString(g.RuleID) + "</code></span>")
	sb.WriteString("<span><b>线索数</b> <span class=\"en\">Findings</span> " + fmt.Sprintf("%d", len(g.Members)) + "</span>")
	sb.WriteString("</p>\n")
	if g.Description != "" {
		sb.WriteString("<p class=\"desc\">" + html.EscapeString(g.Description) + "</p>\n")
	}

	shown := g.Members
	if len(shown) > maxHitsPerGroup {
		shown = shown[:maxHitsPerGroup]
	}
	// 公共事实提到表格上方讲一次；表格里只留"本条差异"，并去掉标签列已能看到的项。
	common := groupCommonFacts(g.Members)
	if len(common) > 0 {
		sb.WriteString("<p class=\"common\"><b>共同事实</b> <span class=\"en\">Common</span>：" +
			html.EscapeString(clipRunes(strings.Join(enrichFacts(common, pidNames), "；"), 220)) + "</p>\n")
	}
	// 每行的"本条差异"分两种放法：
	//   - **所有取值都短的键** → 拆成列（可横向对照，如 PID）；
	//   - **其余**（路径 / 命令行 / 父进程 / 缺失字段…）→ 该实体下方的跨整行明细。
	//
	// 为什么按"每个键的最长取值"判列（2026-10-15 渲染复核实测）：
	// 只要某键有一条长取值，放进窄列就必然被折成碎片——`signature_stat` + `e`、
	// `WeChatAppEx.` + `exe`、甚至把标签"命令行"折成"命令 / 行"。列里塞长文本无解，
	// 而"短键进列 + 其余跨行"在屏幕与打印（页面更窄）两种宽度下都稳。
	type hitRow struct {
		entityID, label string
		order           []string          // 本行成为列的键（顺序）
		short           map[string]string // 列键 → 值
		long            []keyedFact       // 跨整行展示的事实（完整值）
		other           []string          // 无键的事实行
	}
	// 第一遍：统计每个键的最长取值，决定哪些键能当列。
	keyMax := map[string]int{}
	keyOrder := []string{}
	for _, f := range shown {
		label := labels[f.EntityID]
		for _, s := range enrichFacts(rowFacts(f, common, label), pidNames) {
			key := normalizeFactKey(s)
			if key == "" {
				continue
			}
			if !containsString(keyOrder, key) {
				keyOrder = append(keyOrder, key)
			}
			if n := len([]rune(strings.TrimSpace(factValue(s)))); n > keyMax[key] {
				keyMax[key] = n
			}
		}
	}
	var colKeys []string
	for _, k := range keyOrder {
		if k != "path" && k != "command_line" && keyMax[k] <= maxColRunes {
			colKeys = append(colKeys, k)
		}
	}
	// 列太多时只保留前 maxFactColumns 列，其余折进「其它」（否则表格会宽到没法读）。
	var overflowKeys []string
	if len(colKeys) > maxFactColumns {
		overflowKeys = colKeys[maxFactColumns:]
		colKeys = colKeys[:maxFactColumns]
	}
	// 第二遍：按上面的列集合整理每一行。
	rows := make([]hitRow, 0, len(shown))
	for _, f := range shown {
		label := labels[f.EntityID]
		r := hitRow{entityID: f.EntityID, label: label, short: map[string]string{}}
		for _, s := range enrichFacts(rowFacts(f, common, label), pidNames) {
			key := normalizeFactKey(s)
			if key == "" {
				r.other = append(r.other, s)
				continue
			}
			v := strings.TrimSpace(factValue(s))
			if !containsString(colKeys, key) {
				if !containsString(overflowKeys, key) {
					r.long = append(r.long, keyedFact{key, v})
					continue
				}
				// 超出列数上限的短键：折进「其它」列，保持完整值。
				if _, seen := r.short[key]; !seen {
					r.order = append(r.order, key)
				}
				r.short[key] = v
				continue
			}
			if _, seen := r.short[key]; !seen {
				r.order = append(r.order, key)
			}
			r.short[key] = v
		}
		rows = append(rows, r)
	}
	colSpan := 2 + len(colKeys)
	if len(overflowKeys) > 0 {
		colSpan++
	}
	sb.WriteString("<div class=\"block\">\n<span class=\"block-label\">命中实体 <span class=\"en\">Matches</span></span>\n")
	sb.WriteString("<table class=\"hits\">\n")
	sb.WriteString("<colgroup><col class=\"c-id\"><col class=\"c-label\">")
	for range colKeys {
		sb.WriteString("<col>")
	}
	if len(overflowKeys) > 0 {
		sb.WriteString("<col>")
	}
	sb.WriteString("</colgroup>\n<thead><tr><th>实体</th><th>标签</th>")
	for _, k := range colKeys {
		sb.WriteString("<th>" + html.EscapeString(factColumnLabel(k)) + "</th>")
	}
	if len(overflowKeys) > 0 {
		sb.WriteString("<th>其它</th>")
	}
	sb.WriteString("</tr></thead>\n<tbody>\n")

	for _, r := range rows {
		sb.WriteString("<tr><td><code>" + html.EscapeString(r.entityID) + "</code></td>")
		sb.WriteString("<td>" + html.EscapeString(r.label) + "</td>")
		if len(colKeys) == 0 && len(overflowKeys) == 0 && len(r.other) == 0 {
			// 标签与共同事实已经把它说完了；占位格必须 ≥1 列（colspan="0" 是非法值）
			sb.WriteString("<td>—</td>")
		}
		for _, k := range colKeys {
			if v, ok := r.short[k]; ok && v != "" {
				sb.WriteString("<td><span class=\"fact\">" + html.EscapeString(v) + "</span></td>")
			} else {
				sb.WriteString("<td>—</td>")
			}
		}
		if len(overflowKeys) > 0 {
			var parts []string
			for _, k := range overflowKeys {
				if v, ok := r.short[k]; ok && v != "" {
					parts = append(parts, factColumnLabel(k)+"："+v)
				}
			}
			parts = append(parts, r.other...)
			if len(parts) == 0 {
				sb.WriteString("<td>—</td>")
			} else {
				sb.WriteString("<td><span class=\"fact\">" + html.EscapeString(strings.Join(parts, "；")) + "</span></td>")
			}
		}
		sb.WriteString("</tr>\n")

		// 长事实跨整行展示：不截断、不挤进窄列（路径/命令行在窄列里会被折成碎片）。
		if len(r.long) > 0 {
			sb.WriteString("<tr class=\"facts-detail\"><td colspan=\"" + fmt.Sprintf("%d", colSpan) + "\">")
			for i, f := range r.long {
				if i > 0 {
					sb.WriteString("<br>")
				}
				val := html.EscapeString(clipRunes(f.value, longFactMaxRunes))
				if f.key == "command_line" {
					val = breakCommandArgs(val)
				}
				// 被安全上限截断时明确说明：不能让读者以为这就是全文。
				if len([]rune(f.value)) > longFactMaxRunes {
					val += "<span class=\"clip-hint\">（已截断，完整值见 findings.json）</span>"
				}
				sb.WriteString("<span class=\"fact\"><b>" + html.EscapeString(factColumnLabel(f.key)) + "</b>　" +
					"<span class=\"val" + map[bool]string{true: " cmd-args", false: ""}[f.key == "command_line"] + "\">" +
					val + "</span></span>")
			}
			sb.WriteString("</td></tr>\n")
		}
	}
	sb.WriteString("</tbody></table>\n")
	if len(g.Members) > len(shown) {
		sb.WriteString("<p class=\"note\">仅列出前 " + fmt.Sprintf("%d", len(shown)) + " 处（共 " +
			fmt.Sprintf("%d", len(g.Members)) + " 处）；完整清单见事件包 <code>findings.json</code>。</p>\n")
	}
	sb.WriteString("</div>\n")

	if len(g.Advice) > 0 {
		sb.WriteString("<div class=\"advice\">\n<span class=\"block-label\">处置建议 <span class=\"en\">Advice</span></span>\n<ul>\n")
		for _, a := range g.Advice {
			sb.WriteString("<li>" + html.EscapeString(a) + "</li>\n")
		}
		sb.WriteString("</ul>\n</div>\n")
	}
	sb.WriteString("</article>\n")
}

func writeFindingCard(sb *strings.Builder, n int, f reportFinding, pidNames map[uint32]string) {
	sev := severityClass(f.Severity)
	sb.WriteString("<article class=\"finding sev-" + sev + "\" id=\"f-" + fmt.Sprintf("%d", n) + "\">\n")
	sb.WriteString("<header class=\"finding-head\">\n")
	sb.WriteString("<span class=\"badge badge-" + sev + "\">[" + html.EscapeString(f.Severity) + "]</span>\n")
	sb.WriteString("<h3>" + html.EscapeString(f.Title) + "</h3>\n</header>\n")
	sb.WriteString("<p class=\"ids\">")
	sb.WriteString("<span><b>规则</b> <span class=\"en\">Rule</span> <code>" + html.EscapeString(f.RuleID) + "</code></span>")
	sb.WriteString("<span><b>线索</b> <span class=\"en\">Finding</span> <code>" + html.EscapeString(f.FindingID) + "</code></span>")
	sb.WriteString("<span><b>实体</b> <span class=\"en\">Entity</span> <code>" + html.EscapeString(f.EntityID) + "</code></span>")
	sb.WriteString("</p>\n")
	if f.Description != "" {
		sb.WriteString("<p class=\"desc\">" + html.EscapeString(f.Description) + "</p>\n")
	}
	if ev := reportEvidence(f); len(ev) > 0 {
		sb.WriteString("<div class=\"block\">\n<span class=\"block-label\">证据 <span class=\"en\">Evidence</span></span>\n<ul class=\"ev\">\n")
		for _, e := range ev {
			sb.WriteString("<li><code>" + html.EscapeString(enrichPID(e, pidNames)) + "</code></li>\n")
		}
		sb.WriteString("</ul>\n</div>\n")
	}
	for _, c := range contextLabels {
		vs, ok := f.Context[c.Key]
		if !ok || len(vs) == 0 {
			continue
		}
		sb.WriteString("<div class=\"block\">\n<span class=\"block-label\">" + c.Zh + " <span class=\"en\">" + c.En + "</span></span>\n<ul>\n")
		for _, v := range vs {
			sb.WriteString("<li>" + html.EscapeString(v) + "</li>\n")
		}
		sb.WriteString("</ul>\n</div>\n")
	}
	if len(f.Advice) > 0 {
		sb.WriteString("<div class=\"advice\">\n<span class=\"block-label\">处置建议 <span class=\"en\">Advice</span></span>\n<ul>\n")
		for _, a := range f.Advice {
			sb.WriteString("<li>" + html.EscapeString(a) + "</li>\n")
		}
		sb.WriteString("</ul>\n</div>\n")
	}
	sb.WriteString("</article>\n")
}

// maxReportTimelineRows 是 report.html「时间线」区块的展示上限。
//
// timeline.csv 可以有多达 timeline.DefaultMaxRows（10 万）行，但 HTML 是给人看的：
// 超过上限只展示最早的 N 行并写明"完整数据见 timeline.csv"，避免报告文件被撑到打不开。
const maxReportTimelineRows = 100

// buildTimeline 汇总本快照的实体时间事实（V0.3，设计见 docs/设计-时间线.md）。
//
// 关键点：必须用**合并 entity_update 后**的数据——深采补充的 last_write_time 就落在
// entity_update 里，只看实体原始 data 会丢掉"文件最近修改时间"这一大类时间事实。
// 只读数据库，不访问主机、不联网。
func buildTimeline(db *storage.DB, meta *storage.SnapshotMeta, entities []storage.EntityRow,
	byEntity map[string][]storage.EntityUpdateRow, prov *collectionProvenance) (timeline.Result, error) {

	in := make([]timeline.Entity, 0, len(entities))
	for _, e := range entities {
		in = append(in, timeline.Entity{
			EntityType: e.EntityType,
			EntityID:   e.EntityID,
			Label:      entityLabel(e),
			DataJSON:   storage.MergeEntityUpdates(e.DataJSON, byEntity[e.EntityID]),
		})
	}
	return timeline.Build(in, timeline.Options{
		SnapshotID:        meta.SnapshotID,
		CollectedAt:       meta.Timestamp,
		MaxRows:           timeline.DefaultMaxRows,
		AnchorDescription: prov.anchorDescription(),
		AnchorDetail:      prov.anchorDetail(),
	})
}

// writeTimelineSection 输出「时间线」区块。tl 为 nil（普通 report，非 -zip）时**什么都不输出**，
// 以保证普通报告的三文件与既有版本逐字节一致。
//
// 所有动态文本经 html.EscapeString 转义；纯静态表格，无 JavaScript、无外部资源。
func writeTimelineSection(sb *strings.Builder, tl *timeline.Result) {
	if tl == nil {
		return
	}
	writeSectionOpen(sb, "sec-timeline", "时间线", "Timeline", false)
	sb.WriteString("<p class=\"prose\">" + html.EscapeString(tl.StatsLine()) + "</p>\n")

	if len(tl.Rows) == 0 {
		sb.WriteString("<p class=\"empty\">本快照没有可排序的时间事实。</p>\n")
		writeSectionClose(sb)
		return
	}

	shown := tl.Rows
	if len(shown) > maxReportTimelineRows {
		shown = shown[:maxReportTimelineRows]
	}
	// 列宽显式给定，配合 table-layout:fixed —— 否则长路径会把「摘要」列顶出面板。
	sb.WriteString("<table class=\"tl\">\n" +
		"<colgroup><col style=\"width:18%\"><col style=\"width:22%\"><col style=\"width:9%\">" +
		"<col style=\"width:16%\"><col style=\"width:35%\"></colgroup>\n" +
		"<thead><tr><th>时间 (UTC)</th><th>来源</th>" +
		"<th>实体类型</th><th>标签</th><th>摘要</th></tr></thead>\n<tbody>\n")
	for _, r := range shown {
		sb.WriteString("<tr><td class=\"t\">" + html.EscapeString(r.TimeUTC) + "</td>" +
			"<td>" + html.EscapeString(r.Source) + "</td>" +
			"<td>" + html.EscapeString(r.EntityType) + "</td>" +
			"<td>" + html.EscapeString(r.Label) + "</td>" +
			"<td>" + html.EscapeString(r.Detail) + "</td></tr>\n")
	}
	sb.WriteString("</tbody>\n</table>\n")

	if len(shown) < len(tl.Rows) {
		sb.WriteString("<p class=\"note\">本页只展示最早的 " + fmt.Sprintf("%d", len(shown)) +
			" 行（共 " + fmt.Sprintf("%d", len(tl.Rows)) + " 行）；完整时间线见事件包内的 " +
			"<code>timeline.csv</code>。</p>\n")
	}
	anchorDesc := tl.AnchorDescription
	if anchorDesc == "" {
		anchorDesc = "快照时间戳"
	}
	sb.WriteString("<p class=\"note\">每行都标注了时间来源（<code>source</code>）：不同字段的时间语义不同——" +
		"<code>creation_time</code> 是进程启动时间，<code>last_write_time</code> 是文件最近修改时间，" +
		"<code>snapshot.collected_at</code> 是" + html.EscapeString(anchorDesc) + "而<b>非</b>事件时刻。" +
		"本时间线只列采集到的原值，不做推断或插值。</p>\n")
	sb.WriteString("<p class=\"note\"><b>关于 <code>registry_last_write_time</code></b>：" +
		"它是该注册表键<b>最后一次被改动</b>的时间（同一键下的多个值共享这个时间），" +
		"而<b>不是</b>\"这个启动项被人加上去的时刻\"——系统自身在开机、更新、安装时也会改写这类键。" +
		"请把它当作<b>线索</b>（可疑键在什么时候变的），而不是结论。</p>\n")
	writeSectionClose(sb)
}

// buildReportHTML 生成 report.html（纯模板、无外部资源、无 JavaScript）。
//
// 报告可能在隔离网络中直接打开或打印，因此不引用任何外部依赖；
// 所有动态文本都经 html.EscapeString 转义，严重程度经白名单映射为 CSS 令牌。
func buildReportHTML(meta *storage.SnapshotMeta, host map[string]string, collection map[string]int, high, med, low int, findings []reportFinding, prov *collectionProvenance, relations []storage.RelationRow, labels map[string]string, scores []entityScore, tl *timeline.Result, pidNames map[uint32]string, sup suppressionStats) string {
	var sb strings.Builder
	sb.WriteString("<!DOCTYPE html>\n<html lang=\"zh-CN\">\n<head>\n<meta charset=\"utf-8\">\n")
	sb.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
	sb.WriteString("<title>Easy_Trace 调查报告</title>\n<style>")
	sb.WriteString(reportCSS)
	if tl != nil {
		sb.WriteString(reportTimelineCSS)
	}
	sb.WriteString("</style>\n</head>\n<body id=\"top\">\n")

	// 顶部横幅
	sb.WriteString("<header class=\"masthead\">\n<div class=\"mast-inner\">\n")
	sb.WriteString("<p class=\"eyebrow\">Easy_Trace · 离线主机调查</p>\n")
	sb.WriteString("<h1 class=\"title\">Easy_Trace 调查报告</h1>\n")
	// 页头先给人话（谁、什么时候），再给快照 ID（证据溯源用）。原先把一串 ID 放在最显眼处，
	// 第一次读的人不知道那是什么（2026-10-15 反馈）。
	hostLine := host["hostname"]
	if hostLine == "" {
		hostLine = "（未采到主机名）"
	}
	if osName := host["os"]; osName != "" {
		hostLine += " · " + osName
	}
	sb.WriteString("<p class=\"subtitle\">主机 " + html.EscapeString(hostLine) +
		" · " + html.EscapeString(prov.timeSentence()) + "</p>\n")
	sb.WriteString("<p class=\"provenance\">快照 <code>" + html.EscapeString(meta.SnapshotID) +
		"</code>（本次报告只含这一份快照；快照＝某一时刻采集到的主机状态记录）</p>\n")
	sb.WriteString("</div>\n</header>\n")

	sb.WriteString("<main class=\"wrap\">\n")

	// 摘要：给第一次读这份报告的人（这是什么 / 要不要处理 / 能说明什么 / 怎么读 / 术语）
	writeSummarySection(&sb, host, groupFindings(findings), high, med, low, tl != nil, sup, prov)

	// 统计卡片
	sb.WriteString("<section class=\"summary\">\n")
	writeStatCard(&sb, "stat-total", "调查线索", "Findings", len(findings))
	writeStatCard(&sb, "stat-high", "高", "HIGH", high)
	writeStatCard(&sb, "stat-medium", "中", "MEDIUM", med)
	writeStatCard(&sb, "stat-low", "低", "LOW", low)
	sb.WriteString("</section>\n")

	// Host（默认展开：读者要先知道这是哪台机器）
	writeSectionOpen(&sb, "sec-host", "主机信息", "Host", true)
	sb.WriteString("<dl class=\"kv\">\n")
	for _, k := range []string{"hostname", "os", "os_build", "arch", "user", "collected"} {
		if v := host[k]; v != "" {
			label := hostLabels[k]
			if k == "collected" {
				// 快照时间戳不一定等于采集时刻，标签必须按真实来源命名。
				label = prov.timeLabel()
			} else if label == "" {
				label = k
			}
			sb.WriteString("<div><dt>" + label + " <span class=\"en\">" + html.EscapeString(k) +
				"</span></dt><dd>" + html.EscapeString(v) + "</dd></div>\n")
		}
	}
	sb.WriteString("<div><dt>时间来源 <span class=\"en\">timestamp_source</span></dt><dd><code>" +
		html.EscapeString(prov.timeSourceEN()) + "</code>（" + html.EscapeString(prov.timeNote()) +
		"）</dd></div>\n")
	sb.WriteString("</dl>\n")
	writeSectionClose(&sb)

	// 实体风险概览（按分数排序的对象清单；按所有者要求放在「调查线索」之前）
	writeEntityScoreSection(&sb, scores)

	// Findings（正文核心：默认展开）
	writeSectionOpen(&sb, "sec-findings", "调查线索", "Findings", true)
	sb.WriteString("<p class=\"lede\">共 " + fmt.Sprintf("%d", len(findings)) + " 条调查线索" +
		"<span class=\"pill pill-high\">高 <span class=\"en\">HIGH</span> " + fmt.Sprintf("%d", high) + "</span>" +
		"<span class=\"pill pill-medium\">中 <span class=\"en\">MEDIUM</span> " + fmt.Sprintf("%d", med) + "</span>" +
		"<span class=\"pill pill-low\">低 <span class=\"en\">LOW</span> " + fmt.Sprintf("%d", low) + "</span></p>\n")

	groups := groupFindings(findings)
	if len(findings) == 0 {
		sb.WriteString("<p class=\"empty\">未发现需要进一步调查的线索。</p>\n")
	} else {
		if len(groups) < len(findings) {
			sb.WriteString("<p class=\"note\">卡片已<b>按规则聚合</b>：同一条规则命中多处时只讲一次，" +
				"命中实体列在卡片内的表中（逐条清单见事件包 <code>findings.json</code>）。</p>\n")
		}
		if len(groups) > 1 {
			sb.WriteString("<nav class=\"toc\">\n<span class=\"toc-title\">本页线索 <span class=\"en\">Index</span></span>\n<ol>\n")
			for i, g := range groups {
				sb.WriteString("<li><a href=\"#f-" + fmt.Sprintf("%d", i+1) + "\">" +
					"<span class=\"badge badge-" + severityClass(g.Severity) + "\">[" +
					html.EscapeString(g.Severity) + "]</span> " + html.EscapeString(g.Title))
				if len(g.Members) > 1 {
					sb.WriteString(" <span class=\"en\">" + fmt.Sprintf("%d 处", len(g.Members)) + "</span>")
				}
				sb.WriteString("</a></li>\n")
			}
			sb.WriteString("</ol>\n</nav>\n")
		}
		for i, g := range groups {
			writeFindingGroupCard(&sb, i+1, g, labels, pidNames)
		}
	}
	writeSectionClose(&sb)

	// 关系与攻击链（数据来自 SQLite relations；不含任何主机访问）
	writeRelationsSection(&sb, relations, labels)

	// 时间线：只有事件包流程会传 tl（普通 report 传 nil → 不输出该区块）
	writeTimelineSection(&sb, tl)

	// 附录：采集范围与采集环境（供分析员核对；第一次读报告的人不需要先看这些）
	writeCollectionAppendix(&sb, meta, collection, prov)

	sb.WriteString("</main>\n")

	sb.WriteString("<footer class=\"foot\">\n")
	sb.WriteString("<p>本报告由 Easy_Trace 生成，仅列出基于本地规则的调查线索，不构成对主机或文件的定性结论。</p>\n")
	sb.WriteString("<p>报告可能包含主机名、用户名、文件路径与进程信息，请按内部证据保管流程保存与传递。打印前请先展开需要打印的折叠区块。</p>\n")
	sb.WriteString("<a class=\"to-top\" href=\"#top\">↑ 回到顶端</a>\n</footer>\n</body>\n</html>\n")
	return sb.String()
}
