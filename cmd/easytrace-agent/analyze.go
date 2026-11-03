package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"easytrace/internal/analyzer"
	"easytrace/internal/model"
	"easytrace/internal/storage"
)

// runAnalyze 处理 analyze 子命令（Step 10 Analyzer CLI 优化）：
//
//	easytrace analyze --db <path> --snapshot <snapshot_id> [-r|--rules <dir>]
//	                 [-jsonl] [-o <file>] [-silent] [-config <file>] [--summary]
//	                 [--severity low,high] [--rule <rule_id>] [--entity <entity_id>]
//
// 默认输出人类可读 Summary（Nuclei 风格）：Snapshot / Rules loaded / Findings /
// Severity 统计 / 每条线索详情。--jsonl 输出 Finding JSONL（SIEM/自动化/二次分析）。
// --severity / --rule / --entity 为展示层过滤（Step 12.2）：Analyzer 全量分析，
// 输出前收窄结果，支持重复 flag 与逗号分隔多值；不影响 Analyzer 命中逻辑。
// Analyzer 只读快照与规则，不采集、不联网、不写库。
func runAnalyze(args []string) error {
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	dbPath := fs.String("db", "easytrace.db", "SQLite 数据库路径")
	snapshotID := fs.String("snapshot", "", "要分析的快照 snapshot_id（默认最新快照）")
	rulesDir := fs.String("r", "", "规则目录；留空使用**内嵌规则包**（单 exe 即可用），指定则覆盖")
	fs.StringVar(rulesDir, "rules", "", "规则目录别名（-r 同义；留空用内嵌规则包）")
	jsonlOut := fs.Bool("jsonl", false, "输出 Finding JSONL（SIEM/自动化）")
	output := fs.String("o", "", "结果输出到新文件（默认 stdout，拒绝覆盖）")
	fs.StringVar(output, "output", "", "结果输出到新文件（默认 stdout，拒绝覆盖）")
	silent := fs.Bool("silent", false, "只输出线索结果，不输出 Banner/统计")
	config := fs.String("config", "", "配置文件（key=value，命令行参数优先）")
	summary := fs.Bool("summary", false, "输出规则命中统计到 stderr（兼容旧用法）")
	var sevFilter, ruleFilter, entityFilter stringList
	propagate := fs.Int("propagate", 0, "关联传导: 沿 spawn/launch/network_connect 最多扩散 N 跳（0=关闭）；传导项 rule_id 以 derived. 开头，不是独立检测")
	fs.Var(&sevFilter, "severity", "只展示指定严重程度（逗号分隔/可重复，如 low,high）")
	fs.Var(&ruleFilter, "rule", "只展示指定 rule_id（逗号分隔/可重复）")
	fs.Var(&entityFilter, "entity", "只展示指定 entity_id（逗号分隔/可重复）")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// -config 提供默认值；命令行显式指定的参数优先
	explicit := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
	if *config != "" {
		cfg, err := loadConfig(*config)
		if err != nil {
			return err
		}
		if !explicit["db"] && cfg["db"] != "" {
			*dbPath = cfg["db"]
		}
		if !explicit["r"] && !explicit["rules"] && cfg["rules"] != "" {
			*rulesDir = cfg["rules"]
		}
		if !explicit["snapshot"] && cfg["snapshot"] != "" {
			*snapshotID = cfg["snapshot"]
		}
		if !explicit["o"] && !explicit["output"] && cfg["output"] != "" {
			*output = cfg["output"]
		}
		if !explicit["jsonl"] && cfg["jsonl"] == "true" {
			*jsonlOut = true
		}
		if !explicit["silent"] && cfg["silent"] == "true" {
			*silent = true
		}
	}

	rules, rulesSource, err := loadRules(*rulesDir)
	if err != nil {
		return err
	}

	// 只读打开：analyze 不改数据库，不能建表、不能写 journal（证据介质可能只读）。
	db, err := storage.OpenReadOnly(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := storage.CheckSchema(db); err != nil {
		return err
	}

	// 默认快照 = 最新（ListSnapshots 按 created_at DESC）
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

	an, err := analyzer.NewAnalyzer(db, *snapshotID, rules)
	if err != nil {
		return err
	}
	results, err := an.AnalyzeWithContext()
	if err != nil {
		return err
	}
	// V0.3 关联传导（可选，默认关闭）：在直接命中之上叠加 derived.* 提示，
	// 放在过滤之前，保证 --severity/--rule/--entity 对传导项同样生效。
	if *propagate > 0 {
		results, err = an.PropagateFindings(results, analyzer.PropagateOptions{Hops: *propagate})
		if err != nil {
			return err
		}
	}
	// Step 12.2：展示层过滤（Analyzer 已全量分析，只收窄输出）
	results = applyFindingFilter(results, sevFilter, ruleFilter, entityFilter)
	if *summary {
		findings := make([]*model.Finding, 0, len(results))
		for _, r := range results {
			findings = append(findings, r.Finding)
		}
		s := an.Summarize(findings)
		fmt.Fprintf(os.Stderr, "Rules evaluated: %d\n", s.RulesEvaluated)
		fmt.Fprintf(os.Stderr, "Findings: %d\n\n", s.TotalFindings)
		for _, rc := range s.PerRule {
			fmt.Fprintf(os.Stderr, "%-40s %d\n", rc.RuleID, rc.Count)
		}
	}

	out := os.Stdout
	var outFile *os.File
	if *output != "" {
		outFile, err = createNewOutputFile(*output, 0o644)
		if err != nil {
			return err
		}
		defer outFile.Close()
		out = outFile
	}

	if *jsonlOut {
		for _, r := range results {
			line, err := analyzer.MarshalFinding(r.Finding)
			if err != nil {
				return err
			}
			fmt.Fprintln(out, string(line))
		}
		return nil
	}
	writeAnalyzeText(out, *snapshotID, len(rules), rulesSource, results, *silent)
	return nil
}

// writeAnalyzeText 输出人类可读分析结果（Step 10 Nuclei 风格）。
func writeAnalyzeText(out io.Writer, snapshotID string, ruleCount int, rulesSource string, results []*analyzer.AnalysisResult, silent bool) {
	if !silent {
		fmt.Fprintln(out, "Easy_Trace Analyzer")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Snapshot:")
		fmt.Fprintln(out, snapshotID)
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Rules loaded:")
		fmt.Fprintf(out, "%d\n", ruleCount)
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Rules source:")
		fmt.Fprintln(out, rulesSource)
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Findings:")
		fmt.Fprintf(out, "%d\n", len(results))
		fmt.Fprintln(out)
		if derived := countDerived(results); derived > 0 {
			fmt.Fprintln(out, "Derived (propagated, 由关系传导推导，非独立检测):")
			fmt.Fprintf(out, "%d\n", derived)
			fmt.Fprintln(out)
		}
		fmt.Fprintln(out, "Severity:")
		fmt.Fprintln(out)
		high, med, low := countSeverity(results)
		fmt.Fprintln(out, "HIGH:")
		fmt.Fprintf(out, "%d\n", high)
		fmt.Fprintln(out)
		fmt.Fprintln(out, "MEDIUM:")
		fmt.Fprintf(out, "%d\n", med)
		fmt.Fprintln(out)
		fmt.Fprintln(out, "LOW:")
		fmt.Fprintf(out, "%d\n", low)
		fmt.Fprintln(out)
	}
	for _, r := range results {
		fmt.Fprintf(out, "[%s]\n\n", severityLabel(r.Finding.Severity))
		fmt.Fprintln(out, findingDetailText(r))
		fmt.Fprintln(out, "-----------------")
		fmt.Fprintln(out)
	}
	if len(results) == 0 && !silent {
		fmt.Fprintln(out, "未发现需要进一步调查的线索。")
	}
}

// countDerived 统计传导提示条数（rule_id 以 derived. 前缀，不是独立检测）。
func countDerived(results []*analyzer.AnalysisResult) int {
	n := 0
	for _, r := range results {
		if r != nil && r.Finding != nil && strings.HasPrefix(r.Finding.RuleID, analyzer.DerivedRulePrefix) {
			n++
		}
	}
	return n
}

// countSeverity 统计各严重程度线索数（HIGH/MEDIUM/LOW，critical 归 HIGH）。
func countSeverity(results []*analyzer.AnalysisResult) (high, med, low int) {
	for _, r := range results {
		switch r.Finding.Severity {
		case "critical", "high":
			high++
		case "medium":
			med++
		default:
			low++
		}
	}
	return
}

// severityLabel 严重程度大写标签。
func severityLabel(s string) string {
	switch s {
	case "critical":
		return "CRITICAL"
	case "high":
		return "HIGH"
	case "medium":
		return "MEDIUM"
	case "low":
		return "LOW"
	}
	return strings.ToUpper(s)
}

// findingDetailText 格式化单条线索（Step 12.1，analyze / investigate / inspect 复用）：
// Rule → Severity → Entity → Why → Evidence → Next，逐行简洁，回答四个问题——
// 发现了什么（Rule/Title）、证据在哪里（Evidence）、为什么值得关注（Why）、
// 下一步如何调查（Next）。Evidence 为统一摘要（Process: PID/Image/CommandLine；
// File: Path/Hash/Signer；Network: Protocol/Local/State/PID），缺失字段显式
// Unavailable，不猜测。
// 数据来自 FindingContext（Step 8.3），措辞统一"调查线索"。
func findingDetailText(r *analyzer.AnalysisResult) string {
	f := r.Finding
	var ctx *analyzer.FindingContext
	if r.Context != nil {
		ctx = r.Context
	}
	var sb strings.Builder
	rule := f.RuleID
	if f.Title != "" {
		rule += " — " + f.Title
	}
	sb.WriteString("Rule: " + rule + "\n")
	sb.WriteString("Severity: " + severityLabel(f.Severity) + "\n")
	sb.WriteString("Entity: " + f.EntityID + "\n")
	why := f.Description
	if why == "" {
		why = f.Title
	}
	if why != "" {
		sb.WriteString("Why: " + why + "\n")
	}
	if ev := evidenceSummary(ctx); len(ev) > 0 {
		sb.WriteString("Evidence:\n")
		for _, line := range ev {
			sb.WriteString("  " + line + "\n")
		}
	} else if len(f.Evidence) > 0 {
		// 无 FindingContext 时的回退：原始 evidence 行（保持信息不丢失）
		sb.WriteString("Evidence:\n")
		for _, line := range f.Evidence {
			sb.WriteString("  " + line + "\n")
		}
	}
	if len(f.Advice) > 0 {
		sb.WriteString("Next: " + strings.Join(f.Advice, "；"))
	}
	return sb.String()
}

// loadConfig 读取 analyze 配置文件（key=value 每行，支持 db/rules/snapshot/
// output/jsonl/silent）。命令行参数优先于配置文件。
func loadConfig(path string) (map[string]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}
	cfg := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("配置文件格式错误: %q（应为 key=value）", line)
		}
		key := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(kv[1])
		switch key {
		case "db", "rules", "snapshot", "output", "jsonl", "silent":
			cfg[key] = val
		default:
			return nil, fmt.Errorf("配置文件未知键 %q（支持: db/rules/snapshot/output/jsonl/silent）", key)
		}
	}
	return cfg, nil
}
