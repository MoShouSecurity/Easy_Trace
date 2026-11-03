package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"easytrace/internal/analyzer"
	"easytrace/internal/storage"
)

// runInvestigate 处理 investigate 子命令（Step 10，替代 GUI 详情查看）：
//
//	easytrace investigate -id <finding_id> [--db <path>] [-r|--rules <dir>]
//
// 复用 Step 8.3 FindingContext：在全部快照中定位 finding_id，重新分析该快照
// 并输出该线索的完整调查上下文（Rule/Severity/Entity/Why/Evidence/Next +
// Next Investigation 动作引导，Step 12.2）。只读，不修改快照。
func runInvestigate(args []string) error {
	fs := flag.NewFlagSet("investigate", flag.ContinueOnError)
	dbPath := fs.String("db", "easytrace.db", "SQLite 数据库路径")
	id := fs.String("id", "", "调查线索 finding_id")
	fs.StringVar(id, "finding", "", "调查线索 finding_id 别名（--id 同义）")
	rulesDir := fs.String("r", "", "规则目录；留空使用**内嵌规则包**（单 exe 即可用），指定则覆盖")
	fs.StringVar(rulesDir, "rules", "", "规则目录别名（-r 同义；留空用内嵌规则包）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		return fmt.Errorf("用法: investigate -id <finding_id> [--db <path>] [-r <rules_dir>]")
	}

	rules, _, err := loadRules(*rulesDir)
	if err != nil {
		return err
	}

	// 只读打开：investigate 重新分析定位 finding，不写数据库。
	db, err := storage.OpenReadOnly(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := storage.CheckSchema(db); err != nil {
		return err
	}

	// 定位 finding_id 所属快照：遍历全部快照重新分析并匹配。
	// （analyze 不落库，findings 表只在导入时保存旧数据——不可依赖。）
	// finding_id 稳定 = sha256(snapshot|rule|entity)，不同快照结果不同。
	snaps, err := storage.ListSnapshots(db)
	if err != nil {
		return err
	}
	for _, snap := range snaps {
		an, err := analyzer.NewAnalyzer(db, snap.SnapshotID, rules)
		if err != nil {
			return err
		}
		results, err := an.AnalyzeWithContext()
		if err != nil {
			return err
		}
		for _, r := range results {
			if r.Finding.FindingID == *id {
				return writeInvestigate(os.Stdout, r)
			}
		}
	}
	return fmt.Errorf("未找到调查线索 %q（请确认该 finding_id 来自本机快照分析结果）", *id)
}

// writeInvestigate 输出单条线索的调查上下文（Step 12.2）：
// Finding ID + 六段线索（Rule/Severity/Entity/Why/Evidence/Next）+ Next Investigation
// 动作引导列表（每条一行，简洁可执行，回答"这个 Finding 下一步做什么"）。
func writeInvestigate(out io.Writer, r *analyzer.AnalysisResult) error {
	fmt.Fprintln(out, "Finding")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Finding ID:")
	fmt.Fprintln(out, r.Finding.FindingID)
	fmt.Fprintln(out)
	fmt.Fprintln(out, findingDetailText(r))
	if steps := nextInvestigation(r); len(steps) > 0 {
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Next Investigation:")
		for _, s := range steps {
			fmt.Fprintln(out, "  - "+s)
		}
	}
	return nil
}
