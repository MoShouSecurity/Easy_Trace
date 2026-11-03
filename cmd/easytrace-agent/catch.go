package main

// catch.go 实现「痕迹留存」子命令（V0.3 Evidence 模块，命令名 catch）。
//
// 为什么必须是独立的一条命令：collect 时还没有 finding（finding 是 analyze 的产物），
// 而 report 明确承诺"纯离线、不访问主机"。所以"命中即自动抓"在现有架构里做不到。
// 这里把"再碰一次主机"变成**用户显式执行的第二次接触**：
//
//	collect → analyze → catch（显式）→ report -zip --evidence <dir>
//
// 边界（设计 docs/设计-痕迹留存.md `3）：只读打开命中项指向的文件；不执行任何被复制的
// 程序、不修改/不锁定源文件、不联网、不写系统位置、不覆盖已有条目；**不读其它进程内存**
// （进程内存 dump 已明确不做）。命令名 catch 取"把命中的痕迹抓下来"之意，与中文名
// 「痕迹留存」对应；目录与模块英文标识沿用冻结的 Evidence / evidence/。

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"easytrace/internal/analyzer"
	"easytrace/internal/evidence"
	"easytrace/internal/storage"
)

// severityRankOf 把 --min-severity 解析成严重程度权重（越小越严重）。
//
// 口径与报告一致：critical 归到 high 一档。
func severityRankOf(s string) (int, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "high", "critical":
		return 1, nil
	case "medium":
		return 2, nil
	case "low":
		return 3, nil
	}
	return 0, fmt.Errorf("未知的 --min-severity %q（支持: high / medium / low）", s)
}

// runCatch 处理 catch 子命令行。
func runCatch(args []string) error {
	fs := flag.NewFlagSet("catch", flag.ContinueOnError)
	dbPath := fs.String("db", "easytrace.db", "SQLite 数据库路径")
	snapshotID := fs.String("snapshot", "", "要留存的快照 snapshot_id（默认最新快照）")
	rulesDir := fs.String("r", "", "规则目录；留空使用**内嵌规则包**（单 exe 即可用），指定则覆盖")
	fs.StringVar(rulesDir, "rules", "", "规则目录别名（-r 同义；留空用内嵌规则包）")
	outDir := fs.String("out", "evidence", "新建证据目录（已有目录会拒绝）")
	fs.StringVar(outDir, "o", "evidence", "新建证据目录别名（-out 同义，已有目录会拒绝）")
	minSeverity := fs.String("min-severity", "medium", "只对不低于该严重程度的命中留存：high / medium / low")
	maxFiles := fs.Int("max-files", 0, "最多留存多少个文件（0=默认 200）")
	maxFileMB := fs.Int("max-file-mb", 0, "单文件大小上限 MiB（0=默认 64）")
	maxTotalMB := fs.Int("max-total-mb", 0, "合计大小上限 MiB（0=默认 512）")
	// 兼容旧命令行：这两个参数曾经控制 catch 是否跳过被白名单抑制的命中。
	// 现在 catch 绝不读取白名单（白名单只影响报告展示），显式传入时直接报错，
	// 避免使用者误以为“没加 --no-whitelist 就会漏证据”。
	whitelistFile := fs.String("w", "", "已废弃：catch 不再读取白名单（白名单只影响报告展示）")
	fs.StringVar(whitelistFile, "whitelist", "", "-w 同义（已废弃）")
	noWhitelist := fs.Bool("no-whitelist", false, "已废弃：catch 从不受白名单影响，无需此参数")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*whitelistFile) != "" || *noWhitelist {
		return fmt.Errorf("catch 不再读取白名单：白名单只影响报告展示，绝不能抑制证据留存；请移除 --whitelist/-w/--no-whitelist")
	}
	snapshotExplicit := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "snapshot" {
			snapshotExplicit = true
		}
	})
	rank, err := severityRankOf(*minSeverity)
	if err != nil {
		return err
	}
	lim := evidence.DefaultLimits()
	if *maxFiles > 0 {
		lim.MaxFiles = *maxFiles
	}
	if *maxFileMB > 0 {
		lim.MaxFileBytes = int64(*maxFileMB) << 20
	}
	if *maxTotalMB > 0 {
		lim.MaxTotalBytes = int64(*maxTotalMB) << 20
	}

	rules, rulesSource, err := loadRules(*rulesDir)
	if err != nil {
		return err
	}
	// 只读打开：catch 只读快照决定留存哪些文件，不写数据库（证据介质可能只读）。
	db, err := storage.OpenReadOnly(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := storage.CheckSchema(db); err != nil {
		return err
	}
	currentHost, currentHostErr := os.Hostname()
	currentHost = strings.TrimSpace(currentHost)

	if *snapshotID == "" {
		snaps, err := storage.ListSnapshots(db)
		if err != nil {
			return err
		}
		if len(snaps) == 0 {
			return fmt.Errorf("数据库中没有快照，请先执行 collect 或 snapshot import")
		}
		newest := snaps[0]
		// 默认选择必须绑定当前主机：数据库里可能同时有多台主机的快照，若默默
		// 选“最新”，会把另一台主机的命中当成本机文件抓取，manifest 却记在另一份
		// 快照名下——证据归属直接错位。显式 --snapshot 才允许跨主机（并给出警告）。
		if currentHostErr != nil || currentHost == "" {
			return fmt.Errorf("无法获取当前主机名（%v），不能确认最新快照 %s 属于本机；请用 --snapshot 显式选择",
				currentHostErr, newest.SnapshotID)
		}
		if strings.TrimSpace(newest.Hostname) == "" {
			return fmt.Errorf("最新快照 %s 未记录主机名，不能确认它来自本机 %q；请用 --snapshot 显式选择，或重新采集包含 host 实体的快照",
				newest.SnapshotID, currentHost)
		}
		if !sameHostName(newest.Hostname, currentHost) {
			return fmt.Errorf("最新快照 %s 来自主机 %q，当前主机是 %q；数据库可能混有多台主机的快照。请用 snapshot list 查看，并用 --snapshot 显式选择",
				newest.SnapshotID, newest.Hostname, currentHost)
		}
		*snapshotID = newest.SnapshotID
	}
	meta, err := storage.GetSnapshot(db, *snapshotID)
	if err != nil {
		return err
	}
	if meta == nil {
		return fmt.Errorf("快照 %s 不存在", *snapshotID)
	}
	if currentHostErr != nil || currentHost == "" {
		fmt.Fprintf(os.Stderr, "Warning: 无法获取当前主机名（%v），未能核对快照主机 %q。\n",
			currentHostErr, displayHostName(meta.Hostname))
	} else if strings.TrimSpace(meta.Hostname) == "" {
		fmt.Fprintf(os.Stderr, "Warning: 快照 %s 未记录主机名，无法核对它是否来自当前主机 %q。\n",
			meta.SnapshotID, currentHost)
	} else if !sameHostName(meta.Hostname, currentHost) {
		if !snapshotExplicit {
			// 防御性：默认选择路径已在上面拒绝；以后改代码也不允许无提示跨主机。
			return fmt.Errorf("快照 %s 来自主机 %q，当前主机是 %q；跨主机留存必须用 --snapshot 显式选择",
				meta.SnapshotID, meta.Hostname, currentHost)
		}
		fmt.Fprintf(os.Stderr, "Warning: 快照主机 %q 与当前主机 %q 不一致；这是由 --snapshot 显式选择的跨主机留存，manifest 会记录快照来源。\n",
			meta.Hostname, currentHost)
	}
	fmt.Fprintf(os.Stderr, "Snapshot: %s  host=%s  timestamp=%s\n",
		meta.SnapshotID, displayHostName(meta.Hostname), meta.Timestamp)

	// 这条命令会**第二次接触主机**，必须让人在跑之前就知道它要做什么。
	fmt.Fprintln(os.Stderr, "Notice: catch（痕迹留存）会只读打开命中项指向的文件并复制到证据目录。")
	fmt.Fprintln(os.Stderr, "It does not execute those files, modify or lock them, or use the network.")
	fmt.Fprintf(os.Stderr, "Limits: %d file(s), %d MiB per file, %d MiB total.\n",
		lim.MaxFiles, lim.MaxFileBytes>>20, lim.MaxTotalBytes>>20)
	fmt.Fprintf(os.Stderr, "Rules: %s\n", rulesSource)

	an, err := analyzer.NewAnalyzer(db, *snapshotID, rules)
	if err != nil {
		return err
	}
	results, err := an.AnalyzeWithContext()
	if err != nil {
		return err
	}
	entities, err := storage.GetEntities(db, *snapshotID)
	if err != nil {
		return err
	}
	byID := make(map[string]storage.EntityRow, len(entities))
	for _, e := range entities {
		byID[e.EntityID] = e
	}

	var sources []evidence.Source
	var noPathN, belowN int
	for _, r := range results {
		if sevRank(severityLabel(r.Finding.Severity)) > rank {
			belowN++
			continue
		}
		row, ok := byID[r.Finding.EntityID]
		if !ok {
			noPathN++
			continue
		}
		path, ok := evidence.ExtractPath(row.EntityType, row.DataJSON)
		if !ok {
			// 该实体类型本身不指向文件（network / event / user / driver / task …），正常。
			noPathN++
			continue
		}
		// 不再按路径去重：同一文件被多条命中指向时，evidence.Run 会按内容只复制
		// 一份（duplicate），但 manifest 会保留每一条命中的规则/实体归属，避免
		// “证据只有一个来源”的链式证据缺口。白名单也不在这里过滤：报告可以抑制
		// 展示，证据留存必须看到全部命中。
		sources = append(sources, evidence.Source{
			EntityID:   r.Finding.EntityID,
			EntityType: row.EntityType,
			RuleID:     r.Finding.RuleID,
			Severity:   severityLabel(r.Finding.Severity),
			Path:       path,
		})
	}

	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "命中 %d 条；候选目标 %d 个（低于 --min-severity %s 的 %d 条、不指向文件的 %d 条；内容重复只复制一份，manifest 保留各条归属）\n",
		len(results), len(sources), *minSeverity, belowN, noPathN)
	if len(sources) == 0 {
		fmt.Fprintln(os.Stderr, "没有可留存的目标，未创建证据目录。")
		return nil
	}

	outAbs, err := ensureNewOutputDir(*outDir)
	if err != nil {
		return err
	}
	host, _ := os.Hostname() // 尽力而为：取不到时字段留空，不阻断留存
	kept, runErr := evidence.RunWithProvenance(outAbs, sources, lim, evidence.Provenance{
		ToolVersion:  cliVersion,
		Host:         host,
		SnapshotHost: meta.Hostname,
		Operator:     operatorLabel(),
		Database:     *dbPath,
		SnapshotID:   *snapshotID,
		AcquiredAt:   time.Now().UTC(),
	})

	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "痕迹留存（catch）:")
	for _, r := range kept {
		line := fmt.Sprintf("  %-22s %-44s %d bytes", r.Status, r.Name, r.Bytes)
		if r.Reason != "" {
			line += "  " + r.Reason
		}
		fmt.Fprintln(os.Stderr, line)
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Evidence directory:")
	fmt.Fprintln(os.Stderr, outAbs)
	fmt.Fprintln(os.Stderr, "Manifest:")
	fmt.Fprintln(os.Stderr, outAbs+"\\"+evidence.ManifestName)
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "把证据打进事件包（report 只读该目录，不访问主机）:")
	fmt.Fprintf(os.Stderr, "  Easy_Trace.exe report --db %s --snapshot %s -o <新的报告目录> -zip --evidence %s\n",
		*dbPath, *snapshotID, outAbs)
	return runErr
}

// sameHostName 比较主机名（Windows 主机名大小写不敏感）。
func sameHostName(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

// displayHostName 用于终端提示：缺失主机名必须明确写“未记录”，不能留空。
func displayHostName(host string) string {
	if h := strings.TrimSpace(host); h != "" {
		return h
	}
	return "未记录"
}
