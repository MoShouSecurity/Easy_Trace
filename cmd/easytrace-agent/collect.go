package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"time"

	"easytrace/internal/collectionmeta"
	"easytrace/internal/collector"
	"easytrace/internal/collector/driver"
	"easytrace/internal/collector/event"
	"easytrace/internal/collector/execution"
	"easytrace/internal/collector/file"
	"easytrace/internal/collector/host"
	"easytrace/internal/collector/network"
	"easytrace/internal/collector/persistence"
	"easytrace/internal/collector/prefetch"
	"easytrace/internal/collector/process"
	"easytrace/internal/collector/registry"
	"easytrace/internal/collector/runtime"
	"easytrace/internal/collector/service"
	"easytrace/internal/collector/task"
	"easytrace/internal/collector/user"
	"easytrace/internal/output"
	"easytrace/internal/platform/privilege"
	"easytrace/internal/protocol"
	"easytrace/internal/storage"
)

// runCollect 处理 collect 子命令（Step 10 快速应急采集）：
//
//	easytrace collect [--module all|host|process|...|file] [--mode basic|deep|forensic]
//	                 [--pid <pid>] [--db <path>]
//	                 [--path <dir> ...] [--recent-hours <N>] [--max-files <N>] [--depth <N>]
//
// --module all（默认）时逐模块实时展示阶段进度，采集完成后自动导入 SQLite
// 创建快照。JSONL 数据流始终输出到 stdout（管道/重定向兼容）。
func runCollect(args []string) error {
	fs := flag.NewFlagSet("collect", flag.ContinueOnError)
	module := fs.String("module", "all", "采集模块: host, process, network, persistence, service, task, driver, user, file, registry, event, prefetch, execution, all（driver 在 all 中；file 需 --path+deep；registry 需 --key；event 按通道+事件ID白名单只读解析事件日志，不在 all 中；prefetch 只读解析 %SystemRoot%\\Prefetch\\*.pf 文件头，通常需要管理员，不在 all 中；execution 只读执行痕迹：basic 采 UserAssist/BAM/DAM/RecentDocs，deep 追加 PowerShell 历史与 Recent LNK，不在 all 中）")
	pid := fs.Uint("pid", 0, "process 模块: 仅采集指定 PID 的进程 (0=全部)")
	mode := fs.String("mode", "basic", "采集模式: basic（默认，低暴露事实采集）/ deep（补充证据）/ forensic（最大化）")
	dbPath := fs.String("db", "easytrace.db", "SQLite 数据库路径（--module all 自动导入创建快照）")
	evtxDir := fs.String("evtx", "", "同时把白名单事件日志通道导出为原始 .evtx 到**新**目录（阶段 A；在快照采集之后执行，单通道失败只警告）")
	// file 模块（P1-9）：只扫**显式指定**的目录，不提供默认目录。
	var filePaths stringList
	fs.Var(&filePaths, "path", "file 模块: 要枚举的目录（可重复或逗号分隔；必须与 --module file 一起使用）")
	recentHours := fs.Int("recent-hours", 0, "file 模块: 只保留最近 N 小时内修改过的文件（0=不过滤）")
	maxFiles := fs.Int("max-files", 0, "file 模块: 最多输出多少条 file 实体（0=默认 5000）")
	depth := fs.Int("depth", 0, "file 模块: 目录递归深度上限（0=默认 8）")
	var registryKeys stringList
	fs.Var(&registryKeys, "key", "registry 模块: 要枚举的注册表键（可重复或逗号分隔，如 HKLM\\SOFTWARE\\X；必须与 --module registry 一起使用）")
	maxValues := fs.Int("max-values", 0, "registry 模块: 最多输出多少条 registry 实体（0=默认 5000）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Step 2.2 收口：唯一模式入口 --mode，Runtime 统一授权；不再有 Collector 私有深度参数。
	cm, err := parseMode(*mode)
	if err != nil {
		return err
	}
	// Step 12.3：Deep/Forensic 采集行为透明提示（仅 stderr，绝不污染 stdout JSONL）
	printModeNotice(*mode, os.Stderr)
	rt := runtime.New(cm)
	// --db / --pid 是否被**显式**指定（默认值不算）。
	dbExplicit, pidExplicit := false, false
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "db":
			dbExplicit = true
		case "pid":
			pidExplicit = true
		}
	})
	// --pid 只在 process 单模块下有意义。旧行为是接受参数但不作限制、照常采集
	// 整机——操作者会误以为采集范围已被收窄，属于范围/隐私预期错误。这里显式拒绝，
	// 而不是静默忽略；0 仍表示“全部进程”，与默认行为一致。
	if pidExplicit && *pid > math.MaxUint32 {
		return fmt.Errorf("--pid 超出范围：%d（有效值 0-%d，0 表示全部）", *pid, uint64(math.MaxUint32))
	}
	if pidExplicit && *module != "process" {
		return fmt.Errorf("--pid 只能与 --module process 一起使用（当前 --module %s 不会按 PID 收窄采集范围）", *module)
	}

	if len(filePaths) > 0 && *module != "file" {
		return fmt.Errorf("--path 只能与 --module file 一起使用（当前 --module %s）", *module)
	}
	if len(registryKeys) > 0 && *module != "registry" {
		return fmt.Errorf("--key 只能与 --module registry 一起使用（当前 --module %s）", *module)
	}
	// 采集（快照）永远先于 EVTX 导出：事件日志导出要读 Security 通道，非管理员
	// 必然失败；绝不能让“日志导出不完整”变成“连快照都没有”。
	if *module == "all" {
		return runCollectWithEvtx(func() error { return collectAll(rt, *mode, *dbPath) }, *evtxDir)
	}

	step, err := singleStep(*module, rt, collectOptions{
		pid:          *pid,
		filePaths:    filePaths,
		recentHours:  *recentHours,
		maxFiles:     *maxFiles,
		depth:        *depth,
		registryKeys: registryKeys,
		maxValues:    *maxValues,
	})
	if err != nil {
		return err
	}
	// 单模块默认只把事实 JSONL 写到 stdout；但**显式**传入 --db 时必须真的导入，
	// 否则就是"接受参数却静默忽略"，会让人以为快照已创建。
	if !dbExplicit {
		return runCollectWithEvtx(func() error { return collectAndWrite(step.c) }, *evtxDir)
	}
	fmt.Fprintln(os.Stderr, "Easy_Trace "+cliVersion)
	printPrivilegeBanner(os.Stderr, privilege.Detect())
	return runCollectWithEvtx(func() error { return collectSteps([]collectStep{step}, *mode, *dbPath) }, *evtxDir)
}

// evtxReportFn 是 collect 内 EVTX 导出的注入点（测试用 fake 验证顺序与降级）。
var evtxReportFn = reportEvtxExport

// runCollectWithEvtx 先执行采集（快照），再执行可选的 EVTX 导出。
//
// 顺序不可颠倒：EVTX 是独立证据，非管理员读不到 Security 属于常态。先采集
// 并创建快照，事件日志的问题只影响警告；采集本身的错误优先返回，避免被
// EVTX 的错误掩盖。
func runCollectWithEvtx(collect func() error, evtxDir string) error {
	collectErr := collect()
	if evtxDir == "" {
		return collectErr
	}
	evtxErr := evtxReportFn(evtxDir)
	if collectErr != nil {
		if evtxErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: 事件日志导出同样失败: %v\n", evtxErr)
		}
		return collectErr
	}
	return evtxErr
}

// collectOptions 收集单模块采集的选项（目前只有 file 模块会用到后四项）。
type collectOptions struct {
	pid          uint
	filePaths    []string
	recentHours  int
	maxFiles     int
	depth        int
	registryKeys []string
	maxValues    int
}

// singleStep 为单模块采集构造采集步骤（名称/单位与 collectAll 保持一致）。
func singleStep(module string, rt *runtime.Runtime, opt collectOptions) (collectStep, error) {
	switch module {
	case "host":
		return collectStep{"Host", "entities", host.New(rt)}, nil
	case "driver":
		// 只读枚举已加载内核驱动模块（DriverQuery 在 Basic/Deep/Forensic 均授予）。
		return collectStep{"Driver", "drivers", driver.New(rt)}, nil
	case "registry":
		// 只读枚举显式指定键下的值（RegistryQuery 在 Basic 已授予）。
		return collectStep{"Registry", "values", registry.New(rt).
			WithKeys(opt.registryKeys...).
			WithDepth(opt.depth).
			WithMaxValues(opt.maxValues)}, nil
	case "file":
		// 只扫显式指定的目录；Basic 模式会被采集器的 ReadFile 门卫明确拒绝。
		return collectStep{"File", "files", file.New(rt).
			WithPaths(opt.filePaths...).
			WithRecentHours(opt.recentHours).
			WithMaxFiles(opt.maxFiles).
			WithDepth(opt.depth)}, nil
	case "event":
		// 日志阶段 B：按通道 + 事件 ID 白名单只读解析事件（EventQuery 在 Basic 已授予）。
		// 刻意不进 --module all：非管理员读 Security 通道会被拒（access_denied），
		// 那会让默认采集变成"不完整"，因此改为显式请求。
		return collectStep{"Event", "events", event.New(rt)}, nil
	case "prefetch":
		// 只读解析 %SystemRoot%\Prefetch\*.pf 文件头（PrefetchQuery 在 Basic 已授予）。
		// 同样刻意不进 --module all：读取 Prefetch 目录通常需要管理员，且
		// Prefetch 在部分主机上被策略禁用，显式请求才能如实报告"有没有采到"。
		return collectStep{"Prefetch", "entries", prefetch.New(rt)}, nil
	case "execution":
		// 只读执行痕迹：UserAssist/BAM/DAM/RecentDocs（RegistryQuery，Basic）+
		// PowerShell 历史/Recent LNK（ReadFile，Deep 起）。BAM/DAM 通常需要管理员，
		// 深采会读取用户文件，因此刻意不进 --module all。
		return collectStep{"Execution", "traces", execution.New(rt)}, nil
	case "process":
		c := process.New(rt)
		if opt.pid > 0 {
			c = c.WithPID(uint32(opt.pid))
		}
		return collectStep{"Process", "entities", c}, nil
	case "network":
		return collectStep{"Network", "connections", network.New(rt)}, nil
	case "persistence":
		return collectStep{"Persistence", "entries", persistence.New(rt)}, nil
	case "service":
		return collectStep{"Service", "services", service.New(rt)}, nil
	case "task":
		return collectStep{"Task", "tasks", task.New(rt)}, nil
	case "user":
		return collectStep{"User", "users", user.New(rt)}, nil
	}
	return collectStep{}, fmt.Errorf("未知模块 %q（当前支持: host, process, network, persistence, service, task, driver, user, file, registry, event, prefetch, execution, all）", module)
}

// printModeNotice 输出 Deep/Forensic 采集行为提示到 stderr（Step 12.3：
// 行为透明，安全软件可能监控；Process Basic 不读目标 EXE、不哈希、不验签）。
// 这不代表所有 Basic Collector 零文件操作，例如 Task 仍读取任务 XML。
func printModeNotice(mode string, w io.Writer) {
	if mode == "deep" || mode == "forensic" {
		fmt.Fprintln(w, "Notice: deep/forensic collection reads process files, computes hashes,")
		fmt.Fprintln(w, "and verifies signatures for targeted processes.")
		fmt.Fprintln(w, "The file module (--module file) reads file metadata and hashes files in the directories you pass via --path.")
		fmt.Fprintln(w, "Security products may monitor this activity.")
	}
}

// parseMode 解析 --mode 参数为 CollectionMode（Step 2.2 唯一模式入口）。
func parseMode(s string) (runtime.CollectionMode, error) {
	switch s {
	case "", "basic":
		return runtime.Basic, nil
	case "deep":
		return runtime.Deep, nil
	case "forensic":
		return runtime.Forensic, nil
	}
	return runtime.Basic, fmt.Errorf("未知采集模式 %q（支持: basic / deep / forensic）", s)
}

// stepTimeout 是单个采集模块的墙钟超时上限（设计原则 P3「Agent 绝不崩溃」）。
// 默认 10 分钟——正常模块远低于此；这是"某个模块卡死也不能拖住整次采集"的
// 兜底，不是性能目标。声明为 var 便于测试用极小值验证。
var stepTimeout = 10 * time.Minute

// stepOutcome 是 runStep 的返回值载体（goroutine 与主流程之间传递）。
type stepOutcome struct {
	res *collector.Result
	err error
}

// runStep 执行单个采集步骤，把 **panic** 与 **超时** 都转成显式错误。
//
// 设计原则 P3：模块内部的错误、panic 或卡死都不应让整次采集崩掉或永久挂起。
// 超时后该模块结果整体丢弃（无法安全中断已在运行的采集逻辑），并如实报告为
// 失败——不伪造空结果。
func runStep(st collectStep, timeout time.Duration) (*collector.Result, error) {
	done := make(chan stepOutcome, 1)
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				done <- stepOutcome{err: fmt.Errorf("模块 panic 已被拦截: %v", rec)}
			}
		}()
		res, err := st.c.Collect()
		done <- stepOutcome{res: res, err: err}
	}()
	select {
	case o := <-done:
		return o.res, o.err
	case <-time.After(timeout):
		return nil, fmt.Errorf("超过模块超时上限 %s，结果丢弃", timeout)
	}
}

// collectStep 定义一个采集阶段（展示用名称 + 统计单位 + Collector）。
type collectStep struct {
	name string
	unit string
	c    collector.Collector
}

// collectAll 逐模块采集（Step 10）：实时阶段展示 → JSONL 输出 stdout →
// 自动导入 SQLite 创建快照。单模块失败不中断（能采多少采多少），
// 最后展示 Snapshot created / Database / Completed。
func collectAll(rt *runtime.Runtime, mode, dbPath string) error {
	steps := allSteps(rt)
	fmt.Fprintln(os.Stderr, "Easy_Trace "+cliVersion)
	printPrivilegeBanner(os.Stderr, privilege.Detect())
	return collectSteps(steps, mode, dbPath)
}

// allSteps 返回 --module all 的模块清单。
//
// 刻意**不含** file / registry / event / prefetch / execution：它们都要显式参数
// 或更高权限（file 需 --path+deep、registry 需 --key、event 读 Security 通道需管理员、
// prefetch 通常需管理员、execution 的 BAM 与深采用户文件需要管理员/Deep），
// 放进 all 会让默认采集变成"不完整"。
func allSteps(rt *runtime.Runtime) []collectStep {
	return []collectStep{
		{"Host", "entities", host.New(rt)},
		{"Process", "entities", process.New(rt)},
		{"Network", "connections", network.New(rt)},
		{"Persistence", "entries", persistence.New(rt)},
		{"Service", "services", service.New(rt)},
		{"Task", "tasks", task.New(rt)},
		{"Driver", "drivers", driver.New(rt)},
		{"User", "users", user.New(rt)},
	}
}

// collectSteps 复用真实输出/导入链路，测试注入 fake Collector，不触发权限或主机查询。
func collectSteps(steps []collectStep, mode, dbPath string) error {
	// stdout 是终端时进入人类可读模式：隐藏逐条 JSONL，展示模块进度与摘要；
	// JSONL 仍写入临时文件并导入 SQLite，数据链路不变。管道/重定向保持原 JSONL。
	human := stdoutIsTerminal()
	interactive := human && stderrIsTerminal()
	ui := newCollectUI(os.Stderr, len(steps), human, interactive)
	defer ui.close()
	ui.header(mode, dbPath)

	tmp, err := os.CreateTemp("", "easytrace-collect-*.jsonl")
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %w", err)
	}
	tmpPath := tmp.Name()
	tmpClosed := false
	// tmpRemove 仅在“导入成功”或“临时文件为空”时为 true。任何导入前失败都必须
	// 保留临时 JSONL：终端模式下它是采集结果的唯一副本（stdout 不写 JSONL）。
	tmpRemove := true
	defer func() {
		if !tmpClosed {
			_ = tmp.Close()
		}
		if tmpRemove {
			_ = os.Remove(tmpPath)
			_ = collectionmeta.RemoveArtifact(tmpPath)
		}
	}()
	closeTmp := func() error {
		if tmpClosed {
			return nil
		}
		tmpClosed = true
		if err := tmp.Sync(); err != nil {
			_ = tmp.Close()
			return err
		}
		return tmp.Close()
	}

	// 采集元数据必须在模块开始前取时间、取权限；finish 在调用方报告完成时取。
	// 它只写 sidecar，不进入协议/JSONL。
	startedAt := time.Now().UTC()
	privInfo := privilege.Detect()
	var runMeta *collectionmeta.Meta
	runMetaWritten := false
	writeRunMeta := func(finished time.Time) error {
		if runMetaWritten {
			return nil
		}
		if runMeta == nil {
			runMeta = runCollectionMeta(mode, startedAt, finished, privInfo)
		}
		if err := collectionmeta.WriteArtifact(tmpPath, runMeta); err != nil {
			return err
		}
		runMetaWritten = true
		return nil
	}

	fail := func(cause error) error {
		_ = closeTmp()
		sidecarErr := writeRunMeta(time.Now().UTC())
		kept, sidecar, warning := preserveCollectArtifacts(tmpPath, dbPath)
		if kept == "" {
			if warning != nil {
				tmpRemove = false
				return fmt.Errorf("%w；%v；原始 JSONL 仍在 %s", cause, warning, tmpPath)
			}
			if sidecarErr != nil {
				return fmt.Errorf("%w；采集元数据写入失败: %v", cause, sidecarErr)
			}
			return cause
		}
		tmpRemove = false
		note := ""
		switch {
		case sidecar != "":
			note = "；采集元数据: " + sidecar
		case sidecarErr != nil:
			note = fmt.Sprintf("；采集元数据未写入（%v）", sidecarErr)
		case warning != nil:
			note = fmt.Sprintf("；采集元数据未一并保留（%v）", warning)
		}
		return fmt.Errorf("%w；未导入的采集结果已保留: %s%s", cause, kept, note)
	}
	var stream io.Writer = tmp
	if !human {
		stream = io.MultiWriter(os.Stdout, tmp)
	}
	w := output.NewWriter(stream)

	failed := 0
	firstFail := ""
	totalEntities := 0
	// relation_id 命名空间隔离：Collector 各自从 rel_0001 起编号（冻结设计），
	// 合并为一份 JSONL 时重名会违反 (snapshot_id, relation_id) 唯一约束；
	// CLI 合并层用共享分配器确定性改名（analyzer 依赖 source/target entity_id
	// 而非 relation_id，语义不受影响）。改名后仍冲突会自动递增后缀，绝不丢事实。
	relIDs := collector.NewRelationIDAllocator()
	for i, st := range steps {
		ui.startModule(i, st.name)
		start := time.Now()
		res, err := runStep(st, stepTimeout)
		if res == nil && err == nil {
			err = fmt.Errorf("采集返回空结果")
		}
		ui.finishModule(res, err, time.Since(start), st.unit)
		if err != nil {
			if firstFail == "" {
				firstFail = err.Error()
			}
			failed++
		}
		if res == nil {
			continue
		}
		// 协议校验后写入（任一行非法即失败——数据必须符合协议）
		for _, e := range res.Entities {
			if err := protocol.ValidateEntity(e); err != nil {
				return fail(err)
			}
			if err := w.Write(e); err != nil {
				return fail(err)
			}
		}
		for _, u := range res.EntityUpdates {
			if err := protocol.ValidateEntityUpdate(u); err != nil {
				return fail(err)
			}
			if err := w.Write(u); err != nil {
				return fail(err)
			}
		}
		for _, r := range res.Relations {
			if err := protocol.ValidateRelation(r); err != nil {
				return fail(err)
			}
			relIDs.Allocate(st.name, r)
			// 改名后必须重新校验：改名不能产生新的非法 ID。
			if err := protocol.ValidateRelation(r); err != nil {
				return fail(err)
			}
			if err := w.Write(r); err != nil {
				return fail(err)
			}
		}
		totalEntities += len(res.Entities)
	}
	// 先把 JSONL 落稳，再导入；导入读取的是已关闭、已 fsync 的完整文件。
	if err := closeTmp(); err != nil {
		return fail(fmt.Errorf("关闭临时 JSONL 失败: %w", err))
	}

	if totalEntities == 0 && failed > 0 {
		if human {
			ui.summary(nil, mode, dbPath, failed)
		}
		return fail(fmt.Errorf("未采集到实体且有 %d 个模块失败，未生成快照（首个失败: %s）", failed, firstFail))
	}

	// 采集结束时刻与采集进程权限在导入前落盘：导入只读这份记录，不能再用
	// “导入这一刻 / 当前进程权限”冒充采集时状态。sidecar 写失败不阻止导入，
	// 但必须明确提示；数据库旁仍会写入本次内存中的采集元数据。
	if err := writeRunMeta(time.Now().UTC()); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: 采集元数据写入失败: %v（继续导入）\n", err)
	}

	// 自动导入 SQLite 创建快照
	db, err := storage.Open(dbPath)
	if err != nil {
		return fail(fmt.Errorf("打开数据库失败: %w", err))
	}
	defer db.Close()
	if err := storage.InitSchema(db); err != nil {
		return fail(err)
	}
	imported, err := storage.ImportJSONLWithOptions(db, tmpPath, storage.ImportOptions{
		Mode:         mode,
		AgentVersion: cliVersion,
		Collection:   runMeta,
	})
	if err != nil {
		return fail(fmt.Errorf("导入快照失败: %w", err))
	}
	meta := imported.Meta
	// 快照已提交；此后的元数据失败不能走 fail（那会再保留一份重复 JSONL），
	// 但必须显式返回：没有 sidecar 的报告只能显示“未记录”。
	if err := writeSnapshotCollectionMeta(dbPath, meta, runMeta,
		imported.TimestampSource, cliVersion); err != nil {
		return fmt.Errorf("快照已保存（%s），但采集元数据写入失败: %w", meta.SnapshotID, err)
	}

	if human {
		ui.summary(meta, mode, dbPath, failed)
	} else {
		fmt.Fprintln(os.Stderr, "Snapshot created:")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, meta.SnapshotID)
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Database:")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, dbPath)
		fmt.Fprintln(os.Stderr)
	}
	if failed > 0 {
		fmt.Fprintf(os.Stderr, "Completed with %d module(s) failed（快照已保存，可继续分析）\n", failed)
		return fmt.Errorf("采集不完整: %d 个模块失败，快照已保存", failed)
	}
	if !human {
		fmt.Fprintln(os.Stderr, "Completed.")
	}
	return nil
}

// preserveCollectJSONL 在导入前失败时把临时 JSONL 保留到数据库同目录。
// 终端模式下 stdout 不输出 JSONL，因此这个文件就是唯一采集副本；只有导入成功
// 才允许删除。跨卷时 os.Rename 会失败，退化为排他复制，原临时文件仍不删除。
//
// 采集元数据 sidecar（<jsonl>.collection.json）会随 JSONL 一起保留；否则恢复
// 出来的 JSONL 在再次导入时就丢失了采集时权限与起止时间。
func preserveCollectJSONL(tmpPath, dbPath string) (string, error) {
	kept, _, err := preserveCollectArtifacts(tmpPath, dbPath)
	return kept, err
}

// preserveCollectArtifacts 保留 JSONL 及其采集元数据 sidecar，并返回落盘路径。
//
// sidecar 与 JSONL 同目录同名（后缀不同），所以两者必须一起移动到同一个恢复
// 文件名；只移动 JSONL 会留下孤立的 .collection.json。sidecar 移动失败不视为
// JSONL 保留失败，但会通过第三个返回值显式报告（不静默吞掉）。
func preserveCollectArtifacts(tmpPath, dbPath string) (kept, sidecar string, warning error) {
	info, err := os.Stat(tmpPath)
	if err != nil {
		return "", "", err
	}
	if info.Size() == 0 {
		return "", "", nil
	}
	dir := filepath.Dir(dbPath)
	if dir == "" {
		dir = "."
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	base := filepath.Base(tmpPath)
	sidecarSrc := collectionmeta.ArtifactPath(tmpPath)
	for i := 0; i < 100; i++ {
		suffix := ""
		if i > 0 {
			suffix = fmt.Sprintf("-%d", i)
		}
		dest := filepath.Join(dir, fmt.Sprintf(
			"easytrace-collect-recovery-%s-%d-%s%s", stamp, os.Getpid(), base, suffix))
		if _, statErr := os.Lstat(dest); statErr == nil {
			continue
		} else if !os.IsNotExist(statErr) {
			return "", "", statErr
		}
		sidecarDest := collectionmeta.ArtifactPath(dest)
		hasSidecar := false
		switch _, statErr := os.Lstat(sidecarSrc); {
		case statErr == nil:
			hasSidecar = true
			if _, err := os.Lstat(sidecarDest); err == nil {
				continue
			} else if !os.IsNotExist(err) {
				return "", "", err
			}
		case !os.IsNotExist(statErr):
			warning = statErr
		}

		if err := moveCollectFile(dest, tmpPath); err != nil {
			// 复制成功但删除原文件失败时，恢复副本已经存在，不能误报“未保留”。
			if _, statErr := os.Stat(dest); statErr != nil {
				return "", "", err
			}
			warning = err
		}
		kept = dest
		if hasSidecar {
			if err := moveCollectFile(sidecarDest, sidecarSrc); err != nil {
				if _, statErr := os.Stat(sidecarDest); statErr == nil {
					sidecar = sidecarDest
				}
				warning = err
			} else {
				sidecar = sidecarDest
			}
		}
		return kept, sidecar, warning
	}
	return "", "", fmt.Errorf("无法为 %s 生成不冲突的恢复文件名", base)
}

// moveCollectFile 优先重命名；跨卷时退化为排他复制后删除源文件。
func moveCollectFile(dst, src string) error {
	if renameErr := os.Rename(src, dst); renameErr == nil {
		return nil
	} else if copyErr := copyCollectFile(dst, src); copyErr != nil {
		return fmt.Errorf("重命名失败（%v），复制也失败（%v）", renameErr, copyErr)
	}
	if err := os.Remove(src); err != nil {
		return fmt.Errorf("已复制到 %s，但删除原文件失败: %w", dst, err)
	}
	return nil
}

// copyCollectFile 以排他创建方式复制采集临时文件（跨卷回退路径）。
func copyCollectFile(dst, src string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	return out.Close()
}

// collectAndWrite 执行单模块采集并把结果（过协议校验后）写入 JSONL（stdout）。
func collectAndWrite(c collector.Collector) error {
	printPrivilegeBanner(os.Stderr, privilege.Detect())
	return collectAndWriteTo(c, os.Stdout, os.Stderr)
}

// runCollectorSafely 把单个 Collector 放进 P3 保护层（panic → 显式错误；
// 超过 timeout → 丢弃结果并报错）。collectAndWriteTo 与 collectSteps 共用。
func runCollectorSafely(c collector.Collector, timeout time.Duration) (*collector.Result, error) {
	return runStep(collectStep{name: c.Name(), c: c}, timeout)
}

func collectAndWriteTo(c collector.Collector, out, log io.Writer) (err error) {
	// 单模块 + stdout（无 --db）也必须受 P3 保护；此前这里直接调用 c.Collect()，
	// panic 会终止整个进程，卡死也没有超时。
	result, collectErr := runCollectorSafely(c, stepTimeout)
	// 输出失败不能掩盖原始采集错误；部分事实输出后仍以失败状态返回。
	defer func() { err = errors.Join(collectErr, err) }()
	if result == nil {
		if collectErr != nil {
			return nil
		}
		return fmt.Errorf("%s: Collect 返回空结果", c.Name())
	}
	w := output.NewWriter(out)
	defer w.Close()
	for _, e := range result.Entities {
		if err := protocol.ValidateEntity(e); err != nil {
			return err
		}
		if err := w.Write(e); err != nil {
			return err
		}
	}
	for _, u := range result.EntityUpdates {
		if err := protocol.ValidateEntityUpdate(u); err != nil {
			return err
		}
		if err := w.Write(u); err != nil {
			return err
		}
	}
	for _, r := range result.Relations {
		if err := protocol.ValidateRelation(r); err != nil {
			return err
		}
		if err := w.Write(r); err != nil {
			return err
		}
	}
	status := "采集完成"
	if collectErr != nil {
		status = "采集不完整（已保留部分结果）"
	}
	fmt.Fprintf(log, "%s %s: %d entity, %d entity_update, %d relation\n",
		c.Name(), status, len(result.Entities), len(result.EntityUpdates), len(result.Relations))
	return nil
}
