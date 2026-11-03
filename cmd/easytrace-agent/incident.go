// incident.go 实现 report -zip 的 Incident 事件调查包（一期）。
//
// 范围：把**本快照范围内**的数据导出为一个 zip：
//
//	report.html / database.db / 6 个模块 CSV / relations.csv / entity_scores.csv /
//	timeline.csv / hashes.txt（另有可选的 events/*.evtx）
//
// 仍未做（需独立设计项）：evidence/*。
//
// 全部为本地只读导出：不采集主机、不联网、不执行外部程序、不修改源数据库。
package main

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"easytrace/internal/evidence"
	"easytrace/internal/model"
	"easytrace/internal/storage"
	"easytrace/internal/timeline"
)

// incidentEntry 是事件调查包中的一个条目。
type incidentEntry struct {
	Name string
	Data []byte
	// Store 为 true 时用 zip.Store（不压缩）。EVTX 本身已压缩，再 Deflate 只是徒耗 CPU。
	Store bool
}

// moduleCSVSpec 定义一个模块 CSV 的文件名、实体类型、列顺序与取值函数。
type moduleCSVSpec struct {
	File    string
	Type    string
	Columns []string
	Values  func(dataJSON string) ([]string, error)
}

// boolText 把 bool 渲染为 CSV 中的固定小写字面量。
func boolText(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// signedText 用三态导出进程签名结论（CSV 是给外部消费者的导出，不能把“没验过”
// 写成 false；basic 模式下 signed 只是字段零值）。
//
//	true    : 深采 WinVerifyTrust 确认签名有效
//	false   : PE 安全目录不存在（确定没有签名）
//	unknown : 基础模式 / PE 头不可读 / 有签名目录但未完成验签 —— 没有结论
func signedText(d model.ProcessData) string {
	if d.Signed {
		return "true"
	}
	if d.SignatureState == "missing" {
		return "false"
	}
	return "unknown"
}

// moduleCSVSpecs 是模块 CSV 的固定顺序与列定义。
//
// 说明：设计文档第 8 章的清单未列出计划任务，但 task 是已交付的采集模块，
// 这里补上 tasks.csv，避免已采集事实在事件包中被静默丢弃。
var moduleCSVSpecs = []moduleCSVSpec{
	{
		File: "processes.csv", Type: "process",
		Columns: []string{"pid", "name", "path", "parent_pid", "command_line", "username",
			"session", "windowed", "signed", "signature_state", "hash_sha256",
			"creation_time", "collection_level"},
		Values: func(s string) ([]string, error) {
			var d model.ProcessData
			if err := json.Unmarshal([]byte(s), &d); err != nil {
				return nil, err
			}
			return []string{
				fmt.Sprintf("%d", d.PID), d.Name, d.Path, fmt.Sprintf("%d", d.ParentPID),
				d.CommandLine, d.Username, fmt.Sprintf("%d", d.Session),
				boolText(d.Windowed), signedText(d), d.SignatureState, d.HashSHA256,
				d.CreationTime, d.CollectionLevel,
			}, nil
		},
	},
	{
		// remote_ip / remote_port 在 LISTENING 行是 API 占位值。CSV 属于数据导出，
		// 保留原始值以保证证据完整；state 列可区分监听与真实连接。
		// 叙述性展示（report.html / summary.txt）不展示该占位值。
		File: "network.csv", Type: "network",
		Columns: []string{"protocol", "local_ip", "local_port", "remote_ip", "remote_port", "state", "pid"},
		Values: func(s string) ([]string, error) {
			var d model.NetworkData
			if err := json.Unmarshal([]byte(s), &d); err != nil {
				return nil, err
			}
			return []string{
				d.Protocol, d.LocalIP, fmt.Sprintf("%d", d.LocalPort),
				d.RemoteIP, fmt.Sprintf("%d", d.RemotePort), d.State, fmt.Sprintf("%d", d.PID),
			}, nil
		},
	},
	{
		File: "autoruns.csv", Type: "persistence",
		Columns: []string{"type", "location", "name", "command", "path", "user"},
		Values: func(s string) ([]string, error) {
			var d model.PersistenceData
			if err := json.Unmarshal([]byte(s), &d); err != nil {
				return nil, err
			}
			return []string{d.Type, d.Location, d.Name, d.Command, d.Path, d.User}, nil
		},
	},
	{
		File: "services.csv", Type: "service",
		Columns: []string{"service_name", "display_name", "binary_path", "start_type", "status", "account"},
		Values: func(s string) ([]string, error) {
			var d model.ServiceData
			if err := json.Unmarshal([]byte(s), &d); err != nil {
				return nil, err
			}
			return []string{d.ServiceName, d.DisplayName, d.BinaryPath, d.StartType, d.Status, d.Account}, nil
		},
	},
	{
		File: "tasks.csv", Type: "task",
		Columns: []string{"task_name", "path", "author", "command", "trigger", "enabled"},
		Values: func(s string) ([]string, error) {
			var d model.TaskData
			if err := json.Unmarshal([]byte(s), &d); err != nil {
				return nil, err
			}
			return []string{d.TaskName, d.Path, d.Author, d.Command, d.Trigger, boolText(d.Enabled)}, nil
		},
	},
	{
		File: "users.csv", Type: "user",
		Columns: []string{"username", "sid", "groups", "enabled", "last_login"},
		Values: func(s string) ([]string, error) {
			var d model.UserData
			if err := json.Unmarshal([]byte(s), &d); err != nil {
				return nil, err
			}
			return []string{d.Username, d.SID, strings.Join(d.Groups, ";"), boolText(d.Enabled), d.LastLogin}, nil
		},
	},
	{
		// prefetch 实体是显式请求（--module prefetch）才有的；没有时输出空表
		// （仅表头），与其它模块 CSV 一致。
		File: "prefetch.csv", Type: "prefetch",
		Columns: []string{"executable_name", "prefetch_hash", "source_version", "path",
			"file_size", "last_write_time", "collection_level"},
		Values: func(s string) ([]string, error) {
			var d model.PrefetchData
			if err := json.Unmarshal([]byte(s), &d); err != nil {
				return nil, err
			}
			return []string{d.ExecutableName, d.PrefetchHash, fmt.Sprintf("%d", d.SourceVersion),
				d.Path, fmt.Sprintf("%d", d.FileSize), d.LastWriteTime, d.CollectionLevel}, nil
		},
	},
	{
		// execution 实体是显式请求（--module execution）才有的；没有时输出空表。
		// run_count / occurrences 用空单元格表示"该来源不提供"，不写 0。
		File: "execution.csv", Type: "execution",
		Columns: []string{"source", "user", "name", "path", "command", "run_count",
			"last_run_time", "last_write_time", "occurrences", "collection_level"},
		Values: func(s string) ([]string, error) {
			var d model.ExecutionData
			if err := json.Unmarshal([]byte(s), &d); err != nil {
				return nil, err
			}
			return []string{d.Source, d.User, d.Name, d.Path, d.Command,
				uint32Text(d.RunCount), d.LastRunTime, d.LastWriteTime,
				uint32Text(d.Occurrences), d.CollectionLevel}, nil
		},
	},
}

// uint32Text 把可选计数转成 CSV 单元格：nil（来源不提供）为空串，不写 0。
func uint32Text(p *uint32) string {
	if p == nil {
		return ""
	}
	return fmt.Sprintf("%d", *p)
}

// incidentZipName 生成事件调查包文件名：Incident_<YYYYMMDD>_<seq>.zip。
//
// 日期取快照采集时间（UTC）而非当前时间：同一快照重复导出得到相同文件名与相同内容，
// 报告保持确定性。seq 一期固定为 01。
func incidentZipName(meta *storage.SnapshotMeta) string {
	return "Incident_" + incidentDate(meta) + "_01.zip"
}

// incidentDate 从快照元信息推导事件包日期（YYYYMMDD）。
func incidentDate(meta *storage.SnapshotMeta) string {
	if t, err := time.Parse(time.RFC3339, meta.Timestamp); err == nil {
		return t.UTC().Format("20060102")
	}
	// 回退：snapshot_YYYYMMDD_HHMMSS_xxxx
	const prefix = "snapshot_"
	if id := meta.SnapshotID; strings.HasPrefix(id, prefix) && len(id) >= len(prefix)+8 {
		return id[len(prefix) : len(prefix)+8]
	}
	return "undated"
}

// incidentModTime 返回事件包条目的固定时间戳（快照采集时间）。
func incidentModTime(meta *storage.SnapshotMeta) time.Time {
	if t, err := time.Parse(time.RFC3339, meta.Timestamp); err == nil {
		return t.UTC()
	}
	return time.Unix(0, 0).UTC()
}

// buildIncidentEntries 汇总事件调查包的全部条目（顺序固定，便于复现）。
//
// report.html 内的人读视图会截断长清单（“完整清单见事件包 findings.json”），
// 因此 findings.json 与 summary.txt 必须和 report.html 一起进包；否则事件包
// 打开后指针悬空，且交付物缺少机器可读的完整线索。
func buildIncidentEntries(db *storage.DB, meta *storage.SnapshotMeta, reportHTML, findingsJSON, summaryText string, eventsDir, evidenceDir string, scores []entityScore, tl timeline.Result) ([]incidentEntry, error) {
	dbBytes, err := buildSnapshotDatabase(db, meta)
	if err != nil {
		return nil, err
	}
	entries := []incidentEntry{
		{Name: "report.html", Data: []byte(reportHTML)},
		{Name: "findings.json", Data: []byte(findingsJSON)},
		{Name: "summary.txt", Data: []byte(summaryText)},
		{Name: "database.db", Data: dbBytes},
	}
	csvs, err := buildModuleCSVs(db, meta.SnapshotID)
	if err != nil {
		return nil, err
	}
	entries = append(entries, csvs...)

	relCSV, err := buildRelationsCSV(db, meta.SnapshotID)
	if err != nil {
		return nil, err
	}
	entries = append(entries, incidentEntry{Name: "relations.csv", Data: relCSV})

	scoreCSV, err := buildEntityScoresCSV(scores)
	if err != nil {
		return nil, err
	}
	entries = append(entries, incidentEntry{Name: "entity_scores.csv", Data: scoreCSV})

	// 时间线（V0.3，设计见 docs/设计-时间线.md）：排序固定，因此同一快照重复导出逐字节一致。
	tlCSV, err := tl.CSV()
	if err != nil {
		return nil, err
	}
	entries = append(entries, incidentEntry{Name: "timeline.csv", Data: tlCSV})

	// 事件日志（阶段 A 的 collect --evtx 产物）：只打包调用方显式指定的目录，
	// report 本身仍然不访问主机。
	if eventsDir != "" {
		evEntries, err := readEventsDir(eventsDir)
		if err != nil {
			return nil, err
		}
		entries = append(entries, evEntries...)
	}

	// 痕迹留存产物（catch 的证据目录）：同样只打包调用方显式指定的目录。
	if evidenceDir != "" {
		evEntries, err := readEvidenceDir(evidenceDir)
		if err != nil {
			return nil, err
		}
		entries = append(entries, evEntries...)
	}

	hashes, err := buildHashesTxt(db, meta.SnapshotID)
	if err != nil {
		return nil, err
	}
	return append(entries, incidentEntry{Name: "hashes.txt", Data: hashes}), nil
}

// writeIncidentZip 以确定性方式写出 zip：条目顺序固定、使用固定压缩方法，
// 条目时间取快照采集时间。最终文件通过排他创建写出，不覆盖任何已有文件。
//
// 压缩结果直接流式写入目标文件（P1-11）：旧实现先在 bytes.Buffer 里攒出完整 zip
// 再落盘，等于把压缩产物再复制一份到内存。写失败时删除本次创建的不完整文件——
// 截断的 zip 不是可用证据，留着只会让同名重试被“拒绝覆盖”永久挡住。
func writeIncidentZip(path string, entries []incidentEntry, modTime time.Time) error {
	file, err := createNewOutputFile(path, 0o644)
	if err != nil {
		return err
	}
	fail := func(err error) error {
		_ = file.Close()
		_ = os.Remove(file.Name())
		return err
	}
	zw := zip.NewWriter(file)
	for _, e := range entries {
		method := uint16(zip.Deflate)
		if e.Store {
			method = zip.Store
		}
		hdr := &zip.FileHeader{Name: e.Name, Method: method, Modified: modTime}
		hdr.SetMode(0o644)
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			return fail(fmt.Errorf("创建 zip 条目 %s 失败: %w", e.Name, err))
		}
		if _, err := w.Write(e.Data); err != nil {
			return fail(fmt.Errorf("写入 zip 条目 %s 失败: %w", e.Name, err))
		}
	}
	if err := zw.Close(); err != nil {
		return fail(fmt.Errorf("关闭 zip 失败: %w", err))
	}
	// 证据包通常写在移动介质上：显式落盘后再报告成功。
	if err := file.Sync(); err != nil {
		return fail(fmt.Errorf("同步 zip 文件失败: %w", err))
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("关闭 zip 文件失败: %w", err)
	}
	return nil
}

// maxIncidentEventsBytes 是打包事件日志的合计上限。
// 事件包整体在内存中构建，必须有上限，避免把任意大目录当作证据打包。
const maxIncidentEventsBytes = 1 << 30 // 1 GiB

// readEventsDir 读取事件日志目录，返回要放进事件包 events/ 下的条目。
//
// 打包前必须校验导出清单：manifest.txt 自校验、每个 ok 通道的哈希/字节数，
// 以及目录中没有清单未登记的额外文件。否则“复制时被替换”或“目录混入文件”
// 会被原样封进事件包，事后无法区分。
func readEventsDir(dir string) ([]incidentEntry, error) {
	entries, err := readFlatDir(dir, "events", "事件日志")
	if err != nil {
		return nil, err
	}
	files := make(map[string][]byte, len(entries))
	for _, e := range entries {
		files[strings.TrimPrefix(e.Name, "events/")] = e.Data
	}
	if err := verifyEvtxPackage(files); err != nil {
		return nil, fmt.Errorf("事件日志包校验失败: %w", err)
	}
	return entries, nil
}

// readEvidenceDir 读取痕迹留存目录（catch 的产物），返回要放进事件包 evidence/ 下的条目。
// 打包前由 evidence.VerifyPackage 逐文件复核清单、哈希与字节数，并拒绝清单外的文件。
func readEvidenceDir(dir string) ([]incidentEntry, error) {
	entries, err := readFlatDir(dir, "evidence", "痕迹留存")
	if err != nil {
		return nil, err
	}
	files := make(map[string][]byte, len(entries))
	for _, e := range entries {
		files[strings.TrimPrefix(e.Name, "evidence/")] = e.Data
	}
	if err := evidence.VerifyPackage(files); err != nil {
		return nil, fmt.Errorf("痕迹留存包校验失败: %w", err)
	}
	return entries, nil
}

// readFlatDir 读取一个"平铺"目录并映射到事件包里的 prefix/ 下。
//
// 只接受该目录下的**普通文件**（collect --evtx 与 catch 的证据目录都是平铺的）；
// 出现子目录或非普通文件一律显式失败，避免把任意目录树无声地打包进证据包。
// 同一套合计上限也顺带兜住证据目录，避免把任意大目录当证据打包。
func readFlatDir(dir, prefix, label string) ([]incidentEntry, error) {
	absDir, err := localInputDir(dir, label)
	if err != nil {
		return nil, err
	}
	ents, err := os.ReadDir(absDir)
	if err != nil {
		return nil, fmt.Errorf("读取%s目录失败: %w", label, err)
	}
	var out []incidentEntry
	var total int64
	for _, e := range ents {
		info, err := e.Info()
		if err != nil {
			return nil, fmt.Errorf("读取%s条目失败（%s）: %w", label, e.Name(), err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%s目录只接受普通文件，遇到非普通文件: %s", label, e.Name())
		}
		total += info.Size()
		if total > maxIncidentEventsBytes {
			return nil, fmt.Errorf("%s合计超过上限 %d 字节: %s", label, maxIncidentEventsBytes, dir)
		}
		b, err := os.ReadFile(filepath.Join(absDir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("读取%s文件失败（%s）: %w", label, e.Name(), err)
		}
		out = append(out, incidentEntry{Name: prefix + "/" + e.Name(), Data: b, Store: true})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s目录为空: %s", label, dir)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// buildSnapshotDatabase 只把该快照范围内的行导出为独立 SQLite 文件。
//
// 直接复制源数据库会把同一 db 里其它快照一并打包，既超范围也带来隐私问题；
// 因此按 schema 重建一个只含本快照的数据库。中间文件放在系统临时目录并在返回前清理。
func buildSnapshotDatabase(db *storage.DB, meta *storage.SnapshotMeta) ([]byte, error) {
	dir, err := os.MkdirTemp("", "easytrace-incident-")
	if err != nil {
		return nil, fmt.Errorf("创建临时目录失败: %w", err)
	}
	defer os.RemoveAll(dir)

	path := filepath.Join(dir, "database.db")
	out, err := storage.Open(path)
	if err != nil {
		return nil, err
	}
	closed := false
	defer func() {
		if !closed {
			_ = out.Close()
		}
	}()

	if err := storage.InitSchema(out); err != nil {
		return nil, fmt.Errorf("初始化临时数据库失败: %w", err)
	}

	// 快照元信息用副本写入：InsertSnapshot 会在 CreatedAt 为空时补当前时间，
	// 副本避免改动调用方的 meta。
	metaCopy := *meta
	if _, err := storage.InsertSnapshot(out, &metaCopy); err != nil {
		return nil, fmt.Errorf("写入快照元信息失败: %w", err)
	}

	entities, err := storage.GetEntities(db, meta.SnapshotID)
	if err != nil {
		return nil, err
	}
	for i := range entities {
		if err := storage.InsertEntity(out, &entities[i]); err != nil {
			return nil, fmt.Errorf("写入实体 %s 失败: %w", entities[i].EntityID, err)
		}
	}

	relations, err := storage.GetRelations(db, meta.SnapshotID)
	if err != nil {
		return nil, err
	}
	for i := range relations {
		if err := storage.InsertRelation(out, &relations[i]); err != nil {
			return nil, fmt.Errorf("写入关系 %s 失败: %w", relations[i].RelationID, err)
		}
	}

	updates, err := storage.GetEntityUpdatesAll(db, meta.SnapshotID)
	if err != nil {
		return nil, err
	}
	for i := range updates {
		if err := storage.InsertEntityUpdate(out, &updates[i]); err != nil {
			return nil, fmt.Errorf("写入证据补充失败: %w", err)
		}
	}

	findings, err := storage.GetFindings(db, meta.SnapshotID)
	if err != nil {
		return nil, err
	}
	for i := range findings {
		if err := storage.InsertFinding(out, &findings[i]); err != nil {
			return nil, fmt.Errorf("写入线索 %s 失败: %w", findings[i].FindingID, err)
		}
	}

	if err := out.Close(); err != nil {
		return nil, fmt.Errorf("关闭临时数据库失败: %w", err)
	}
	closed = true

	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取临时数据库失败: %w", err)
	}
	return b, nil
}

// csvSafeCell 防止电子表格把采集到的文本当作公式执行（CSV injection）。
//
// 路径/命令行/用户名/进程名完全由被测主机决定；以 = + - @ 或制表符/回车开头的
// 文本被 Excel/WPS 打开时会被求值（`=HYPERLINK(...)` 一类）。在值前加一个
// 单引号是通行做法：电子表格会隐藏前导单引号、显示原值，但不再执行。
func csvSafeCell(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

// buildModuleCSVs 生成模块 CSV。行按 entity_id 排序，列顺序固定；
// Data 反序列化失败会明确报错，而不是静默跳过该行。
func buildModuleCSVs(db *storage.DB, snapshotID string) ([]incidentEntry, error) {
	entities, err := storage.GetEntities(db, snapshotID)
	if err != nil {
		return nil, err
	}
	byType := map[string][]storage.EntityRow{}
	for _, e := range entities {
		byType[e.EntityType] = append(byType[e.EntityType], e)
	}

	out := make([]incidentEntry, 0, len(moduleCSVSpecs))
	for _, spec := range moduleCSVSpecs {
		rows := byType[spec.Type]
		sort.Slice(rows, func(i, j int) bool { return rows[i].EntityID < rows[j].EntityID })

		var buf bytes.Buffer
		w := csv.NewWriter(&buf)
		if err := w.Write(append([]string{"entity_id"}, spec.Columns...)); err != nil {
			return nil, fmt.Errorf("生成 %s 表头失败: %w", spec.File, err)
		}
		for _, r := range rows {
			vals, err := spec.Values(r.DataJSON)
			if err != nil {
				return nil, fmt.Errorf("生成 %s 失败（%s）: %w", spec.File, r.EntityID, err)
			}
			for i := range vals {
				vals[i] = csvSafeCell(vals[i])
			}
			if err := w.Write(append([]string{r.EntityID}, vals...)); err != nil {
				return nil, fmt.Errorf("生成 %s 行失败（%s）: %w", spec.File, r.EntityID, err)
			}
		}
		w.Flush()
		if err := w.Error(); err != nil {
			return nil, fmt.Errorf("生成 %s 失败: %w", spec.File, err)
		}
		out = append(out, incidentEntry{Name: spec.File, Data: buf.Bytes()})
	}
	return out, nil
}

// buildRelationsCSV 生成 relations.csv —— 攻击链数据。
//
// 列：relation_id, relation_type, source_id, target_id, command, attrs_json
// relation 的 attrs_json 是关系特有属性（spawn 带 command、launch 带 status）；
// 除把 spawn 的 command 单列出来便于排序筛选外，原始 JSON 一律原样保留。
// 行按 relation_id 排序；attrs_json 解析失败会显式报错，不静默产出空值。
func buildRelationsCSV(db *storage.DB, snapshotID string) ([]byte, error) {
	rels, err := storage.GetRelations(db, snapshotID)
	if err != nil {
		return nil, err
	}
	sort.Slice(rels, func(i, j int) bool { return rels[i].RelationID < rels[j].RelationID })

	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write([]string{"relation_id", "relation_type", "source_id",
		"target_id", "command", "attrs_json"}); err != nil {
		return nil, fmt.Errorf("生成 relations.csv 表头失败: %w", err)
	}
	for _, rel := range rels {
		var attrs map[string]any
		if err := json.Unmarshal([]byte(rel.AttrsJSON), &attrs); err != nil {
			return nil, fmt.Errorf("生成 relations.csv 失败（%s）: attrs_json 解析失败: %w",
				rel.RelationID, err)
		}
		command := ""
		if v, ok := attrs["command"].(string); ok {
			command = v
		}
		raw := rel.AttrsJSON
		if raw == "" {
			raw = "{}"
		}
		if err := w.Write([]string{rel.RelationID, rel.RelationType, rel.SourceID,
			rel.TargetID, csvSafeCell(command), raw}); err != nil {
			return nil, fmt.Errorf("生成 relations.csv 行失败（%s）: %w", rel.RelationID, err)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, fmt.Errorf("生成 relations.csv 失败: %w", err)
	}
	return buf.Bytes(), nil
}

// buildEntityScoresCSV 生成 entity_scores.csv（实体风险分，按分数降序）。
//
// 列：entity_id, entity_type, label, risk_score, level, verdict, finding_count, rules
// 评分模型见协议 v0.1 §3；分值为派生结果，不落库、不进协议。
func buildEntityScoresCSV(scores []entityScore) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write([]string{"entity_id", "entity_type", "label", "risk_score",
		"level", "verdict", "finding_count", "rules"}); err != nil {
		return nil, fmt.Errorf("生成 entity_scores.csv 表头失败: %w", err)
	}
	for _, s := range scores {
		// label 来自实体事实（进程名/路径等），同样由被测主机决定，必须防公式注入。
		if err := w.Write([]string{s.EntityID, s.EntityType, csvSafeCell(s.Label),
			fmt.Sprintf("%d", s.Score), s.Level, s.Verdict,
			fmt.Sprintf("%d", s.FindingCount), csvSafeCell(strings.Join(s.Rules, ";"))}); err != nil {
			return nil, fmt.Errorf("生成 entity_scores.csv 行失败（%s）: %w", s.EntityID, err)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, fmt.Errorf("生成 entity_scores.csv 失败: %w", err)
	}
	return buf.Bytes(), nil
}

// buildHashesTxt 生成 hashes.txt：每行「<sha256>  <path>」，按 path 排序。
//
// 哈希来自所有携带 hash_sha256 的文件型实体：process / file / persistence。
// 深采的哈希写在 entity_update 里，必须先通过 MergeEntityUpdates 合并；
// 同一路径同一哈希只会输出一行（同一文件可能同时被进程与启动项引用）。
// 没有任何哈希时输出一行说明，而不是空文件，避免读者误以为导出失败。
func buildHashesTxt(db *storage.DB, snapshotID string) ([]byte, error) {
	entities, err := storage.GetEntities(db, snapshotID)
	if err != nil {
		return nil, err
	}
	updates, err := storage.GetEntityUpdatesAll(db, snapshotID)
	if err != nil {
		return nil, err
	}
	byEntity := map[string][]storage.EntityUpdateRow{}
	for _, u := range updates {
		byEntity[u.EntityID] = append(byEntity[u.EntityID], u)
	}

	type hashRow struct{ Hash, Path string }
	var rows []hashRow
	seen := map[string]bool{}
	for _, e := range entities {
		switch e.EntityType {
		case "process", "file", "persistence":
		default:
			continue
		}
		merged := storage.MergeEntityUpdates(e.DataJSON, byEntity[e.EntityID])
		// 三类实体的 hash_sha256 与 path 字段同名，用最小视图解码，
		// 避免为每种类型重复维护一份只取两个字段的结构。
		var d struct {
			Hash string `json:"hash_sha256"`
			Path string `json:"path"`
		}
		if err := json.Unmarshal([]byte(merged), &d); err != nil {
			return nil, fmt.Errorf("解析%s实体失败（%s）: %w", e.EntityType, e.EntityID, err)
		}
		if d.Hash == "" {
			continue
		}
		p := d.Path
		if p == "" {
			p = e.EntityID
		}
		key := d.Hash + "\x00" + p
		if seen[key] {
			continue
		}
		seen[key] = true
		rows = append(rows, hashRow{Hash: d.Hash, Path: p})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Path != rows[j].Path {
			return rows[i].Path < rows[j].Path
		}
		return rows[i].Hash < rows[j].Hash
	})

	if len(rows) == 0 {
		return []byte("# 本快照没有可用的文件哈希（hash_sha256 需要 Deep 采集；persistence 需深采补充）\n"), nil
	}
	var sb strings.Builder
	for _, r := range rows {
		sb.WriteString(r.Hash + "  " + r.Path + "\n")
	}
	return []byte(sb.String()), nil
}
