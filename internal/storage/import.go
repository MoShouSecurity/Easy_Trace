package storage

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"time"

	"easytrace/internal/collectionmeta"
	"easytrace/internal/model"
	"easytrace/internal/protocol"
)

// JSONL 事件类型
const (
	msgEntity       = "entity"
	msgEntityUpdate = "entity_update"
	msgRelation     = "relation"
	msgFinding      = "finding"
)

// maxJSONLLine 单行 JSONL 上限（4MB）：超限行明确报错（含行号），不做静默截断/跳过。
const maxJSONLLine = 4 * 1024 * 1024

// importScanner 允许测试确定性地在两遍扫描之间改变临时文件。
type importScanner func(string, func(string, int) error) ([]byte, error)

// ImportJSONL 将一份 JSONL（collect --module all 输出）导入为一个新 Snapshot。
//
// 规则：
//   - 每次调用生成新的 snapshot_id（同一 JSONL 重复导入产生多个独立 Snapshot）。
//   - 整体在单个事务内完成：写 snapshots → entities → entity_updates → relations → findings；
//     任何一步失败即 rollback，绝不留下半个 Snapshot。
//   - 事件顺序：entity 必须先于其 entity_update；违反则拒绝导入并返回明确错误（不静默丢弃）。
//   - entity 的 data 与 relation 的 attrs 以原始 JSON 原样保存。
//
// Step 11.3 加固（不改变协议/结构，只收紧导入纪律）：
//   - 流式解析：两遍扫描文件，内存只保留 entity_id 集合，不再整文件载入内存；
//   - 严格校验：每行 schema_version 必须等于协议版本（拒绝空/未知/9.9），
//     未知/缺失 type 与未知 entity_type 一律报错（含行号），不静默丢弃；
//   - entity 顺序按文件顺序真实校验（entity_update 引用尚未出现的实体即拒绝）。
//
// mode 是采集模式（basic/deep/forensic），由 CLI 显式传入以保证准确；为空时自动探测。
// maxImportBytes 是单个 JSONL 导入文件的字节上限。
// 声明为 var 便于测试用极小上限验证；默认 1 GiB —— 真实采集远小于此，
// 这里是资源上限而非正常限制，防止把任意大文件当作快照导入（两遍扫描的时间/IO）。
var maxImportBytes int64 = 1 << 30

// checkImportSize 在导入前检查文件大小，超限显式失败（不读取、不落库）。
func checkImportSize(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("storage: 无法读取导入文件信息 %s: %w", path, err)
	}
	if info.Size() > maxImportBytes {
		return fmt.Errorf("storage: 导入文件超过上限 %d 字节（实际 %d）: %s",
			maxImportBytes, info.Size(), path)
	}
	return nil
}

func ImportJSONL(db *DB, path, mode string) (*SnapshotMeta, error) {
	// 先做整体大小检查：这是唯一会访问真实文件路径的入口，
	// 注入 scanner 的测试路径不受影响。
	if err := checkImportSize(path); err != nil {
		return nil, err
	}
	return importJSONLWithScanner(db, path, mode, scanJSONLLines)
}

// ImportOptions 是带采集来源的导入选项。
//
// Collection 来自采集时写下的 JSONL sidecar；为 nil 表示没有采集时记录
// （例如外部工具生成的 JSONL 或旧产物）。它只影响 snapshots 表已有的
// timestamp / agent_version 字段，不改变协议或 schema。
type ImportOptions struct {
	Mode         string
	AgentVersion string
	Collection   *collectionmeta.Meta
}

// ImportResult 返回导入后的快照与时间戳来源。
//
// TimestampSource 说明 snapshots.timestamp 到底是什么时刻：
//   - collection：采集器记录的 collection_started_at；
//   - host_current_time：旧产物没有 sidecar，但 host 实体带有 current_time；
//   - import_time：两者都没有，只能退化为导入时刻。
//
// 报告层必须据此标注，不能一律写成"采集时间"。
type ImportResult struct {
	Meta            *SnapshotMeta
	TimestampSource string
}

// ImportJSONLWithOptions 导入并保留采集时间来源。
func ImportJSONLWithOptions(db *DB, path string, opts ImportOptions) (*ImportResult, error) {
	if err := checkImportSize(path); err != nil {
		return nil, err
	}
	return importJSONLWithOptionsScanner(db, path, opts, scanJSONLLines)
}

// maxSnapshotIDAttempts 是 snapshot_id 碰撞时的最大重试次数。
const maxSnapshotIDAttempts = 5

// insertSnapshotWithRetry 在 snapshot_id 唯一约束冲突时换一个新 ID 重试；
// 其它错误一律原样返回，不做掩盖。
func insertSnapshotWithRetry(db *DB, meta *SnapshotMeta) error {
	var lastErr error
	for i := 0; i < maxSnapshotIDAttempts; i++ {
		if _, err := InsertSnapshot(db, meta); err == nil {
			return nil
		} else {
			lastErr = err
			if !isSnapshotIDConflict(err) {
				return err
			}
		}
		meta.SnapshotID = NewSnapshotID()
	}
	return fmt.Errorf("storage: 生成唯一 snapshot_id 失败（已重试 %d 次）: %w",
		maxSnapshotIDAttempts, lastErr)
}

// isSnapshotIDConflict 判定错误是否来自 snapshots.snapshot_id 的唯一约束冲突。
// 只匹配该列，避免把 entity/relation 的唯一冲突也当成 ID 碰撞而重试。
func isSnapshotIDConflict(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	// 必须匹配**表限定**的列名：实体表的唯一约束是
	// UNIQUE(snapshot_id, entity_id)，其报错同样含 "snapshot_id"，
	// 只按列名匹配会把实体冲突误判为 ID 碰撞并错误重试。
	return strings.Contains(msg, "UNIQUE") && strings.Contains(msg, "snapshots.snapshot_id")
}

func importJSONLWithScanner(db *DB, path, mode string, scan importScanner) (*SnapshotMeta, error) {
	res, err := importJSONLWithOptionsScanner(db, path, ImportOptions{Mode: mode}, scan)
	if err != nil {
		return nil, err
	}
	return res.Meta, nil
}

func importJSONLWithOptionsScanner(db *DB, path string, opts ImportOptions, scan importScanner) (*ImportResult, error) {
	if opts.Collection != nil {
		if err := collectionmeta.ValidateCollected(opts.Collection); err != nil {
			return nil, fmt.Errorf("storage: 采集元数据非法: %w", err)
		}
	}

	now := time.Now().UTC().Format(time.RFC3339)
	meta := &SnapshotMeta{
		SnapshotID:     NewSnapshotID(),
		Timestamp:      now, // 仅在后续两级回退都不可用时保留
		CollectionMode: opts.Mode,
		AgentVersion:   opts.AgentVersion,
		CreatedAt:      now,
	}
	timestampSource := collectionmeta.TimestampSourceImportTime
	mode := opts.Mode
	if opts.Collection != nil {
		cm := opts.Collection
		// 采集器写下的开始时刻优先于导入时刻。ReadArtifact 已保证其合法；
		// 此处再校验一次，避免库调用方绕过 sidecar 读取直接构造结构。
		start, err := collectionmeta.NormalizeTimestamp(cm.CollectionStartedAt)
		if err != nil {
			return nil, fmt.Errorf("storage: collection_started_at 非法: %w", err)
		}
		meta.Timestamp = start
		timestampSource = collectionmeta.TimestampSourceCollection
		if meta.CollectionMode == "" {
			mode = cm.CollectionMode
			meta.CollectionMode = cm.CollectionMode
		}
		if meta.Hostname == "" {
			meta.Hostname = cm.Hostname
		}
		if meta.AgentVersion == "" {
			meta.AgentVersion = cm.ToolVersion
		}
	}

	// 第一遍（流式）：逐行校验协议一致性 + 提取 host 元信息 + 探测采集模式。
	// 不落库，任何错误立即返回（后续无副作用）。
	contentLines := 0
	hostCurrentTime := ""
	firstDigest, err := scan(path, func(line string, lineno int) error {
		contentLines++
		typ, fields, err := parseLine(line)
		if err != nil {
			return fmt.Errorf("storage: 第 %d 行解析失败: %w", lineno, err)
		}
		if err := validateImportLine(typ, fields, lineno); err != nil {
			return err
		}
		if typ == msgEntity {
			row, err := entityRowFromFields(meta.SnapshotID, fields)
			if err != nil {
				return fmt.Errorf("storage: 第 %d 行 entity 字段缺失: %w", lineno, err)
			}
			if row.EntityType == "host" {
				if ts := fillMetaFromEntity(meta, row); hostCurrentTime == "" && ts != "" {
					hostCurrentTime = ts
				}
			}
		}
		// 从字段探测而非匹配 JSON 排版；update 也可带 collection_level。
		if mode == "" && (typ == msgEntity || typ == msgEntityUpdate) {
			var data map[string]json.RawMessage
			json.Unmarshal(fields["data"], &data) // 已校验为对象
			level := strField(data, "collection_level")
			if level == "forensic" || (level == "deep" && meta.CollectionMode != "forensic") {
				meta.CollectionMode = level
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if contentLines == 0 {
		return nil, fmt.Errorf("storage: JSONL 文件为空: %s", path)
	}
	if meta.CollectionMode == "" {
		meta.CollectionMode = "basic"
	}
	// 没有采集 sidecar 时，host.current_time 是采集器在采集时刻写下的第二个来源；
	// 只有它也不可用时才退回导入时刻。
	if timestampSource != collectionmeta.TimestampSourceCollection && hostCurrentTime != "" {
		meta.Timestamp = hostCurrentTime
		timestampSource = collectionmeta.TimestampSourceHostCurrentTime
	}

	if err := db.Exec("BEGIN IMMEDIATE"); err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			db.Exec("ROLLBACK")
		}
	}()

	// snapshot_id 由 4 位随机 hex 生成，同一秒内理论上可能碰撞；
	// UNIQUE(snapshot_id) 会显式拒绝。此处做**有界重试**：插入发生在
	// 写入实体之前，失败时事务内没有任何孤儿行，换 ID 重试是安全的。
	if err := insertSnapshotWithRetry(db, meta); err != nil {
		return nil, err
	}

	// 第二遍（流式，事务内）：按文件顺序写入全部行。
	// seenEntities 随写入增长：entity_update 引用尚未出现的实体 → 拒绝（真实顺序校验）。
	seenEntities := make(map[string]bool)
	secondDigest, err := scan(path, func(line string, lineno int) error {
		typ, fields, err := parseLine(line)
		if err != nil {
			return fmt.Errorf("storage: 第 %d 行解析失败: %w", lineno, err)
		}
		if err := validateImportLine(typ, fields, lineno); err != nil {
			return err
		}
		switch typ {
		case msgEntity:
			row, err := entityRowFromFields(meta.SnapshotID, fields)
			if err != nil {
				return fmt.Errorf("storage: 第 %d 行 entity 字段缺失: %w", lineno, err)
			}
			if err := InsertEntity(db, row); err != nil {
				return fmt.Errorf("storage: 第 %d 行写入 entity 失败: %w", lineno, err)
			}
			seenEntities[row.EntityID] = true
		case msgEntityUpdate:
			row, err := updateRowFromFields(meta.SnapshotID, fields)
			if err != nil {
				return fmt.Errorf("storage: 第 %d 行 entity_update 字段缺失: %w", lineno, err)
			}
			if !seenEntities[row.EntityID] {
				return fmt.Errorf(
					"storage: 第 %d 行 entity_update 引用不存在的实体 %q（entity 必须先于 entity_update）",
					lineno, row.EntityID)
			}
			if err := InsertEntityUpdate(db, row); err != nil {
				return err
			}
		case msgRelation:
			row, err := relationRowFromFields(meta.SnapshotID, fields)
			if err != nil {
				return fmt.Errorf("storage: 第 %d 行 relation 字段缺失: %w", lineno, err)
			}
			if err := InsertRelation(db, row); err != nil {
				return err
			}
		case msgFinding:
			row, err := findingRowFromFields(meta.SnapshotID, fields)
			if err != nil {
				return fmt.Errorf("storage: 第 %d 行 finding 字段缺失: %w", lineno, err)
			}
			if err := InsertFinding(db, row); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(firstDigest, secondDigest) {
		return nil, fmt.Errorf("storage: JSONL 在两遍读取之间发生变化，导入已回滚")
	}
	if err := db.Exec("COMMIT"); err != nil {
		return nil, err
	}
	committed = true
	return &ImportResult{Meta: meta, TimestampSource: timestampSource}, nil
}

// scanJSONLLines 流式扫描非空行并摘要原始字节（含空白/换行），超限报错不截断。
func scanJSONLLines(path string, fn func(line string, lineno int) error) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("storage: 打开 JSONL 失败: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	sc := bufio.NewScanner(io.TeeReader(f, h))
	sc.Buffer(make([]byte, 64*1024), maxJSONLLine)
	lineno := 0
	for sc.Scan() {
		lineno++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if err := fn(line, lineno); err != nil {
			return nil, err
		}
	}
	if err := sc.Err(); err != nil {
		if err == bufio.ErrTooLong {
			return nil, fmt.Errorf("storage: 第 %d 行超过单行上限 %d 字节", lineno+1, maxJSONLLine)
		}
		return nil, fmt.Errorf("storage: 读取 JSONL 失败: %w", err)
	}
	return h.Sum(nil), nil
}

// validateImportLine 复用协议信封校验，data 只校验对象形状，不重建事实字段校验器。
// 校验时解码 model，入库仍取 fields 中的原始 JSON，避免重编码事实。
func validateImportLine(typ string, fields map[string]json.RawMessage, lineno int) error {
	var err error
	switch typ {
	case msgEntity:
		var e model.Entity
		if err = decodeImportEnvelope(fields, &e); err == nil {
			err = protocol.ValidateEntity(&e)
		}
	case msgEntityUpdate:
		var u model.EntityUpdate
		if err = decodeImportEnvelope(fields, &u); err == nil {
			err = protocol.ValidateEntityUpdate(&u)
		}
	case msgRelation:
		var r model.Relation
		if err = decodeImportEnvelope(fields, &r); err == nil {
			err = protocol.ValidateRelation(&r)
		}
	case msgFinding:
		var f model.Finding
		if err = decodeImportEnvelope(fields, &f); err == nil {
			err = protocol.ValidateFinding(&f)
		}
	default:
		err = fmt.Errorf("未知/缺失 type %q（拒绝导入，不静默丢弃）", typ)
	}
	if err == nil {
		err = validateNoNULImportIdentifiers(typ, fields)
	}
	if err == nil && (typ == msgEntity || typ == msgEntityUpdate ||
		(typ == msgRelation && fields["data"] != nil)) {
		var data map[string]json.RawMessage
		if e := json.Unmarshal(fields["data"], &data); e != nil || data == nil {
			err = fmt.Errorf("data 必须为非 null 对象")
		}
	}
	if err != nil {
		return fmt.Errorf("storage: 第 %d 行: %w", lineno, err)
	}
	return nil
}

// validateNoNULImportIdentifiers 拒绝会在 SQLite C API 边界产生歧义的标识符。
// 协议保持不变；此处仅在导入前收紧本地存储的完整性要求。
func validateNoNULImportIdentifiers(typ string, fields map[string]json.RawMessage) error {
	switch typ {
	case msgEntity:
		var e model.Entity
		if err := decodeImportEnvelope(fields, &e); err != nil {
			return err
		}
		return rejectNUL("entity_id", e.EntityID)
	case msgEntityUpdate:
		var u model.EntityUpdate
		if err := decodeImportEnvelope(fields, &u); err != nil {
			return err
		}
		return rejectNUL("entity_id", u.EntityID)
	case msgRelation:
		var r model.Relation
		if err := decodeImportEnvelope(fields, &r); err != nil {
			return err
		}
		return rejectNUL("relation_id", r.RelationID, "source_id", r.SourceID, "target_id", r.TargetID)
	case msgFinding:
		var f model.Finding
		if err := decodeImportEnvelope(fields, &f); err != nil {
			return err
		}
		values := []string{"finding_id", f.FindingID, "rule_id", f.RuleID, "entity_id", f.EntityID}
		for _, entityID := range f.RelatedEntities {
			values = append(values, "related_entities", entityID)
		}
		return rejectNUL(values...)
	}
	return nil
}

// rejectNUL 接受成对的字段名和值，发现 NUL 时返回可定位的导入错误。
func rejectNUL(values ...string) error {
	for i := 0; i+1 < len(values); i += 2 {
		if strings.IndexByte(values[i+1], 0) >= 0 {
			return fmt.Errorf("%s 不能包含 NUL 字符", values[i])
		}
	}
	return nil
}

// decodeImportEnvelope 只取四种 model 信封中 JSON tag 精确匹配的键。
// encoding/json 默认接受大小写别名，入库却按精确键取值；不能出现校验通过但落库为空。
// 字段名来自 model，不维护另一份字段表；data 内部仍保持原样，不做键名转换。
func decodeImportEnvelope(fields map[string]json.RawMessage, dst any) error {
	typ := reflect.TypeOf(dst).Elem()
	exact := make(map[string]json.RawMessage, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		key, _, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ",")
		if raw, ok := fields[key]; ok {
			exact[key] = raw
		}
	}
	b, err := json.Marshal(exact)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, dst)
}

// parseLine 解析一行 JSONL，返回事件类型与字段表。
func parseLine(line string) (string, map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &fields); err != nil {
		return "", nil, err
	}
	var typ string
	if raw, ok := fields["type"]; ok {
		if err := json.Unmarshal(raw, &typ); err != nil {
			return "", nil, err
		}
	}
	return typ, fields, nil
}

// strField 提取字符串字段。
func strField(fields map[string]json.RawMessage, key string) string {
	raw, ok := fields[key]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

// rawField 提取原始 JSON 字段（不存在返回 ""）。
func rawField(fields map[string]json.RawMessage, key string) string {
	raw, ok := fields[key]
	if !ok || len(raw) == 0 {
		return ""
	}
	return string(raw)
}

// entityRowFromFields 从 entity 行构建 EntityRow。
func entityRowFromFields(snapshotID string, fields map[string]json.RawMessage) (*EntityRow, error) {
	entityID := strField(fields, "entity_id")
	if entityID == "" {
		return nil, fmt.Errorf("entity_id 缺失")
	}
	return &EntityRow{
		SnapshotID:    snapshotID,
		EntityID:      entityID,
		EntityType:    strField(fields, "entity_type"),
		SchemaVersion: strField(fields, "schema_version"),
		DataJSON:      rawField(fields, "data"),
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// updateRowFromFields 从 entity_update 行构建 EntityUpdateRow。
func updateRowFromFields(snapshotID string, fields map[string]json.RawMessage) (*EntityUpdateRow, error) {
	entityID := strField(fields, "entity_id")
	if entityID == "" {
		return nil, fmt.Errorf("entity_id 缺失")
	}
	return &EntityUpdateRow{
		SnapshotID:    snapshotID,
		EntityID:      entityID,
		UpdateType:    strField(fields, "update_type"),
		SchemaVersion: strField(fields, "schema_version"),
		DataJSON:      rawField(fields, "data"),
		Timestamp:     strField(fields, "timestamp"),
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// relationRowFromFields 从 relation 行构建 RelationRow。
func relationRowFromFields(snapshotID string, fields map[string]json.RawMessage) (*RelationRow, error) {
	relationID := strField(fields, "relation_id")
	if relationID == "" {
		return nil, fmt.Errorf("relation_id 缺失")
	}
	return &RelationRow{
		SnapshotID:    snapshotID,
		RelationID:    relationID,
		SourceID:      strField(fields, "source_id"),
		TargetID:      strField(fields, "target_id"),
		RelationType:  strField(fields, "relation_type"),
		SchemaVersion: strField(fields, "schema_version"),
		AttrsJSON:     rawField(fields, "data"), // 协议中 relation 的 attrs 位于 data 键
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// findingRowFromFields 从 finding 行构建 FindingRow。
func findingRowFromFields(snapshotID string, fields map[string]json.RawMessage) (*FindingRow, error) {
	findingID := strField(fields, "finding_id")
	if findingID == "" {
		return nil, fmt.Errorf("finding_id 缺失")
	}
	return &FindingRow{
		SnapshotID:          snapshotID,
		FindingID:           findingID,
		RuleID:              strField(fields, "rule_id"),
		Severity:            strField(fields, "severity"),
		Title:               strField(fields, "title"),
		Description:         strField(fields, "description"),
		EntityID:            strField(fields, "entity_id"),
		RelatedEntitiesJSON: rawField(fields, "related_entities"),
		EvidenceJSON:        rawField(fields, "evidence"),
		Advice:              rawField(fields, "advice"),
		CreatedAt:           time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// fillMetaFromEntity 从 host 实体提取快照元信息（hostname/os_version/architecture），
// 并返回归一化后的 host.current_time（无有效值时返回空串）。
//
// current_time 是采集器在采集时刻写下的值，是没有采集 sidecar 时的首选回退来源；
// 导入层绝不能把"导入这一刻"直接当成"采集时刻"且不说明。
func fillMetaFromEntity(meta *SnapshotMeta, row *EntityRow) string {
	if row.EntityType != "host" {
		return ""
	}
	var h struct {
		Hostname     string `json:"hostname"`
		OSVersion    string `json:"os_version"`
		Architecture string `json:"architecture"`
		CurrentTime  string `json:"current_time"`
	}
	if err := json.Unmarshal([]byte(row.DataJSON), &h); err != nil {
		return ""
	}
	if meta.Hostname == "" {
		meta.Hostname = h.Hostname
	}
	if meta.OSVersion == "" {
		meta.OSVersion = h.OSVersion
	}
	if meta.Architecture == "" {
		meta.Architecture = h.Architecture
	}
	if h.CurrentTime == "" {
		return ""
	}
	ts, err := collectionmeta.NormalizeTimestamp(h.CurrentTime)
	if err != nil {
		return ""
	}
	return ts
}
