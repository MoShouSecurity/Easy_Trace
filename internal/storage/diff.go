package storage

import (
	"encoding/json"
	"fmt"
	"sort"
)

// DiffChange 是一次实体变化（added / removed / changed）。
// 只描述状态变化事实，不做安全判断、不生成 finding/severity/risk_score。
type DiffChange struct {
	ChangeType    string          `json:"change_type"` // added / removed / changed
	EntityType    string          `json:"entity_type"`
	EntityID      string          `json:"entity_id"`
	Data          json.RawMessage `json:"data,omitempty"`           // added/removed 时的完整事实
	Before        json.RawMessage `json:"before,omitempty"`         // changed 时 A 快照视图
	After         json.RawMessage `json:"after,omitempty"`          // changed 时 B 快照视图
	ChangedFields []string        `json:"changed_fields,omitempty"` // changed 时的差异字段
}

// SnapshotDiff 是两个快照之间的事实差异（只读，不修改任何快照数据）。
type SnapshotDiff struct {
	FromSnapshot string       `json:"from_snapshot"`
	ToSnapshot   string       `json:"to_snapshot"`
	Changes      []DiffChange `json:"changes"`
	// Warnings 是稳定键降级提示（实体 data 字段缺失/损坏时用 entity_id 兜底匹配，
	// 不静默丢弃实体）。JSON 输出为空时省略（additive，兼容既有输出）。
	Warnings []string `json:"warnings,omitempty"`
}

// diffScope 第一阶段比较范围（host/user/task/finding 暂不参与）。
var diffScope = map[string]bool{"process": true, "persistence": true, "service": true, "network": true}

// DiffSnapshots 比较同一数据库内两个快照（--from / --to）的事实差异。
//
// 匹配方式（部分 entity_id 是采集序号，不稳定，需稳定事实键）：
//   - process ：沿用 entity_id = process_<pid> 匹配；PID 复用不是可靠跨快照身份；
//     比较视图 = entity data + 全部 entity_update data 合并（update 不修改原实体）
//   - persistence：稳定键 = type|location|name（启动项名唯一）
//   - service   ：entity_id = service_<name>，稳定
//   - network   ：稳定键 = protocol|local_ip|local_port|pid，同键实体分桶而非覆盖
//
// 输出按 entity_type → change_type → entity_id 稳定排序（多次执行结果一致）。
func DiffSnapshots(db *DB, fromID, toID string) (*SnapshotDiff, error) {
	// 只读校验：两个快照必须存在
	if _, err := GetSnapshot(db, fromID); err != nil {
		return nil, fmt.Errorf("storage: from 快照不存在: %w", err)
	}
	if _, err := GetSnapshot(db, toID); err != nil {
		return nil, fmt.Errorf("storage: to 快照不存在: %w", err)
	}

	fromEnts, err := GetEntities(db, fromID)
	if err != nil {
		return nil, err
	}
	toEnts, err := GetEntities(db, toID)
	if err != nil {
		return nil, err
	}
	fromUpdates, err := GetEntityUpdatesAll(db, fromID)
	if err != nil {
		return nil, err
	}
	toUpdates, err := GetEntityUpdatesAll(db, toID)
	if err != nil {
		return nil, err
	}

	fromView, fromWarnings := buildEntityViews(fromEnts, fromUpdates)
	toView, toWarnings := buildEntityViews(toEnts, toUpdates)

	diff := &SnapshotDiff{FromSnapshot: fromID, ToSnapshot: toID}
	diff.Warnings = append(diff.Warnings, fromWarnings...)
	diff.Warnings = append(diff.Warnings, toWarnings...)
	for key, to := range toView {
		appendBucketDiff(diff, key, fromView[key], to)
	}
	for key, from := range fromView {
		if _, ok := toView[key]; !ok {
			appendBucketDiff(diff, key, from, nil)
		}
	}
	sort.Strings(diff.Warnings)

	sort.Slice(diff.Changes, func(i, j int) bool {
		a, b := diff.Changes[i], diff.Changes[j]
		if a.EntityType != b.EntityType {
			return a.EntityType < b.EntityType
		}
		if a.ChangeType != b.ChangeType {
			return a.ChangeType < b.ChangeType
		}
		return a.EntityID < b.EntityID
	})
	return diff, nil
}

// viewEntry 是稳定键 → 实体视图的映射项。
type viewEntry struct {
	typ      string
	id       string
	dataJSON string
}

// buildEntityViews 构建快照内"稳定键 → 实体视图"。
// process 视图合并 entity_update：以 entity data 为基，update data 覆盖/补充字段。
//
// Step 11.3：稳定键计算失败（data 字段缺失/损坏）时用 entity_id 兜底键，保证实体
// 不静默丢失；同时返回明确警告（含快照/类型/实体 ID），由调用方输出。
func buildEntityViews(ents []EntityRow, updates []EntityUpdateRow) (map[string][]viewEntry, []string) {
	// update 按 entity_id 聚合（保留历史，按 id 顺序合并）
	updatesByEntity := make(map[string][]EntityUpdateRow)
	for _, u := range updates {
		updatesByEntity[u.EntityID] = append(updatesByEntity[u.EntityID], u)
	}

	views := make(map[string][]viewEntry)
	var warnings []string
	for _, e := range ents {
		if !diffScope[e.EntityType] {
			continue
		}
		merged := e.DataJSON
		if ups := updatesByEntity[e.EntityID]; len(ups) > 0 {
			merged = MergeEntityUpdates(e.DataJSON, ups)
		}
		key := stableKey(e.EntityType, e.EntityID, merged)
		if key == "" {
			key = fallbackKey(e.EntityType, e.EntityID)
			warnings = append(warnings, fmt.Sprintf(
				"快照 %s: 实体 %s/%s 无法计算稳定键（data 字段缺失或损坏），已用 entity_id 兜底匹配",
				e.SnapshotID, e.EntityType, e.EntityID))
		}
		views[key] = append(views[key], viewEntry{typ: e.EntityType, id: e.EntityID, dataJSON: merged})
	}
	return views, warnings
}

// appendBucketDiff 先按规范化 JSON 消去相同事实（保留重复数量），再处理剩余项。
// 桶内仅剩一对才可认定 changed；多对多不能凭不稳定的采集序号强行配对。
func appendBucketDiff(diff *SnapshotDiff, key string, from, to []viewEntry) {
	group := func(entries []viewEntry) map[string][]viewEntry {
		groups := make(map[string][]viewEntry)
		for _, e := range entries {
			var data any
			normalized := e.dataJSON
			if json.Unmarshal([]byte(e.dataJSON), &data) == nil {
				if b, err := json.Marshal(data); err == nil {
					normalized = string(b)
				}
			}
			groups[normalized] = append(groups[normalized], e)
		}
		for _, bucket := range groups {
			sort.Slice(bucket, func(i, j int) bool { return bucket[i].id < bucket[j].id })
		}
		return groups
	}
	fg, tg := group(from), group(to)
	var left, right []viewEntry
	for data, a := range fg {
		b := tg[data]
		n := min(len(a), len(b))
		left = append(left, a[n:]...)
		tg[data] = b[n:]
	}
	for _, b := range tg {
		right = append(right, b...)
	}
	if len(left) == 1 && len(right) == 1 {
		a, b := left[0], right[0]
		diff.Changes = append(diff.Changes, DiffChange{
			ChangeType: "changed", EntityType: b.typ, EntityID: b.id,
			Before: json.RawMessage(a.dataJSON), After: json.RawMessage(b.dataJSON),
			ChangedFields: dataDiffFields(a.dataJSON, b.dataJSON),
		})
		return
	}
	if len(left) > 0 && len(right) > 0 {
		diff.Warnings = append(diff.Warnings, fmt.Sprintf(
			"稳定键 %s 存在配对歧义（剩余 %d → %d 项），已分别保留为 removed/added", key, len(left), len(right)))
	}
	for _, e := range left {
		diff.Changes = append(diff.Changes, DiffChange{
			ChangeType: "removed", EntityType: e.typ, EntityID: e.id, Data: json.RawMessage(e.dataJSON),
		})
	}
	for _, e := range right {
		diff.Changes = append(diff.Changes, DiffChange{
			ChangeType: "added", EntityType: e.typ, EntityID: e.id, Data: json.RawMessage(e.dataJSON),
		})
	}
}

// fallbackKey 稳定键计算失败时的兜底键（"fallback:" 前缀不会与任何正常键冲突，
// entity_id 在快照内唯一，不会产生重复兜底键）。
func fallbackKey(typ, entityID string) string {
	return "fallback:" + typ + "|" + entityID
}

// stableKey 计算实体的稳定匹配键（entity_id 不稳定的类型用事实字段）。
func stableKey(typ, entityID, dataJSON string) string {
	switch typ {
	case "process", "service":
		return typ + "|" + entityID
	case "persistence":
		var d struct {
			Type     string `json:"type"`
			Location string `json:"location"`
			Name     string `json:"name"`
		}
		if err := json.Unmarshal([]byte(dataJSON), &d); err != nil {
			return ""
		}
		return "persistence|" + d.Type + "|" + d.Location + "|" + d.Name
	case "network":
		var d struct {
			Protocol  string `json:"protocol"`
			LocalIP   string `json:"local_ip"`
			LocalPort uint16 `json:"local_port"`
			PID       uint32 `json:"pid"`
		}
		if err := json.Unmarshal([]byte(dataJSON), &d); err != nil {
			return ""
		}
		// 稳定键排除会变化的 remote_ip/remote_port/state：
		// 相同 local 端点的连接，remote 变化应识别为 changed（而非 removed+added）
		return fmt.Sprintf("network|%s|%s|%d|%d", d.Protocol, d.LocalIP, d.LocalPort, d.PID)
	}
	return ""
}

// MergeEntityUpdates 将 entity 的 data 与全部 entity_update 的 data 合并为最终可比较视图。
// 以 entity 为基，按 update 顺序覆盖/新增字段（update 不修改原实体，仅内存视图）。
// 供 Snapshot Diff（Step 7）与 Analyzer（Step 8.1）复用，避免两套合并逻辑。
func MergeEntityUpdates(base string, updates []EntityUpdateRow) string {
	out := map[string]any{}
	if err := json.Unmarshal([]byte(base), &out); err != nil || out == nil {
		return base
	}
	for _, u := range updates {
		var part map[string]any
		if err := json.Unmarshal([]byte(u.DataJSON), &part); err != nil {
			continue
		}
		for k, v := range part {
			out[k] = v
		}
	}
	b, err := json.Marshal(out)
	if err != nil {
		return base
	}
	return string(b)
}

// dataDiffFields 返回两个 data JSON 之间值不同的字段名。
// 仅在 A 或仅在 B 存在的字段也算变化（单方存在应明确标记，而非不可解释）。
func dataDiffFields(a, b string) []string {
	ma, mb := map[string]any{}, map[string]any{}
	errA := json.Unmarshal([]byte(a), &ma)
	errB := json.Unmarshal([]byte(b), &mb)
	if errA != nil || errB != nil || ma == nil || mb == nil {
		if a != b {
			return []string{"data"}
		}
		return nil
	}

	keys := map[string]bool{}
	for k := range ma {
		keys[k] = true
	}
	for k := range mb {
		keys[k] = true
	}
	var fields []string
	for k := range keys {
		av, aok := ma[k]
		bv, bok := mb[k]
		if aok != bok || !jsonEqual(av, bv) {
			fields = append(fields, k)
		}
	}
	sort.Strings(fields)
	return fields
}

// jsonEqual 比较两个 JSON 值（数字按 float64 统一比较）。
func jsonEqual(a, b any) bool {
	ab, err := json.Marshal(a)
	if err != nil {
		return false
	}
	bb, err := json.Marshal(b)
	if err != nil {
		return false
	}
	return string(ab) == string(bb)
}
