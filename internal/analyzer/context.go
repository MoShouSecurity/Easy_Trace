package analyzer

import (
	"sort"

	"easytrace/internal/storage"
)

// FindingContext 为 Finding 提供结构化调查上下文（Go API，不改变协议）。
// 后续 GUI 可直接使用此结构体；CLI 将其展平为 evidence []string。
type FindingContext struct {
	// EntityType 命中实体类型（process/persistence/network/...），CLI 据此选择
	// 统一证据摘要（Process: PID/Image/CommandLine、File: Path/Hash/Signer 或
	// Network: Protocol/Local/State/PID，Step 13）。
	EntityType string            `json:"entity_type,omitempty"`
	Process    map[string]string `json:"process,omitempty"`
	Network    map[string]string `json:"network,omitempty"`
	// EntityData 是非 process/network 实体的命中事实（service/registry/task/file/...）。
	// 展平为 evidence 时按实体类型前缀输出，例如 service.binary_path=...。
	EntityData      map[string]string   `json:"entity_data,omitempty"`
	ParentProcess   map[string]string   `json:"parent_process,omitempty"`
	ChildProcesses  []map[string]string `json:"child_processes,omitempty"`
	NetworkConns    []map[string]string `json:"network_connections,omitempty"`
	PersistenceRefs []map[string]string `json:"persistence,omitempty"`
	MissingEvidence []string            `json:"missing_evidence,omitempty"`
}

// entityContextFields 定义各类实体在 evidence 中应展示的最小事实集。
//
// process / network 有专门的丰富上下文；其余类型此前完全没有 evidence，
// 导致 service / registry 规则命中时“只有标题，没有匹配到的路径/键值”。
// 这里按类型列出调查必需字段，展平时统一加 <entity_type>. 前缀。
var entityContextFields = map[string][]string{
	"persistence": {"type", "location", "name", "command", "path", "user", "key_last_write_time",
		"signature_state", "hash_sha256", "last_write_time", "collection_level"},
	"service":  {"service_name", "display_name", "binary_path", "start_type", "status", "account"},
	"task":     {"task_name", "path", "author", "command", "trigger", "enabled"},
	"user":     {"username", "sid", "groups", "enabled", "last_login"},
	"file":     {"path", "size", "last_write_time", "extension", "hash_sha256", "collection_level"},
	"registry": {"path", "key", "name", "value_type", "value_data", "truncated", "collection_level"},
	"driver":   {"name", "path", "base_address", "collection_level"},
	"host":     {"hostname", "os_version", "os_build", "architecture", "username", "current_time", "boot_time"},
	"event": {"channel", "event_id", "level", "provider", "record_id", "time_created", "computer", "summary",
		"logon_type", "target_user", "target_sid", "subject_user", "ip_address", "logon_process", "share_name",
		"ticket_encryption_type", "service_name", "process_name", "command_line", "script_block_text"},
	"prefetch": {"executable_name", "prefetch_hash", "source_version", "path", "file_size",
		"last_write_time", "collection_level"},
	"execution": {"source", "user", "name", "path", "command", "run_count", "last_run_time",
		"last_write_time", "occurrences", "collection_level"},
}

// contextBuilder 基于快照的实体视图与关系为命中实体构建调查上下文。
type contextBuilder struct {
	views     map[string]entityView
	relations []storage.RelationRow
	// 关系索引：O(1) 查找
	relBySource map[string][]storage.RelationRow
	relByTarget map[string][]storage.RelationRow
}

// newContextBuilder 在 NewAnalyzer 时建立关系索引（O(N+R) 一次性开销）。
func newContextBuilder(views map[string]entityView, relations []storage.RelationRow) *contextBuilder {
	cb := &contextBuilder{
		views:       views,
		relations:   relations,
		relBySource: map[string][]storage.RelationRow{},
		relByTarget: map[string][]storage.RelationRow{},
	}
	for _, r := range relations {
		cb.relBySource[r.SourceID] = append(cb.relBySource[r.SourceID], r)
		cb.relByTarget[r.TargetID] = append(cb.relByTarget[r.TargetID], r)
	}
	return cb
}

// build 为命中实体构建完整调查上下文。
func (cb *contextBuilder) build(entityID string) *FindingContext {
	ctx := &FindingContext{}
	v, ok := cb.views[entityID]
	if !ok {
		return ctx
	}
	ctx.EntityType = v.typ

	// 1. Process 上下文（仅 process 类型）
	if v.typ == "process" {
		ctx.Process = cb.buildProcessContext(v)
		ctx.MissingEvidence = cb.checkMissingEvidence(v, ctx.Process)

		// 2. 父进程（spawn relation 中 target=self → source 是父）
		ctx.ParentProcess = cb.buildParentContext(entityID)

		// 3. 子进程（spawn relation 中 source=self → target 是子）
		ctx.ChildProcesses = cb.buildChildContext(entityID)

		// 4. 网络连接（network_connect relation 中 source=self）
		ctx.NetworkConns = cb.buildNetworkContext(entityID)

		// 5. 持久化关联（execute relation 中 target=self → source 是持久化项）
		ctx.PersistenceRefs = cb.buildPersistenceContext(entityID)
	}

	// network 类型实体保留命中本身的监听/连接事实；不从 PID 推断进程身份。
	if v.typ == "network" {
		ctx.Network = cb.buildNetworkTargetContext(v)
	}

	// 其余类型（persistence/service/registry/task/file/driver/host/event/user）
	// 输出命中实体自身的关键事实。没有这一步，这些规则命中时 Evidence 为空。
	if v.typ != "process" && v.typ != "network" {
		ctx.EntityData = cb.buildEntityData(v)
	}

	return ctx
}

// buildEntityData 按 entityContextFields 提取命中实体的关键事实。
func (cb *contextBuilder) buildEntityData(v entityView) map[string]string {
	fields := entityContextFields[v.typ]
	if len(fields) == 0 {
		return nil
	}
	out := map[string]string{}
	for _, f := range fields {
		if s := stringify(v.data[f]); s != "" {
			out[f] = s
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// buildProcessContext 从实体视图提取 process 关键字段。
func (cb *contextBuilder) buildProcessContext(v entityView) map[string]string {
	// signature_valid 保留缺失/true/false；publisher 和 PE 目录不能单独证明信任。
	fields := []string{"pid", "name", "path", "signature_state", "signature_valid",
		"hash_sha256", "command_line", "username", "collection_level", "publisher"}
	out := map[string]string{}
	for _, f := range fields {
		if s := stringify(v.data[f]); s != "" {
			out[f] = s
		}
	}
	return out
}

// buildNetworkTargetContext 提取 network Finding 命中实体本身的事实。
// PID 只作为网络表采集到的字段保留，不据此猜测进程名称或路径。
func (cb *contextBuilder) buildNetworkTargetContext(v entityView) map[string]string {
	fields := []string{"protocol", "local_ip", "local_port", "remote_ip", "remote_port", "state", "pid"}
	out := map[string]string{}
	for _, f := range fields {
		if s := stringify(v.data[f]); s != "" {
			out[f] = s
		}
	}
	return out
}

// buildParentContext 查找父进程（spawn relation 中自己是 target）。
func (cb *contextBuilder) buildParentContext(entityID string) map[string]string {
	rels := cb.relByTarget[entityID]
	for _, r := range rels {
		if r.RelationType != "spawn" {
			continue
		}
		parent, ok := cb.views[r.SourceID]
		if !ok || parent.typ != "process" {
			continue
		}
		out := map[string]string{}
		for _, f := range []string{"pid", "name", "path"} {
			if s := stringify(parent.data[f]); s != "" {
				out[f] = s
			}
		}
		out["entity_id"] = r.SourceID
		return out // 只取第一个父进程
	}
	return nil
}

// buildChildContext 查找子进程（spawn relation 中自己是 source）。
func (cb *contextBuilder) buildChildContext(entityID string) []map[string]string {
	var out []map[string]string
	for _, r := range cb.relBySource[entityID] {
		if r.RelationType != "spawn" {
			continue
		}
		child, ok := cb.views[r.TargetID]
		if !ok || child.typ != "process" {
			continue
		}
		item := map[string]string{"entity_id": r.TargetID}
		for _, f := range []string{"pid", "name", "path"} {
			if s := stringify(child.data[f]); s != "" {
				item[f] = s
			}
		}
		out = append(out, item)
	}
	return out
}

// buildNetworkContext 查找网络连接（network_connect 中自己是 source）。
//
// 这里列出**全部**关联连接（含监听/回环），state 字段原样带出：上下文是事实清单，
// 不承担“是否对外连接”的判定。检测侧（process.user_path.network、关系传导）用
// isOutboundConnection 过滤，避免把监听端口当成联网证据。
func (cb *contextBuilder) buildNetworkContext(entityID string) []map[string]string {
	var out []map[string]string
	for _, r := range cb.relBySource[entityID] {
		if r.RelationType != "network_connect" {
			continue
		}
		netEnt, ok := cb.views[r.TargetID]
		if !ok || netEnt.typ != "network" {
			continue
		}
		item := map[string]string{"entity_id": r.TargetID}
		for _, f := range []string{"protocol", "remote_ip", "remote_port", "state", "local_ip", "local_port"} {
			if s := stringify(netEnt.data[f]); s != "" {
				item[f] = s
			}
		}
		out = append(out, item)
	}
	return out
}

// buildPersistenceContext 查找持久化关联（execute relation 中自己是 target）。
func (cb *contextBuilder) buildPersistenceContext(entityID string) []map[string]string {
	var out []map[string]string
	for _, r := range cb.relByTarget[entityID] {
		if r.RelationType != "execute" {
			continue
		}
		pers, ok := cb.views[r.SourceID]
		if !ok || pers.typ != "persistence" {
			continue
		}
		item := map[string]string{"entity_id": r.SourceID}
		for _, f := range []string{"type", "location", "name", "command", "path"} {
			if s := stringify(pers.data[f]); s != "" {
				item[f] = s
			}
		}
		out = append(out, item)
	}
	return out
}

// checkMissingEvidence 列出 snapshot 中缺失的关键调查字段（不是采集失败，是模式决定不采）。
func (cb *contextBuilder) checkMissingEvidence(v entityView, proc map[string]string) []string {
	// 关键字段列表中排除已存在的（字段名必须与协议一致：signature_state）
	critical := []string{"command_line", "hash_sha256", "signature_state"}
	var missing []string
	for _, f := range critical {
		if f == "signature_state" && proc[f] == "unknown" {
			missing = append(missing, f)
			continue
		}
		if _, ok := proc[f]; !ok {
			// 检查原始 data 中是否确实不存在
			if stringify(v.data[f]) == "" {
				missing = append(missing, f)
			}
		}
	}
	return missing
}

// flattenContext 将 FindingContext 展平为 evidence []string（CLI JSONL 输出用）。
// 格式: "section.field=value"，GUI 可直接使用 FindingContext 跳过此步骤。
func flattenContext(ctx *FindingContext) []string {
	var out []string

	// network target（命中的 network 实体本身）
	if ctx.Network != nil {
		keys := sortedKeys(ctx.Network)
		for _, k := range keys {
			out = append(out, "network."+k+"="+ctx.Network[k])
		}
	}

	// 非 process/network 实体自身的关键事实（service/registry/persistence/...）
	if ctx.EntityData != nil {
		prefix := ctx.EntityType
		if prefix == "" {
			prefix = "entity"
		}
		keys := sortedKeys(ctx.EntityData)
		for _, k := range keys {
			out = append(out, prefix+"."+k+"="+ctx.EntityData[k])
		}
	}

	// process
	if ctx.Process != nil {
		keys := sortedKeys(ctx.Process)
		for _, k := range keys {
			out = append(out, "process."+k+"="+ctx.Process[k])
		}
	}

	// parent_process
	if ctx.ParentProcess != nil {
		keys := sortedKeys(ctx.ParentProcess)
		for _, k := range keys {
			out = append(out, "parent."+k+"="+ctx.ParentProcess[k])
		}
	}

	// child_processes
	for i, child := range ctx.ChildProcesses {
		keys := sortedKeys(child)
		for _, k := range keys {
			out = append(out, formatIndexedKey("child", i, k, child[k]))
		}
	}

	// network_connections
	for i, conn := range ctx.NetworkConns {
		keys := sortedKeys(conn)
		for _, k := range keys {
			out = append(out, formatIndexedKey("network", i, k, conn[k]))
		}
	}

	// persistence
	for i, pers := range ctx.PersistenceRefs {
		keys := sortedKeys(pers)
		for _, k := range keys {
			out = append(out, formatIndexedKey("persistence", i, k, pers[k]))
		}
	}

	// missing_evidence
	for _, f := range ctx.MissingEvidence {
		out = append(out, "missing="+f)
	}

	return out
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func formatIndexedKey(prefix string, idx int, key, val string) string {
	return prefix + "." + key + "=" + val
}
