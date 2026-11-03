// Package protocol 提供协议校验（v0.2 冻结）。
//
// 所有输出到 JSONL 流的消息应先在采集/分析侧通过本包校验，
// 保证下游（SQLite / GUI / 规则引擎）收到的数据符合协议。
package protocol

import (
	"fmt"
	"sort"
	"strings"

	"easytrace/internal/model"
	"easytrace/internal/schema"
)

// 已知 entity_type / relation_type / severity 集合（协议 v0.2 §1）。
// 新增类型按协议变更流程：先更新 protocol-spec-v0.2.md，再同步本集合与单测。
var knownEntityTypes = map[string]bool{
	"host": true, "process": true, "file": true, "user": true,
	"service": true, "task": true, "registry": true, "network": true,
	"driver": true, "persistence": true,
	// event：日志采集阶段 B（2026-10-15 批准）新增。v0.2 冻结规范**不改写**，
	// EventData 形状记录在 docs/实现状态.md「实体类型补充」。
	"event": true,
	// prefetch：活动痕迹采集（2026-10-30 批准）新增。v0.2 冻结规范**不改写**，
	// PrefetchData 形状记录在 docs/实现状态.md「实体类型补充」。
	"prefetch": true,
	// execution：执行痕迹采集（2026-10-30 批准）新增。v0.2 冻结规范**不改写**，
	// ExecutionData 形状记录在 docs/实现状态.md「实体类型补充」。
	"execution": true,
}

// IsKnownEntityType 报告 entity_type 是否在协议白名单内。
// 供规则校验等只读消费者使用，避免复制一份类型表后漂移。
func IsKnownEntityType(entityType string) bool {
	return knownEntityTypes[entityType]
}

// KnownEntityTypes 返回排序后的已知 entity_type（用于错误提示/文档生成）。
func KnownEntityTypes() []string {
	out := make([]string, 0, len(knownEntityTypes))
	for t := range knownEntityTypes {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

var knownRelationTypes = map[string]bool{
	"spawn": true, "parent_child": true, "network_connect": true,
	"execute": true, "launch": true, "connect": true,
	"read": true, "write": true, "create": true, "load": true,
}

var knownSeverities = map[string]bool{
	"critical": true, "high": true, "medium": true, "low": true,
}

var knownUpdateTypes = map[string]bool{
	"enrichment": true, "correction": true, "removal": true,
}

func checkSchemaVersion(sv string) error {
	if sv != schema.Version {
		return fmt.Errorf("schema_version 不匹配: got %q, want %q", sv, schema.Version)
	}
	return nil
}

// ValidateEntity 校验 Entity 是否符合 v0.2 协议。
func ValidateEntity(e *model.Entity) error {
	if e == nil {
		return fmt.Errorf("entity 为 nil")
	}
	if err := checkSchemaVersion(e.SchemaVersion); err != nil {
		return err
	}
	if e.Type != "entity" {
		return fmt.Errorf("type 必须是 entity, got %q", e.Type)
	}
	if e.EntityType == "" {
		return fmt.Errorf("entity_type 为空")
	}
	if !knownEntityTypes[e.EntityType] {
		return fmt.Errorf("未知 entity_type %q", e.EntityType)
	}
	if e.EntityID == "" {
		return fmt.Errorf("entity_id 为空")
	}
	if !strings.HasPrefix(e.EntityID, e.EntityType+"_") {
		return fmt.Errorf("entity_id %q 必须以 %q 开头", e.EntityID, e.EntityType+"_")
	}
	if e.Timestamp.IsZero() {
		return fmt.Errorf("timestamp 为零值")
	}
	if e.Data == nil {
		return fmt.Errorf("data 为 nil")
	}
	return nil
}

// ValidateRelation 校验 Relation 是否符合 v0.2 协议。
func ValidateRelation(r *model.Relation) error {
	if r == nil {
		return fmt.Errorf("relation 为 nil")
	}
	if err := checkSchemaVersion(r.SchemaVersion); err != nil {
		return err
	}
	if r.Type != "relation" {
		return fmt.Errorf("type 必须是 relation, got %q", r.Type)
	}
	if r.RelationID == "" {
		return fmt.Errorf("relation_id 为空")
	}
	if r.SourceID == "" {
		return fmt.Errorf("source_id 为空")
	}
	if r.TargetID == "" {
		return fmt.Errorf("target_id 为空")
	}
	if r.RelationType == "" {
		return fmt.Errorf("relation_type 为空")
	}
	if !knownRelationTypes[r.RelationType] {
		return fmt.Errorf("未知 relation_type %q", r.RelationType)
	}
	if r.Timestamp.IsZero() {
		return fmt.Errorf("timestamp 为零值")
	}
	return nil
}

// ValidateEntityUpdate 校验 EntityUpdate 是否符合 v0.2 协议（§1.2）。
func ValidateEntityUpdate(u *model.EntityUpdate) error {
	if u == nil {
		return fmt.Errorf("entity_update 为 nil")
	}
	if err := checkSchemaVersion(u.SchemaVersion); err != nil {
		return err
	}
	if u.Type != "entity_update" {
		return fmt.Errorf("type 必须是 entity_update, got %q", u.Type)
	}
	if u.EntityID == "" {
		return fmt.Errorf("entity_id 为空（必须引用已输出的实体）")
	}
	if u.UpdateType == "" || !knownUpdateTypes[u.UpdateType] {
		return fmt.Errorf("update_type 非法: %q", u.UpdateType)
	}
	if u.Timestamp.IsZero() {
		return fmt.Errorf("timestamp 为零值")
	}
	if u.Data == nil {
		return fmt.Errorf("data 为 nil")
	}
	return nil
}

// ValidateFinding 校验 Finding 是否符合 v0.2 协议。
func ValidateFinding(f *model.Finding) error {
	if f == nil {
		return fmt.Errorf("finding 为 nil")
	}
	if err := checkSchemaVersion(f.SchemaVersion); err != nil {
		return err
	}
	if f.Type != "finding" {
		return fmt.Errorf("type 必须是 finding, got %q", f.Type)
	}
	if f.FindingID == "" {
		return fmt.Errorf("finding_id 为空")
	}
	if f.RuleID == "" {
		return fmt.Errorf("rule_id 为空")
	}
	if f.Title == "" {
		return fmt.Errorf("title 为空")
	}
	if f.Severity == "" || !knownSeverities[f.Severity] {
		return fmt.Errorf("severity 非法: %q", f.Severity)
	}
	if f.EntityID == "" {
		return fmt.Errorf("entity_id 为空")
	}
	if f.Timestamp.IsZero() {
		return fmt.Errorf("timestamp 为零值")
	}
	return nil
}
