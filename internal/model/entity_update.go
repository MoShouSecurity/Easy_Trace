package model

import (
	"time"

	"easytrace/internal/schema"
)

// EntityUpdate 表示已存在实体的后续证据补充（协议 v0.2 §1.2）。
//
// 用于 IR 调查过程的流式证据更新：先输出基础 entity，证据到位后
// 输出 entity_update 补充（enrichment）/修正（correction）/撤回（removal）。
type EntityUpdate struct {
	SchemaVersion string    `json:"schema_version"`
	Type          string    `json:"type"`
	EntityID      string    `json:"entity_id"`
	UpdateType    string    `json:"update_type"`
	Timestamp     time.Time `json:"timestamp"`
	Data          any       `json:"data"`
}

// NewEntityUpdate 构造 EntityUpdate（默认 type=entity_update, update_type=enrichment）。
func NewEntityUpdate(entityID string, data any) *EntityUpdate {
	return &EntityUpdate{
		SchemaVersion: schema.Version,
		Type:          "entity_update",
		EntityID:      entityID,
		UpdateType:    "enrichment",
		Timestamp:     time.Now().UTC(),
		Data:          data,
	}
}
