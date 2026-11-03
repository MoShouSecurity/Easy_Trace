// Package model 定义 Easy_Trace 数据协议的核心模型：
// Entity（实体）、Relation（关系）、Finding（发现项）及强类型 Data 结构。
//
// 字段定义以 docs/protocol-spec-v0.2.md 为唯一事实来源。
package model

import (
	"time"

	"easytrace/internal/schema"
)

// Entity 表示系统中存在的一个对象（主机/进程/文件/用户/服务/任务/IP/注册表/驱动/持久化项）。
type Entity struct {
	SchemaVersion string    `json:"schema_version"`
	Type          string    `json:"type"`
	EntityType    string    `json:"entity_type"`
	EntityID      string    `json:"entity_id"`
	Timestamp     time.Time `json:"timestamp"`
	Data          any       `json:"data"`
}

// NewEntity 构造带默认字段值的 Entity。
// Data 必须使用协议定义的强类型结构体（见 data.go）。
func NewEntity(entityType, entityID string, data any) *Entity {
	return &Entity{
		SchemaVersion: schema.Version,
		Type:          "entity",
		EntityType:    entityType,
		EntityID:      entityID,
		Timestamp:     time.Now().UTC(),
		Data:          data,
	}
}
