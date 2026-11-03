package model

import (
	"time"

	"easytrace/internal/schema"
)

// Relation 表示两个实体之间发生的关系（spawn / network_connect / execute / ...）。
// SourceID / TargetID 引用已输出的 entity_id。
type Relation struct {
	SchemaVersion string    `json:"schema_version"`
	Type          string    `json:"type"`
	RelationID    string    `json:"relation_id"`
	SourceID      string    `json:"source_id"`
	TargetID      string    `json:"target_id"`
	RelationType  string    `json:"relation_type"`
	Timestamp     time.Time `json:"timestamp"`
	Data          any       `json:"data"`
}

// NewRelation 构造带默认字段值的 Relation。
func NewRelation(relationID, sourceID, targetID, relationType string, data any) *Relation {
	return &Relation{
		SchemaVersion: schema.Version,
		Type:          "relation",
		RelationID:    relationID,
		SourceID:      sourceID,
		TargetID:      targetID,
		RelationType:  relationType,
		Timestamp:     time.Now().UTC(),
		Data:          data,
	}
}
