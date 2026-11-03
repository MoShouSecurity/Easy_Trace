package model

import (
	"time"

	"easytrace/internal/schema"
)

// Finding 表示分析模块认为值得关注的问题（不是实体，是判定结果）。
// EntityID 是主挂载实体（风险评分落点）；RelatedEntities 是其它涉及实体（攻击链/组合告警）。
type Finding struct {
	SchemaVersion   string    `json:"schema_version"`
	Type            string    `json:"type"`
	FindingID       string    `json:"finding_id"`
	RuleID          string    `json:"rule_id"`
	Title           string    `json:"title"`
	Description     string    `json:"description"`
	Severity        string    `json:"severity"`
	EntityID        string    `json:"entity_id"`
	RelatedEntities []string  `json:"related_entities,omitempty"`
	Evidence        []string  `json:"evidence,omitempty"`
	Advice          []string  `json:"advice,omitempty"`
	Timestamp       time.Time `json:"timestamp"`
}

// NewFinding 构造带默认字段值的 Finding。
func NewFinding(findingID, ruleID, title, description, severity, entityID string,
	related, evidence, advice []string) *Finding {
	return &Finding{
		SchemaVersion:   schema.Version,
		Type:            "finding",
		FindingID:       findingID,
		RuleID:          ruleID,
		Title:           title,
		Description:     description,
		Severity:        severity,
		EntityID:        entityID,
		RelatedEntities: related,
		Evidence:        evidence,
		Advice:          advice,
		Timestamp:       time.Now().UTC(),
	}
}
