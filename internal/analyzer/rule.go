package analyzer

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"easytrace/internal/protocol"
)

// ConditionOperator 第一阶段支持的比较运算符（全部 AND 组合）。
type ConditionOperator string

const (
	OpEquals      ConditionOperator = "equals"
	OpNotEquals   ConditionOperator = "not_equals"
	OpContains    ConditionOperator = "contains"
	OpContainsAny ConditionOperator = "contains_any"
	OpStartsWith  ConditionOperator = "starts_with"
	OpEndsWith    ConditionOperator = "ends_with"
	OpEndsWithAny ConditionOperator = "ends_with_any"
	OpExists      ConditionOperator = "exists"
	OpNotExists   ConditionOperator = "not_exists"
)

var validOperators = map[ConditionOperator]bool{
	OpEquals: true, OpNotEquals: true, OpContains: true, OpContainsAny: true,
	OpStartsWith: true, OpEndsWith: true, OpEndsWithAny: true, OpExists: true, OpNotExists: true,
}

// Condition 是一条字段比较条件（与其它条件 AND）。
type Condition struct {
	Field    string   `yaml:"field"`
	Operator string   `yaml:"operator"`
	Value    string   `yaml:"value,omitempty"`
	Values   []string `yaml:"values,omitempty"` // contains_any / ends_with_any 用
}

// Rule 是 YAML 规则解析后的模型。
type Rule struct {
	RuleID      string `yaml:"rule_id"`
	Title       string `yaml:"title"`
	Description string `yaml:"description"`
	Severity    string `yaml:"severity"`
	// Score 是可选的风险分值（协议 v0.1 §3.2 的分值表）。0 表示未声明，
	// 此时由 severity 推导默认分（见 report.go 的 severityDefaultScore）。
	Score      int         `yaml:"score"`
	Target     string      `yaml:"target"` // entity_type
	Conditions []Condition `yaml:"conditions"`
	Advice     string      `yaml:"advice"`
	Source     string      `yaml:"-" json:"-"` // 相对规则包路径，仅供本地管理命令使用
}

// validSeverities 第一阶段允许的 severity。
var validSeverities = map[string]bool{"low": true, "medium": true, "high": true}

// IOC 规则只允许引用已采集的网络连接事实；LISTENING 实体中的 remote_*
// 是 API 占位值，必须通过 state 条件排除。deepOnlyFields 来自深采补证，
// 需要显式声明 collection_level=deep，避免 basic 快照的静默零命中被误解。
var (
	remoteFactFields = map[string]bool{"remote_ip": true, "remote_port": true}
	deepOnlyFields   = map[string]bool{
		"hash_sha256":         true,
		"parent_command_line": true,
		"signature_valid":     true,
		"signature_state":     true,
		"publisher":           true,
		"last_write_time":     true,
	}
)

// isDeepOnlyField 判断某实体类型的条件字段是否只在深采补证后才有值。
//
// command_line 不能放进全局 deepOnlyFields：process 的命令行来自深采 PEB 读取，
// 但 event 实体的 4688 command_line 是 Basic 采集的普通字段。按 target 区分，
// 避免未来 event 规则被错误要求 collection_level=deep。
func isDeepOnlyField(target, field string) bool {
	if deepOnlyFields[strings.ToLower(field)] {
		return true
	}
	if strings.EqualFold(target, "process") && strings.EqualFold(field, "command_line") {
		return true
	}
	// execution 的 command/occurrences 只来自 pshistory（Deep 才采集）；
	// name/path 在 Basic 的 UserAssist/BAM/RecentDocs 里也有，不能整体标为深采。
	if strings.EqualFold(target, "execution") {
		switch strings.ToLower(field) {
		case "command", "occurrences":
			return true
		}
	}
	return false
}

// 已知 YAML 字段白名单（严格校验：拒绝未知字段，防止拼写错误被静默忽略）。
var (
	knownRuleKeys = map[string]bool{
		"rule_id": true, "title": true, "description": true, "severity": true, "score": true,
		"target": true, "conditions": true, "advice": true,
	}
	knownTargetKeys = map[string]bool{"entity_type": true}
	knownCondKeys   = map[string]bool{
		"field": true, "operator": true, "value": true, "values": true,
	}
)

// checkUnknownKeys 校验 map 节点只包含 known 中的键（多余字段一律报错）。
func checkUnknownKeys(node *yamlNode, known map[string]bool, ctx string) error {
	if node == nil || node.kind != yamlMap {
		return nil
	}
	for _, kv := range node.kv {
		if !known[kv.key] {
			return fmt.Errorf("%s: 未知字段 %q（拼写错误将被拒绝，而不是被静默忽略）", ctx, kv.key)
		}
	}
	return nil
}

// parseRule 从 yamlNode 解析并校验一条规则。
func parseRule(node *yamlNode, src string) (*Rule, error) {
	if node == nil || node.kind != yamlMap {
		return nil, fmt.Errorf("规则必须是 map（文件: %s）", src)
	}
	if err := checkUnknownKeys(node, knownRuleKeys, "规则"); err != nil {
		return nil, fmt.Errorf("%s（文件: %s）", err.Error(), src)
	}
	r := &Rule{Source: filepath.ToSlash(src)}
	r.RuleID = node.get("rule_id").strVal()
	r.Title = node.get("title").strVal()
	r.Description = node.get("description").strVal()
	r.Severity = node.get("severity").strVal()
	// 可选：风险分值。缺省或空值时保持 0（由 severity 推导默认分）。
	if sc := node.get("score"); sc != nil {
		if raw := sc.strVal(); raw != "" {
			v, err := sc.asInt()
			if err != nil {
				return nil, fmt.Errorf("规则 %s: score 必须是整数: %q", r.RuleID, raw)
			}
			r.Score = v
		}
	}
	r.Advice = node.get("advice").strVal()

	if t := node.get("target"); t != nil && t.kind == yamlMap {
		if err := checkUnknownKeys(t, knownTargetKeys, fmt.Sprintf("规则 %s target", r.RuleID)); err != nil {
			return nil, err
		}
		r.Target = t.get("entity_type").strVal()
	} else if t != nil {
		r.Target = t.strVal()
	}

	conds := node.get("conditions")
	if conds != nil {
		if conds.kind != yamlSeq {
			return nil, fmt.Errorf("规则 %s: conditions 必须是列表", r.RuleID)
		}
		for i, c := range conds.items {
			ctx := fmt.Sprintf("规则 %s 条件 %d", r.RuleID, i+1)
			if err := checkUnknownKeys(c, knownCondKeys, ctx); err != nil {
				return nil, err
			}
			cond := Condition{}
			cond.Field = c.get("field").strVal()
			cond.Operator = c.get("operator").strVal()
			cond.Value = c.get("value").strVal()
			if vs := c.get("values"); vs != nil {
				lst, err := vs.listStrings()
				if err != nil {
					return nil, fmt.Errorf("规则 %s: values 解析失败: %v", r.RuleID, err)
				}
				cond.Values = lst
			} else if v := c.get("value"); v != nil && v.kind == yamlSeq {
				lst, err := v.listStrings()
				if err != nil {
					return nil, fmt.Errorf("规则 %s: value 列表解析失败: %v", r.RuleID, err)
				}
				cond.Values = lst
			}
			r.Conditions = append(r.Conditions, cond)
		}
	}

	if err := r.Validate(); err != nil {
		return nil, fmt.Errorf("%s（文件: %s）", err.Error(), src)
	}
	return r, nil
}

// Validate 校验规则字段合法性（严格报错，不静默忽略）。
func (r *Rule) Validate() error {
	if r.RuleID == "" {
		return fmt.Errorf("rule_id 缺失")
	}
	if r.Title == "" {
		return fmt.Errorf("规则 %s: title 缺失", r.RuleID)
	}
	if !validSeverities[r.Severity] {
		return fmt.Errorf("规则 %s: severity 非法（允许 low/medium/high）: %q", r.RuleID, r.Severity)
	}
	if r.Score < 0 || r.Score > 1000 {
		return fmt.Errorf("规则 %s: score 超出允许范围 0-1000: %d", r.RuleID, r.Score)
	}
	if r.Target == "" {
		return fmt.Errorf("规则 %s: target.entity_type 缺失", r.RuleID)
	}
	if !protocol.IsKnownEntityType(r.Target) {
		return fmt.Errorf("规则 %s: 未知 target.entity_type %q（允许: %s）",
			r.RuleID, r.Target, strings.Join(protocol.KnownEntityTypes(), "/"))
	}
	if len(r.Conditions) == 0 {
		return fmt.Errorf("规则 %s: conditions 不能为空", r.RuleID)
	}
	for i, c := range r.Conditions {
		if c.Field == "" {
			return fmt.Errorf("规则 %s: 条件 %d field 缺失", r.RuleID, i+1)
		}
		if !isKnownEntityField(r.Target, strings.ToLower(c.Field)) {
			return fmt.Errorf("规则 %s: 条件 %d 字段 %q 不是 target %s 的已知字段（拼写错误会被拒绝，而不是静默不命中）",
				r.RuleID, i+1, c.Field, r.Target)
		}
		if !validOperators[ConditionOperator(c.Operator)] {
			return fmt.Errorf("规则 %s: 条件 %d operator 非法: %q（允许: equals/not_equals/contains/contains_any/starts_with/ends_with/ends_with_any/exists/not_exists）", r.RuleID, i+1, c.Operator)
		}
		switch ConditionOperator(c.Operator) {
		case OpContainsAny, OpEndsWithAny:
			if len(c.Values) == 0 {
				return fmt.Errorf("规则 %s: 条件 %d %s 需要 values 列表", r.RuleID, i+1, c.Operator)
			}
			for _, v := range c.Values {
				if v == "" {
					return fmt.Errorf("规则 %s: 条件 %d %s 的 values 不能包含空值", r.RuleID, i+1, c.Operator)
				}
			}
		case OpExists, OpNotExists:
			// exists/not_exists 不需要 value；exists 语义 = 字段存在且值非空（matcher 实现）
		default:
			// equals/not_equals/contains/starts_with/ends_with：value 必须非空
			// （空值规则无实际检测意义，只会造成声明与执行不一致）
			if c.Value == "" {
				return fmt.Errorf("规则 %s: 条件 %d %s 的 value 不能为空", r.RuleID, i+1, c.Operator)
			}
		}
	}
	if err := r.validateDeepOnlyFields(); err != nil {
		return err
	}
	return r.validateIOCConventions()
}

// validateDeepOnlyFields 对所有规则（不仅是 IOC）强制深采守卫。
//
// 这是"显式优于静默"的校验：条件使用深采字段却不在同一规则要求
// collection_level=deep 时，Basic 快照会静默零命中，容易被误读成"没有风险"。
func (r *Rule) validateDeepOnlyFields() error {
	for i, condition := range r.Conditions {
		if !isDeepOnlyField(r.Target, condition.Field) {
			continue
		}
		if !r.hasCondition("collection_level", OpEquals, "deep") {
			return fmt.Errorf("规则 %s: 条件 %d 使用深采字段 %s 时必须同时包含 collection_level equals deep；basic 快照没有该字段", r.RuleID, i+1, condition.Field)
		}
	}
	return nil
}

// hasCondition checks for an exact condition that will be ANDed with every
// other condition by the Matcher. Field and value matching are case-insensitive
// to mirror the Matcher’s Windows-oriented comparison semantics.
func (r *Rule) hasCondition(field string, op ConditionOperator, value string) bool {
	for _, condition := range r.Conditions {
		if strings.EqualFold(condition.Field, field) && ConditionOperator(condition.Operator) == op && strings.EqualFold(condition.Value, value) {
			return true
		}
	}
	return false
}

// isIOCSource reports whether Source is beneath the rule pack's ioc directory.
func (r *Rule) isIOCSource() bool {
	return strings.HasPrefix(filepath.ToSlash(r.Source), "ioc/")
}

// validateIOCConventions enforces local-file-only IOC lifecycle rules without
// adding a second file format or changing the rule YAML key whitelist.
func (r *Rule) validateIOCConventions() error {
	inIOCDir := r.isIOCSource()
	isIOCRule := strings.HasPrefix(r.RuleID, "ioc.")
	if inIOCDir && !isIOCRule {
		return fmt.Errorf("规则 %s: ioc/ 目录中的规则 rule_id 必须以 ioc. 开头", r.RuleID)
	}
	if isIOCRule && !inIOCDir {
		return fmt.Errorf("规则 %s: ioc. 规则必须位于 ioc/ 目录", r.RuleID)
	}
	if !isIOCRule {
		return nil
	}
	if !hasSourceMarker(r.Description) && !hasSourceMarker(r.Advice) {
		return fmt.Errorf("规则 %s: IOC 规则 description 或 advice 必须包含非空 Source: 来源标记", r.RuleID)
	}
	for i, condition := range r.Conditions {
		field := strings.ToLower(condition.Field)
		if remoteFactFields[field] && !r.hasCondition("state", OpNotEquals, "LISTENING") {
			return fmt.Errorf("规则 %s: 条件 %d 使用 %s 时必须同时包含 state not_equals LISTENING；监听实体的 remote_* 是采集占位值", r.RuleID, i+1, condition.Field)
		}
	}
	return nil
}

func hasSourceMarker(text string) bool {
	const marker = "Source:"
	index := strings.Index(text, marker)
	return index >= 0 && strings.TrimSpace(text[index+len(marker):]) != ""
}

// validateUniqueRuleIDs 校验规则 ID 唯一。
func validateUniqueRuleIDs(rules []*Rule) error {
	seen := map[string]string{}
	for _, r := range rules {
		if prev, ok := seen[r.RuleID]; ok {
			return fmt.Errorf("规则 ID 重复: %q（出现在 %s 与当前规则）", r.RuleID, prev)
		}
		seen[r.RuleID] = r.Title
	}
	return nil
}

// sortRules 按 rule_id 稳定排序（输出确定性）。
func sortRules(rules []*Rule) {
	sort.Slice(rules, func(i, j int) bool { return rules[i].RuleID < rules[j].RuleID })
}

// RuleNeedsDeepCollection 报告规则是否依赖**深采字段**（deepOnlyFields）。
// 供 `rules validate` 汇总提示使用——名单只有这一份，避免各调用方各写一份而漂移
// （历史缺陷：cmd 侧曾自建名单，漏了 signature_state）。
func RuleNeedsDeepCollection(r *Rule) bool {
	if r == nil {
		return false
	}
	for _, c := range r.Conditions {
		if deepOnlyFields[strings.ToLower(c.Field)] {
			return true
		}
	}
	return false
}

// 统一字符串化（用于比较）。
func stringify(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case float64:
		return strings.TrimSuffix(fmt.Sprintf("%v", t), ".0")
	default:
		return fmt.Sprintf("%v", t)
	}
}
