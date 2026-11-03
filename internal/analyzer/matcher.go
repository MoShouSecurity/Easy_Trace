package analyzer

import (
	"encoding/json"
	"fmt"
	"strings"
)

// matchConditions 判断实体的最终视图 data 是否满足规则的全部条件（AND）。
//
// 语义（Step 11.2 对齐）：
//   - exists：字段存在且值非空才匹配（存在但为空视为不满足）
//   - not_exists：字段不存在才匹配
//   - 值类运算符在字段不存在时一律不匹配（视为与任何值都不等）
//   - 字符串比较一律大小写不敏感（Windows 语义：路径/进程名/注册表类型均不区分大小写，
//     避免 "C:\Users" vs "c:\users" 造成漏报）
func matchConditions(conds []Condition, data map[string]any) bool {
	for _, c := range conds {
		val, exists := data[c.Field]
		op := ConditionOperator(c.Operator)
		switch op {
		case OpExists:
			if !exists || stringify(val) == "" {
				return false
			}
			continue
		case OpNotExists:
			if exists {
				return false
			}
			continue
		}
		if !exists {
			// 字段不存在：对值类运算符一律不匹配
			return false
		}
		s := fold(stringify(val))
		switch op {
		case OpEquals:
			if s != fold(c.Value) {
				return false
			}
		case OpNotEquals:
			if s == fold(c.Value) {
				return false
			}
		case OpContains:
			if !strings.Contains(s, fold(c.Value)) {
				return false
			}
		case OpContainsAny:
			hit := false
			for _, v := range c.Values {
				if strings.Contains(s, fold(v)) {
					hit = true
					break
				}
			}
			if !hit {
				return false
			}
		case OpStartsWith:
			if !strings.HasPrefix(s, fold(c.Value)) {
				return false
			}
		case OpEndsWith:
			if !strings.HasSuffix(s, fold(c.Value)) {
				return false
			}
		case OpEndsWithAny:
			hit := false
			for _, v := range c.Values {
				if strings.HasSuffix(s, fold(v)) {
					hit = true
					break
				}
			}
			if !hit {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// fold 大小写折叠（比较用）。
func fold(s string) string { return strings.ToLower(s) }

// extractValues 从视图提取若干字段的展示值（用于 evidence 构造）。
func extractValues(data map[string]any, fields ...string) []string {
	var out []string
	for _, f := range fields {
		if v, ok := data[f]; ok {
			s := stringify(v)
			if s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

// buildEvidence 构建 "field=value" 格式的 evidence 行，跳过空值字段。
func buildEvidence(data map[string]any, fields ...string) []string {
	var out []string
	for _, f := range fields {
		v := stringify(data[f])
		if v != "" {
			out = append(out, f+"="+v)
		}
	}
	return out
}

// parseDataMap 解析 entity data JSON 为对象。Analyzer 只读内存副本，但不能把
// 已损坏的数据库事实静默降级为空 map，否则规则会以“零命中”掩盖数据完整性问题。
func parseDataMap(dataJSON string) (map[string]any, error) {
	var m map[string]any
	if err := json.Unmarshal([]byte(dataJSON), &m); err != nil {
		return nil, fmt.Errorf("data JSON 解析失败: %w", err)
	}
	if m == nil {
		return nil, fmt.Errorf("data JSON 必须为对象")
	}
	return m, nil
}
