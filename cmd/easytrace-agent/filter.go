package main

import (
	"strings"

	"easytrace/internal/analyzer"
)

// 本文件实现 Finding 展示层过滤（Step 12.2）：
//
//	easytrace analyze --severity low,high --rule process.user_path --entity proc_1
//
// 原则：
//   - 过滤只影响展示（文本 / JSONL / summary），Analyzer 全量分析，绝不前置到规则引擎
//   - --severity / --rule / --entity 均支持重复 flag 与逗号分隔多值，大小写不敏感
//   - 多个条件之间为 AND（同规则 conditions 语义），同条件多值为 OR
//
// 不是检测能力增强：不改变命中逻辑，只收窄展示结果。

// stringList flag.Value：支持重复 flag 与逗号分隔多值（Step 12.2）。
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		if p := strings.TrimSpace(part); p != "" {
			*s = append(*s, p)
		}
	}
	return nil
}

// applyFindingFilter 按 --severity / --rule / --entity 过滤分析结果（展示层）。
// 无过滤条件时原样返回；条件为空集合时不参与过滤（该维度全放行）。
func applyFindingFilter(results []*analyzer.AnalysisResult, severities, rules, entities []string) []*analyzer.AnalysisResult {
	if len(severities) == 0 && len(rules) == 0 && len(entities) == 0 {
		return results
	}
	sevSet := toSet(severities)
	ruleSet := toSet(rules)
	entSet := toSet(entities)

	out := make([]*analyzer.AnalysisResult, 0, len(results))
	for _, r := range results {
		if len(sevSet) > 0 && !sevSet[strings.ToLower(r.Finding.Severity)] {
			continue
		}
		if len(ruleSet) > 0 && !ruleSet[strings.ToLower(r.Finding.RuleID)] {
			continue
		}
		if len(entSet) > 0 && !entSet[strings.ToLower(r.Finding.EntityID)] {
			continue
		}
		out = append(out, r)
	}
	return out
}

// toSet 规范化（小写）字符串列表为集合。
func toSet(items []string) map[string]bool {
	set := make(map[string]bool, len(items))
	for _, s := range items {
		set[strings.ToLower(s)] = true
	}
	return set
}
