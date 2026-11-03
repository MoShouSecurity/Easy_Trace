package main

import (
	"strings"

	"easytrace"
	"easytrace/internal/analyzer"
)

// embeddedRulesLabel 是内嵌规则包在输出中的标识，便于事后核对"这份报告用的是哪套规则"。
const embeddedRulesLabel = "embedded:rules"

// loadRules 决定规则来源：
//
//   - 显式给出 -r <dir> → 从磁盘加载（外挂/覆盖内嵌；现场临时加规则走这条）
//   - 未给出 → 使用**编译进二进制的内嵌规则包**（单 exe 即可用：不依赖 cwd，
//     也不要求随包分发 rules/ 目录）
//
// 两条路径共用 analyzer.FSRuleProvider（同一套遍历/解析/校验），因此行为一致。
// 返回 (规则, 来源标识, 错误)。
func loadRules(rulesDir string) ([]*analyzer.Rule, string, error) {
	if strings.TrimSpace(rulesDir) != "" {
		rules, err := analyzer.NewFileRuleProvider(rulesDir).Load()
		if err != nil {
			return nil, rulesDir, err
		}
		return rules, rulesDir, nil
	}
	rules, err := analyzer.NewFSRuleProvider(easytrace.EmbeddedRules, "rules").Load()
	if err != nil {
		return nil, embeddedRulesLabel, err
	}
	return rules, embeddedRulesLabel, nil
}
