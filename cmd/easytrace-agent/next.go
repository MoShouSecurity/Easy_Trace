package main

import (
	"strings"

	"easytrace/internal/analyzer"
)

// 本文件实现 Next Investigation 动作引导（Step 12.2）：
// 基于 Finding 上下文生成"下一步调查动作"列表，回答"这个 Finding 下一步做什么"。
//
// 原则：
//   - 静态规则映射（cmd 层），不改变 Analyzer / 规则文件 / Finding 结构
//   - 每行一个可执行动作，简洁不展开长篇说明
//   - 缺失证据 → 引导深采（inspect）；规则分类 → 引导验证动作
//
// 不是检测能力增强，不是自动化处置：只输出建议，由应急响应人员决策执行。

// nextInvestigation 基于 Finding 与上下文生成下一步调查动作列表。
func nextInvestigation(r *analyzer.AnalysisResult) []string {
	f := r.Finding
	var ctx *analyzer.FindingContext
	if r.Context != nil {
		ctx = r.Context
	}

	rule := strings.ToLower(f.RuleID)
	var pid string
	if ctx != nil && ctx.Process != nil {
		pid = ctx.Process["pid"]
	}

	switch {
	case ctx != nil && ctx.EntityType == "process":
		return processSteps(ctx, rule, pid)
	case ctx != nil && ctx.EntityType == "persistence":
		return persistenceSteps(ctx, rule)
	case ctx != nil && ctx.EntityType == "network":
		return []string{"review the process owning this listener", "check exposure scope of the listening address"}
	default:
		return []string{"verify entity origin and integrity"}
	}
}

// processSteps 进程实体：缺证据 → 深采补证据；签名/网络相关规则 → 对应验证动作。
func processSteps(ctx *analyzer.FindingContext, rule, pid string) []string {
	var steps []string
	if len(ctx.MissingEvidence) > 0 {
		cmd := "easytrace inspect -pid " + pid
		if pid == "" {
			cmd = "easytrace inspect -pid <pid>"
		}
		steps = append(steps, "inspect process metadata (deep collection): "+cmd)
	}
	if strings.Contains(rule, "unsigned") || strings.Contains(rule, "signature") {
		steps = append(steps, "verify file signature and integrity")
	}
	if strings.Contains(rule, "network") || len(ctx.NetworkConns) > 0 {
		steps = append(steps, "review network connections and destination")
	}
	if len(steps) == 0 {
		steps = append(steps, "verify file origin and integrity (compare hash)")
	}
	return steps
}

// persistenceSteps 持久化实体：核实文件来源 + 审查启动项本体。
func persistenceSteps(ctx *analyzer.FindingContext, rule string) []string {
	steps := []string{"verify file origin and hash (file existence check)"}
	// EntityData 是当前的持久化上下文；Process 是旧调用方/旧测试的兼容字段。
	// 两者都缺失时按“非注册表来源”处理，不猜测为注册表启动项。
	typ := ctx.EntityData["type"]
	if typ == "" && ctx.Process != nil {
		typ = ctx.Process["type"]
	}
	if strings.Contains(typ, "registry") {
		steps = append(steps, "review registry startup entry (name/command)")
	} else {
		steps = append(steps, "list startup folder contents and timestamps")
	}
	return steps
}
