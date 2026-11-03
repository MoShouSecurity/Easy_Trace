package analyzer

import (
	"fmt"
	"sort"
	"strings"

	"easytrace/internal/model"
)

// propagateRelationTypes 是允许参与「关联传导」的关系类型（方向即语义）：
//
//	spawn           父进程 → 子进程
//	launch          服务   → 进程
//	network_connect 进程   → 网络连接
//
// 其它冻结关系类型（parent_child / execute / connect / read / write / create / load）
// 当前采集器不产生，也**不**参与传导——新增必须先把方向语义讲清楚，避免把
// "包含/读写"这类非可疑关系当成可疑扩散。
var propagateRelationTypes = map[string]bool{
	"spawn":           true,
	"launch":          true,
	"network_connect": true,
}

// DerivedRulePrefix 是传导提示的 rule_id 前缀。据此可以把"传导提示"与"直接命中"
// 在统计、报告与事件包里分开看，不会混为一谈。
const DerivedRulePrefix = "derived."

// PropagateOptions 控制关联传导（V0.3）。
type PropagateOptions struct {
	// Hops 是最大边数（1 = 只扩散到直接相邻实体）；<= 0 表示不做任何传导。
	Hops int
}

// derivedAgg 汇总落到同一 (关系类型, 目标实体) 上的全部传导路径。
type derivedAgg struct {
	severity       string
	minHops        int
	sources        map[string]bool // 源 entity_id
	sourceFindings map[string]bool // 源 finding_id
	paths          map[string]bool // 关系路径描述
	relationTypes  map[string]bool
}

// edge 是传导用的一条有向边。
type edge struct {
	to  string
	typ string
}

// PropagateFindings 在直接命中之上做关系传导：把每条直接命中沿允许的关系边
// 扩散最多 Hops 跳，在**尚无直接命中**的相邻实体上生成传导提示。
//
// 语义边界（刻意保守，宁可少报）：
//   - 只从**直接命中**出发；传导提示本身不再二次扩散。
//   - 已有直接命中的实体不再生成传导提示（避免同一实体被重复计分）。
//   - 严重度**衰减一级**（critical→high→medium→low，low 为下限）：传导是推断，不是独立检测。
//   - 每条提示的证据都是 `derived.*` 行：写明源 finding_id、源 entity_id、关系路径与跳数。
//   - 结果确定性：按 rule_id → entity_id 排序；来源、路径均排序去重。
func (a *Analyzer) PropagateFindings(results []*AnalysisResult, opt PropagateOptions) ([]*AnalysisResult, error) {
	if opt.Hops < 1 {
		return results, nil
	}
	if err := a.buildViews(); err != nil {
		return nil, err
	}

	direct := map[string]bool{}
	ordered := make([]*AnalysisResult, 0, len(results))
	for _, r := range results {
		if r == nil || r.Finding == nil || r.Finding.EntityID == "" {
			continue
		}
		direct[r.Finding.EntityID] = true
		ordered = append(ordered, r)
	}
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].Finding.FindingID < ordered[j].Finding.FindingID
	})

	// 有向邻接表：只保留允许的关系类型；同源边按 (to, type) 排序保证扩展顺序稳定。
	adj := map[string][]edge{}
	for _, rel := range a.relations {
		if !propagateRelationTypes[rel.RelationType] || rel.SourceID == "" || rel.TargetID == "" {
			continue
		}
		// network_connect 只沿真正的对外连接扩散：监听/回环端点不是“联网”证据，
		// 否则一个正常监听本地端口的进程会把风险传导给无关实体。
		if rel.RelationType == "network_connect" && !a.isOutboundRelation(rel.TargetID) {
			continue
		}
		adj[rel.SourceID] = append(adj[rel.SourceID], edge{to: rel.TargetID, typ: rel.RelationType})
	}
	for k := range adj {
		edges := adj[k]
		sort.Slice(edges, func(i, j int) bool {
			if edges[i].to != edges[j].to {
				return edges[i].to < edges[j].to
			}
			return edges[i].typ < edges[j].typ
		})
	}

	aggs := map[string]*derivedAgg{}
	type node struct {
		id   string
		path string
		hops int
	}
	for _, src := range ordered {
		start := src.Finding.EntityID
		seen := map[string]int{start: 0}
		queue := []node{{id: start, path: start, hops: 0}}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			if cur.hops >= opt.Hops {
				continue
			}
			for _, e := range adj[cur.id] {
				hops := cur.hops + 1
				path := cur.path + " -" + e.typ + "-> " + e.to
				if !direct[e.to] {
					mergeDerived(aggs, e.typ, e.to, src, path, hops)
				}
				if prev, ok := seen[e.to]; ok && prev <= hops {
					continue // 已有更短或等长路径：不重复入队
				}
				seen[e.to] = hops
				queue = append(queue, node{id: e.to, path: path, hops: hops})
			}
		}
	}
	if len(aggs) == 0 {
		return results, nil
	}

	derived := a.buildDerivedResults(aggs)
	out := make([]*AnalysisResult, 0, len(results)+len(derived))
	out = append(out, results...)
	out = append(out, derived...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Finding.RuleID != out[j].Finding.RuleID {
			return out[i].Finding.RuleID < out[j].Finding.RuleID
		}
		return out[i].Finding.EntityID < out[j].Finding.EntityID
	})
	return out, nil
}

// mergeDerived 把一条传导路径并入对应聚合。
func mergeDerived(aggs map[string]*derivedAgg, relationType, target string, src *AnalysisResult, path string, hops int) {
	key := relationType + "|" + target
	agg := aggs[key]
	if agg == nil {
		agg = &derivedAgg{
			minHops:        hops,
			sources:        map[string]bool{},
			sourceFindings: map[string]bool{},
			paths:          map[string]bool{},
			relationTypes:  map[string]bool{},
		}
		aggs[key] = agg
	}
	if hops < agg.minHops {
		agg.minHops = hops
	}
	sev := attenuateSeverity(src.Finding.Severity)
	if severityRank(sev) > severityRank(agg.severity) {
		agg.severity = sev
	}
	agg.sources[src.Finding.EntityID] = true
	agg.sourceFindings[src.Finding.FindingID] = true
	agg.paths[path] = true
	agg.relationTypes[relationType] = true
}

// buildDerivedResults 把聚合结果渲染成传导提示（rule_id = derived.<关系类型>）。
func (a *Analyzer) buildDerivedResults(aggs map[string]*derivedAgg) []*AnalysisResult {
	keys := make([]string, 0, len(aggs))
	for k := range aggs {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]*AnalysisResult, 0, len(keys))
	for _, key := range keys {
		parts := strings.SplitN(key, "|", 2)
		relationType, entityID := parts[0], parts[1]
		agg := aggs[key]
		sources := sortedSet(agg.sources)
		findingIDs := sortedSet(agg.sourceFindings)
		paths := sortedSet(agg.paths)
		relations := sortedSet(agg.relationTypes)
		ruleID := DerivedRulePrefix + relationType

		evidence := []string{
			"derived.notice=由关系传导推导，不是独立检测；请回到源 finding 核对证据",
			fmt.Sprintf("derived.hops=%d", agg.minHops),
			fmt.Sprintf("derived.relation_types=%s", strings.Join(relations, ",")),
			fmt.Sprintf("derived.source_count=%d", len(sources)),
		}
		if _, ok := a.views[entityID]; ok {
			evidence = append(evidence, "derived.target_present=true")
		} else {
			evidence = append(evidence, "derived.target_present=false")
		}
		for _, id := range findingIDs {
			evidence = append(evidence, "derived.source_finding="+id)
		}
		for _, id := range sources {
			evidence = append(evidence, "derived.source_entity="+id)
		}
		for _, p := range paths {
			evidence = append(evidence, "derived.relation_path="+p)
		}

		title := fmt.Sprintf("（传导）关系关联提示：%d 条直接命中经 %s 关系落到此实体",
			len(findingIDs), strings.Join(relations, "/"))
		description := fmt.Sprintf(
			"本条不是独立检测结论：实体 %s 与 %d 条直接命中之间存在已采集的关系（%s），"+
				"因此把该实体标为值得一并核对。请先核对 derived.source_finding 指向的直接结论，再决定是否补充取证。",
			entityID, len(findingIDs), strings.Join(relations, "/"))
		advice := []string{
			"这是传导推断（关联传导），不是独立命中：核对源 finding 的证据后再决定是否取证。",
		}

		f := model.NewFinding(
			stableFindingID(a.snapshot, ruleID, entityID),
			ruleID, title, description, agg.severity, entityID,
			sources, evidence, advice,
		)
		out = append(out, &AnalysisResult{Finding: f})
	}
	return out
}

// attenuateSeverity 把严重度衰减一级（low 为下限）。传导是推断，不得与直接命中等价。
func attenuateSeverity(s string) string {
	switch s {
	case "critical":
		return "high"
	case "high":
		return "medium"
	case "medium":
		return "low"
	default:
		return "low"
	}
}

// severityRank 用于取"最强来源"的严重度（越大越严重）。
func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// sortedSet 把集合渲染为排序后的切片（确定性输出）。
func sortedSet(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
