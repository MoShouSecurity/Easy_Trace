package analyzer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"easytrace/internal/cmdline"
	"easytrace/internal/model"
	"easytrace/internal/schema"
	"easytrace/internal/storage"
)

// Analyzer 是纯离线分析器：只读 SQLite 快照 + 规则匹配 → Finding。
// 不联网、不执行外部程序、不调用 Windows API、不写数据库。
type Analyzer struct {
	db        *storage.DB
	snapshot  string
	rules     []*Rule
	entities  []storage.EntityRow
	updates   []storage.EntityUpdateRow
	relations []storage.RelationRow
	cb        *contextBuilder       // 调查上下文构建器（含关系索引）
	views     map[string]entityView // 实体最终视图（合并 entity_update）
}

// NewAnalyzer 构造 Analyzer（只读快照数据，不触发任何写入）。
func NewAnalyzer(db *storage.DB, snapshotID string, rules []*Rule) (*Analyzer, error) {
	if _, err := storage.GetSnapshot(db, snapshotID); err != nil {
		return nil, fmt.Errorf("analyzer: 快照不存在: %w", err)
	}
	ents, err := storage.GetEntities(db, snapshotID)
	if err != nil {
		return nil, err
	}
	ups, err := storage.GetEntityUpdatesAll(db, snapshotID)
	if err != nil {
		return nil, err
	}
	rels, err := storage.GetRelations(db, snapshotID)
	if err != nil {
		return nil, err
	}
	return &Analyzer{db: db, snapshot: snapshotID, rules: rules,
		entities: ents, updates: ups, relations: rels}, nil
}

// buildViews 构建实体最终视图 + 关系索引（首次 Analyze/AnalyzeWithContext 时延迟初始化）。
func (a *Analyzer) buildViews() error {
	if a.views != nil {
		return nil // 已构建
	}
	updatesByEntity := groupUpdates(a.updates)
	views := map[string]entityView{}
	for _, e := range a.entities {
		data, err := mergeEntityViewData(e.DataJSON, updatesByEntity[e.EntityID])
		if err != nil {
			return fmt.Errorf("analyzer: 解析实体 %q 数据失败: %w", e.EntityID, err)
		}
		if e.EntityType == "persistence" {
			addPersistenceCommandFields(data)
		}
		views[e.EntityID] = entityView{typ: e.EntityType, id: e.EntityID, data: data}
	}
	a.views = views
	a.cb = newContextBuilder(a.views, a.relations)
	return nil
}

// mergeEntityViewData 合并实体基础数据及其更新。导入路径会校验 data，但数据库
// 可能被损坏或被旧版本写入；这种情况必须被调查流程明确报告，不能降级为空视图。
func mergeEntityViewData(base string, updates []storage.EntityUpdateRow) (map[string]any, error) {
	data, err := parseDataMap(base)
	if err != nil {
		return nil, fmt.Errorf("基础 data: %w", err)
	}
	for _, update := range updates {
		patch, err := parseDataMap(update.DataJSON)
		if err != nil {
			return nil, fmt.Errorf("entity_update %q: %w", update.EntityID, err)
		}
		for key, value := range patch {
			data[key] = value
		}
	}
	return data, nil
}

// addPersistenceCommandFields 为持久化实体派生 command_exe / command_arguments。
//
// 派生值只存在于分析视图，不回写数据库：command 仍保持原始命令行。规则要判断
// “启动项指向哪个文件”时用 path（缺失时由 persistenceMatchData 用 command_exe 补），
// 要匹配参数特征时才显式使用 command_arguments——绝不能让参数内容冒充目标路径。
func addPersistenceCommandFields(data map[string]any) {
	cmd := strings.TrimSpace(stringify(data["command"]))
	if cmd == "" {
		return
	}
	exe, args := cmdline.Split(cmd)
	if _, ok := data["command_exe"]; !ok && exe != "" {
		data["command_exe"] = exe
	}
	if _, ok := data["command_arguments"]; !ok && args != "" {
		data["command_arguments"] = args
	}
}

// persistenceMatchData 返回用于匹配的持久化视图：path 缺失时用解析出的
// command_exe 填充。只填可执行文件本身（不含参数），因此不会再出现
// “参数里的 \Users\ 让 System32 下的 rundll32 被当成用户目录文件”的误报。
func persistenceMatchData(data map[string]any) map[string]any {
	if strings.TrimSpace(stringify(data["path"])) != "" {
		return data
	}
	exe := strings.TrimSpace(stringify(data["command_exe"]))
	if exe == "" {
		return data
	}
	dup := make(map[string]any, len(data)+1)
	for k, v := range data {
		dup[k] = v
	}
	dup["path"] = exe
	return dup
}

// Analyze 对快照执行全部规则，返回 Finding 列表（按 rule_id → entity_id 稳定排序）。
// evidence 由 FindingContext 展平为 section.field=value 格式填充。未来 GUI 请用 AnalyzeWithContext。
func (a *Analyzer) Analyze() ([]*model.Finding, error) {
	if err := a.buildViews(); err != nil {
		return nil, err
	}

	var findings []*model.Finding
	for _, rule := range a.rules {
		switch {
		// 所有 persistence 目标规则都走持久化匹配器（path 缺失时用 command_exe 补位）：
		// 新增 persistence 规则不需要在别处登记 rule_id，避免"忘登记 → 掉进 default → 静默漏报"。
		case rule.Target == "persistence":
			findings = append(findings, a.matchPersistenceRule(rule)...)
		case rule.RuleID == "process.user_path.unsigned":
			findings = append(findings, a.matchSimpleRule(rule)...)
		case rule.RuleID == "process.user_path.executable":
			findings = append(findings, a.matchUserPathExecutable(rule)...)
		case rule.RuleID == "process.office_to_shell":
			findings = append(findings, a.matchOfficeToShell(rule)...)
		case rule.RuleID == "process.user_path.network":
			findings = append(findings, a.matchProcessNetwork(rule)...)
		default:
			findings = append(findings, a.matchSimpleRule(rule)...)
		}
	}

	return sortFindings(findings), nil
}

// AnalysisResult 是 Finding + 结构化调查上下文（供 GUI/API 直接使用）。
// CLI 使用 Analyze() 获得展平 evidence；GUI 使用 AnalyzeWithContext() 获得结构化上下文字段。
type AnalysisResult struct {
	Finding *model.Finding  `json:"finding"`
	Context *FindingContext `json:"context"`
}

// AnalyzeWithContext 返回带结构化上下文的 Finding 列表（供 GUI/API 使用）。
func (a *Analyzer) AnalyzeWithContext() ([]*AnalysisResult, error) {
	if err := a.buildViews(); err != nil {
		return nil, err
	}

	var results []*AnalysisResult
	for _, rule := range a.rules {
		switch {
		case rule.Target == "persistence":
			results = append(results, a.matchPersistenceRuleWithCtx(rule)...)
		case rule.RuleID == "process.user_path.unsigned":
			results = append(results, a.matchSimpleRuleWithCtx(rule)...)
		case rule.RuleID == "process.user_path.executable":
			results = append(results, a.matchUserPathExecutableWithCtx(rule)...)
		case rule.RuleID == "process.office_to_shell":
			results = append(results, a.matchOfficeToShellWithCtx(rule)...)
		case rule.RuleID == "process.user_path.network":
			results = append(results, a.matchProcessNetworkWithCtx(rule)...)
		default:
			results = append(results, a.matchSimpleRuleWithCtx(rule)...)
		}
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].Finding.RuleID != results[j].Finding.RuleID {
			return results[i].Finding.RuleID < results[j].Finding.RuleID
		}
		return results[i].Finding.EntityID < results[j].Finding.EntityID
	})
	return results, nil
}

func sortFindings(findings []*model.Finding) []*model.Finding {
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].RuleID != findings[j].RuleID {
			return findings[i].RuleID < findings[j].RuleID
		}
		return findings[i].EntityID < findings[j].EntityID
	})
	return findings
}

// entityView 是实体最终视图（含类型与合并后 data）。
type entityView struct {
	typ  string
	id   string
	data map[string]any
}

// groupUpdates 按 entity_id 聚合 entity_update。
func groupUpdates(ups []storage.EntityUpdateRow) map[string][]storage.EntityUpdateRow {
	m := map[string][]storage.EntityUpdateRow{}
	for _, u := range ups {
		m[u.EntityID] = append(m[u.EntityID], u)
	}
	return m
}

// ============================================================
// Match 函数 — 使用 a.views 和 a.cb（不再传参）
// ============================================================

// matchSimpleRule 通用规则：target.entity_type + conditions 全部 AND 匹配。
func (a *Analyzer) matchSimpleRule(rule *Rule) []*model.Finding {
	var out []*model.Finding
	for _, v := range a.views {
		if v.typ != rule.Target {
			continue
		}
		if !matchConditions(rule.Conditions, v.data) {
			continue
		}
		ctx := a.cb.build(v.id)
		out = append(out, a.newFinding(rule, v.id, nil, ctx))
	}
	return out
}

func (a *Analyzer) matchSimpleRuleWithCtx(rule *Rule) []*AnalysisResult {
	var out []*AnalysisResult
	for _, v := range a.views {
		if v.typ != rule.Target {
			continue
		}
		if !matchConditions(rule.Conditions, v.data) {
			continue
		}
		ctx := a.cb.build(v.id)
		out = append(out, a.newResult(rule, v.id, nil, ctx))
	}
	return out
}

// executableExts：Rule 2 关注的可执行扩展名。
var executableExts = map[string]bool{
	".exe": true, ".dll": true, ".scr": true, ".com": true,
	".bat": true, ".cmd": true, ".ps1": true,
}

// matchUserPathExecutable 适配 process.user_path.executable。
// 用户目录判定来自 YAML conditions（path contains_any），可执行扩展名判定保留
// 代码实现（规则声明"可执行文件"语义，DSL 无扩展名运算符）。
func (a *Analyzer) matchUserPathExecutable(rule *Rule) []*model.Finding {
	var out []*model.Finding
	for _, v := range a.views {
		if v.typ != rule.Target {
			continue
		}
		if !matchConditions(rule.Conditions, v.data) {
			continue
		}
		ext := strings.ToLower(pathExt(stringify(v.data["path"])))
		if !executableExts[ext] {
			continue
		}
		ctx := a.cb.build(v.id)
		out = append(out, a.newFinding(rule, v.id, nil, ctx))
	}
	return out
}

func (a *Analyzer) matchUserPathExecutableWithCtx(rule *Rule) []*AnalysisResult {
	var out []*AnalysisResult
	for _, v := range a.views {
		if v.typ != rule.Target {
			continue
		}
		if !matchConditions(rule.Conditions, v.data) {
			continue
		}
		ext := strings.ToLower(pathExt(stringify(v.data["path"])))
		if !executableExts[ext] {
			continue
		}
		ctx := a.cb.build(v.id)
		out = append(out, a.newResult(rule, v.id, nil, ctx))
	}
	return out
}

// pathExt 提取文件扩展名（含点；无扩展名返回空）。
func pathExt(path string) string {
	base := path
	if i := strings.LastIndexAny(base, "/\\"); i >= 0 {
		base = base[i+1:]
	}
	i := strings.LastIndex(base, ".")
	if i < 0 {
		return ""
	}
	return base[i:]
}

// officeShellParents：Rule 3 的父进程名单（Office 判定保留代码实现；
// 子进程 Shell 名单由 YAML conditions 声明，避免两份名单漂移）。
var officeShellParents = map[string]bool{
	"winword.exe": true, "excel.exe": true, "powerpnt.exe": true, "outlook.exe": true,
}

// matchOfficeToShell 通过 spawn relation 找 Office 父进程 → 满足 YAML 条件的子进程。
// 父子关系逻辑保留代码实现（不强行设计通用关系 DSL）。
func (a *Analyzer) matchOfficeToShell(rule *Rule) []*model.Finding {
	var out []*model.Finding
	seen := map[string]bool{}
	for _, rel := range a.relations {
		if rel.RelationType != "spawn" {
			continue
		}
		parent, ok := a.views[rel.SourceID]
		if !ok {
			continue
		}
		child, ok := a.views[rel.TargetID]
		if !ok {
			continue
		}
		parentName := strings.ToLower(stringify(parent.data["name"]))
		if !officeShellParents[parentName] {
			continue
		}
		// 子进程条件来自 YAML（name contains_any [powershell.exe, ...]）
		if !matchConditions(rule.Conditions, child.data) {
			continue
		}
		key := rel.SourceID + ">" + rel.TargetID
		if seen[key] {
			continue
		}
		seen[key] = true
		ctx := a.cb.build(rel.TargetID)
		relIDs := []string{rel.SourceID}
		out = append(out, a.newFinding(rule, rel.TargetID, relIDs, ctx))
	}
	return out
}

func (a *Analyzer) matchOfficeToShellWithCtx(rule *Rule) []*AnalysisResult {
	var out []*AnalysisResult
	seen := map[string]bool{}
	for _, rel := range a.relations {
		if rel.RelationType != "spawn" {
			continue
		}
		parent, ok := a.views[rel.SourceID]
		if !ok {
			continue
		}
		child, ok := a.views[rel.TargetID]
		if !ok {
			continue
		}
		parentName := strings.ToLower(stringify(parent.data["name"]))
		if !officeShellParents[parentName] {
			continue
		}
		if !matchConditions(rule.Conditions, child.data) {
			continue
		}
		key := rel.SourceID + ">" + rel.TargetID
		if seen[key] {
			continue
		}
		seen[key] = true
		ctx := a.cb.build(rel.TargetID)
		relIDs := []string{rel.SourceID}
		out = append(out, a.newResult(rule, rel.TargetID, relIDs, ctx))
	}
	return out
}

// matchPersistenceRule 适配所有 persistence 目标规则。
// 类型/路径条件全部来自 YAML conditions；path 缺失时只用解析出的 command_exe
// 补位（见 persistenceMatchData），不再用整条 command 覆盖 path。
func (a *Analyzer) matchPersistenceRule(rule *Rule) []*model.Finding {
	var out []*model.Finding
	for _, v := range a.views {
		if v.typ != rule.Target {
			continue
		}
		if !matchConditions(rule.Conditions, persistenceMatchData(v.data)) {
			continue
		}
		ctx := a.cb.build(v.id)
		out = append(out, a.newFinding(rule, v.id, nil, ctx))
	}
	return out
}

func (a *Analyzer) matchPersistenceRuleWithCtx(rule *Rule) []*AnalysisResult {
	var out []*AnalysisResult
	for _, v := range a.views {
		if v.typ != rule.Target {
			continue
		}
		if !matchConditions(rule.Conditions, persistenceMatchData(v.data)) {
			continue
		}
		ctx := a.cb.build(v.id)
		out = append(out, a.newResult(rule, v.id, nil, ctx))
	}
	return out
}

// matchProcessNetwork 通过 network_connect relation 找满足 YAML 条件（path contains_any
// 用户目录）的进程的对外连接。进程路径条件来自规则 conditions，不再硬编码 userDirs。
// 只认真正的对外连接：监听、回环、未指定远端地址的连接不算（见 isOutboundConnection）。
func (a *Analyzer) matchProcessNetwork(rule *Rule) []*model.Finding {
	var out []*model.Finding
	seen := map[string]bool{}
	for _, rel := range a.relations {
		if rel.RelationType != "network_connect" {
			continue
		}
		proc, ok := a.views[rel.SourceID]
		if !ok || proc.typ != rule.Target {
			continue
		}
		if !a.isOutboundRelation(rel.TargetID) {
			continue
		}
		if !matchConditions(rule.Conditions, proc.data) {
			continue
		}
		if seen[rel.SourceID] {
			continue
		}
		seen[rel.SourceID] = true
		ctx := a.cb.build(rel.SourceID)
		out = append(out, a.newFinding(rule, rel.SourceID, []string{rel.TargetID}, ctx))
	}
	return out
}

func (a *Analyzer) matchProcessNetworkWithCtx(rule *Rule) []*AnalysisResult {
	var out []*AnalysisResult
	seen := map[string]bool{}
	for _, rel := range a.relations {
		if rel.RelationType != "network_connect" {
			continue
		}
		proc, ok := a.views[rel.SourceID]
		if !ok || proc.typ != rule.Target {
			continue
		}
		if !a.isOutboundRelation(rel.TargetID) {
			continue
		}
		if !matchConditions(rule.Conditions, proc.data) {
			continue
		}
		if seen[rel.SourceID] {
			continue
		}
		seen[rel.SourceID] = true
		ctx := a.cb.build(rel.SourceID)
		out = append(out, a.newResult(rule, rel.SourceID, []string{rel.TargetID}, ctx))
	}
	return out
}

// isOutboundRelation 判断 network_connect 的目标实体是否是真正的对外连接。
// 目标实体缺失或类型不符时返回 false：无法核实的事实不能当作联网证据。
func (a *Analyzer) isOutboundRelation(targetID string) bool {
	netView, ok := a.views[targetID]
	if !ok || netView.typ != "network" {
		return false
	}
	return isOutboundConnection(netView.data)
}

// ============================================================
// Finding 构造
// ============================================================

// newFinding 用结构化 Context 展平为 evidence []string 构造 Finding。
func (a *Analyzer) newFinding(rule *Rule, entityID string, related []string, ctx *FindingContext) *model.Finding {
	id := stableFindingID(a.snapshot, rule.RuleID, entityID)
	evidence := flattenContext(ctx)
	if related == nil {
		related = []string{}
	}
	advice := []string{}
	if rule.Advice != "" {
		advice = []string{rule.Advice}
	}
	return &model.Finding{
		SchemaVersion:   schema.Version,
		Type:            "finding",
		FindingID:       id,
		RuleID:          rule.RuleID,
		Title:           rule.Title,
		Description:     rule.Description,
		Severity:        rule.Severity,
		EntityID:        entityID,
		RelatedEntities: related,
		Evidence:        evidence,
		Advice:          advice,
		Timestamp:       time.Now().UTC(),
	}
}

// newResult 构造 AnalysisResult（保留结构化 Context，GUI 使用）。
func (a *Analyzer) newResult(rule *Rule, entityID string, related []string, ctx *FindingContext) *AnalysisResult {
	return &AnalysisResult{
		Finding: a.newFinding(rule, entityID, related, ctx),
		Context: ctx,
	}
}

// stableFindingID 计算稳定 finding_id：sha256(snapshot_id|rule_id|entity_id) 前 16 位。
func stableFindingID(snapshotID, ruleID, entityID string) string {
	h := sha256.Sum256([]byte(snapshotID + "|" + ruleID + "|" + entityID))
	return "finding_" + hex.EncodeToString(h[:8])
}

// ============================================================
// Summary
// ============================================================

// RuleSummary 规则命中统计。
type RuleSummary struct {
	RulesEvaluated int
	TotalFindings  int
	PerRule        []RuleCount
}

// RuleCount 单条规则命中计数。
type RuleCount struct {
	RuleID string
	Count  int
}

// Summarize 按 rule_id 统计 Finding 分布（与 Analyze 输出一致，稳定排序）。
func (a *Analyzer) Summarize(findings []*model.Finding) *RuleSummary {
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.RuleID]++
	}
	s := &RuleSummary{RulesEvaluated: len(a.rules), TotalFindings: len(findings)}
	for _, r := range a.rules {
		s.PerRule = append(s.PerRule, RuleCount{RuleID: r.RuleID, Count: counts[r.RuleID]})
	}
	sort.Slice(s.PerRule, func(i, j int) bool { return s.PerRule[i].RuleID < s.PerRule[j].RuleID })
	return s
}

// MarshalFinding 输出单条 Finding JSON 行（CLI stdout 用）。
func MarshalFinding(f *model.Finding) ([]byte, error) {
	return json.Marshal(f)
}
