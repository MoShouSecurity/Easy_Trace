// Package timeline 把快照里**已经采到的时间事实**排成时间轴（V0.3，设计见
// docs/设计-时间线.md）。
//
// 设计要点（本包刻意遵守，改代码前先读设计稿）：
//   - 时间一律归一为 **UTC + RFC3339（秒精度）**，输入带偏移（如 +08:00）就换算，不隐式用本地时区；
//   - 每行带 **source**（如 process.creation_time 与 file.last_write_time 语义完全不同，读者必须一眼分辨）；
//   - **不做推断/插值**：只输出采集到的原值，不把"采集时刻"当"事件时刻"（采集时刻用独立 source 标明）；
//   - 缺时间/时间解析失败的实体**不进时间线**，但计入统计（"看不见"不等于"没有"）；
//   - 排序键固定 (time_utc, entity_type, entity_id, source)，保证报告逐字节可复现。
//
// 本包是纯函数：只吃实体数据，不读数据库、不碰主机、不联网。
package timeline

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"easytrace/internal/model"
)

// 资源上限（见设计稿 §3）。MaxRows 是 timeline.csv 的总行数上限；
// report.html 的展示上限由报告层单独控制（更小）。
const (
	DefaultMaxRows = 100000
	// MaxDetailRunes 是 detail 列的字符数上限。
	MaxDetailRunes = 200
)

// Entity 是构建时间线所需的最小实体输入。
//
// DataJSON 必须是**已合并 entity_update** 的数据：深采补充的 last_write_time 就在
// entity_update 里，不合并就会丢掉"文件最近修改时间"这一大类时间事实。
type Entity struct {
	EntityType string
	EntityID   string
	Label      string
	DataJSON   string
}

// Row 是时间线的一行。列顺序与 timeline.csv 一致。
type Row struct {
	TimeUTC    string // RFC3339、UTC、秒精度（"...Z"）
	Source     string // 时间来源字段，如 process.creation_time
	EntityType string
	EntityID   string
	Label      string
	Detail     string // 一句话摘要，<= MaxDetailRunes
}

// Options 控制锚点与上限。
type Options struct {
	SnapshotID  string // 用于 snapshot.collected_at 锚点行的 entity_id
	CollectedAt string // 快照时间戳（meta.Timestamp），作为时间轴锚点
	MaxRows     int    // <=0 时用 DefaultMaxRows

	// AnchorDescription / AnchorDetail 让调用方按**真实时间来源**描述锚点。
	//
	// meta.Timestamp 不一定等于采集时刻：旧产物没有采集元数据时，导入层会退化为
	// host.current_time 或导入时间。调用方知道来源，就应显式传入；留空时只写
	// “快照时间戳”，绝不默认声称是采集时刻。
	AnchorDescription string // StatsLine 中“锚点为……”的描述
	AnchorDetail      string // 锚点行的 detail 列
}

// Result 是构建结果（含"没纳入的有多少"的统计，供报告显示）。
type Result struct {
	Rows      []Row // 已排序、已按上限截断
	Total     int   // 截断前的行数
	Truncated int   // 因上限被丢弃的行数

	Entities       int // 参与构建的实体数（不含锚点行）
	Included       int // 至少产出一行的实体数
	ExcludedNoTime int // 没有任何时间字段、未纳入时间线的实体数
	BadTimeValues  int // 时间字段存在但解析失败、被丢弃的时间值个数

	// ExcludedByType 是"未纳入时间线"的实体按类型计数。
	//
	// 为什么要按类型拆：真实采集里 1376 个实体只有 125 个带时间（service / network /
	// driver 这些采集器**本来就不产生时间事实**）。只报一个总数，读者会误以为时间线漏了大半。
	ExcludedByType map[string]int

	AnchorIncluded bool // 是否纳入了 snapshot.collected_at 锚点

	// AnchorDescription 是锚点的真实时间来源说明（来自 Options）。
	AnchorDescription string
}

// StatsLine 返回给读者看的一行统计说明。
//
// 为什么必须输出：时间线只显示"有时间"的记录，如果不说明被排除的数量，
// 读者会把"时间线里没有"误读成"没发生过"。
func (r Result) StatsLine() string {
	var b strings.Builder
	fmt.Fprintf(&b, "共 %d 个实体：%d 个纳入时间线（%d 行）",
		r.Entities, r.Included, r.Total)
	if r.Truncated > 0 {
		fmt.Fprintf(&b, "，因上限截断 %d 行", r.Truncated)
	}
	if r.ExcludedNoTime > 0 {
		fmt.Fprintf(&b, "，%d 个实体缺时间字段未纳入", r.ExcludedNoTime)
		if s := excludedBreakdown(r.ExcludedByType, 4); s != "" {
			fmt.Fprintf(&b, "（%s）", s)
		}
	}
	if r.BadTimeValues > 0 {
		fmt.Fprintf(&b, "，%d 个时间值解析失败已丢弃", r.BadTimeValues)
	}
	if r.AnchorIncluded {
		desc := r.AnchorDescription
		if desc == "" {
			desc = "快照时间戳"
		}
		fmt.Fprintf(&b, "；锚点 snapshot.collected_at 为%s，非事件时刻", desc)
	}
	b.WriteString("。")
	return b.String()
}

// Build 生成时间线。实体顺序不影响结果（内部按固定键排序）。
// 仅在实体 JSON 损坏时返回错误——**不静默产出空时间线**。
func Build(entities []Entity, opts Options) (Result, error) {
	maxRows := opts.MaxRows
	if maxRows <= 0 {
		maxRows = DefaultMaxRows
	}
	var res Result
	exclude := func(entityType string) {
		res.ExcludedNoTime++
		if res.ExcludedByType == nil {
			res.ExcludedByType = map[string]int{}
		}
		res.ExcludedByType[entityType]++
	}

	// 锚点：快照时间戳。用独立 source 标明“这是快照锚点”，避免被当成事件时刻；
	// detail 由调用方按真实来源提供（采集开始 / 主机当前时间 / 导入时间 / 未记录）。
	if strings.TrimSpace(opts.CollectedAt) != "" {
		if utc, ok := normalizeUTC(opts.CollectedAt); ok {
			label := opts.SnapshotID
			if label == "" {
				label = "snapshot"
			}
			detail := strings.TrimSpace(opts.AnchorDetail)
			if detail == "" {
				detail = "快照时间戳（锚点，非事件时刻）"
			}
			res.Rows = append(res.Rows, Row{
				TimeUTC:    utc,
				Source:     "snapshot.collected_at",
				EntityType: "snapshot",
				EntityID:   opts.SnapshotID,
				Label:      label,
				Detail:     detail,
			})
			res.AnchorIncluded = true
			res.AnchorDescription = strings.TrimSpace(opts.AnchorDescription)
		} else {
			res.BadTimeValues++
		}
	}

	res.Entities = len(entities)
	for _, e := range entities {
		values, err := timeValues(e)
		if err != nil {
			return Result{}, err
		}
		if len(values) == 0 {
			exclude(e.EntityType)
			continue
		}
		detail := truncateRunes(entityDetail(e), MaxDetailRunes)
		added := 0
		for _, v := range values {
			utc, ok := normalizeUTC(v.raw)
			if !ok {
				res.BadTimeValues++
				continue
			}
			res.Rows = append(res.Rows, Row{
				TimeUTC:    utc,
				Source:     v.source,
				EntityType: e.EntityType,
				EntityID:   e.EntityID,
				Label:      e.Label,
				Detail:     detail,
			})
			added++
		}
		if added > 0 {
			res.Included++
		} else {
			// 有时间字段、但一个值都没解析成功：该实体同样未纳入
			exclude(e.EntityType)
		}
	}

	// 排序键固定：同一时刻多实体也要有确定顺序，否则报告无法逐字节复现。
	sort.SliceStable(res.Rows, func(i, j int) bool {
		a, b := res.Rows[i], res.Rows[j]
		if a.TimeUTC != b.TimeUTC {
			return a.TimeUTC < b.TimeUTC
		}
		if a.EntityType != b.EntityType {
			return a.EntityType < b.EntityType
		}
		if a.EntityID != b.EntityID {
			return a.EntityID < b.EntityID
		}
		return a.Source < b.Source
	})
	res.Total = len(res.Rows)
	if len(res.Rows) > maxRows {
		res.Truncated = len(res.Rows) - maxRows
		res.Rows = res.Rows[:maxRows]
	}
	return res, nil
}

// csvCell 防止电子表格把采集到的文本当作公式执行（CSV injection）。
//
// label/detail 来自被测主机（进程名、路径、命令行），完全由对方决定。以
// = + - @ 或制表符/回车开头的单元格被 Excel/WPS 打开时会被求值
// （`=HYPERLINK(...)` 一类）。前置单引号是通行做法：电子表格隐藏它、显示原值，
// 但不再执行。与 incident.go 的 csvSafeCell 保持一致。
func csvCell(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

// CSV 渲染 timeline.csv：列固定、LF 换行、行序即 Build 的排序结果。
func (r Result) CSV() ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write([]string{"time_utc", "source", "entity_type", "entity_id", "label", "detail"}); err != nil {
		return nil, fmt.Errorf("生成 timeline.csv 表头失败: %w", err)
	}
	for _, row := range r.Rows {
		if err := w.Write([]string{row.TimeUTC, row.Source, row.EntityType,
			row.EntityID, csvCell(row.Label), csvCell(row.Detail)}); err != nil {
			return nil, fmt.Errorf("生成 timeline.csv 行失败（%s）: %w", row.EntityID, err)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, fmt.Errorf("生成 timeline.csv 失败: %w", err)
	}
	return buf.Bytes(), nil
}

// normalizeUTC 把时间字符串归一为 UTC/RFC3339 秒精度。解析失败返回 ok=false。
//
// 只接受 RFC3339（含可选的秒以下精度）——采集器输出的就是这一种；不做"猜格式"式补全，
// 猜错会产生假的时间事实。
func normalizeUTC(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return "", false
	}
	return t.UTC().Format(time.RFC3339), true
}

// timeValue 是一个候选时间值及其来源标注。
type timeValue struct {
	source string
	raw    string
}

// compact 丢弃空值，保留顺序。全部为空时返回 nil（表示"该实体没有时间字段"）。
func compact(vals []timeValue) []timeValue {
	out := vals[:0]
	for _, v := range vals {
		if strings.TrimSpace(v.raw) != "" {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// timeValues 按实体类型取出候选时间值。
//
// 只列**真实存在**的时间字段：service / driver / registry / network 当前没有时间事实，
// 因此它们必然计入 ExcludedNoTime（而不是编一个假的时间出来）。
func timeValues(e Entity) ([]timeValue, error) {
	switch e.EntityType {
	case "host":
		var d model.HostData
		if err := unmarshal(e, &d); err != nil {
			return nil, err
		}
		return compact([]timeValue{
			{"host.current_time", d.CurrentTime},
			{"host.boot_time", d.BootTime},
		}), nil

	case "process":
		var d model.ProcessData
		if err := unmarshal(e, &d); err != nil {
			return nil, err
		}
		// last_write_time 来自深采 enrichment（ProcessEnrichmentData），已并入 merged JSON。
		var en model.ProcessEnrichmentData
		if err := unmarshal(e, &en); err != nil {
			return nil, err
		}
		return compact([]timeValue{
			{"process.creation_time", d.CreationTime},
			{"process.last_write_time", en.LastWriteTime},
		}), nil

	case "file":
		var d model.FileData
		if err := unmarshal(e, &d); err != nil {
			return nil, err
		}
		return compact([]timeValue{{"file.last_write_time", d.LastWriteTime}}), nil

	case "event":
		// 日志阶段 B：event 实体带的是**事件自身的时间**（UTC/RFC3339 秒精度），
		// 与采集时刻（snapshot.collected_at）语义完全不同，必须分开标注。
		var d model.EventData
		if err := unmarshal(e, &d); err != nil {
			return nil, err
		}
		return compact([]timeValue{{"event.time_created", d.TimeCreated}}), nil

	case "prefetch":
		// source 特意写明是 **.pf 文件自身的写入时间**，而不是"执行时间"：
		// Windows 在程序再次运行时重写该文件，所以它是最近一次运行的实用近似。
		var d model.PrefetchData
		if err := unmarshal(e, &d); err != nil {
			return nil, err
		}
		return compact([]timeValue{{"prefetch.prefetch_file_last_write_time", d.LastWriteTime}}), nil

	case "execution":
		// 两个时间语义完全不同，必须分开标注：
		//   - last_run_time：只有 UserAssist / BAM / DAM 有，表示"何时运行"；
		//   - 来源文件的 last_write_time：PowerShell 历史 / .lnk 文件本身的写入时间，
		//     **不是**命令或目标的执行时间。
		var d model.ExecutionData
		if err := unmarshal(e, &d); err != nil {
			return nil, err
		}
		return compact([]timeValue{
			{"execution.last_run_time", d.LastRunTime},
			{"execution.source_file_last_write_time", d.LastWriteTime},
		}), nil

	case "user":
		var d model.UserData
		if err := unmarshal(e, &d); err != nil {
			return nil, err
		}
		return compact([]timeValue{{"user.last_login", d.LastLogin}}), nil

	case "persistence":
		// persistence 的时间来自两处，语义不同，必须分开标注：
		//   - 注册表键的 LastWriteTime：启动项**什么时候被加上去的**（Basic 即采）；
		//   - 目标文件的 LastWriteTime：payload 文件本身最近改动（Deep 深采）。
		var d model.PersistenceData
		if err := unmarshal(e, &d); err != nil {
			return nil, err
		}
		var en model.PersistenceEnrichmentData
		if err := unmarshal(e, &en); err != nil {
			return nil, err
		}
		return compact([]timeValue{
			{"persistence.registry_last_write_time", d.KeyLastWriteTime},
			{"persistence.file_last_write_time", en.LastWriteTime},
		}), nil
	}
	return nil, nil
}

// unmarshal 解析实体数据；失败时给出带实体标识的错误，避免"静默没有时间"。
func unmarshal(e Entity, dst any) error {
	if strings.TrimSpace(e.DataJSON) == "" {
		return nil
	}
	if err := json.Unmarshal([]byte(e.DataJSON), dst); err != nil {
		return fmt.Errorf("时间线：解析实体 %s（%s）数据失败: %w", e.EntityID, e.EntityType, err)
	}
	return nil
}

// entityDetail 生成一句话摘要（不含时间信息本身，时间在独立列）。
func entityDetail(e Entity) string {
	switch e.EntityType {
	case "host":
		var d model.HostData
		if json.Unmarshal([]byte(e.DataJSON), &d) == nil {
			return strings.TrimSpace(d.Hostname + " " + d.OSVersion)
		}
	case "process":
		var d model.ProcessData
		if json.Unmarshal([]byte(e.DataJSON), &d) == nil {
			if d.CommandLine != "" {
				return d.Name + ": " + d.CommandLine
			}
			return d.Name
		}
	case "file":
		var d model.FileData
		if json.Unmarshal([]byte(e.DataJSON), &d) == nil {
			return fmt.Sprintf("%s size=%d", d.Path, d.Size)
		}
	case "event":
		var d model.EventData
		if json.Unmarshal([]byte(e.DataJSON), &d) == nil {
			// 事件本身已经有一句人话摘要（event.summary），直接用；
			// 不要在这里重新拼装，避免两处口径不一致。
			if d.Summary != "" {
				return d.Summary
			}
			return fmt.Sprintf("%s %d", d.Channel, d.EventID)
		}
	case "persistence":
		var d model.PersistenceData
		if json.Unmarshal([]byte(e.DataJSON), &d) == nil {
			// 命令（真正会执行什么）放最前，长路径放最后：detail 按字符截断，截尾能保住命令。
			// 不再重复 Name —— 它已经是 label 列。
			parts := []string{d.Type}
			if d.Command != "" {
				parts = append(parts, d.Command)
			}
			if d.Location != "" {
				parts = append(parts, d.Location)
			}
			return strings.Join(parts, " | ")
		}
	case "user":
		var d model.UserData
		if json.Unmarshal([]byte(e.DataJSON), &d) == nil {
			return d.Username
		}
	case "prefetch":
		var d model.PrefetchData
		if json.Unmarshal([]byte(e.DataJSON), &d) == nil {
			// 明确标出这是 .pf 头里的名字 + hash，避免读者把"文件写入时间"
			// 当成"执行时间"。
			return fmt.Sprintf("%s（prefetch hash %s）", d.ExecutableName, d.PrefetchHash)
		}
	case "execution":
		var d model.ExecutionData
		if json.Unmarshal([]byte(e.DataJSON), &d) == nil {
			// source 放最前：读者必须一眼看出这是"运行过"还是"打开过/历史文件"。
			parts := []string{d.Source}
			if d.Command != "" {
				parts = append(parts, d.Command)
			}
			if d.Name != "" {
				parts = append(parts, d.Name)
			}
			if d.Path != "" && d.Path != d.Name {
				parts = append(parts, d.Path)
			}
			if d.User != "" {
				parts = append(parts, d.User)
			}
			return strings.Join(parts, " | ")
		}
	}
	return e.EntityID
}

// excludedBreakdown 把"缺时间字段"的实体按类型汇总成一句（数量降序，最多 n 类）。
func excludedBreakdown(byType map[string]int, n int) string {
	if len(byType) == 0 || n <= 0 {
		return ""
	}
	type kv struct {
		name  string
		count int
	}
	all := make([]kv, 0, len(byType))
	for name, count := range byType {
		all = append(all, kv{name, count})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].count != all[j].count {
			return all[i].count > all[j].count
		}
		return all[i].name < all[j].name
	})
	parts := make([]string, 0, n+1)
	for i, e := range all {
		if i == n {
			parts = append(parts, fmt.Sprintf("另 %d 类", len(all)-n))
			break
		}
		parts = append(parts, fmt.Sprintf("%s %d", e.name, e.count))
	}
	return strings.Join(parts, " / ")
}

// truncateRunes 按字符（而非字节）截断，避免截出半个汉字。
func truncateRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}
