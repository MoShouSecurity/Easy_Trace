// Package event 实现 Event Collector（日志采集阶段 B，2026-10-15 批准）：
// 把 Windows 事件日志按**通道 + 事件 ID 白名单**解析为 entity_type=event 的实体。
//
// 设计依据：docs/设计-日志采集.md §3。
//
// 边界（全部为"不做"，任何一条改动都要先过设计）：
//   - 不做全通道无差别采集：只查白名单通道上白名单事件 ID（设计 §3.2，固定表）；
//   - 不执行外部程序：只用 wevtapi.dll（不用 wevtutil.exe / PowerShell）；
//   - 不导出、不清除、不修改通道配置、不订阅实时事件；
//   - 不建模关系（logged_on / created_process / installed_service 属二期）；
//   - 不放完整原始 XML：只落结构化的通用字段 + 关键字段。
//
// 权限门卫（Step 2.2 能力集）：EventQuery（只读系统查询，与 ServiceQuery /
// TaskQuery 同级，Basic 模式也授予）。被拒时返回空结果并记录 deny 事件。
package event

import (
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"easytrace/internal/collector"
	"easytrace/internal/collector/runtime"
	"easytrace/internal/model"
)

// DefaultMaxEvents 是单次解析的事件数上限（设计 §3.5）。
//
// 超过即**显式失败并说明**，不静默截断：报告里少了几条必须能被看见。
const DefaultMaxEvents = 20000

// SummaryMaxRunes 是 summary 的字符上限（设计 §3.5）。
const SummaryMaxRunes = 200

// LongFieldMaxRunes 是 command_line / script_block_text 的裁剪上限（设计 §3.1）。
const LongFieldMaxRunes = 512

// errTooManyEvents 表示事件数超过上限（设计 §3.5：显式失败，不静默截断）。
var errTooManyEvents = errors.New("事件数超过上限")

// channelRule 是"某通道上采哪些事件 ID"的白名单条目（设计 §3.2）。
//
// 一期固定，不做配置项：避免"配置错误导致导出全通道"。
type channelRule struct {
	channel string
	ids     []uint32
}

// defaultAllowlist 是内置的通道 + 事件 ID 白名单。
//
// 设计 §3.2 列出的是安全基线（登录 / 进程创建 / 创建用户 / 服务安装 / 日志清空 /
// 事件日志服务启停 / 服务启动类型变更）；这里另纳入设计 §3.1「关键字段」表明确
// 点名的 4648 / 4672 / 4768 / 4769 / 5140 / 5145 / 4104 —— 否则 ip_address /
// share_name / ticket_encryption_type / script_block_text 这些字段永远取不到值，
// 横向移动、Kerberoasting、共享访问就查不了。
//
// Application 与 Microsoft-Windows-TaskScheduler/Operational 目前没有白名单事件 ID，
// 因此不查询（阶段 A 仍会导出原始 .evtx）。
var defaultAllowlist = []channelRule{
	{"Security", []uint32{1102, 4624, 4625, 4648, 4672, 4688, 4697, 4720, 4768, 4769, 5140, 5145}},
	{"System", []uint32{6005, 6006, 7040, 7045}},
	{"Microsoft-Windows-PowerShell/Operational", []uint32{4104}},
}

// levelNames 把事件 XML 里的数字级别映射成可读名字（设计 §3.1）。
var levelNames = map[uint32]string{
	0: "LogAlways",
	1: "Critical",
	2: "Error",
	3: "Warning",
	4: "Information",
	5: "Verbose",
}

// Collector 实现 event 采集；query 可注入以便离线测试。
type Collector struct {
	rt        *runtime.Runtime
	query     func(channel string, ids []uint32, limit int) (queryResult, error)
	allowlist []channelRule
	maxEvents int
}

// New 创建 Event Collector，绑定调用方注入的 Runtime。
func New(rt *runtime.Runtime) *Collector {
	if rt == nil {
		panic("event: New 必须传入 runtime.Runtime（禁止 Collector 内部创建）")
	}
	return &Collector{rt: rt, allowlist: defaultAllowlist, maxEvents: DefaultMaxEvents}
}

// WithAllowlist 覆盖通道/事件 ID 白名单（测试与将来扩展用；空列表保持默认）。
func (c *Collector) WithAllowlist(rules []channelRule) *Collector {
	if len(rules) > 0 {
		c.allowlist = rules
	}
	return c
}

// WithMaxEvents 设置事件数上限（<=0 时保持默认）。
func (c *Collector) WithMaxEvents(n int) *Collector {
	if n > 0 {
		c.maxEvents = n
	}
	return c
}

// WithQuery 注入查询实现（测试用：不触碰真实事件日志）。
func (c *Collector) WithQuery(f func(channel string, ids []uint32, limit int) (queryResult, error)) *Collector {
	c.query = f
	return c
}

// Runtime 返回绑定的行为控制 Runtime（供注入一致性校验）。
func (c *Collector) Runtime() *runtime.Runtime { return c.rt }

// Name 实现 collector.Collector 接口。
func (c *Collector) Name() string { return "event" }

// Collect 实现 collector.Collector 接口：输出 event 实体。
//
// 输出顺序固定（按 entity_id 升序）。任何"少采"（超上限、通道查询失败、
// 单条 XML 解析失败）都会进入返回错误，不静默。
func (c *Collector) Collect() (*collector.Result, error) {
	if !c.rt.Allow("event", "EventQuery", "whitelisted_channels") {
		debugf("event_query_denied mode=%s", c.rt.Mode())
		return &collector.Result{}, nil
	}
	query := c.query
	if query == nil {
		query = queryChannelEvents
	}

	var problems []string
	var raw []string
	var skipped []string
	more := false
	renderFailed := 0
	for i, rule := range c.allowlist {
		remaining := c.maxEvents - len(raw)
		if remaining <= 0 {
			// 预算已耗尽：后面的通道不能再静默地“没查过”。点名记录，
			// 并让返回错误明确说明哪些通道没有覆盖。
			skipped = append(skipped, channelNames(c.allowlist[i:])...)
			break
		}
		budget := channelBudget(c.maxEvents, len(raw), len(c.allowlist)-i)
		if budget > remaining {
			budget = remaining
		}
		res, err := query(rule.channel, rule.ids, budget)
		if err != nil {
			// 单通道失败不中断其它通道：能采多少采多少，但必须如实报告。
			problems = append(problems, fmt.Sprintf("通道 %s 查询失败: %v", rule.channel, err))
		}
		renderFailed += res.Failed
		if res.More {
			more = true
			problems = append(problems, fmt.Sprintf("通道 %s 达到本次预算 %d，结果不完整", rule.channel, budget))
		}
		raw = append(raw, res.XML...)
	}
	if len(skipped) > 0 {
		problems = append(problems, "未查询通道: "+strings.Join(skipped, ", ")+
			fmt.Sprintf("（总预算 %d 已耗尽；请缩小时间范围或分通道重跑）", c.maxEvents))
	}
	if renderFailed > 0 {
		problems = append(problems, fmt.Sprintf("%d 条事件渲染失败，未产出实体", renderFailed))
	}

	seen := make(map[string]bool, len(raw))
	entities := make([]*model.Entity, 0, len(raw))
	bad := 0
	for _, x := range raw {
		pe, err := parseEventXML(x)
		if err != nil {
			bad++
			continue
		}
		id := pe.entityID()
		if seen[id] {
			continue
		}
		seen[id] = true
		entities = append(entities, pe.entity())
	}
	if bad > 0 {
		problems = append(problems, fmt.Sprintf("%d 条事件 XML 解析失败，未产出实体", bad))
	}
	sort.Slice(entities, func(i, j int) bool { return entities[i].EntityID < entities[j].EntityID })
	debugf("event_query entities=%d channels=%d", len(entities), len(c.allowlist))

	res := &collector.Result{Entities: entities}
	var errs []error
	if more {
		errs = append(errs, fmt.Errorf("%w %d：只保留最新的 %d 条，请缩小通道/时间范围后重跑（结果不完整）",
			errTooManyEvents, c.maxEvents, len(entities)))
	}
	if len(problems) > 0 {
		errs = append(errs, errors.New(strings.Join(problems, "；")))
	}
	if len(errs) > 0 {
		return res, errors.Join(errs...)
	}
	return res, nil
}

// channelBudget 计算当前通道可用的条数。
//
// 旧实现让 Security 先吃掉全部 20000 配额，后面的 System/PowerShell 直接
// break——4104/7045 在繁忙主机上会完全缺失。这里给后续通道保留底线：
//   - 预算充足（>= 每通道 4 条）时，后续每个通道至少保留 reservePerChannel；
//   - 预算很小时，至少给每个后续通道留 1 条，避免前面的通道独占。
func channelBudget(total, used, channelsLeft int) int {
	remaining := total - used
	if channelsLeft <= 1 || remaining <= 0 {
		return remaining
	}
	later := channelsLeft - 1
	reserve := later // 小预算：每个后续通道至少 1 条
	if total >= channelsLeft*4 {
		want := later * reservePerChannel
		if want > remaining/2 {
			want = remaining / 2
		}
		if want > reserve {
			reserve = want
		}
	}
	budget := remaining - reserve
	if budget < 1 {
		budget = 1
	}
	return budget
}

// reservePerChannel 是预算充足时为每个后续通道保留的最少条数。
const reservePerChannel = 1000

func channelNames(rules []channelRule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.channel)
	}
	return out
}

// ---- 事件 XML 解析 ----

// eventXML 是 EvtRender(EvtRenderEventXml) 输出的 <Event> 文档的裁剪视图。
//
// 只建模一期真正要用的部分：System（通用字段）与 EventData（关键字段）。
// 不建模 UserData，也不保留原始 XML。
type eventXML struct {
	XMLName xml.Name `xml:"Event"`
	System  struct {
		Provider struct {
			Name            string `xml:"Name,attr"`
			EventSourceName string `xml:"EventSourceName,attr"`
		} `xml:"Provider"`
		EventID     uint32 `xml:"EventID"`
		Level       uint32 `xml:"Level"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		EventRecordID uint64 `xml:"EventRecordID"`
		Channel       string `xml:"Channel"`
		Computer      string `xml:"Computer"`
	} `xml:"System"`
	EventData struct {
		Data []eventDataItem `xml:"Data"`
	} `xml:"EventData"`
}

type eventDataItem struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

// parsedEvent 是一条已解析的事件（内部结构，便于离线测试）。
type parsedEvent struct {
	Channel  string
	EventID  uint32
	Level    string
	Provider string
	RecordID uint64
	TimeUTC  string // RFC3339 秒精度；无法解析时为空
	Computer string
	fields   map[string]string
}

// parseEventXML 解析 EvtRender 输出的 Event XML。
//
// 解析失败（不是 Event 文档 / EventID 为 0 / 时间无法解析）一律返回错误，
// 由调用方计数并如实报告，绝不产出"半条"实体。
func parseEventXML(raw string) (parsedEvent, error) {
	var doc eventXML
	if err := xml.Unmarshal([]byte(raw), &doc); err != nil {
		return parsedEvent{}, fmt.Errorf("事件 XML 解析失败: %w", err)
	}
	if doc.XMLName.Local != "Event" {
		return parsedEvent{}, fmt.Errorf("不是 Event 文档（根元素 %q）", doc.XMLName.Local)
	}
	if doc.System.EventID == 0 {
		return parsedEvent{}, fmt.Errorf("缺少 EventID")
	}
	pe := parsedEvent{
		Channel:  strings.TrimSpace(doc.System.Channel),
		EventID:  doc.System.EventID,
		Level:    levelNames[doc.System.Level],
		Provider: firstNonEmpty(doc.System.Provider.Name, doc.System.Provider.EventSourceName),
		RecordID: doc.System.EventRecordID,
		Computer: strings.TrimSpace(doc.System.Computer),
		fields:   make(map[string]string, len(doc.EventData.Data)),
	}
	if ts := strings.TrimSpace(doc.System.TimeCreated.SystemTime); ts != "" {
		// 事件自身的时间，统一转成 UTC 并截断到秒（设计 §3.4）。
		t, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return parsedEvent{}, fmt.Errorf("TimeCreated 无法解析: %q", ts)
		}
		pe.TimeUTC = t.UTC().Truncate(time.Second).Format(time.RFC3339)
	}
	for _, d := range doc.EventData.Data {
		name := strings.TrimSpace(d.Name)
		if name == "" {
			continue
		}
		pe.fields[name] = strings.TrimSpace(d.Value)
	}
	return pe, nil
}

// get 取事件字段值；Windows 事件日志用 "-" 表示"无值"，一律当空，
// 避免把占位符当成真实事实（与报告隐藏 LISTENING 远端地址同理）。
func (p parsedEvent) get(names ...string) string {
	for _, n := range names {
		v := strings.TrimSpace(p.fields[n])
		if v != "" && v != "-" {
			return v
		}
	}
	return ""
}

// entityID 按设计 §3.1 的冻结规则生成：event_<通道归一>_<record_id>。
// 时间不参与 ID——否则同一事件会因精度/时区差异生成不同 ID。
func (p parsedEvent) entityID() string {
	return fmt.Sprintf("event_%s_%d", normalizeChannel(p.Channel), p.RecordID)
}

// entity 把解析结果转成 event 实体。
func (p parsedEvent) entity() *model.Entity {
	d := model.EventData{
		Channel:              p.Channel,
		EventID:              p.EventID,
		Level:                p.Level,
		Provider:             p.Provider,
		RecordID:             p.RecordID,
		TimeCreated:          p.TimeUTC,
		Computer:             p.Computer,
		Summary:              truncateRunes(p.summary(), SummaryMaxRunes),
		LogonType:            parseUint32(p.get("LogonType")),
		TargetUser:           p.get("TargetUserName"),
		TargetSid:            p.get("TargetUserSid"),
		SubjectUser:          p.get("SubjectUserName"),
		IPAddress:            p.get("IpAddress", "ClientAddress"),
		LogonProcess:         p.get("LogonProcessName"),
		ShareName:            p.get("ShareName"),
		TicketEncryptionType: p.get("TicketEncryptionType"),
		ServiceName:          p.get("ServiceName"),
		ProcessName:          p.get("NewProcessName", "ProcessName"),
		ImagePath:            truncateRunes(p.get("ImagePath", "ServiceFileName"), LongFieldMaxRunes),
		ParentProcessName:    truncateRunes(p.get("ParentProcessName", "ParentImage"), LongFieldMaxRunes),
		CommandLine:          truncateRunes(p.get("CommandLine"), LongFieldMaxRunes),
		ScriptBlockText:      truncateRunes(p.get("ScriptBlockText"), LongFieldMaxRunes),
	}
	return model.NewEntity("event", p.entityID(), d)
}

// summary 生成"人类可读的一句话"（设计 §3.1）。这里只描述事实，不定性。
func (p parsedEvent) summary() string {
	who := p.get("TargetUserName", "SubjectUserName")
	switch p.EventID {
	case 1102:
		return withWho("审计日志被清空（可能有人在清理痕迹）", who)
	case 4624:
		return fmt.Sprintf("登录成功：%s（类型 %s，来源 %s，进程 %s）",
			orDash(who), orDash(p.get("LogonType")), orDash(p.get("IpAddress")), orDash(p.get("LogonProcessName")))
	case 4625:
		return fmt.Sprintf("登录失败：%s（类型 %s，来源 %s）",
			orDash(who), orDash(p.get("LogonType")), orDash(p.get("IpAddress")))
	case 4648:
		return fmt.Sprintf("凭据被显式用于登录：%s（来源 %s，目标 %s）",
			orDash(p.get("SubjectUserName")), orDash(p.get("IpAddress")), orDash(who))
	case 4672:
		return withWho("分配了高权限（特权登录）", who)
	case 4688:
		return fmt.Sprintf("进程创建：%s %s",
			orDash(p.get("NewProcessName", "ProcessName")),
			truncateRunes(p.get("CommandLine"), 120))
	case 4697:
		return "安装服务：" + orDash(p.get("ServiceName"))
	case 4720:
		return "创建账号：" + orDash(who)
	case 4768:
		return fmt.Sprintf("Kerberos TGT 请求：%s（加密 %s，来源 %s）",
			orDash(who), orDash(p.get("TicketEncryptionType")), orDash(p.get("IpAddress")))
	case 4769:
		return fmt.Sprintf("Kerberos 服务票据请求：%s -> %s（加密 %s，来源 %s）",
			orDash(who), orDash(p.get("ServiceName")), orDash(p.get("TicketEncryptionType")), orDash(p.get("IpAddress")))
	case 5140, 5145:
		return fmt.Sprintf("访问共享：%s（来源 %s，账号 %s）",
			orDash(p.get("ShareName")), orDash(p.get("IpAddress")), orDash(who))
	case 6005:
		return "事件日志服务已启动"
	case 6006:
		return "事件日志服务已停止"
	case 7040:
		return "服务启动类型被变更：" + orDash(p.get("ServiceName"))
	case 7045:
		return "安装服务（System 通道）：" + orDash(p.get("ServiceName"))
	case 4104:
		return "PowerShell 脚本块：" + truncateRunes(p.get("ScriptBlockText"), 150)
	}
	// 未单独建模的事件 ID：给出通道 + ID + 首个可用标识，不编造含义。
	if extra := firstNonEmpty(p.get("ServiceName"), p.get("ShareName"), p.get("NewProcessName"), p.get("TargetUserName")); extra != "" {
		return fmt.Sprintf("事件 %d（通道 %s）：%s", p.EventID, p.Channel, extra)
	}
	return fmt.Sprintf("事件 %d（通道 %s）", p.EventID, p.Channel)
}

func withWho(prefix, who string) string {
	if who == "" {
		return prefix
	}
	return prefix + "：" + who
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// normalizeChannel 把通道名归一成可安全放进 entity_id 的形式：
// 非 [A-Za-z0-9_-] 的字符替换为下划线（设计 §3.1）。
func normalizeChannel(ch string) string {
	var sb strings.Builder
	sb.Grow(len(ch))
	for _, r := range ch {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			sb.WriteRune(r)
		default:
			sb.WriteRune('_')
		}
	}
	if sb.Len() == 0 {
		return "unknown"
	}
	return sb.String()
}

// truncateRunes 按**字符**（不是字节）截断，避免把多字节汉字切成半个。
func truncateRunes(s string, max int) string {
	s = strings.TrimSpace(s)
	if max <= 0 || utf8.RuneCountInString(s) <= max {
		return s
	}
	n := 0
	for i := range s {
		if n == max {
			return s[:i] + "…"
		}
		n++
	}
	return s
}

func parseUint32(s string) uint32 {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}

// debugf 输出采集阶段/内部错误日志到 stderr（不污染 stdout 的 JSONL 流）。
func debugf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[event] "+format+"\n", args...)
}
