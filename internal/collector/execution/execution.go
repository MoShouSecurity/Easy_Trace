// Package execution 实现执行痕迹采集（2026-10-30 批准新增 entity_type=execution）。
//
// 只读采集六类本地执行/打开痕迹，统一输出 execution 实体，用 data.source 区分：
//
//	userassist  HKCU/HKU UserAssist（ROT13 值名 + FILETIME + 运行次数）
//	bam / dam   HKLM BAM/DAM UserSettings（可执行路径 + FILETIME）
//	recentdocs  HKCU/HKU RecentDocs（最近打开的文件名）
//	pshistory   PSReadLine ConsoleHost_history.txt（Deep 起）
//	lnk         Recent\*.lnk 目标路径（Deep 起）
//
// 边界（全部为"不做"，任何一条改动都要先过设计）：
//   - 不新增 SQLite 表、不改冻结协议 v0.2 与 Snapshot/Finding 顶层结构；
//   - 只读上述注册表键与文件，不写、不删、不改、不执行；
//   - 不解析 Prefetch 压缩块（Prefetch 仍由 prefetch 模块只读文件头）；
//   - **不把"最近打开"或"文件写入时间"冒充执行时间**：只有 UserAssist 与
//     BAM/DAM 填 last_run_time；RecentDocs / PowerShell 历史 / LNK 不填，
//     文件类来源的 last_write_time 单独标注（语义见 model.ExecutionData）；
//   - 单个来源失败不阻断其它来源；上限/截断/解析失败都写进返回错误，不静默。
//
// 权限门卫（Step 2.2 能力集）：注册表类来源需要 RegistryQuery（Basic 已授予）；
// PowerShell 历史与 LNK 需要 ReadFile（Deep/Forensic 授予）。Basic 下文件类来源
// 跳过，不报错（这是模式设计，不是采集失败）。
package execution

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"easytrace/internal/collector"
	"easytrace/internal/collector/runtime"
	"easytrace/internal/model"
)

const (
	// DefaultMaxEntities 是单次输出的实体总上限（失控保护，不是性能目标）。
	DefaultMaxEntities = 10000

	maxUserAssistEntries = 2000
	maxBAMEntries        = 5000
	maxRecentDocsEntries = 2000
	maxPSHistoryEntries  = 5000
	maxPSHistoryPerFile  = 2000
	maxLNKEntries        = 2000

	// maxPSHistoryBytes 是单个 PowerShell 历史文件的读取上限；历史是追加写，
	// 超出时只读**末尾**这一段（最近的命令才在尾部）。
	maxPSHistoryBytes = 4 << 20
	// maxPSHistoryLine 是单行命令的保留上限（字符数）；超出截断并标记。
	maxPSHistoryLine = 4096
)

// sourceReader 是一个来源的读取函数（测试可注入）。
type sourceReader struct {
	name string
	read func() ([]rawEntry, []string, error)
}

// rawEntry 是各来源统一的中间结构；entityID 由 source + idKey 派生。
type rawEntry struct {
	source      string
	idKey       string
	user        string
	name        string
	path        string
	command     string
	runCount    *uint32
	lastRun     time.Time
	lastWrite   time.Time
	occurrences *uint32
}

// entityID 生成稳定的 execution 实体 ID：`execution_<source>_<sha256前8字节>`。
//
// 用内容哈希而不是序号：同一痕迹跨快照可比较；ID 不以时间/枚举顺序变化。
func (r rawEntry) entityID() string {
	key := r.idKey
	if key == "" {
		key = strings.Join([]string{r.source, r.user, r.name, r.path, r.command}, "\x00")
	}
	sum := sha256.Sum256([]byte(r.source + "\x00" + key))
	return "execution_" + r.source + "_" + hex.EncodeToString(sum[:8])
}

// entity 把中间结构转成 execution 实体。
func (r rawEntry) entity(id, level string) *model.Entity {
	d := model.ExecutionData{
		Source:          r.source,
		User:            r.user,
		Name:            r.name,
		Path:            r.path,
		Command:         r.command,
		RunCount:        r.runCount,
		LastRunTime:     formatTime(r.lastRun),
		LastWriteTime:   formatTime(r.lastWrite),
		Occurrences:     r.occurrences,
		CollectionLevel: level,
	}
	return model.NewEntity("execution", id, d)
}

// Collector 实现 execution 采集；各来源读取函数可注入以便离线测试。
type Collector struct {
	rt          *runtime.Runtime
	maxEntities int

	userAssistFn func() ([]rawEntry, []string, error)
	bamFn        func() ([]rawEntry, []string, error)
	recentDocsFn func() ([]rawEntry, []string, error)
	psHistoryFn  func() ([]rawEntry, []string, error)
	lnkFn        func() ([]rawEntry, []string, error)
}

// New 创建 Execution Collector，绑定调用方注入的 Runtime（Collector 不在内部创建 Runtime）。
func New(rt *runtime.Runtime) *Collector {
	if rt == nil {
		panic("execution: New 必须传入 runtime.Runtime（禁止 Collector 内部创建）")
	}
	c := &Collector{rt: rt, maxEntities: DefaultMaxEntities}
	c.userAssistFn = c.readUserAssist
	c.bamFn = c.readBAM
	c.recentDocsFn = c.readRecentDocs
	c.psHistoryFn = c.readPSHistory
	c.lnkFn = c.readLNK
	return c
}

// WithMaxEntities 设置实体总上限（<=0 时保持默认）。
func (c *Collector) WithMaxEntities(n int) *Collector {
	if n > 0 {
		c.maxEntities = n
	}
	return c
}

// Runtime 返回绑定的行为控制 Runtime（供注入一致性校验）。
func (c *Collector) Runtime() *runtime.Runtime { return c.rt }

// Name 实现 collector.Collector 接口。
func (c *Collector) Name() string { return "execution" }

// Collect 实现 collector.Collector 接口：输出 execution 实体（按 entity_id 升序）。
func (c *Collector) Collect() (*collector.Result, error) {
	var problems []string
	entries := make([]rawEntry, 0, 64)

	// 注册表类来源：UserAssist / BAM / DAM / RecentDocs。
	regAllowed := c.rt.Allow("execution", "RegistryQuery", "execution_registry_sources")
	if regAllowed {
		for _, src := range []sourceReader{
			{name: "UserAssist", read: c.userAssistFn},
			{name: "BAM/DAM", read: c.bamFn},
			{name: "RecentDocs", read: c.recentDocsFn},
		} {
			es, notes, err := src.read()
			problems = append(problems, notes...)
			if err != nil {
				problems = append(problems, src.name+"："+err.Error())
				continue
			}
			entries = append(entries, es...)
		}
	} else {
		debugf("registry_query_denied module=execution mode=%s", c.rt.Mode())
	}

	// 文件类来源：PowerShell 历史 / Recent LNK（仅 Deep/Forensic 有 ReadFile）。
	fileAllowed := c.rt.Allow("execution", "ReadFile", "execution_user_files")
	if fileAllowed {
		for _, src := range []sourceReader{
			{name: "PowerShell 历史", read: c.psHistoryFn},
			{name: "Recent LNK", read: c.lnkFn},
		} {
			es, notes, err := src.read()
			problems = append(problems, notes...)
			if err != nil {
				problems = append(problems, src.name+"："+err.Error())
				continue
			}
			entries = append(entries, es...)
		}
	} else {
		debugf("read_file_denied module=execution mode=%s sources=pshistory,lnk", c.rt.Mode())
	}

	// 先按 ID 排序再截断，保证上限截断的结果确定、可复现。
	sort.Slice(entries, func(i, j int) bool { return entries[i].entityID() < entries[j].entityID() })
	if len(entries) > c.maxEntities {
		problems = append(problems, fmt.Sprintf("执行痕迹总数 %d 超过上限 %d：只保留前 %d 条（结果不完整）",
			len(entries), c.maxEntities, c.maxEntities))
		entries = entries[:c.maxEntities]
	}

	seen := make(map[string]bool, len(entries))
	entities := make([]*model.Entity, 0, len(entries))
	level := string(c.rt.Mode())
	for _, e := range entries {
		id := e.entityID()
		if seen[id] {
			// 不同键哈希碰撞概率极低；真出现说明输入重复，如实报告而不是静默丢一条。
			problems = append(problems, fmt.Sprintf("实体 ID 冲突已跳过: %s", id))
			continue
		}
		seen[id] = true
		entities = append(entities, e.entity(id, level))
	}
	sort.Slice(entities, func(i, j int) bool { return entities[i].EntityID < entities[j].EntityID })

	debugf("entities=%d registry=%v files=%v mode=%s", len(entities), regAllowed, fileAllowed, c.rt.Mode())

	res := &collector.Result{Entities: entities}
	if len(problems) > 0 {
		return res, errors.New(strings.Join(problems, "；"))
	}
	return res, nil
}

// formatTime 输出 UTC/RFC3339 秒精度；零值输出空串（不伪造时间）。
func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Truncate(time.Second).Format(time.RFC3339)
}

// filetimeAt 读取偏移处的 Windows FILETIME 并转成 UTC 时间。
// 返回 false 表示越界、为 0 或明显不合理（早于 1990 / 晚于 2100）。
//
// FILETIME 是 1601-01-01 起的 100ns 计数；先做无符号下界检查，避免
// `ft - 116444736000000000` 下溢成巨大的负纳秒。
func filetimeAt(b []byte, off int) (time.Time, bool) {
	const epochDiff = uint64(116444736000000000) // 1601 → 1970 的 100ns 数
	if off < 0 || off+8 > len(b) {
		return time.Time{}, false
	}
	ft := binary.LittleEndian.Uint64(b[off : off+8])
	if ft < epochDiff {
		return time.Time{}, false
	}
	t := time.Unix(0, int64(ft-epochDiff)*100).UTC()
	if t.Year() < 1990 || t.Year() > 2100 {
		return time.Time{}, false
	}
	return t, true
}

func u32ptr(v uint32) *uint32 { return &v }

// truncateRunes 按字符数截断，避免切断 UTF-8；超出时追加省略号。
func truncateRunes(s string, max int) string {
	if max <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}

func debugf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[execution] "+format+"\n", args...)
}
