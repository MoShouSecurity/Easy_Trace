// Package prefetch 实现 Prefetch Collector（2026-10-30 批准新增 entity_type=prefetch）。
//
// 只读枚举并解析 %SystemRoot%\Prefetch\*.pf 的**固定文件头**：
//
//	0x00 version          (uint32)
//	0x04 signature        "SCCA"
//	0x0C file size        (uint32)
//	0x10 executable name  60 × UTF-16LE
//	0x88 prefetch hash    (uint32)
//
// 边界（全部为"不做"，任何一条改动都要先过设计）：
//   - 不解析压缩段：文件列表、卷信息、metrics（运行次数 / 最近运行时间）都不解压；
//   - 不读 %SystemRoot%\Prefetch 以外的任何目录，不按用户指定路径扫描；
//   - 不执行、不删除、不改写 .pf，也不启停 SysMain / 修改注册表；
//   - 不把 .pf 文件的 LastWriteTime 冒充成"确凿的执行时间"——它是实用近似，
//     语义写在 model.PrefetchData 与报告中。
//
// 权限门卫（Step 2.2 能力集）：PrefetchQuery（路径固定、只读文件头，与
// DriverQuery/EventQuery 同级，Basic 模式也授予）。被拒时返回空结果并记录 deny。
package prefetch

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf16"

	"easytrace/internal/collector"
	"easytrace/internal/collector/runtime"
	"easytrace/internal/model"
)

// DefaultMaxPrefetch 是单次输出的实体上限。正常主机通常远低于此；
// 上限是失控保护，不是性能目标。
const DefaultMaxPrefetch = 4096

const (
	// headerBytes 是解析所需的最小文件头长度（0x88 + 4）。
	headerBytes = 0x8C
	// nameOffset / nameBytes：可执行文件名位于 0x10，固定 60 个 UTF-16 码元。
	nameOffset = 0x10
	nameBytes  = 120
	// hashOffset：prefetch hash 位于 0x88。
	hashOffset = 0x88
	// signature 是 .pf 头的固定签名（"SCCA"）。
	signature = "SCCA"
)

// Collector 实现 prefetch 采集；目录可注入以便离线测试。
type Collector struct {
	rt       *runtime.Runtime
	dir      string
	maxFiles int
}

// New 创建 Prefetch Collector，绑定调用方注入的 Runtime。
func New(rt *runtime.Runtime) *Collector {
	if rt == nil {
		panic("prefetch: New 必须传入 runtime.Runtime（禁止 Collector 内部创建）")
	}
	return &Collector{rt: rt, dir: defaultDir(), maxFiles: DefaultMaxPrefetch}
}

// WithDir 覆盖扫描目录（测试与将来扩展用；空字符串保持默认）。
func (c *Collector) WithDir(dir string) *Collector {
	if strings.TrimSpace(dir) != "" {
		c.dir = dir
	}
	return c
}

// WithMaxFiles 设置实体上限（<=0 时保持默认）。
func (c *Collector) WithMaxFiles(n int) *Collector {
	if n > 0 {
		c.maxFiles = n
	}
	return c
}

// Runtime 返回绑定的行为控制 Runtime（供注入一致性校验）。
func (c *Collector) Runtime() *runtime.Runtime { return c.rt }

// Name 实现 collector.Collector 接口。
func (c *Collector) Name() string { return "prefetch" }

// defaultDir 返回 %SystemRoot%\Prefetch；SystemRoot 缺失时回退到 C:\Windows。
func defaultDir() string {
	root := strings.TrimSpace(os.Getenv("SystemRoot"))
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "Prefetch")
}

// Collect 实现 collector.Collector 接口：输出 prefetch 实体。
//
// 输出顺序固定（按 entity_id 升序）。目录不可读、单文件解析失败、超过上限
// 都会进入返回错误，不静默。
func (c *Collector) Collect() (*collector.Result, error) {
	if !c.rt.Allow("prefetch", "PrefetchQuery", "system_root_prefetch") {
		debugf("prefetch_query_denied mode=%s", c.rt.Mode())
		return &collector.Result{}, nil
	}

	entries, notes, err := c.list()
	if err != nil {
		return &collector.Result{}, err
	}

	problems := append([]string(nil), notes...)
	entities := make([]*model.Entity, 0, len(entries))
	seen := make(map[string]bool, len(entries))
	bad := 0
	for _, e := range entries {
		pe, err := parseFile(e.path)
		if err != nil {
			bad++
			continue
		}
		id := pe.entityID(e.path)
		if seen[id] {
			// 同一目录下文件名（去掉 .pf）归一后理论上不会重复；重复说明
			// 存在大小写/特殊字符层面的冲突，如实报告而不是静默丢一条。
			problems = append(problems, fmt.Sprintf("实体 ID 冲突已跳过: %s（%s）", id, e.path))
			continue
		}
		seen[id] = true
		entities = append(entities, pe.entity(id, e.path, e.size, e.modTime, string(c.rt.Mode())))
	}
	if bad > 0 {
		problems = append(problems, fmt.Sprintf("%d 个 .pf 文件解析失败（签名/头长度/文件名校验不通过），未产出实体", bad))
	}

	sort.Slice(entities, func(i, j int) bool { return entities[i].EntityID < entities[j].EntityID })
	debugf("prefetch_query entities=%d dir=%s", len(entities), c.dir)

	res := &collector.Result{Entities: entities}
	if len(problems) > 0 {
		return res, errors.New(strings.Join(problems, "；"))
	}
	return res, nil
}

// entry 是待解析的 .pf 文件元数据。
type entry struct {
	path    string
	size    int64
	modTime time.Time
}

// list 枚举目录下的 .pf 文件（os.ReadDir 按文件名排序，保证确定性）。
//
// 超过上限时保留前 maxFiles 条并把"少了多少"写进 notes；单个文件 stat 失败
// 同样计入 notes。两者都不阻断整次采集，但绝不静默。
func (c *Collector) list() ([]entry, []string, error) {
	dirEntries, err := os.ReadDir(c.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, fmt.Errorf("Prefetch 目录不存在：%s（Prefetch 可能已被禁用）", c.dir)
		}
		if os.IsPermission(err) {
			return nil, nil, fmt.Errorf("无权读取 Prefetch 目录：%s（通常需要管理员权限）", c.dir)
		}
		return nil, nil, fmt.Errorf("读取 Prefetch 目录失败（%s）: %w", c.dir, err)
	}

	var notes []string
	out := make([]entry, 0, len(dirEntries))
	total, statFailed := 0, 0
	for _, de := range dirEntries {
		if de.IsDir() || !strings.EqualFold(filepath.Ext(de.Name()), ".pf") {
			continue
		}
		total++
		if len(out) >= c.maxFiles {
			continue
		}
		info, err := de.Info()
		if err != nil {
			statFailed++
			continue
		}
		out = append(out, entry{path: filepath.Join(c.dir, de.Name()), size: info.Size(), modTime: info.ModTime()})
	}
	if statFailed > 0 {
		notes = append(notes, fmt.Sprintf("%d 个 .pf 文件读取元数据失败，未产出实体", statFailed))
	}
	if total > c.maxFiles {
		notes = append(notes, fmt.Sprintf("Prefetch 文件数 %d 超过上限 %d：只解析前 %d 个（结果不完整）",
			total, c.maxFiles, c.maxFiles))
	}
	return out, notes, nil
}

// parsed 是单个 .pf 头解析结果（内部结构，便于离线测试）。
type parsed struct {
	version uint32
	exeName string
	hash    uint32
}

// parseFile 读取并解析一个 .pf 文件的固定头。
//
// 只读取前 headerBytes 字节，不加载整个文件（.pf 通常几十 KB 到几 MB）。
func parseFile(path string) (parsed, error) {
	f, err := os.Open(path)
	if err != nil {
		return parsed{}, fmt.Errorf("打开失败: %w", err)
	}
	defer f.Close()

	buf := make([]byte, headerBytes)
	if _, err := io.ReadFull(f, buf); err != nil {
		return parsed{}, fmt.Errorf("读取文件头失败（可能不足 %d 字节）: %w", headerBytes, err)
	}

	version := binary.LittleEndian.Uint32(buf[0:4])
	if version == 0 {
		return parsed{}, errors.New("version 为 0")
	}
	if string(buf[4:8]) != signature {
		return parsed{}, fmt.Errorf("签名不是 %q", signature)
	}
	name := decodeUTF16Name(buf[nameOffset : nameOffset+nameBytes])
	if name == "" {
		return parsed{}, errors.New("可执行文件名为空")
	}
	return parsed{
		version: version,
		exeName: name,
		hash:    binary.LittleEndian.Uint32(buf[hashOffset : hashOffset+4]),
	}, nil
}

// decodeUTF16Name 解码 60 个 UTF-16LE 码元，遇到 NUL 截止，去掉首尾空白。
func decodeUTF16Name(b []byte) string {
	units := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u := binary.LittleEndian.Uint16(b[i : i+2])
		if u == 0 {
			break
		}
		units = append(units, u)
	}
	return strings.TrimSpace(string(utf16.Decode(units)))
}

// entityID 由 .pf 文件名（去掉扩展名）生成稳定 ID：
// `prefetch_<小写文件名归一>`，非 [a-z0-9._-] 字符替换为下划线。
//
// 不用时间或序号：同一主机同一程序的 .pf 文件名稳定，跨快照可比较。
func (p parsed) entityID(path string) string {
	base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	base = strings.ToLower(base)
	var b strings.Builder
	for _, r := range base {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		// 理论上不可能（文件名非空），但仍给出确定性兜底而不是空 ID。
		return fmt.Sprintf("prefetch_%08X", p.hash)
	}
	return "prefetch_" + b.String()
}

// entity 把解析结果转成 prefetch 实体。
func (p parsed) entity(id, path string, size int64, modTime time.Time, level string) *model.Entity {
	d := model.PrefetchData{
		ExecutableName:  p.exeName,
		PrefetchHash:    fmt.Sprintf("%08X", p.hash),
		SourceVersion:   p.version,
		Path:            path,
		FileSize:        size,
		LastWriteTime:   modTime.UTC().Truncate(time.Second).Format(time.RFC3339),
		CollectionLevel: level,
	}
	return model.NewEntity("prefetch", id, d)
}

func debugf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[prefetch] "+format+"\n", args...)
}
