// Package file 实现 Easy_Trace 的首个 File Collector（协议白名单 entity_type=file，P1-9）。
//
// 用途：按"最近修改优先"枚举**显式指定**的目录下的文件并记录事实
// （路径 / 大小 / 修改时间 / 可选 SHA256），用于落地文件排查
// （webshell、上传目录、临时目录、回收站等）。只读：不删除、不修改、不执行任何文件。
//
// 权限门卫（Step 2.2 冻结能力集）：目录枚举与文件元数据都算 **ReadFile** 能力。
// Basic 模式不含 ReadFile，因此本采集器在 Basic 下**明确拒绝**并不返回空结果——
// 必须由操作者显式使用 --mode deep / --mode forensic 授权。
//
// 不提供默认目录：不指定 --path 直接报错，避免误扫整盘（证据工具不应自作主张扩大范围）。
package file

import (
	"container/heap"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"easytrace/internal/collector"
	"easytrace/internal/collector/runtime"
	"easytrace/internal/model"
	"easytrace/internal/safepath"
)

const (
	// DefaultMaxFiles 单次采集默认最多输出多少条 file 实体（确定性截断，超出即如实报错）。
	DefaultMaxFiles = 5000
	// DefaultDepth 目录递归默认深度上限（根目录 = 0）。
	DefaultDepth = 8
	// DefaultMaxHashBytes 单文件哈希上限（超过只记事实、不算哈希，避免把大镜像读穿）。
	DefaultMaxHashBytes = 64 * 1024 * 1024
	// DefaultMaxScanEntries 单次扫描最多查看多少目录项（含目录、链接与不可读项）。
	// 没有它，`--path C:\` 这类误用会让采集在整盘上跑任意久。
	DefaultMaxScanEntries = 200000
	// DefaultMaxHashTotalBytes 单次采集合计哈希读取上限（按枚举到的大小估算）。
	// 单文件上限挡不住“5000 个 64 MB 文件”，合计上限才是真正的资源边界。
	DefaultMaxHashTotalBytes = 2 << 30 // 2 GiB
	// DefaultScanBudget 单次 file 采集的墙钟预算。
	//
	// runStep 的超时只能放弃等待，无法中断已运行的 goroutine；采集器自己检查
	// 预算并主动收尾，才能保证超时后不会在后台继续扫盘。
	DefaultScanBudget = 5 * time.Minute
)

// errHashChanged 表示文件在枚举之后被替换或改写，哈希不再属于清单里的事实。
var errHashChanged = errors.New("文件在枚举后已变化")

// item 是单个文件的中间结构（内部结构，便于测试注入）。
type item struct {
	Path          string
	Size          int64
	LastWriteTime time.Time
	HashSHA256    string
}

// betterItem 定义确定性的“优先保留”顺序：最近修改优先，同时间按路径升序。
// topN 与最终排序共用同一比较，保证截断前后的顺序语义一致。
func betterItem(a, b item) bool {
	if !a.LastWriteTime.Equal(b.LastWriteTime) {
		return a.LastWriteTime.After(b.LastWriteTime)
	}
	return a.Path < b.Path
}

// topN 是只保留最优 N 项的有界容器（堆顶 = 最差项）。
// 旧实现先把整个目录树收进切片再排序，超大目录会先耗尽内存。
type topN struct {
	limit   int
	offered int
	items   []item
}

func (t *topN) Len() int           { return len(t.items) }
func (t *topN) Less(i, j int) bool { return betterItem(t.items[j], t.items[i]) }
func (t *topN) Swap(i, j int)      { t.items[i], t.items[j] = t.items[j], t.items[i] }
func (t *topN) Push(x any)         { t.items = append(t.items, x.(item)) }
func (t *topN) Pop() any {
	old := t.items
	x := old[len(old)-1]
	t.items = old[:len(old)-1]
	return x
}

// add 把候选项放进有界容器；offered 记录经过去重/时间过滤后的候选总数。
func (t *topN) add(it item) {
	t.offered++
	if t.limit <= 0 {
		return
	}
	if len(t.items) < t.limit {
		heap.Push(t, it)
		return
	}
	if betterItem(it, t.items[0]) {
		heap.Pop(t)
		heap.Push(t, it)
	}
}

// sorted 返回“最优优先”的副本，顺序与旧的全量稳定排序完全一致。
func (t *topN) sorted() []item {
	out := append([]item(nil), t.items...)
	sort.Slice(out, func(i, j int) bool { return betterItem(out[i], out[j]) })
	return out
}

// scanState 是单次采集的扫描预算状态（不放进 Collector，避免复用/并发时串味）。
type scanState struct {
	deadline time.Time
	scanned  int
	// reason 非空表示预算已触发，同时是写入结果说明的原因文本。
	reason string
}

// Collector 实现 file 采集。now / hash / maxHashBytes 可注入，保证测试可确定复现。
type Collector struct {
	rt                *runtime.Runtime
	paths             []string
	recentHours       int
	maxFiles          int
	depth             int
	maxHashBytes      int64
	maxScanEntries    int
	maxHashTotalBytes int64
	scanBudget        time.Duration
	now               func() time.Time
	hash              func(item) (string, error)
}

// New 创建 File Collector，绑定调用方注入的 Runtime（Collector 不在内部创建 Runtime）。
func New(rt *runtime.Runtime) *Collector {
	if rt == nil {
		panic("file: New 必须传入 runtime.Runtime（禁止 Collector 内部创建）")
	}
	return &Collector{
		rt:                rt,
		maxFiles:          DefaultMaxFiles,
		depth:             DefaultDepth,
		maxHashBytes:      DefaultMaxHashBytes,
		maxScanEntries:    DefaultMaxScanEntries,
		maxHashTotalBytes: DefaultMaxHashTotalBytes,
		scanBudget:        DefaultScanBudget,
		now:               time.Now,
	}
}

// WithPaths 设置要枚举的根目录（按给定顺序处理）。
func (c *Collector) WithPaths(paths ...string) *Collector {
	c.paths = append([]string(nil), paths...)
	return c
}

// WithRecentHours 只保留最近 N 小时内修改过的文件（0 = 不过滤）。
func (c *Collector) WithRecentHours(hours int) *Collector {
	c.recentHours = hours
	return c
}

// WithMaxFiles 设置实体数量上限（<=0 时保持默认）。
func (c *Collector) WithMaxFiles(n int) *Collector {
	if n > 0 {
		c.maxFiles = n
	}
	return c
}

// WithDepth 设置递归深度上限（<=0 时保持默认）。
func (c *Collector) WithDepth(d int) *Collector {
	if d > 0 {
		c.depth = d
	}
	return c
}

// WithMaxHashBytes 设置单文件哈希上限（仅供测试与特殊场景；生产用默认值）。
func (c *Collector) WithMaxHashBytes(n int64) *Collector {
	if n > 0 {
		c.maxHashBytes = n
	}
	return c
}

// WithMaxScanEntries 设置单次扫描的目录项上限（<=0 时保持默认）。
func (c *Collector) WithMaxScanEntries(n int) *Collector {
	if n > 0 {
		c.maxScanEntries = n
	}
	return c
}

// WithMaxHashTotalBytes 设置合计哈希读取上限（<=0 时保持默认）。
func (c *Collector) WithMaxHashTotalBytes(n int64) *Collector {
	if n > 0 {
		c.maxHashTotalBytes = n
	}
	return c
}

// WithScanBudget 设置扫描墙钟预算（仅供测试与特殊场景；0 表示不设墙钟上限）。
func (c *Collector) WithScanBudget(d time.Duration) *Collector {
	c.scanBudget = d
	return c
}

// Runtime 返回绑定的行为控制 Runtime（供注入一致性校验）。
func (c *Collector) Runtime() *runtime.Runtime { return c.rt }

// Name 实现 collector.Collector 接口。
func (c *Collector) Name() string { return "file" }

// Collect 实现 collector.Collector 接口：输出 file 实体。
//
// 顺序固定：先按 last_write_time 倒序（最近改动的在前，便于排查落地文件），
// 同时间按路径升序 —— 因此 entity_id 的序号在同一次输入下可复现。
// 任一目录/文件失败都保留其它事实，并把"不完整"如实放进返回错误里（绝不静默）。
//
// 资源边界（P1-11）：扫描边枚举边裁剪到 maxFiles（堆，不先收全量再排序）；
// 目录项数、墙钟预算、单文件与合计哈希字节都有上限，触发后停止并写明原因。
func (c *Collector) Collect() (*collector.Result, error) {
	if len(c.paths) == 0 {
		return nil, fmt.Errorf("file 采集必须至少指定一个 --path <目录>（不提供默认目录，避免误扫整盘）")
	}
	if !c.rt.Allow("file", "ReadFile", "paths:"+strings.Join(c.paths, ";")) {
		debugf("file_scan_denied mode=%s paths=%d", c.rt.Mode(), len(c.paths))
		return nil, fmt.Errorf("file 采集需要显式授权：当前模式 %s 不含 ReadFile 能力，请使用 --mode deep 或 --mode forensic", c.rt.Mode())
	}

	now := c.now()
	st := &scanState{}
	if c.scanBudget != 0 {
		st.deadline = now.Add(c.scanBudget)
	}
	var notes []string
	roots := 0
	seen := map[string]bool{}
	top := &topN{limit: c.maxFiles}
	var cutoff time.Time
	if c.recentHours > 0 {
		cutoff = now.Add(-time.Duration(c.recentHours) * time.Hour)
	}

	for _, raw := range c.paths {
		root, err := filepath.Abs(raw)
		if err != nil {
			notes = append(notes, fmt.Sprintf("路径无法解析 %s: %v", raw, err))
			continue
		}
		// 根目录必须在任何 ReadDir 之前确认是本地盘符、非网络映射、且最终组件
		// 不是链接/重解析点；否则一次“目录枚举”就可能变成 SMB/设备读取。
		if _, err := safepath.RequireLocalDrivePath(root, "file 根目录"); err != nil {
			notes = append(notes, fmt.Sprintf("路径不可用 %s: %v", root, err))
			continue
		}
		if err := safepath.RejectUnsafeParents(root, "file 根目录"); err != nil {
			notes = append(notes, fmt.Sprintf("路径不可用 %s: %v", root, err))
			continue
		}
		info, err := os.Lstat(root)
		if err != nil {
			notes = append(notes, fmt.Sprintf("路径不可用 %s: %v", root, err))
			continue
		}
		if !info.IsDir() || safepath.IsUnsafeParent(info) {
			notes = append(notes, fmt.Sprintf("不是目录，已跳过 %s", root))
			continue
		}
		roots++
		before := top.offered
		notes = append(notes, c.walk(root, st, func(it item) {
			key := strings.ToLower(it.Path)
			if seen[key] {
				return
			}
			seen[key] = true
			if c.recentHours > 0 && it.LastWriteTime.Before(cutoff) {
				return
			}
			top.add(it)
		})...)
		debugf("file_scan root=%s candidates=%d", root, top.offered-before)
		if st.reason != "" {
			break
		}
	}
	if roots == 0 {
		return nil, fmt.Errorf("file 采集没有可用目录：%s", strings.Join(notes, "；"))
	}
	if st.reason != "" {
		notes = append(notes, st.reason)
	}
	if top.offered > c.maxFiles {
		notes = append(notes, fmt.Sprintf("文件数 %d 超过上限 %d，只保留最近修改的 %d 个（结果不完整）", top.offered, c.maxFiles, c.maxFiles))
	}
	found := top.sorted()

	// 深采阶段：允许 HashFile 时对保留的文件计算 SHA256（一次门卫判定，避免逐文件刷事件）。
	hashAllowed := c.rt.Allow("file", "HashFile", fmt.Sprintf("files:%d", len(found)))
	skippedOversize := 0
	hashFailed := 0
	hashChanged := 0
	hashOverBudget := 0
	var hashTotal int64
	deadlineHit := false
	if hashAllowed {
		for i := range found {
			it := found[i]
			if !st.deadline.IsZero() && c.now().After(st.deadline) {
				deadlineHit = true
				break
			}
			if it.Size > c.maxHashBytes {
				skippedOversize++
				continue
			}
			if c.maxHashTotalBytes > 0 && hashTotal+it.Size > c.maxHashTotalBytes {
				hashOverBudget++
				continue
			}
			h, err := c.hashOne(it)
			if err != nil {
				hashFailed++
				if errors.Is(err, errHashChanged) {
					hashChanged++
				}
				debugf("file_hash_failed path=%s error=%v", it.Path, err)
				continue
			}
			hashTotal += it.Size
			found[i].HashSHA256 = h
		}
		if skippedOversize > 0 {
			notes = append(notes, fmt.Sprintf("%d 个文件超过单个哈希上限 %d 字节，只记事实未计算哈希", skippedOversize, c.maxHashBytes))
		}
		if hashOverBudget > 0 {
			notes = append(notes, fmt.Sprintf("哈希读取合计达到上限 %d 字节，%d 个文件未计算哈希", c.maxHashTotalBytes, hashOverBudget))
		}
		if hashChanged > 0 {
			notes = append(notes, fmt.Sprintf("%d 个文件在枚举之后发生变化（大小/时间不符），未输出哈希", hashChanged))
		}
		if deadlineHit {
			notes = append(notes, fmt.Sprintf("扫描时间超过上限 %s，剩余文件未计算哈希", c.scanBudget))
		}
		if hashFailed > 0 {
			notes = append(notes, fmt.Sprintf("%d 个文件哈希失败（已保留路径/大小/时间）", hashFailed))
		}
	} else {
		notes = append(notes, fmt.Sprintf("当前模式 %s 未授予 HashFile，仅输出路径/大小/修改时间", c.rt.Mode()))
	}

	res := &collector.Result{}
	for i := range found {
		it := found[i]
		data := model.FileData{
			Path:            it.Path,
			Size:            it.Size,
			LastWriteTime:   it.LastWriteTime.UTC().Format(time.RFC3339),
			Extension:       strings.ToLower(filepath.Ext(it.Path)),
			HashSHA256:      it.HashSHA256,
			CollectionLevel: string(c.rt.Mode()),
		}
		res.Entities = append(res.Entities, model.NewEntity("file", entityID(it.HashSHA256, i+1), data))
	}

	if len(notes) > 0 {
		return res, fmt.Errorf("file 采集不完整（已保留可核对的事实）：%s", strings.Join(notes, "；"))
	}
	return res, nil
}

// maxWalkNotes 限制单次扫描保留的说明条数：不可读目录可以非常多，
// 说明本身也不该成为内存放大器（被截断的条数会如实汇总）。
const maxWalkNotes = 500

// scanLimit 检查扫描预算；一旦触发就记录原因并让调用方收尾。
func (c *Collector) scanLimit(st *scanState) bool {
	if st.reason != "" {
		return true
	}
	if c.maxScanEntries > 0 && st.scanned > c.maxScanEntries {
		st.reason = fmt.Sprintf("扫描目录项数超过上限 %d，已停止枚举（结果不完整）", c.maxScanEntries)
		return true
	}
	if !st.deadline.IsZero() && c.now().After(st.deadline) {
		st.reason = fmt.Sprintf("扫描时间超过上限 %s，已停止枚举（结果不完整）", c.scanBudget)
		return true
	}
	return false
}

// walk 递归枚举目录下的普通文件，逐个交给 emit（不再先在内存里攒全量）。
// 不跟随符号链接/重解析点；达到深度、项数或时间上限即停止并记录说明。
func (c *Collector) walk(root string, st *scanState, emit func(item)) []string {
	var (
		notes   []string
		dropped int
	)
	addNote := func(format string, args ...any) {
		if len(notes) >= maxWalkNotes {
			dropped++
			return
		}
		notes = append(notes, fmt.Sprintf(format, args...))
	}
	var rec func(dir string, depth int)
	rec = func(dir string, depth int) {
		if c.scanLimit(st) {
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			addNote("目录不可读 %s: %v", dir, err)
			return
		}
		for _, e := range entries {
			st.scanned++
			if c.scanLimit(st) {
				return
			}
			// 不跟随链接/重解析点（避免循环与越界读取）。
			if e.Type()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
				continue
			}
			p := filepath.Join(dir, e.Name())
			if e.IsDir() {
				if depth >= c.depth {
					addNote("达到深度上限 %d，未下钻 %s", c.depth, p)
					continue
				}
				rec(p, depth+1)
				if st.reason != "" {
					return
				}
				continue
			}
			if !e.Type().IsRegular() {
				continue
			}
			info, err := e.Info()
			if err != nil {
				addNote("读取文件信息失败 %s: %v", p, err)
				continue
			}
			emit(item{Path: p, Size: info.Size(), LastWriteTime: info.ModTime()})
		}
	}
	rec(root, 0)
	if dropped > 0 {
		notes = append(notes, fmt.Sprintf("另有 %d 条扫描说明已省略", dropped))
	}
	return notes
}

// entityID 按协议 ID 规则生成 file 实体 ID：有哈希用 file_<sha256前12>_<seq>，
// 无哈希用 file_na_<seq>。
func entityID(hash string, seq int) string {
	if hash == "" {
		return fmt.Sprintf("file_na_%d", seq)
	}
	return fmt.Sprintf("file_%s_%d", hash[:12], seq)
}

// hashOne 计算单个文件的哈希；测试可注入 c.hash 替代真实读取。
func (c *Collector) hashOne(it item) (string, error) {
	if c.hash != nil {
		return c.hash(it)
	}
	return hashItemSHA256(it, c.maxHashBytes)
}

// hashItemSHA256 流式计算文件 SHA256（只读该文件本身，不读其它进程内存）。
//
// 打开前重新做本地路径/重解析点校验：枚举与哈希之间存在时间窗，不能信任旧路径。
// 哈希绑定到打开后的文件句柄：大小/修改时间与枚举结果不一致（文件被替换或改写）
// 就拒绝输出哈希，而不是把“另一个文件”的哈希贴到清单路径上。
func hashItemSHA256(it item, maxBytes int64) (string, error) {
	if _, err := safepath.ValidateLocalFilePath(it.Path, "file 文件路径"); err != nil {
		return "", err
	}
	f, err := os.Open(it.Path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("不是普通文件")
	}
	if info.Size() != it.Size || !info.ModTime().Equal(it.LastWriteTime) {
		return "", errHashChanged
	}
	if maxBytes > 0 && info.Size() > maxBytes {
		return "", fmt.Errorf("文件超过单个哈希上限")
	}
	h := sha256.New()
	// 多读 1 字节：文件在读取过程中变大时能发现，而不是静默算出截断哈希。
	n, err := io.Copy(h, io.LimitReader(f, info.Size()+1))
	if err != nil {
		return "", err
	}
	if n != info.Size() {
		return "", errHashChanged
	}
	after, err := f.Stat()
	if err != nil {
		return "", err
	}
	if after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return "", errHashChanged
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// debugf 输出采集阶段/内部错误日志到 stderr（不污染 stdout 的 JSONL 流）。
func debugf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[file] "+format+"\n", args...)
}
