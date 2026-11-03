// Package evidence 实现「痕迹留存」（V0.3 Evidence 模块）：把**命中项指向的文件**
// 只读复制进证据目录，并写下证据清单 manifest.txt。
//
// 设计依据：docs/设计-痕迹留存.md。三条边界不可动摇：
//  1. **只读**：只打开源文件读，不修改、不锁定（Go 的 os.Open 走
//     FILE_SHARE_READ|WRITE|DELETE）、不执行、不联网；源文件属性与修改时间不变；
//  2. **先算哈希再复制**：同一份内存缓冲**先算 SHA256 再写出**，所以"哈希 ↔ 落盘内容"
//     由构造保证一一对应，不存在"有文件没哈希"或"哈希与内容不符"；单文件上限也因此
//     就是内存占用上限（默认 64 MiB，一次只处理一个文件）；
//  3. **绝不静默**：路径不安全（UNC/NT/父目录链接）、打不开、超限、不是普通文件、
//     读取期间被替换或改写、写失败、内容重复，全部写进 manifest.txt 并如实返回
//     （退出码体现"不完整"）。
//
// 明确不做（设计 `0）：进程内存 dump、文件内容分析、逆向、YARA、内存扫描。
// 本包不做任何安全判断，也不自动处置（不结束进程、不删文件、不改注册表）。
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"easytrace/internal/integrity"
	"easytrace/internal/model"
	"easytrace/internal/safepath"
)

// 包级注入点：测试用它模拟父目录链接与读取后变化，生产路径始终走 os。
var (
	lstatSource = os.Lstat
	openSource  = os.Open
)

// ManifestName 是证据清单文件名（放在证据目录内）。
const ManifestName = "manifest.txt"

// Limits 是痕迹留存的上限（设计 `2.1）。
type Limits struct {
	// MaxFileBytes 单文件上限（默认 64 MiB，与既有哈希上限一致）。
	MaxFileBytes int64
	// MaxTotalBytes 合计上限（默认 512 MiB）。
	MaxTotalBytes int64
	// MaxFiles 文件数量上限（默认 200）。
	MaxFiles int
}

// DefaultLimits 返回设计稿建议的上限：64 MiB / 512 MiB / 200 个。
func DefaultLimits() Limits {
	return Limits{
		MaxFileBytes:  64 << 20,
		MaxTotalBytes: 512 << 20,
		MaxFiles:      200,
	}
}

// Source 是一个"要留存的痕迹"：来自一条命中，指向主机上的一个文件。
type Source struct {
	EntityID   string
	EntityType string
	RuleID     string
	Severity   string
	Path       string // 源文件路径（已归一为带盘符/UNC 的绝对路径）
}

// Provenance 是证据采集的来源信息（写入 manifest 头部，并受清单自校验覆盖）。
// 留空字段不写；Run 调用不带 provenance，RunWithProvenance 供 catch 使用。
type Provenance struct {
	ToolVersion string
	Host        string
	// SnapshotHost 是快照记录的主机名。跨主机显式 --snapshot 留存时，它与 Host
	// （执行 catch 的当前主机）可能不同，必须分别记录，避免证据归属混淆。
	SnapshotHost string
	Operator     string
	Database     string
	SnapshotID   string
	AcquiredAt   time.Time
}

// Result 是单个目标的留存结果。
type Result struct {
	Source Source
	// Status 是机器可读的结果码（kept 或 skipped_* / duplicate）。
	Status string
	// Reason 是给人看的原因（失败/跳过时必填，成功时为空）。
	Reason string
	Bytes  int64
	SHA256 string
	// Name 是落盘文件名（跳过时为期望文件名或空）。
	Name string
}

// 结果码。只有 kept 表示证据已经落下。
const (
	StatusKept        = "kept"
	StatusDuplicate   = "duplicate"
	StatusMissing     = "skipped_missing"
	StatusNotRegular  = "skipped_not_regular"
	StatusFileLimit   = "skipped_file_limit"
	StatusCountLimit  = "skipped_count_limit"
	StatusTotalLimit  = "skipped_total_limit"
	StatusUnreadable  = "skipped_unreadable"
	StatusWriteFailed = "skipped_write_failed"
	// StatusUnsafePath：路径不是本地盘符绝对路径，或父目录链包含链接/重解析点。
	StatusUnsafePath = "skipped_unsafe_path"
	// StatusChanged：读取后复核发现源文件在采集期间被替换/改写（内容不可信）。
	StatusChanged = "skipped_changed"
)

// ExtractPath 从实体的 data JSON 里取出"指向的文件路径"。
//
// 只认**按定义就是文件路径**的字段，绝不把命令行/描述当路径：
//   - process.path            进程镜像
//   - persistence.path        启动项指向的目标文件（location 是注册表键/启动文件夹，不是文件）
//   - file.path               落地文件
//   - service.binary_path     服务二进制
//
// 刻意不支持 driver / task：driver.path 是 NT 形式（\\SystemRoot\\...）不是可直接打开的
// Win32 路径；task.path 是 System32\\Tasks 下的任务 XML，不是攻击载荷。两者都要另行设计，
// 不在本期声称支持。
func ExtractPath(entityType, dataJSON string) (string, bool) {
	var raw string
	switch entityType {
	case "process":
		var d model.ProcessData
		if json.Unmarshal([]byte(dataJSON), &d) != nil {
			return "", false
		}
		raw = d.Path
	case "persistence":
		var d model.PersistenceData
		if json.Unmarshal([]byte(dataJSON), &d) != nil {
			return "", false
		}
		raw = d.Path
	case "file":
		var d model.FileData
		if json.Unmarshal([]byte(dataJSON), &d) != nil {
			return "", false
		}
		raw = d.Path
	case "service":
		var d model.ServiceData
		if json.Unmarshal([]byte(dataJSON), &d) != nil {
			return "", false
		}
		raw = d.BinaryPath
	default:
		return "", false
	}
	return CleanPath(raw)
}

// CleanPath 归一一个候选路径；不是"可直接打开的**本地**盘符绝对路径"就返回 false。
//
// 只接受 C:\... / D:\... 这种本地盘符路径，并进一步确认该盘符不是映射的网络
// 驱动器。刻意**不接受 UNC**（\\server\share\...）：复制 UNC 路径等于让这个
// "零网络"工具自动向网络位置发起 SMB 读取，与安全边界冲突。也不接受 NT 形式
// （\SystemRoot\...、\??\C:\...），它们不是可直接打开的 Win32 路径
// （\SystemRoot\... 还会被 filepath.VolumeName 误当成 UNC 卷标，所以这里不靠 VolumeName 判定）。
//
// 被挡掉的候选由 cmd 层计入"不指向文件"，不产生误导性的目标条目。
func CleanPath(p string) (string, bool) {
	p = strings.TrimSpace(p)
	p = strings.Trim(p, "\"") // 服务的 binary_path 常带引号
	p = strings.TrimSpace(p)
	cleaned, ok := safepath.LocalDrivePath(p)
	if !ok {
		return "", false
	}
	abs, err := safepath.RequireLocalDrivePath(cleaned, "源文件路径")
	if err != nil {
		return "", false
	}
	return abs, true
}

// Run 把 sources 留存的痕迹复制进 dir（dir 必须已存在且是本次新建的目录）。
//
// 源路径在读取前重新过 CleanPath 与父目录链校验（不信任调用方），读取有界，
// 读取后复核文件身份/大小/修改时间。任一环节不满足都会记为 skipped_* 并解释原因。
//
// 返回每个目标的结果与"是否存在未留存目标"的错误。**单个目标失败不中断其它目标**，
// 所有结果都会写进 dir/manifest.txt——"留了什么、为什么没留"必须都能查。
func Run(dir string, sources []Source, lim Limits) ([]Result, error) {
	return run(dir, sources, lim, Provenance{})
}

// RunWithProvenance 与 Run 相同，但把本次采集的工具版本、主机、操作者、数据库/
// 快照与采集时间写进清单头部。这些元数据也受 manifest 自校验行覆盖。
func RunWithProvenance(dir string, sources []Source, lim Limits, prov Provenance) ([]Result, error) {
	return run(dir, sources, lim, prov)
}

func run(dir string, sources []Source, lim Limits, prov Provenance) ([]Result, error) {
	if lim.MaxFiles <= 0 {
		lim = DefaultLimits()
	}
	// 顺序固定（路径 → 实体 → 规则），保证同一输入产出同一份 manifest。
	ordered := append([]Source(nil), sources...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].Path != ordered[j].Path {
			return ordered[i].Path < ordered[j].Path
		}
		if ordered[i].EntityID != ordered[j].EntityID {
			return ordered[i].EntityID < ordered[j].EntityID
		}
		return ordered[i].RuleID < ordered[j].RuleID
	})

	results := make([]Result, 0, len(ordered))
	byHash := make(map[string]string, len(ordered)) // sha256 → 落盘文件名
	kept := 0
	var total int64
	var problems []string

	for _, s := range ordered {
		r := Result{Source: s}
		if kept >= lim.MaxFiles {
			r.Status = StatusCountLimit
			r.Reason = fmt.Sprintf("已达数量上限 %d 个", lim.MaxFiles)
			results = append(results, r)
			problems = append(problems, describe(r))
			continue
		}

		// 源路径同样必须过本地盘符校验与父目录链校验：Run 是导出 API，
		// 不能假设调用方已经做过 CleanPath（cmd 层的过滤是第二道，不是唯一一道）。
		path, ok := CleanPath(s.Path)
		if !ok {
			r.Status = StatusUnsafePath
			r.Reason = "路径不是可直接打开的本地盘符绝对路径（UNC / NT / 相对路径一律拒绝）"
			results = append(results, r)
			problems = append(problems, describe(r))
			continue
		}
		if err := safepath.RejectUnsafeParents(path, "源文件路径"); err != nil {
			r.Status = StatusUnsafePath
			r.Reason = err.Error()
			results = append(results, r)
			problems = append(problems, describe(r))
			continue
		}

		info, err := lstatSource(path)
		if err != nil {
			r.Status = StatusMissing
			r.Reason = "无法访问源文件: " + err.Error()
			results = append(results, r)
			problems = append(problems, describe(r))
			continue
		}
		if !info.Mode().IsRegular() {
			// 目录、符号链接、Windows 重解析点（junction）一律不跟随、不复制：
			// 证据目录不该因为一个链接把任意位置的文件拖进来。
			r.Status = StatusNotRegular
			r.Reason = "不是普通文件（目录 / 符号链接 / 重解析点），拒绝复制"
			results = append(results, r)
			problems = append(problems, describe(r))
			continue
		}
		size := info.Size()
		if size > lim.MaxFileBytes {
			r.Status = StatusFileLimit
			r.Bytes = size
			r.Reason = fmt.Sprintf("超过单文件上限 %d 字节（实际 %d）", lim.MaxFileBytes, size)
			results = append(results, r)
			problems = append(problems, describe(r))
			continue
		}
		if total+size > lim.MaxTotalBytes {
			r.Status = StatusTotalLimit
			r.Bytes = size
			r.Reason = fmt.Sprintf("超过合计上限 %d 字节（已留存 %d）", lim.MaxTotalBytes, total)
			results = append(results, r)
			problems = append(problems, describe(r))
			continue
		}

		// 有界读取：上限取"单文件上限"与"合计剩余额度"的较小值。预检查到读取之间
		// 文件可能增长，所以读取本身也必须有界，不能依赖 stat 的结论。
		limit := lim.MaxFileBytes
		if remain := lim.MaxTotalBytes - total; remain < limit {
			limit = remain
		}
		blob, tooLarge, err := readBoundedSource(path, limit)
		if err != nil {
			r.Status = StatusUnreadable
			r.Reason = "读取失败: " + err.Error()
			results = append(results, r)
			problems = append(problems, describe(r))
			continue
		}
		if tooLarge {
			r.Bytes = int64(len(blob))
			if limit == lim.MaxFileBytes {
				r.Status = StatusFileLimit
				r.Reason = fmt.Sprintf("超过单文件上限 %d 字节（读取时已增长）", lim.MaxFileBytes)
			} else {
				r.Status = StatusTotalLimit
				r.Reason = fmt.Sprintf("超过合计上限 %d 字节（已留存 %d）", lim.MaxTotalBytes, total)
			}
			results = append(results, r)
			problems = append(problems, describe(r))
			continue
		}

		// 读取后复核：同一文件、仍是普通文件、大小与修改时间未变。任何一项不满足，
		// 说明落盘内容可能来自"读取瞬间之前的另一个版本"，哈希不再可信。
		if reason := verifyUnchanged(path, info, blob); reason != "" {
			r.Status = StatusChanged
			r.Bytes = int64(len(blob))
			r.Reason = reason
			results = append(results, r)
			problems = append(problems, describe(r))
			continue
		}

		// 按实际读到的长度再复核一次上限（防御性：注入的读取实现可能不遵守 limit）。
		if int64(len(blob)) > lim.MaxFileBytes {
			r.Status = StatusFileLimit
			r.Bytes = int64(len(blob))
			r.Reason = fmt.Sprintf("超过单文件上限 %d 字节（实际 %d）", lim.MaxFileBytes, len(blob))
			results = append(results, r)
			problems = append(problems, describe(r))
			continue
		}
		if total+int64(len(blob)) > lim.MaxTotalBytes {
			r.Status = StatusTotalLimit
			r.Bytes = int64(len(blob))
			r.Reason = fmt.Sprintf("超过合计上限 %d 字节（已留存 %d）", lim.MaxTotalBytes, total)
			results = append(results, r)
			problems = append(problems, describe(r))
			continue
		}

		sum := sha256.Sum256(blob)
		hexSum := hex.EncodeToString(sum[:])
		r.SHA256 = hexSum
		r.Bytes = int64(len(blob))

		if prev, ok := byHash[hexSum]; ok {
			// 完全相同的内容已经在证据目录里了：不再复制第二份，但如实记录。
			r.Status = StatusDuplicate
			r.Name = prev
			r.Reason = "与已留存文件内容相同（同一 sha256），未重复复制"
			results = append(results, r)
			continue
		}

		name := destName(hexSum, path)
		if err := writeExclusive(filepath.Join(dir, name), blob); err != nil {
			r.Status = StatusWriteFailed
			r.Name = name
			r.Reason = "写入证据文件失败: " + err.Error()
			results = append(results, r)
			problems = append(problems, describe(r))
			continue
		}
		byHash[hexSum] = name
		r.Status = StatusKept
		r.Name = name
		kept++
		total += int64(len(blob))
		results = append(results, r)
	}

	manifest := buildManifest(results, kept, total, prov)
	// 落盘前先确认生成器拼出的清单自校验行正确；文件内容在打包时会重新逐字节核对。
	if err := integrity.VerifyManifestHash([]byte(manifest)); err != nil {
		return results, fmt.Errorf("证据清单自校验失败: %w", err)
	}
	if err := writeExclusive(filepath.Join(dir, ManifestName), []byte(manifest)); err != nil {
		return results, fmt.Errorf("写入 %s 失败: %w", ManifestName, err)
	}
	if len(problems) > 0 {
		return results, fmt.Errorf("痕迹留存不完整：%d/%d 个目标未能留存（已留存 %d 个文件，详情见 %s）",
			len(problems), len(results), kept, ManifestName)
	}
	return results, nil
}

// readBoundedSource 有界读取源文件：最多返回 limit 字节。返回 tooLarge 表示
// 文件超过 limit（此时内容被截断，调用方只能用于记录长度，不得留存）。
func readBoundedSource(path string, limit int64) (data []byte, tooLarge bool, err error) {
	f, err := openSource(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	data, err = io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > limit {
		return data[:limit], true, nil
	}
	return data, false, nil
}

// verifyUnchanged 在读取后复核源文件没有在读取期间被替换或改写。
// 返回非空字符串即说明内容不可信（调用方记为 skipped_changed）。
func verifyUnchanged(path string, before os.FileInfo, blob []byte) string {
	after, err := lstatSource(path)
	if err != nil {
		return "读取后复核失败: " + err.Error()
	}
	if !after.Mode().IsRegular() {
		return "读取后源文件不再是普通文件（可能被替换为链接/目录）"
	}
	if !os.SameFile(before, after) {
		return "读取后源文件已被替换（与读取前不是同一个文件）"
	}
	if after.Size() != int64(len(blob)) {
		return fmt.Sprintf("读取后源文件大小变化（stat %d / 读取 %d）", after.Size(), len(blob))
	}
	if !after.ModTime().Equal(before.ModTime()) {
		return "读取后源文件修改时间变化（内容可能在读取期间被改写）"
	}
	return ""
}

// destName 生成落盘文件名：<sha256前12>_<原名>（设计 `2.1）。
// 只取基名，避免源路径里的分隔符影响证据目录结构；并清理 Windows 非法字符。
// 特别是冒号：<name>:<stream> 会被解释为 NTFS 备用数据流，写入成功但不会生成
// 清单里那个“文件”，使证据包在事后校验时对不上。
func destName(hexSum, srcPath string) string {
	base := safeDestBase(filepath.Base(filepath.Clean(srcPath)))
	return hexSum[:12] + "_" + base
}

// safeDestBase 把源基名收敛成可安全落盘的 Windows 文件名组件。
func safeDestBase(base string) string {
	const maxBaseRunes = 120
	var b strings.Builder
	count := 0
	for _, r := range base {
		if count >= maxBaseRunes {
			break
		}
		if r < 0x20 || strings.ContainsRune(`\/:*?"<>|`, r) {
			r = '_'
		}
		b.WriteRune(r)
		count++
	}
	out := strings.TrimRight(b.String(), ". ")
	if out == "" || out == "." || out == ".." {
		out = "file"
	}
	return out
}

// writeExclusive 用排他创建写文件：证据目录里**绝不覆盖**已有条目
// （与 report 的导出语义一致）。
func writeExclusive(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// describe 生成"哪个目标的哪条规则没留存成"的一句话（用于汇总错误）。
func describe(r Result) string {
	return fmt.Sprintf("%s（%s / %s）：%s", r.Source.Path, r.Source.RuleID, r.Source.EntityID, r.Reason)
}

// buildManifest 生成证据清单。
//
// 列（制表符分隔）：<sha256> <原路径> <字节数> <结果> <落盘文件名> <规则ID> <实体ID> <说明>
// 全部目标都在，**包括没留存成的**——"留了什么、为什么没留"必须都能查。
// 末尾追加 manifest 自校验行（见 integrity.AppendManifestHash），让清单内容与
// 逐文件哈希在打包时可整体校验。
func buildManifest(results []Result, kept int, total int64, prov Provenance) string {
	var sb strings.Builder
	sb.WriteString("# Easy_Trace 痕迹留存清单（evidence/" + ManifestName + "）\n")
	writeProvenance(&sb, prov)
	sb.WriteString("# 列：<sha256>\t<原路径>\t<字节数>\t<结果>\t<落盘文件名>\t<规则ID>\t<实体ID>\t<说明>\n")
	sb.WriteString("# 结果码：kept=已留存 / duplicate=内容与已留存文件相同 / skipped_*=未留存（原因见说明）\n")
	for _, r := range results {
		sb.WriteString(manifestField(r.SHA256))
		sb.WriteString("\t" + manifestField(r.Source.Path))
		sb.WriteString("\t" + fmt.Sprintf("%d", r.Bytes))
		sb.WriteString("\t" + manifestField(r.Status))
		sb.WriteString("\t" + manifestField(r.Name))
		sb.WriteString("\t" + manifestField(r.Source.RuleID))
		sb.WriteString("\t" + manifestField(r.Source.EntityID))
		sb.WriteString("\t" + manifestField(r.Reason) + "\n")
	}
	sb.WriteString("# 合计：已留存 " + fmt.Sprintf("%d", kept) + " 个文件，" + fmt.Sprintf("%d", total) + " 字节\n")
	return integrity.AppendManifestHash(sb.String())
}

// writeProvenance 把采集来源写进 manifest 头部；空值不写（Run 的测试/调用
// 不携带采集元数据，仍产出确定性清单）。
func writeProvenance(sb *strings.Builder, p Provenance) {
	var lines []string
	add := func(key, value string) {
		if v := strings.TrimSpace(value); v != "" {
			lines = append(lines, "# "+key+": "+manifestField(v))
		}
	}
	if !p.AcquiredAt.IsZero() {
		add("acquired_at_utc", p.AcquiredAt.UTC().Format(time.RFC3339))
	}
	add("tool_version", p.ToolVersion)
	add("host", p.Host)
	add("snapshot_host", p.SnapshotHost)
	add("operator", p.Operator)
	add("database", p.Database)
	add("snapshot_id", p.SnapshotID)
	if len(lines) == 0 {
		return
	}
	sb.WriteString("# 采集元数据（provenance）:\n")
	for _, line := range lines {
		sb.WriteString(line + "\n")
	}
}

// manifestField 把字段压成单行：文件名/错误文本里的制表符与换行不能改变清单结构。
func manifestField(s string) string {
	return strings.NewReplacer("\t", " ", "\r", " ", "\n", " ").Replace(s)
}
