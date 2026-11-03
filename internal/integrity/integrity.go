// Package integrity 实现 Easy_Trace 构建产物的自校验（设计原则 P8「自身可信」）。
//
// 职责：为可执行文件与规则包生成 SHA256 清单，并在运行时重新计算比对，回答
// "手上这个 exe 与 rules/ 是否就是清单所描述的那一份"。
//
// 边界（如实说明，不得夸大）：
//   - 只有哈希比对，没有签名。清单自身未签名，因此它能发现"文件与清单不一致"
//     （下载损坏、被误改、构建产物与分发物不匹配），但**不能**对抗有能力同时
//     改写二进制与清单的攻击者；来源认证需要代码签名（仅分发场景需要）。
//   - 不联网、不执行外部程序、不读其它进程内存；只读本工具自己的文件。
package integrity

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ManifestName 是与可执行文件同目录的默认清单文件名。
const ManifestName = "Easy_Trace.manifest.sha256"

// ExeLabel 是清单中可执行文件条目的标签。
const ExeLabel = "exe"

// RulesPrefix 是清单中规则文件条目的标签前缀（统一用 '/'，跨平台可复现）。
const RulesPrefix = "rules/"

const manifestHeader = "# Easy_Trace 自校验清单 v1（SHA256；清单未签名，只能发现与清单不一致）"

// Entry 是清单中的一条：标签 + 该文件的 SHA256（小写十六进制）。
type Entry struct {
	Label  string
	SHA256 string
}

// Manifest 是一份自校验清单。Entries 按 Label 升序，Text() 输出逐字节可复现。
type Manifest struct {
	Entries []Entry
}

// ManifestHashPrefix 是证据/事件清单末尾自校验行的前缀。自校验行覆盖它之前的
// 全部字节，因此清单的 provenance、逐文件哈希与文件列表不能被整体替换后仍通过。
const ManifestHashPrefix = "# manifest_sha256: "

// AppendManifestHash 在清单正文末尾追加 "<前缀><正文 SHA256>" 行。
// 正文必须以换行结尾（现有清单生成器都满足）；返回值可直接写盘。
func AppendManifestHash(body string) string {
	sum := sha256.Sum256([]byte(body))
	return body + ManifestHashPrefix + hex.EncodeToString(sum[:]) + "\n"
}

// VerifyManifestHash 校验 AppendManifestHash 追加的自校验行。
// 自校验行必须是最后一个非空行；缺失、格式错误或摘要不符都返回错误（fail closed）。
func VerifyManifestHash(data []byte) error {
	text := string(data)
	trimmed := strings.TrimRight(text, "\r\n")
	idx := strings.LastIndex(trimmed, ManifestHashPrefix)
	if idx < 0 || (idx > 0 && trimmed[idx-1] != '\n') {
		return fmt.Errorf("清单缺少自校验行 %s", ManifestHashPrefix)
	}
	prefix := text[:idx]
	// 自校验行必须是最后一行：若其后还有内容，expected 会包含换行而格式校验失败。
	expected := strings.TrimSpace(trimmed[idx+len(ManifestHashPrefix):])
	if len(expected) != 64 {
		return fmt.Errorf("清单自校验行哈希长度非法")
	}
	if _, err := hex.DecodeString(expected); err != nil {
		return fmt.Errorf("清单自校验行哈希非法: %w", err)
	}
	sum := sha256.Sum256([]byte(prefix))
	if !strings.EqualFold(expected, hex.EncodeToString(sum[:])) {
		return fmt.Errorf("清单自校验失败：清单内容与自校验行不一致")
	}
	return nil
}

// HashFile 流式计算文件的 SHA256（小写十六进制）。读的是文件，不读进程内存。
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// RuleLabels 递归列出规则目录下的 *.yaml / *.yml，返回按路径排序的清单标签
// （形如 rules/process/user_path_unsigned.yaml）。目录不存在时报错，不静默返回空。
func RuleLabels(rulesDir string) ([]string, error) {
	info, err := os.Stat(rulesDir)
	if err != nil {
		return nil, fmt.Errorf("规则目录不可用: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("规则目录不是目录: %s", rulesDir)
	}

	var labels []string
	err = filepath.WalkDir(rulesDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		rel, err := filepath.Rel(rulesDir, path)
		if err != nil {
			return err
		}
		labels = append(labels, RulesPrefix+filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("遍历规则目录失败: %w", err)
	}
	sort.Strings(labels)
	return labels, nil
}

// LabelPath 把清单标签解析为文件系统路径（exe → exePath；rules/ → rulesDir 下的文件）。
func LabelPath(label, exePath, rulesDir string) (string, error) {
	switch {
	case label == ExeLabel:
		if exePath == "" {
			return "", fmt.Errorf("清单含 exe 条目，但未提供可执行文件路径")
		}
		return exePath, nil
	case strings.HasPrefix(label, RulesPrefix):
		if rulesDir == "" {
			return "", fmt.Errorf("清单含规则条目，但未提供规则目录")
		}
		rel := strings.TrimPrefix(label, RulesPrefix)
		if rel == "" {
			return "", fmt.Errorf("非法清单标签: %q", label)
		}
		return filepath.Join(rulesDir, filepath.FromSlash(rel)), nil
	}
	return "", fmt.Errorf("未知清单标签前缀: %q", label)
}

// Build 为 exePath 与 rulesDir 生成清单（exe 条目在标签排序中自然排在最前）。
// exePath 为空表示不校验可执行文件；rulesDir 为空表示不含规则（两者仅供测试 fixture 使用）。
func Build(exePath, rulesDir string) (*Manifest, error) {
	m := &Manifest{}
	if exePath != "" {
		h, err := HashFile(exePath)
		if err != nil {
			return nil, fmt.Errorf("计算可执行文件哈希失败: %w", err)
		}
		m.Entries = append(m.Entries, Entry{Label: ExeLabel, SHA256: h})
	}
	if rulesDir != "" {
		labels, err := RuleLabels(rulesDir)
		if err != nil {
			return nil, err
		}
		for _, label := range labels {
			path, err := LabelPath(label, exePath, rulesDir)
			if err != nil {
				return nil, err
			}
			h, err := HashFile(path)
			if err != nil {
				return nil, fmt.Errorf("计算规则哈希失败 %s: %w", label, err)
			}
			m.Entries = append(m.Entries, Entry{Label: label, SHA256: h})
		}
	}
	sort.Slice(m.Entries, func(i, j int) bool { return m.Entries[i].Label < m.Entries[j].Label })
	return m, nil
}

// Text 渲染清单文本：注释头 + 每行 "<sha256>  <label>"，LF 换行，无时间戳、无本机路径。
func (m *Manifest) Text() string {
	var b strings.Builder
	b.WriteString(manifestHeader)
	b.WriteString("\n")
	b.WriteString("# 每行: <sha256>  <label>；label 为 exe 或 rules/<相对路径>\n")
	for _, e := range m.Entries {
		b.WriteString(e.SHA256)
		b.WriteString("  ")
		b.WriteString(e.Label)
		b.WriteString("\n")
	}
	return b.String()
}

// Parse 解析清单文本。空行与 '#' 注释行忽略；格式错误、哈希非法、标签重复都报错
// （不静默跳过，否则"少校验了一项"会被当成通过）。
func Parse(text string) (*Manifest, error) {
	m := &Manifest{}
	seen := map[string]bool{}
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) != 2 {
			return nil, fmt.Errorf("清单第 %d 行格式非法（应为 <sha256>  <label>）: %q", i+1, line)
		}
		hash := strings.ToLower(fields[0])
		if len(hash) != 64 {
			return nil, fmt.Errorf("清单第 %d 行哈希长度非法: %q", i+1, fields[0])
		}
		if _, err := hex.DecodeString(hash); err != nil {
			return nil, fmt.Errorf("清单第 %d 行哈希非法: %q", i+1, fields[0])
		}
		label := fields[1]
		if seen[label] {
			return nil, fmt.Errorf("清单第 %d 行标签重复: %q", i+1, label)
		}
		seen[label] = true
		m.Entries = append(m.Entries, Entry{Label: label, SHA256: hash})
	}
	if len(m.Entries) == 0 {
		return nil, fmt.Errorf("清单不含任何条目")
	}
	sort.Slice(m.Entries, func(i, j int) bool { return m.Entries[i].Label < m.Entries[j].Label })
	return m, nil
}

// Load 读取并解析清单文件。
func Load(path string) (*Manifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取清单失败: %w", err)
	}
	m, err := Parse(string(b))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return m, nil
}

// Save 写入清单文件（LF、无 BOM）。清单是构建产物而非证据，允许覆盖同名文件。
func Save(path string, m *Manifest) error {
	if err := os.WriteFile(path, []byte(m.Text()), 0o644); err != nil {
		return fmt.Errorf("写入清单失败: %w", err)
	}
	return nil
}

// 比对状态。
const (
	StatusOK         = "ok"
	StatusMismatch   = "mismatch"
	StatusMissing    = "missing"
	StatusUnreadable = "unreadable"
	StatusExtra      = "extra"
)

// Result 是一条比对结果。Want 为清单中的哈希，Got 为实测哈希（不可读时是原因说明）。
type Result struct {
	Label  string
	Status string
	Want   string
	Got    string
}

// OK 表示该条通过。
func (r Result) OK() bool { return r.Status == StatusOK }

// Verify 重新计算 exePath 与 rulesDir 下所有规则文件的哈希，并与清单比对。
// 返回结果按标签排序；"清单里有但文件缺失/不可读"与"文件存在但清单没记录"都判失败。
func Verify(m *Manifest, exePath, rulesDir string) ([]Result, error) {
	actual := map[string]string{}
	unreadable := map[string]string{}

	if exePath != "" {
		if h, err := HashFile(exePath); err != nil {
			unreadable[ExeLabel] = err.Error()
		} else {
			actual[ExeLabel] = h
		}
	}
	if rulesDir != "" {
		labels, err := RuleLabels(rulesDir)
		if err != nil {
			return nil, err
		}
		for _, label := range labels {
			path, err := LabelPath(label, exePath, rulesDir)
			if err != nil {
				return nil, err
			}
			if h, err := HashFile(path); err != nil {
				unreadable[label] = err.Error()
			} else {
				actual[label] = h
			}
		}
	}

	var results []Result
	seen := map[string]bool{}
	for _, e := range m.Entries {
		seen[e.Label] = true
		switch {
		case actual[e.Label] != "":
			if actual[e.Label] == e.SHA256 {
				results = append(results, Result{e.Label, StatusOK, e.SHA256, actual[e.Label]})
			} else {
				results = append(results, Result{e.Label, StatusMismatch, e.SHA256, actual[e.Label]})
			}
		case unreadable[e.Label] != "":
			results = append(results, Result{e.Label, StatusUnreadable, e.SHA256, unreadable[e.Label]})
		default:
			results = append(results, Result{e.Label, StatusMissing, e.SHA256, ""})
		}
	}
	for label, h := range actual {
		if !seen[label] {
			results = append(results, Result{label, StatusExtra, "", h})
		}
	}
	for label, reason := range unreadable {
		if !seen[label] {
			results = append(results, Result{label, StatusUnreadable, "", reason})
		}
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Label < results[j].Label })
	return results, nil
}
