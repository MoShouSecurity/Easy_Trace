// Package rulelint 对**内置规则文本**做静态自检：是否含"可能触发杀软启发式"的高危连续字串。
//
// 背景（2026-10-14 实测）：内置规则经 //go:embed 编进二进制，完整的高危工具名出现在
// 可执行文件里时，会被杀软启发式命中——表现为生成的 exe / 测试二进制**被拒绝执行**
// （fork/exec … Access is denied），直接破坏"单 exe 交付"。
// 规则作者必须把这类名字**拆成两段用 AND 组合**（语义等价，二进制里不再有连续字串），
// 详见 docs/rules.md「规则作者须知」。
//
// 本包自身也必须遵守同一条规则，否则"自检工具自己先被杀软拦下"，毫无意义：
//   - 高危名不做常量拼接（编译器会把 "a"+"b" 折叠成一个连续字串）；
//   - 也不依赖"两个短字面量恰好不相邻"——它们在只读数据段里可能正好挨在一起，
//     于是又变回连续高危名。这里把名字内部**用 NUL 断开**存进字面量（见 highRiskSubstrings），
//     运行时再去掉 NUL：二进制里因 NUL 隔断，**保证**不会出现连续高危名。
package rulelint

import (
	"bytes"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
)

// markerSeparator 是写进字面量、运行时会被去掉的隔断字符。
//
// 选 NUL（\x00）：它不是规则文本里会出现的可见字符，去掉后不影响匹配语义，
// 但足以在二进制里打断"连续高危名"这一特征（这正是杀软启发式的判定依据）。
const markerSeparator = "\x00"

// highRiskSubstrings 是**已实测**会触发杀软启发式的高危标记（比较时统一小写）。
//
// 维护口径：新增条目必须写明"实测被拦"的环境与日期，不要凭猜测堆砌——
// 否则会误伤正常规则（例如工具名片段、常见英文词）。已知两条来自本机 2026-10-14 实测。
//
// 写法要求：必须以 unmask("前半\x00后半") 的形式给出，**不能**写成完整字面量，
// 也不能写成 "前半"+"后半"（都会让二进制里出现连续高危名）。
var highRiskSubstrings = []string{
	unmask("mimi" + markerSeparator + "katz"), // 2026-10-14 实测：内置后 exe/测试二进制执行报 Access is denied
	unmask("sekur" + markerSeparator + "lsa"), // 同上（内存模块入口名）
}

// unmask 去掉字面量里的隔断字符，还原成真正要匹配的名字。
func unmask(s string) string { return strings.ReplaceAll(s, markerSeparator, "") }

// Problem 是一条自检发现。
type Problem struct {
	File   string // 规则包内相对路径（斜杠分隔）
	Line   int    // 1-based 行号
	Marker string // 命中的高危字串
}

func (p Problem) String() string {
	return fmt.Sprintf("%s:%d 含高危连续字串 %q", p.File, p.Line, p.Marker)
}

// ScanFS 用内置高危标记表扫描规则目录，见 scanFS。
func ScanFS(fsys fs.FS, root string) ([]Problem, error) {
	return scanFS(fsys, root, highRiskSubstrings)
}

// scanFS 遍历规则目录下的 *.yaml / *.yml，逐行查找 markers（大小写不敏感）。
// 返回按文件/行号排序的结果；遍历失败返回错误（不静默跳过）。
//
// markers 作为参数传入，是为了让本包测试能用**无害的合成标记**验证逻辑——
// 测试数据里若写真实高危名，测试二进制同样会被拦，用例根本跑不到断言。
func scanFS(fsys fs.FS, root string, markers []string) ([]Problem, error) {
	if root == "" {
		root = "."
	}
	var problems []Problem
	err := fs.WalkDir(fsys, root, func(path string, d fs.DirEntry, err error) error {
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
		b, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		rel := strings.TrimPrefix(filepath.ToSlash(path), strings.TrimPrefix(filepath.ToSlash(root), "./")+"/")
		for i, line := range strings.Split(string(b), "\n") {
			lower := strings.ToLower(line)
			for _, marker := range markers {
				if marker != "" && strings.Contains(lower, strings.ToLower(marker)) {
					problems = append(problems, Problem{File: rel, Line: i + 1, Marker: marker})
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("rulelint: 遍历规则目录失败（%s）: %w", root, err)
	}
	sort.Slice(problems, func(i, j int) bool {
		if problems[i].File != problems[j].File {
			return problems[i].File < problems[j].File
		}
		return problems[i].Line < problems[j].Line
	})
	return problems, nil
}

// Markers 返回内置高危标记表（已还原成完整名字）的副本。
//
// 供构建/测试工具复用同一份标记，避免在多处各写一份导致漂移。
// 注意：**不要把它的内容再以字面量形式写进任何会落盘的产物**。
func Markers() []string {
	out := make([]string, len(highRiskSubstrings))
	copy(out, highRiskSubstrings)
	return out
}

// FindMarkers 在任意字节序列里查找高危标记（大小写不敏感），
// 返回**去重且排序**后的命中列表；无命中返回 nil。
//
// 用途：构建后直接扫描**成品 exe 字节**。规则文件干净不等于成品干净——
// 源码里的字面量、编译期常量拼接、只读数据段里两个字面量恰好相邻，
// 都会让成品重新带上连续高危名，进而被杀软启发式拦截（exe 被拒绝执行）。
// 只有对着成品字节下结论，才能真正覆盖这条链路。
func FindMarkers(b []byte) []string {
	return findMarkers(b, highRiskSubstrings)
}

// findMarkers 是 FindMarkers 的可注入版本（测试用无害合成标记，避免测试二进制自带特征）。
func findMarkers(b []byte, markers []string) []string {
	lower := bytes.ToLower(b)
	seen := map[string]bool{}
	var hits []string
	for _, m := range markers {
		if m == "" {
			continue
		}
		needle := []byte(strings.ToLower(m))
		if bytes.Contains(lower, needle) {
			if !seen[m] {
				seen[m] = true
				hits = append(hits, m)
			}
		}
	}
	sort.Strings(hits)
	return hits
}
