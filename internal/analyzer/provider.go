package analyzer

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// maxRuleFileBytes 限制单个本地规则文件大小，避免规则包输入导致无界内存占用。
const maxRuleFileBytes int64 = 4 * 1024 * 1024

// RuleProvider 规则来源抽象（第一阶段仅本地文件；预留在线更新/规则包管理）。
type RuleProvider interface {
	// Load 返回全部规则；任何规则加载/校验失败必须返回错误（不静默忽略）。
	Load() ([]*Rule, error)
}

// FSRuleProvider 从任意 fs.FS 加载规则包：内嵌规则（//go:embed）与磁盘目录
// **共用同一套遍历/解析/校验逻辑**，避免两条路径产生行为差异。
type FSRuleProvider struct {
	FS    fs.FS  // 规则文件系统
	Root  string // 规则包根（如 "rules"）；"." 表示 FS 根
	Label string // 错误信息与展示用的来源标识；为空时用 Root

	// AllowEmpty 允许空规则包。默认拒绝：0 条规则会让 analyze 返回空 Finding，
	// 操作者看到的是"没有风险"而不是"规则没加载成功"。
	AllowEmpty bool
}

// NewFSRuleProvider 构造 fs.FS 规则提供者。
func NewFSRuleProvider(fsys fs.FS, root string) *FSRuleProvider {
	return &FSRuleProvider{FS: fsys, Root: root}
}

// FileRuleProvider 从磁盘目录加载 *.yaml / *.yml 规则文件（FSRuleProvider 的薄封装）。
type FileRuleProvider struct {
	Dir string
	// AllowEmpty 允许空规则包（默认拒绝，理由见 FSRuleProvider.AllowEmpty）。
	AllowEmpty bool
}

// NewFileRuleProvider 构造文件规则提供者。
func NewFileRuleProvider(dir string) *FileRuleProvider {
	return &FileRuleProvider{Dir: dir}
}

// Load 递归读取目录（含子目录，如 rules/process/、rules/persistence/）下全部
// 规则文件并解析、校验（rule_id 唯一性全局校验）。
func (p *FileRuleProvider) Load() ([]*Rule, error) {
	return (&FSRuleProvider{FS: os.DirFS(p.Dir), Root: ".", Label: p.Dir, AllowEmpty: p.AllowEmpty}).Load()
}

// Load 从 FS 递归加载规则：按相对路径稳定排序，逐文件做大小上限检查与解析，
// 最后做全局 rule_id 唯一性校验。任何失败都返回错误（不静默跳过）。
func (p *FSRuleProvider) Load() ([]*Rule, error) {
	root := p.Root
	if root == "" {
		root = "."
	}
	label := p.Label
	if label == "" {
		label = root
	}

	var files []string
	err := fs.WalkDir(p.FS, root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if isRuleFileName(d.Name()) {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("analyzer: 遍历规则目录失败（%s）: %w", label, err)
	}
	sort.Strings(files) // 稳定加载顺序

	var all []*Rule
	for _, f := range files {
		info, err := fs.Stat(p.FS, f)
		if err != nil {
			return nil, fmt.Errorf("analyzer: 检查规则文件失败 %s: %w", displayPath(label, root, f), err)
		}
		if info.Size() > maxRuleFileBytes {
			return nil, fmt.Errorf("analyzer: 规则文件超过 %d 字节上限: %s", maxRuleFileBytes, displayPath(label, root, f))
		}
		b, err := fs.ReadFile(p.FS, f)
		if err != nil {
			return nil, fmt.Errorf("analyzer: 读取规则文件失败 %s: %w", displayPath(label, root, f), err)
		}
		rules, err := parseRulesFile(string(b), relativeRulePath(root, f))
		if err != nil {
			return nil, err
		}
		all = append(all, rules...)
	}
	if err := validateUniqueRuleIDs(all); err != nil {
		return nil, err
	}
	if len(all) == 0 && !p.AllowEmpty {
		return nil, fmt.Errorf("analyzer: 规则包 %s 中没有可加载的规则（*.yaml / *.yml）；空规则集会让分析静默变成“没有风险”。确需空规则请显式设置 AllowEmpty", label)
	}
	sortRules(all)
	return all, nil
}

// isRuleFileName 判断是否规则文件（.yaml / .yml，扩展名大小写不敏感）。
//
// 必须与 internal/integrity.RuleLabels 的判定一致：verify 列出 .YAML 文件、
// 分析器却不加载它，会让“自校验通过”和“规则实际生效”脱节。
func isRuleFileName(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".yaml", ".yml":
		return true
	default:
		return false
	}
}

// relativeRulePath 把 FS 路径转成规则包内的相对路径（斜杠分隔），与历史 Source 值一致。
func relativeRulePath(root, path string) string {
	path = strings.TrimPrefix(filepath.ToSlash(path), "./")
	root = strings.TrimPrefix(filepath.ToSlash(root), "./")
	if root == "" || root == "." {
		return path
	}
	if rel, err := filepath.Rel(filepath.FromSlash(root), filepath.FromSlash(path)); err == nil {
		return filepath.ToSlash(rel)
	}
	return path
}

// displayPath 生成错误信息里的完整来源（label + 相对路径）。
func displayPath(label, root, path string) string {
	rel := relativeRulePath(root, path)
	if label == "" || label == "." {
		return rel
	}
	return label + "/" + rel
}

// parseRulesFile 解析单个 YAML 文件：顶层 map（单条规则）或顶层 list（多条规则）。
// 多文档分隔符 --- 会被 yamlParse 明确拒绝，不做“部分加载”。
func parseRulesFile(src, name string) ([]*Rule, error) {
	// 顶层 list：- rule_id: ...；或单个 map
	root, err := yamlParse(src)
	if err != nil {
		return nil, fmt.Errorf("analyzer: %s: %v", name, err)
	}
	var rules []*Rule
	switch root.kind {
	case yamlMap:
		r, err := parseRule(root, name)
		if err != nil {
			return nil, fmt.Errorf("analyzer: %s: %v", name, err)
		}
		rules = append(rules, r)
	case yamlSeq:
		for _, item := range root.items {
			r, err := parseRule(item, name)
			if err != nil {
				return nil, fmt.Errorf("analyzer: %s: %v", name, err)
			}
			rules = append(rules, r)
		}
	default:
		return nil, fmt.Errorf("analyzer: %s: 顶层必须是规则 map 或规则列表", name)
	}
	// 检查单文件内 rule_id 重复
	seen := make(map[string]bool, len(rules))
	for _, r := range rules {
		if seen[r.RuleID] {
			return nil, fmt.Errorf("analyzer: %s: 重复 rule_id: %s", name, r.RuleID)
		}
		seen[r.RuleID] = true
	}
	return rules, nil
}
