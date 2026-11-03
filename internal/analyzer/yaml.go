package analyzer

import (
	"fmt"
	"strconv"
	"strings"
)

// yamlNode 是极简 YAML 子集解析结果：map / list / scalar。
// 只覆盖规则文件所需结构（block mapping、block sequence、注释、引号/裸标量），
// 不实现 flow 语法、锚点、多行块标量等（规则文件不使用）。
type yamlNode struct {
	kind  int // yamlMap / yamlSeq / yamlScalar
	kv    []yamlKV
	items []*yamlNode
	str   string
}

type yamlKV struct {
	key string
	val *yamlNode
}

const (
	yamlMap = iota
	yamlSeq
	yamlScalar
)

// maxYAMLDepth 限制规则文件的嵌套层级，避免不受信任的本地 YAML 触发深递归。
const maxYAMLDepth = 64

// yamlParse 解析规则 YAML（缩进 2 空格，不支持 tab 缩进）。
//
// 严格模式：多文档分隔符（--- / ...）、tab 缩进、重复 key、解析后仍剩下的行
// 都直接报错。规则文件“只加载了一部分却成功”比解析失败危险得多——操作者会以为
// 整套规则都生效了。
func yamlParse(src string) (*yamlNode, error) {
	lines := strings.Split(src, "\n")
	// 去掉首行 BOM
	if len(lines) > 0 {
		lines[0] = strings.TrimPrefix(lines[0], "\ufeff")
	}
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "---" || strings.HasPrefix(trimmed, "--- ") {
			return nil, fmt.Errorf("yaml: 第 %d 行: 不支持多文档分隔符 ---（一个文件只放一个文档；多条规则请用“- rule_id:”列表或拆成多个文件）", i+1)
		}
		if trimmed == "..." || strings.HasPrefix(trimmed, "... ") {
			return nil, fmt.Errorf("yaml: 第 %d 行: 不支持文档结束符 ...（一个文件只放一个文档）", i+1)
		}
		if hasTabIndent(line) {
			return nil, fmt.Errorf("yaml: 第 %d 行使用 tab 缩进（只支持空格）", i+1)
		}
	}
	p := &yamlParser{lines: lines}
	node, err := p.parseBlock(0, "")
	if err != nil {
		return nil, err
	}
	if node == nil {
		return nil, fmt.Errorf("yaml: 文件为空")
	}
	// 解析结束后仍有非空、非注释行 ⇒ 内容没有被完整消费（例如 map 后跟 sequence、
	// 缩进突然变浅）。旧实现直接忽略，等于“只加载了一部分规则却报成功”。
	for p.pos < len(p.lines) {
		trimmed := strings.TrimSpace(p.lines[p.pos])
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			p.pos++
			continue
		}
		return nil, fmt.Errorf("yaml: 第 %d 行无法解析（多余内容或缩进不一致）: %s", p.pos+1, trimmed)
	}
	return node, nil
}

// hasTabIndent 判断行首缩进是否含 tab（tab 宽度依赖编辑器，不能用来表达层级）。
func hasTabIndent(line string) bool {
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case ' ':
			continue
		case '\t':
			return true
		default:
			return false
		}
	}
	return false
}

type yamlParser struct {
	lines []string
	pos   int
	depth int
}

// parseBlock 解析从当前行开始的同级块（缩进 ind 的 mapping 或 sequence）。
// parentKey 用于错误信息（"conditions" 下的项）。
func (p *yamlParser) parseBlock(ind int, parentKey string) (*yamlNode, error) {
	if p.depth >= maxYAMLDepth {
		return nil, fmt.Errorf("yaml: 嵌套层级超过上限 %d", maxYAMLDepth)
	}
	p.depth++
	defer func() { p.depth-- }()

	// 跳过空行与注释
	for p.pos < len(p.lines) {
		line := p.lines[p.pos]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			p.pos++
			continue
		}
		break
	}
	if p.pos >= len(p.lines) {
		return nil, nil
	}

	lineInd := indentOf(p.lines[p.pos])
	if lineInd < ind {
		return nil, nil // 返回上一层
	}
	if lineInd > ind {
		return nil, fmt.Errorf("yaml: 第 %d 行缩进异常（期望缩进 %d，实际 %d）: %s", p.pos+1, ind, lineInd, p.lines[p.pos])
	}

	// 判定本块类型：mapping（key: value）或 sequence（- item）
	trimmed := strings.TrimSpace(p.lines[p.pos])
	if strings.HasPrefix(trimmed, "- ") || trimmed == "-" {
		return p.parseSeq(ind)
	}
	return p.parseMap(ind)
}

// parseMap 解析 mapping 块（同缩进连续 key: value 行）。
func (p *yamlParser) parseMap(ind int) (*yamlNode, error) {
	node := &yamlNode{kind: yamlMap}
	seen := map[string]bool{}
	for p.pos < len(p.lines) {
		line := p.lines[p.pos]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			p.pos++
			continue
		}
		lineInd := indentOf(line)
		if lineInd < ind {
			break
		}
		if lineInd > ind {
			return nil, fmt.Errorf("yaml: 第 %d 行缩进异常: %s", p.pos+1, line)
		}
		if strings.HasPrefix(trimmed, "- ") || trimmed == "-" {
			break // 块类型切换（属于父级 sequence 项）
		}

		// key: value 或 key:
		colon := findKeyColon(trimmed)
		if colon < 0 {
			return nil, fmt.Errorf("yaml: 第 %d 行不是合法的 key: value 格式: %s", p.pos+1, line)
		}
		key := unquoteScalar(strings.TrimSpace(trimmed[:colon]))
		if seen[key] {
			return nil, fmt.Errorf("yaml: 第 %d 行: 重复 key %q（同一 mapping 中每个 key 只能出现一次）", p.pos+1, key)
		}
		seen[key] = true
		rest := strings.TrimSpace(trimmed[colon+1:])

		if rest == "" {
			// 嵌套块（下一行更深缩进）
			p.pos++
			child, err := p.parseBlock(ind+2, key)
			if err != nil {
				return nil, err
			}
			if child == nil {
				// 允许空值（null）
				node.kv = append(node.kv, yamlKV{key: key, val: &yamlNode{kind: yamlScalar, str: ""}})
				continue
			}
			node.kv = append(node.kv, yamlKV{key: key, val: child})
			continue
		}

		// 内联值：标量或内联 list（- a - b，规则文件不用，但支持单个 - 后的标量序列）
		if strings.HasPrefix(rest, "-") && !strings.HasPrefix(rest, "- ") {
			return nil, fmt.Errorf("yaml: 第 %d 行内联列表不支持（请用块序列）: %s", p.pos+1, line)
		}
		if strings.HasPrefix(rest, "- ") {
			// 内联序列 ["a","b"] 风格仅支持 - a - b 形式（实际规则文件用块序列，这里兜底）
			node.kv = append(node.kv, yamlKV{key: key, val: parseInlineSeq(rest)})
			p.pos++
			continue
		}

		node.kv = append(node.kv, yamlKV{key: key, val: &yamlNode{kind: yamlScalar, str: unquoteScalar(rest)}})
		p.pos++
	}
	return node, nil
}

// parseSeq 解析 sequence 块（同缩进连续 "- item" 行）。
func (p *yamlParser) parseSeq(ind int) (*yamlNode, error) {
	node := &yamlNode{kind: yamlSeq}
	for p.pos < len(p.lines) {
		line := p.lines[p.pos]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			p.pos++
			continue
		}
		lineInd := indentOf(line)
		if lineInd < ind {
			break
		}
		if lineInd > ind {
			return nil, fmt.Errorf("yaml: 第 %d 行缩进异常: %s", p.pos+1, line)
		}
		if !(strings.HasPrefix(trimmed, "- ") || trimmed == "-") {
			break
		}
		item := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
		if item == "" {
			// "-" 后是嵌套块
			p.pos++
			child, err := p.parseBlock(ind+2, "list-item")
			if err != nil {
				return nil, err
			}
			node.items = append(node.items, child)
			continue
		}
		// 标量项（含内联 key: value 的单行 map）
		if isInlineKV(item) {
			child, err := p.parseInlineMap(item)
			if err != nil {
				return nil, err
			}
			node.items = append(node.items, child)
			continue
		}
		node.items = append(node.items, &yamlNode{kind: yamlScalar, str: unquoteScalar(item)})
		p.pos++
	}
	return node, nil
}

// parseInlineMap 解析序列项内联的 "key: value" 起始行及后续同缩进键。
// 例如 "- rule_id: r1"（后续 title/conditions 键缩进 = 当前行缩进+2）。
func (p *yamlParser) parseInlineMap(first string) (*yamlNode, error) {
	node := &yamlNode{kind: yamlMap}
	// map 键的基础缩进 = 当前行缩进 + 2（"- key: v" 中键从列 ind+2 开始）
	baseInd := indentOf(p.lines[p.pos]) + 2
	colon := findKeyColon(first)
	if colon < 0 {
		return nil, fmt.Errorf("yaml: 序列项内联 map 格式错误: %s", first)
	}
	key := unquoteScalar(strings.TrimSpace(first[:colon]))
	seen := map[string]bool{key: true}
	rest := strings.TrimSpace(first[colon+1:])
	kv := yamlKV{key: key}
	if rest != "" {
		kv.val = &yamlNode{kind: yamlScalar, str: unquoteScalar(rest)}
		p.pos++
	} else {
		// 嵌套块：接下来更深缩进的行属于该项
		p.pos++
		child, err := p.parseBlock(baseInd, key)
		if err != nil {
			return nil, err
		}
		kv.val = child
	}
	node.kv = append(node.kv, kv)
	// 后续同缩进（>= baseInd）的 key 行也属于该项
	for p.pos < len(p.lines) {
		line := p.lines[p.pos]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			p.pos++
			continue
		}
		lineInd := indentOf(line)
		if lineInd < baseInd {
			break // 回到父级
		}
		// 同缩进 key: 行加入当前 map（嵌套键已由 parseBlock 消费）
		colon2 := findKeyColon(trimmed)
		if colon2 < 0 {
			break
		}
		key2 := unquoteScalar(strings.TrimSpace(trimmed[:colon2]))
		if seen[key2] {
			return nil, fmt.Errorf("yaml: 第 %d 行: 重复 key %q（同一 mapping 中每个 key 只能出现一次）", p.pos+1, key2)
		}
		seen[key2] = true
		rest2 := strings.TrimSpace(trimmed[colon2+1:])
		if rest2 == "" {
			p.pos++
			child2, err := p.parseBlock(lineInd+2, key2)
			if err != nil {
				return nil, err
			}
			node.kv = append(node.kv, yamlKV{key: key2, val: child2})
			continue
		}
		node.kv = append(node.kv, yamlKV{key: key2, val: &yamlNode{kind: yamlScalar, str: unquoteScalar(rest2)}})
		p.pos++
	}
	return node, nil
}

// parseInlineSeq 解析 "- a - b" 风格内联序列（兜底，规则文件用块序列）。
func parseInlineSeq(rest string) *yamlNode {
	node := &yamlNode{kind: yamlSeq}
	for _, part := range strings.Split(rest, "- ") {
		part = strings.TrimSpace(part)
		if part != "" {
			node.items = append(node.items, &yamlNode{kind: yamlScalar, str: unquoteScalar(part)})
		}
	}
	return node
}

// findKeyColon 找到 key 与 value 之间的冒号（忽略引号内的冒号）。
func findKeyColon(s string) int {
	inSingle, inDouble := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case ':':
			if !inSingle && !inDouble {
				return i
			}
		}
	}
	return -1
}

// isInlineKV 判断是否为 "key: value" 单行。
func isInlineKV(s string) bool {
	colon := findKeyColon(s)
	if colon < 0 {
		return false
	}
	key := strings.TrimSpace(s[:colon])
	return key != "" && !strings.HasPrefix(key, "-")
}

// unquoteScalar 解析标量：双引号（含 \n \t \\ \" 转义）、单引号、裸标量、注释剥离。
func unquoteScalar(s string) string {
	s = strings.TrimSpace(s)
	// 剥离行尾注释（# 前有空格时；URL/路径含 # 例外——规则值无 #，按空格规则）
	if idx := strings.Index(s, " #"); idx >= 0 {
		s = strings.TrimSpace(s[:idx])
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		inner := s[1 : len(s)-1]
		var b strings.Builder
		for i := 0; i < len(inner); i++ {
			c := inner[i]
			if c == '\\' && i+1 < len(inner) {
				i++
				switch inner[i] {
				case 'n':
					b.WriteByte('\n')
				case 't':
					b.WriteByte('\t')
				case '\\':
					b.WriteByte('\\')
				case '"':
					b.WriteByte('"')
				case 'r':
					b.WriteByte('\r')
				default:
					b.WriteByte('\\')
					b.WriteByte(inner[i])
				}
				continue
			}
			b.WriteByte(c)
		}
		return b.String()
	}
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return s[1 : len(s)-1]
	}
	// 裸标量：布尔/数字保持字符串
	if s == "null" || s == "~" {
		return ""
	}
	return s
}

// indentOf 计算行缩进（空格数；tab 视为错误由调用方处理）。
func indentOf(line string) int {
	n := 0
	for n < len(line) && line[n] == ' ' {
		n++
	}
	return n
}

// --- 便捷访问器 ---

// str 返回标量字符串。
func (n *yamlNode) strVal() string {
	if n == nil {
		return ""
	}
	return n.str
}

// get 获取 mapping 的 key 值（标量）。
func (n *yamlNode) get(key string) *yamlNode {
	if n == nil || n.kind != yamlMap {
		return nil
	}
	for _, kv := range n.kv {
		if kv.key == key {
			return kv.val
		}
	}
	return nil
}

// listStrings 将序列节点转为字符串列表。
func (n *yamlNode) listStrings() ([]string, error) {
	if n == nil {
		return nil, nil
	}
	if n.kind == yamlScalar {
		// 兼容单值（写成标量而非列表）
		return []string{n.str}, nil
	}
	if n.kind != yamlSeq {
		return nil, fmt.Errorf("yaml: 期望列表，实际为 %s", kindName(n.kind))
	}
	out := make([]string, 0, len(n.items))
	for _, it := range n.items {
		if it.kind != yamlScalar {
			return nil, fmt.Errorf("yaml: 列表项必须为标量")
		}
		out = append(out, it.str)
	}
	return out, nil
}

// asInt 尝试按整数读取（供 strconv 等使用）。
func (n *yamlNode) asInt() (int, error) {
	return strconv.Atoi(strings.TrimSpace(n.str))
}

func kindName(k int) string {
	switch k {
	case yamlMap:
		return "map"
	case yamlSeq:
		return "list"
	default:
		return "scalar"
	}
}
