// Package cmdline 从 Windows 命令行中切分「可执行文件」与「参数」。
//
// 为什么需要单独实现：`strings.Split(cmd, " ")[0]` 会把未加引号的
// `C:\Program Files\Vendor\app.exe /quiet` 截成 `C:\Program`，而把**整条**
// 命令行当成可执行文件路径又会让参数里的线索（例如 rundll32 加载的 DLL 路径）
// 冒充目标文件路径——两者都会造成错误的检测结论与错误的证据归属。
//
// 本包只做语法层面的切分，不访问文件系统、不展开环境变量、不执行任何东西。
package cmdline

import "strings"

// executableSuffixes 是「这个词很可能就是可执行文件本体」的扩展名。
//
// 只用于**未加引号且路径含空格**时判断吸收到哪个 token 为止；不会把参数里的
// .dll/.ps1 之类误当成 exe，因为只有在首 token 呈现路径形态时才启用吸收逻辑，
// 且遇到开关（-x / /x）立即停止。
var executableSuffixes = []string{
	".exe", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse",
	".wsf", ".wsh", ".msi", ".msp", ".scr", ".pif", ".cpl", ".dll", ".sys",
	".lnk", ".hta",
}

// maxJoinTokens 限制吸收 token 的数量，避免畸形输入把整条命令行当成 exe。
const maxJoinTokens = 16

// Split 把命令行拆成可执行文件部分与参数部分。
//
// 规则（按优先级）：
//  1. 以引号开头：引号内为可执行文件（Windows 的 CreateProcess 语义），其余为参数。
//     引号不配对时按「带空格路径」继续处理。
//  2. 首 token 不呈路径形态（无盘符/分隔符/环境变量前缀），例如 `powershell -enc ...`：
//     首 token 即 exe，其余为参数。
//  3. 首 token 呈路径形态但还没有可执行扩展名（`C:\Program`）：继续吸收后续 token，
//     直到出现可执行扩展名；遇到开关（`-` / `/` 开头）或达到上限则停止。
//
// 返回的 exe / args 已去除首尾空白；args 为空表示没有参数。
func Split(cmd string) (exe, args string) {
	s := strings.TrimSpace(cmd)
	if s == "" {
		return "", ""
	}

	if strings.HasPrefix(s, `"`) {
		if end := strings.IndexByte(s[1:], '"'); end >= 0 {
			return s[1 : 1+end], strings.TrimSpace(s[1+end+1:])
		}
		// 引号不配对：去掉开引号，按未加引号处理（宁可少吸收，也不把参数当路径）。
		s = strings.TrimSpace(s[1:])
		if s == "" {
			return "", ""
		}
	}

	first, rest := nextToken(s)
	if !looksLikePath(first) || hasExecutableSuffix(first) {
		return first, rest
	}

	cur := first
	for i := 0; i < maxJoinTokens && rest != ""; i++ {
		tok, after := nextToken(rest)
		if strings.HasPrefix(tok, "-") || strings.HasPrefix(tok, "/") {
			break
		}
		cur += " " + tok
		rest = after
		if hasExecutableSuffix(tok) {
			break
		}
	}
	return cur, rest
}

// nextToken 取出第一个空白分隔的 token 与剩余部分（已去空白）。
func nextToken(s string) (string, string) {
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i], strings.TrimSpace(s[i:])
	}
	return s, ""
}

// looksLikePath 判断 token 是否可能是一个（尚不完整的）Windows 路径。
func looksLikePath(tok string) bool {
	if tok == "" {
		return false
	}
	if strings.ContainsAny(tok, `\/:`) || strings.HasPrefix(tok, "%") || strings.HasPrefix(tok, `.`) {
		return true
	}
	return false
}

// hasExecutableSuffix 判断 token 是否以已知可执行扩展名结尾（大小写不敏感，
// 允许尾随逗号/引号等命令行常见分隔符）。
func hasExecutableSuffix(tok string) bool {
	t := strings.ToLower(strings.TrimRight(tok, `",`))
	for _, ext := range executableSuffixes {
		if strings.HasSuffix(t, ext) {
			return true
		}
	}
	return false
}
