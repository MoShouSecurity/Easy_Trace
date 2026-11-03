package execution

import (
	"encoding/binary"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// decodeUTF16Z 解码 UTF-16LE 字节串，遇到 NUL 码元停止。
func decodeUTF16Z(b []byte) string {
	units := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u := binary.LittleEndian.Uint16(b[i : i+2])
		if u == 0 {
			break
		}
		units = append(units, u)
	}
	return string(utf16.Decode(units))
}

// firstUTF16String 在二进制值里找第一段可打印的 UTF-16LE 字符串。
//
// RecentDocs 的值通常以 UTF-16LE 文件名开头，但部分 Windows 版本会在前面
// 放 4 字节头。这里按 2 字节步长扫描前 64 字节，返回第一段长度 >= 2 的
// 可打印字符串；找不到返回空串（不猜、不把二进制当文件名）。
func firstUTF16String(b []byte) string {
	limit := len(b)
	if limit > 64 {
		limit = 64
	}
	for start := 0; start+4 <= limit; start += 2 {
		s := decodeUTF16Z(b[start:])
		if utf8.RuneCountInString(s) < 2 || !printableString(s) {
			continue
		}
		return s
	}
	return ""
}

// printableString 判断字符串是否由可打印字符组成（拒绝控制字符和替换符）。
func printableString(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		// 控制字符、替换符、UTF-16 非字符（0xFFFE/0xFFFF）都不是文件名的一部分。
		if r < 0x20 || r == 0x7f || r == utf8.RuneError || r == 0xFFFE || r == 0xFFFF {
			return false
		}
	}
	return true
}

// ansiZ 截断到 NUL 并去掉首尾空白。
//
// LinkInfo / StringData 的非 Unicode 字符串使用系统 ANSI 码页（中文系统为 GBK）。
// 标准库没有 GBK 解码器，这里按原始字节保留；能按 UTF-8 解码时就是正常文本，
// 否则由上层如实记录（不引入第三方依赖）。
func ansiZ(b []byte) string {
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		b = b[:i]
	}
	return strings.TrimSpace(string(b))
}
