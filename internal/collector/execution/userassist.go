package execution

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

// userAssistPath 是 UserAssist 键相对用户配置单元（HKCU / HKU\<SID>）的路径。
const userAssistPath = `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`

// readUserAssist 读取当前用户与已加载用户的 UserAssist。
//
// 结构：UserAssist\{GUID}\Count，值名是 ROT13 编码的痕迹名。
// 数据布局（Windows 7+ 72 字节 / XP 16 字节）：
//
//	+4  run count (uint32)
//	+60 last run FILETIME（72 字节格式；16 字节格式在 +8）
//
// 只读取，不写入；UEME_CTLSESSION 是会话标记而不是程序痕迹，跳过。
func (c *Collector) readUserAssist() ([]rawEntry, []string, error) {
	var notes []string
	entries := make([]rawEntry, 0, 64)
	seen := make(map[string]bool)
	capHit := false

	hives, hiveNotes := userHives()
	notes = append(notes, hiveNotes...)

	for _, hive := range hives {
		if capHit {
			break
		}
		keyPath := joinReg(hive.base, userAssistPath)
		h, err := openKey(hive.root, keyPath)
		if err != nil {
			if !isNotFound(err) && !isAccessDenied(err) {
				notes = append(notes, fmt.Sprintf("UserAssist（%s）：%v", hive.user, err))
			} else if isAccessDenied(err) {
				debugf("userassist_denied user=%s: %v", hive.user, err)
			}
			continue
		}
		guids, err := enumSubKeys(h)
		closeKey(h)
		if err != nil {
			notes = append(notes, fmt.Sprintf("UserAssist（%s）枚举子键失败：%v", hive.user, err))
			continue
		}
		sort.Strings(guids)

		for _, guid := range guids {
			if capHit {
				break
			}
			countPath := keyPath + `\` + guid + `\Count`
			ch, err := openKey(hive.root, countPath)
			if err != nil {
				if !isNotFound(err) && !isAccessDenied(err) {
					notes = append(notes, fmt.Sprintf("UserAssist（%s）打开 %s 失败：%v", hive.user, guid, err))
				}
				continue
			}
			vals, err := enumValues(ch)
			closeKey(ch)
			if err != nil {
				notes = append(notes, fmt.Sprintf("UserAssist（%s）枚举 %s 值失败：%v", hive.user, guid, err))
				continue
			}
			for _, v := range vals {
				name := stripGUIDPrefix(rot13(v.name))
				if name == "" || strings.EqualFold(name, "UEME_CTLSESSION") {
					continue
				}
				idKey := hive.user + "\x00" + name
				if seen[idKey] {
					continue
				}
				seen[idKey] = true
				if len(entries) >= maxUserAssistEntries {
					capHit = true
					break
				}
				e := rawEntry{
					source: "userassist",
					idKey:  idKey,
					user:   hive.user,
					name:   name,
				}
				if len(v.data) >= 8 {
					e.runCount = u32ptr(binary.LittleEndian.Uint32(v.data[4:8]))
				}
				// 72 字节格式的时间在 +60；XP/旧格式在 +8。先试 +60，
				// 无效再回退 +8——不用文件写入时间顶替执行时间。
				if t, ok := filetimeAt(v.data, 60); ok {
					e.lastRun = t
				} else if t, ok := filetimeAt(v.data, 8); ok {
					e.lastRun = t
				}
				entries = append(entries, e)
			}
		}
	}
	if capHit {
		notes = append(notes, fmt.Sprintf("UserAssist 条目超过上限 %d，结果不完整", maxUserAssistEntries))
	}
	debugf("userassist entries=%d", len(entries))
	return entries, notes, nil
}

// rot13 解码 UserAssist 值名（只转字母，其它字符原样保留）。
func rot13(s string) string {
	b := []byte(s)
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z':
			b[i] = 'a' + (c-'a'+13)%26
		case c >= 'A' && c <= 'Z':
			b[i] = 'A' + (c-'A'+13)%26
		}
	}
	return string(b)
}

// stripGUIDPrefix 去掉形如 `{GUID}\` 的前缀（部分 UserAssist 值名带该前缀）。
func stripGUIDPrefix(s string) string {
	if strings.HasPrefix(s, "{") {
		if i := strings.Index(s, "}"); i > 0 && i+1 < len(s) && s[i+1] == '\\' {
			return s[i+2:]
		}
	}
	return s
}
