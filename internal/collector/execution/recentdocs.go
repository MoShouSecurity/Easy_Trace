package execution

import (
	"fmt"
	"strconv"
	"strings"
)

// recentDocsPath 是 RecentDocs 键相对用户配置单元的路径。
// 只读根键下的数字值（最近打开的文件）；Folder 子键（最近打开的目录）暂不展开。
const recentDocsPath = `Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`

// readRecentDocs 读取当前用户与已加载用户的 RecentDocs 文件名。
//
// 值名是 MRU 序号（0、1、2…），值数据为二进制：通常是 UTF-16LE 文件名，
// 部分版本前面带 4 字节头；MRUListEx 不读（顺序信息不是执行时间）。
//
// RecentDocs 只证明"最近打开过"，不填 last_run_time。
func (c *Collector) readRecentDocs() ([]rawEntry, []string, error) {
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
		keyPath := joinReg(hive.base, recentDocsPath)
		h, err := openKey(hive.root, keyPath)
		if err != nil {
			if isAccessDenied(err) {
				debugf("recentdocs_denied user=%s: %v", hive.user, err)
			} else if !isNotFound(err) {
				notes = append(notes, fmt.Sprintf("RecentDocs（%s）：%v", hive.user, err))
			}
			continue
		}
		vals, err := enumValues(h)
		closeKey(h)
		if err != nil {
			notes = append(notes, fmt.Sprintf("RecentDocs（%s）枚举值失败：%v", hive.user, err))
			continue
		}
		for _, v := range vals {
			if _, err := strconv.Atoi(v.name); err != nil {
				continue // MRUListEx 等非数字值
			}
			name := firstUTF16String(v.data)
			if name == "" {
				continue
			}
			idKey := hive.user + "\x00" + strings.ToLower(name)
			if seen[idKey] {
				continue
			}
			seen[idKey] = true
			if len(entries) >= maxRecentDocsEntries {
				capHit = true
				break
			}
			entries = append(entries, rawEntry{
				source: "recentdocs",
				idKey:  idKey,
				user:   hive.user,
				name:   name,
			})
		}
	}
	if capHit {
		notes = append(notes, fmt.Sprintf("RecentDocs 条目超过上限 %d，结果不完整", maxRecentDocsEntries))
	}
	debugf("recentdocs entries=%d", len(entries))
	return entries, notes, nil
}
