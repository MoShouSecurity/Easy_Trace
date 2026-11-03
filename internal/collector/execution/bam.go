package execution

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// BAM/DAM 键路径（相对 HKLM）。
//
// Windows 10/11 使用 bam|dam\State\UserSettings\<SID>；旧版本曾用 bam\UserSettings\<SID>。
// 两条路径都尝试，按 SID + 路径去重。
var bamPaths = []struct {
	source string
	path   string
}{
	{source: "bam", path: `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings`},
	{source: "dam", path: `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings`},
	{source: "bam", path: `SYSTEM\CurrentControlSet\Services\bam\UserSettings`},
}

// readBAM 读取 BAM（Background Activity Moderator）与 DAM（Desktop Activity Moderator）。
//
// 每个值名是可执行文件路径，值数据里的 FILETIME 表示最近一次执行/活动时间。
// 注意：BAM/DAM 键通常只有管理员或 SYSTEM 可读；普通用户下读不到是预期权限边界，
// 只写 debug 日志，不把整个 execution 模块判为失败。
func (c *Collector) readBAM() ([]rawEntry, []string, error) {
	var notes []string
	entries := make([]rawEntry, 0, 64)
	seen := make(map[string]bool)
	capHit := false

	for _, bp := range bamPaths {
		if capHit {
			break
		}
		h, err := openKey(hkeyLocalMachine, bp.path)
		if err != nil {
			if isAccessDenied(err) {
				debugf("%s_denied path=%s: %v", bp.source, bp.path, err)
			} else if !isNotFound(err) {
				notes = append(notes, fmt.Sprintf("%s（%s）：%v", bp.source, bp.path, err))
			}
			continue
		}
		sids, err := enumSubKeys(h)
		closeKey(h)
		if err != nil {
			notes = append(notes, fmt.Sprintf("%s 枚举 SID 失败（%s）：%v", bp.source, bp.path, err))
			continue
		}
		sort.Strings(sids)

		for _, sid := range sids {
			if capHit {
				break
			}
			keyPath := bp.path + `\` + sid
			sh, err := openKey(hkeyLocalMachine, keyPath)
			if err != nil {
				if isAccessDenied(err) {
					debugf("%s_denied sid=%s: %v", bp.source, sid, err)
				} else if !isNotFound(err) {
					notes = append(notes, fmt.Sprintf("%s 打开 %s 失败：%v", bp.source, sid, err))
				}
				continue
			}
			vals, err := enumValues(sh)
			closeKey(sh)
			if err != nil {
				notes = append(notes, fmt.Sprintf("%s 枚举 %s 值失败：%v", bp.source, sid, err))
				continue
			}
			for _, v := range vals {
				path := strings.TrimSpace(v.name)
				if !looksLikePath(path) {
					// UserSettings 下偶尔有 Version 之类的非路径值，跳过。
					continue
				}
				idKey := sid + "\x00" + strings.ToLower(path)
				if seen[idKey] {
					continue
				}
				seen[idKey] = true
				if len(entries) >= maxBAMEntries {
					capHit = true
					break
				}
				e := rawEntry{
					source: bp.source,
					idKey:  idKey,
					user:   sid,
					name:   filepath.Base(path),
					path:   path,
				}
				// 常见布局：+8 FILETIME（24 字节项）；旧布局在 +0。
				if t, ok := filetimeAt(v.data, 8); ok {
					e.lastRun = t
				} else if t, ok := filetimeAt(v.data, 0); ok {
					e.lastRun = t
				}
				entries = append(entries, e)
			}
		}
	}
	if capHit {
		notes = append(notes, fmt.Sprintf("BAM/DAM 条目超过上限 %d，结果不完整", maxBAMEntries))
	}
	debugf("bam_dam entries=%d", len(entries))
	return entries, notes, nil
}

// looksLikePath 判断值名是否像文件路径（BAM 值名可能是设备路径或盘符路径）。
func looksLikePath(s string) bool {
	if s == "" || len(s) > 4096 {
		return false
	}
	return strings.ContainsAny(s, `\/:`)
}
