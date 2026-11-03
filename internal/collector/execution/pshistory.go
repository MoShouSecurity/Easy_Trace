package execution

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// readPSHistory 读取所有可访问用户的 PSReadLine 命令历史。
//
// 每行是一条命令痕迹；按行去重，occurrences 记录出现次数。历史文件是追加写，
// 超过 maxPSHistoryBytes 时只读末尾一段（最近的命令在尾部）。
//
// 只填 last_write_time（文件自身写入时间），**不填 last_run_time**：历史文件
// 写入时间不是逐条命令的执行时间。
func (c *Collector) readPSHistory() ([]rawEntry, []string, error) {
	profiles, notes := userProfiles()
	entries := make([]rawEntry, 0, 128)
	seenFile := make(map[string]bool)
	total := 0
	capHit := false

	for _, p := range profiles {
		if capHit {
			break
		}
		for _, path := range psHistoryPaths(p) {
			if capHit {
				break
			}
			key := strings.ToLower(filepath.Clean(path))
			if seenFile[key] {
				continue
			}
			seenFile[key] = true

			es, fileNotes, err := readOnePSHistory(p, path)
			notes = append(notes, fileNotes...)
			if err != nil {
				if os.IsNotExist(err) {
					continue
				}
				if os.IsPermission(err) {
					debugf("pshistory_denied path=%s: %v", path, err)
					continue
				}
				notes = append(notes, fmt.Sprintf("PowerShell 历史（%s）：%v", path, err))
				continue
			}
			for _, e := range es {
				if total >= maxPSHistoryEntries {
					capHit = true
					break
				}
				entries = append(entries, e)
				total++
			}
		}
	}
	if capHit {
		notes = append(notes, fmt.Sprintf("PowerShell 历史条目超过上限 %d，结果不完整", maxPSHistoryEntries))
	}
	debugf("pshistory entries=%d", len(entries))
	return entries, notes, nil
}

// readOnePSHistory 读取单个历史文件并去重。
func readOnePSHistory(p userProfile, path string) ([]rawEntry, []string, error) {
	var notes []string
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if fi.Size() > maxPSHistoryBytes {
		if _, err := f.Seek(fi.Size()-maxPSHistoryBytes, io.SeekStart); err != nil {
			return nil, nil, err
		}
		notes = append(notes, fmt.Sprintf("PowerShell 历史 %s 超过 %d 字节，只读取末尾部分", path, maxPSHistoryBytes))
	}

	counts := make(map[string]uint32)
	order := make([]string, 0, 64)
	fileTruncated := false

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(strings.TrimPrefix(scanner.Text(), string(rune(0xFEFF))))
		if line == "" {
			continue
		}
		line = truncateRunes(line, maxPSHistoryLine)
		if _, ok := counts[line]; ok {
			counts[line]++
			continue
		}
		if len(order) >= maxPSHistoryPerFile {
			fileTruncated = true
			continue
		}
		counts[line] = 1
		order = append(order, line)
	}
	if err := scanner.Err(); err != nil {
		notes = append(notes, fmt.Sprintf("读取 PowerShell 历史 %s 中断：%v", path, err))
	}
	if fileTruncated {
		notes = append(notes, fmt.Sprintf("PowerShell 历史 %s 的去重条目超过上限 %d，结果不完整", path, maxPSHistoryPerFile))
	}

	sort.Strings(order)
	mtime := fi.ModTime()
	out := make([]rawEntry, 0, len(order))
	for _, line := range order {
		n := counts[line]
		out = append(out, rawEntry{
			source:      "pshistory",
			idKey:       strings.ToLower(filepath.Clean(path)) + "\x00" + line,
			user:        p.name,
			path:        path,
			command:     line,
			lastWrite:   mtime,
			occurrences: &n,
		})
	}
	return out, notes, nil
}
