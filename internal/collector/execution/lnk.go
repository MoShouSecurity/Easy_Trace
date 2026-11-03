package execution

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// maxLNKFileBytes 是单个 .lnk 的解析上限；正常 .lnk 只有几 KB。
const maxLNKFileBytes = 1 << 20

// MS-SHLLINK 头常量。
var (
	lnkHeaderSize = 0x4C
	lnkCLSID      = []byte{
		0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
	}
)

// LinkFlags 位（只使用本模块需要的部分）。
const (
	lnkHasLinkInfo     = 0x00000002
	lnkHasName         = 0x00000004
	lnkHasRelativePath = 0x00000008
	lnkHasWorkingDir   = 0x00000010
	lnkHasArguments    = 0x00000020
	lnkIsUnicode       = 0x00000080
	lnkForceNoLinkInfo = 0x00000100
)

// lnkInfo 是从 .lnk 中提取的目标信息。
type lnkInfo struct {
	target     string // LinkInfo 的本地/网络目标
	relative   string // StringData::RelativePath
	workingDir string
	arguments  string
}

// readLNK 读取各用户 Recent 目录下的 .lnk 目标路径。
//
// .lnk 的 last_write_time 是快捷方式文件自身的写入时间，**不是目标程序的执行时间**，
// 因此不填 last_run_time。解析失败时仍输出实体（保留文件名与写入时间），并计数上报。
func (c *Collector) readLNK() ([]rawEntry, []string, error) {
	profiles, notes := userProfiles()
	entries := make([]rawEntry, 0, 64)
	seen := make(map[string]bool)
	capHit := false
	parseFailed := 0

	for _, p := range profiles {
		if capHit {
			break
		}
		for _, dir := range recentDirs(p) {
			if capHit {
				break
			}
			des, err := os.ReadDir(dir)
			if err != nil {
				if os.IsNotExist(err) {
					continue
				}
				if os.IsPermission(err) {
					debugf("recent_dir_denied dir=%s: %v", dir, err)
					continue
				}
				notes = append(notes, fmt.Sprintf("读取 Recent 目录 %s 失败：%v", dir, err))
				continue
			}
			for _, de := range des {
				if de.IsDir() || !strings.EqualFold(filepath.Ext(de.Name()), ".lnk") {
					continue
				}
				path := filepath.Join(dir, de.Name())
				key := strings.ToLower(filepath.Clean(path))
				if seen[key] {
					continue
				}
				seen[key] = true
				if len(entries) >= maxLNKEntries {
					capHit = true
					break
				}
				info, err := de.Info()
				if err != nil {
					notes = append(notes, fmt.Sprintf("读取 .lnk 元数据失败（%s）：%v", path, err))
					continue
				}
				base := strings.TrimSuffix(de.Name(), filepath.Ext(de.Name()))
				e := rawEntry{
					source:    "lnk",
					idKey:     key,
					user:      p.name,
					name:      base,
					lastWrite: info.ModTime(),
				}
				if info.Size() <= maxLNKFileBytes {
					data, err := os.ReadFile(path)
					if err != nil {
						if os.IsPermission(err) {
							debugf("lnk_read_denied path=%s: %v", path, err)
						} else {
							notes = append(notes, fmt.Sprintf("读取 .lnk 失败（%s）：%v", path, err))
						}
					} else if parsed, err := parseLNK(data); err != nil {
						parseFailed++
					} else if parsed.target != "" {
						e.path = parsed.target
					} else if parsed.relative != "" {
						e.path = parsed.relative
					}
				} else {
					parseFailed++
				}
				entries = append(entries, e)
			}
		}
	}
	if parseFailed > 0 {
		notes = append(notes, fmt.Sprintf("%d 个 .lnk 未能解析目标路径，仅保留文件名与写入时间", parseFailed))
	}
	if capHit {
		notes = append(notes, fmt.Sprintf("Recent LNK 条目超过上限 %d，结果不完整", maxLNKEntries))
	}
	debugf("lnk entries=%d parse_failed=%d", len(entries), parseFailed)
	return entries, notes, nil
}

// parseLNK 解析最小 MS-SHLLINK：文件头 + LinkInfo + StringData。
//
// 不解析 IDList / ExtraData；解析失败只影响目标路径，不影响实体输出。
func parseLNK(data []byte) (lnkInfo, error) {
	var info lnkInfo
	if len(data) < lnkHeaderSize {
		return info, fmt.Errorf("文件不足 %d 字节", lnkHeaderSize)
	}
	if binary.LittleEndian.Uint32(data[0:4]) != uint32(lnkHeaderSize) {
		return info, errors.New("HeaderSize 不是 0x4C")
	}
	if !bytes.Equal(data[4:20], lnkCLSID) {
		return info, errors.New("CLSID 不匹配")
	}
	flags := binary.LittleEndian.Uint32(data[0x14:0x18])
	off := lnkHeaderSize

	if flags&lnkHasLinkInfo != 0 && flags&lnkForceNoLinkInfo == 0 {
		target, size, err := parseLinkInfo(data[off:])
		if err == nil {
			info.target = target
			off += size
		} else if size > 0 && off+size <= len(data) {
			// LinkInfo 损坏但长度可信时仍跳到 StringData，尽量拿到相对路径。
			off += size
		} else {
			return info, err
		}
	}

	isUnicode := flags&lnkIsUnicode != 0
	readString := func() (string, bool) {
		if off+2 > len(data) {
			return "", false
		}
		n := int(binary.LittleEndian.Uint16(data[off : off+2]))
		off += 2
		if isUnicode {
			if off+n*2 > len(data) {
				return "", false
			}
			s := strings.TrimSpace(decodeUTF16Z(data[off : off+n*2]))
			off += n * 2
			return s, true
		}
		if off+n > len(data) {
			return "", false
		}
		s := ansiZ(data[off : off+n])
		off += n
		return s, true
	}

	if flags&lnkHasName != 0 {
		if _, ok := readString(); !ok {
			return info, nil
		}
	}
	if flags&lnkHasRelativePath != 0 {
		if s, ok := readString(); ok {
			info.relative = s
		} else {
			return info, nil
		}
	}
	if flags&lnkHasWorkingDir != 0 {
		if s, ok := readString(); ok {
			info.workingDir = s
		} else {
			return info, nil
		}
	}
	if flags&lnkHasArguments != 0 {
		if s, ok := readString(); ok {
			info.arguments = s
		}
	}
	return info, nil
}

// parseLinkInfo 解析 LinkInfo，返回目标路径与整个 LinkInfo 的长度。
func parseLinkInfo(b []byte) (string, int, error) {
	if len(b) < 0x1C {
		return "", 0, errors.New("LinkInfo 头不足 0x1C 字节")
	}
	size := int(binary.LittleEndian.Uint32(b[0:4]))
	headerSize := int(binary.LittleEndian.Uint32(b[4:8]))
	flags := binary.LittleEndian.Uint32(b[8:12])
	if size < 0x1C || size > len(b) {
		return "", 0, fmt.Errorf("LinkInfoSize 越界（%d）", size)
	}
	if headerSize < 0x1C || headerSize > size {
		return "", size, fmt.Errorf("LinkInfoHeaderSize 非法（%d）", headerSize)
	}
	li := b[:size]
	hasUnicode := headerSize >= 0x24

	var base, suffix string
	switch {
	case flags&0x1 != 0: // VolumeIDAndLocalBasePath
		baseOff := readU32(li, 0x10)
		suffixOff := readU32(li, 0x18)
		if hasUnicode {
			if off := readU32(li, 0x1C); off > 0 {
				base = readLNKStringAt(li, off, true)
			} else {
				base = readLNKStringAt(li, baseOff, false)
			}
			if off := readU32(li, 0x20); off > 0 {
				suffix = readLNKStringAt(li, off, true)
			} else {
				suffix = readLNKStringAt(li, suffixOff, false)
			}
		} else {
			base = readLNKStringAt(li, baseOff, false)
			suffix = readLNKStringAt(li, suffixOff, false)
		}
	case flags&0x2 != 0: // CommonNetworkRelativeLinkAndPathSuffix
		cnrlOff := readU32(li, 0x14)
		suffixOff := readU32(li, 0x18)
		base = parseCommonNetworkRelativeLink(li, cnrlOff, hasUnicode)
		if hasUnicode {
			if off := readU32(li, 0x20); off > 0 {
				suffix = readLNKStringAt(li, off, true)
			} else {
				suffix = readLNKStringAt(li, suffixOff, false)
			}
		} else {
			suffix = readLNKStringAt(li, suffixOff, false)
		}
	}
	return joinLNKTarget(base, suffix), size, nil
}

// parseCommonNetworkRelativeLink 提取网络共享的 NetName。
func parseCommonNetworkRelativeLink(li []byte, off int, unicode bool) string {
	if off <= 0 || off+0x14 > len(li) {
		return ""
	}
	size := int(binary.LittleEndian.Uint32(li[off : off+4]))
	if size < 0x14 || off+size > len(li) {
		return ""
	}
	netNameOff := readU32(li, off+8)
	if unicode && size >= 0x1C {
		if uoff := readU32(li, off+20); uoff > 0 {
			if s := readLNKStringAt(li, off+uoff, true); s != "" {
				return s
			}
		}
	}
	return readLNKStringAt(li, off+netNameOff, false)
}

// readU32 读取小端 uint32；越界返回 0（调用方的字符串读取会再校验）。
func readU32(b []byte, off int) int {
	if off < 0 || off+4 > len(b) {
		return 0
	}
	return int(binary.LittleEndian.Uint32(b[off : off+4]))
}

// readLNKStringAt 读取偏移处的 NUL 结尾字符串（Unicode 或 ANSI）。
func readLNKStringAt(b []byte, off int, unicode bool) string {
	if off <= 0 || off >= len(b) {
		return ""
	}
	if unicode {
		return strings.TrimSpace(decodeUTF16Z(b[off:]))
	}
	return ansiZ(b[off:])
}

// joinLNKTarget 拼接基础路径与公共后缀，避免出现双反斜杠或漏分隔符。
func joinLNKTarget(base, suffix string) string {
	base = strings.TrimSpace(base)
	suffix = strings.TrimSpace(suffix)
	if base == "" {
		return suffix
	}
	if suffix == "" {
		return base
	}
	if strings.HasSuffix(base, `\`) || strings.HasPrefix(suffix, `\`) {
		return base + suffix
	}
	return base + `\` + suffix
}
