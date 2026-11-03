package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"easytrace/internal/integrity"
)

// VerifyPackage 校验一份内存中的证据包（文件名 → 内容）。
//
// 校验三层，任何一层失败都拒绝打包：
//  1. manifest.txt 的自校验行（覆盖清单头部 provenance 与全部行）；
//  2. 每个 kept/duplicate 条目的落盘文件存在，且内容 SHA256、字节数与清单一致；
//  3. 证据目录里没有清单未登记的额外文件。
//
// 只接受平铺的文件名（不得含路径分隔符/冒号），避免把 ADS 或目录穿越
// 当成清单条目。跳过条目不得指向实际存在的文件。
func VerifyPackage(files map[string][]byte) error {
	manifest, ok := files[ManifestName]
	if !ok {
		return fmt.Errorf("缺少证据清单 %s", ManifestName)
	}
	if err := integrity.VerifyManifestHash(manifest); err != nil {
		return fmt.Errorf("%s 校验失败: %w", ManifestName, err)
	}

	listed := make(map[string]bool)
	for i, line := range strings.Split(string(manifest), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 8 {
			return fmt.Errorf("%s 第 %d 行列数不足（应为 8 列）", ManifestName, i+1)
		}
		status := fields[3]
		name := fields[4]
		switch status {
		case StatusKept, StatusDuplicate:
			if err := validatePackageName(name); err != nil {
				return fmt.Errorf("%s 第 %d 行: %w", ManifestName, i+1, err)
			}
			data, ok := files[name]
			if !ok {
				return fmt.Errorf("清单记录的证据文件不存在: %s", name)
			}
			wantHash := strings.ToLower(strings.TrimSpace(fields[0]))
			if got := fileSHA256(data); got != wantHash {
				return fmt.Errorf("证据文件哈希与清单不一致: %s（清单 %s，实际 %s）", name, wantHash, got)
			}
			wantBytes, err := strconv.ParseInt(fields[2], 10, 64)
			if err != nil || wantBytes != int64(len(data)) {
				return fmt.Errorf("证据文件字节数与清单不一致: %s（清单 %s，实际 %d）", name, fields[2], len(data))
			}
			listed[name] = true
		default:
			// 未留存条目不应在证据目录里留下同名文件（写失败可能保留了 Name，
			// 但新证据目录是空的；若真的存在则说明包被改写/混入）。
			if name != "" {
				if _, exists := files[name]; exists {
					return fmt.Errorf("未留存条目声称的文件却存在于证据目录: %s（%s）", name, status)
				}
			}
		}
	}

	for name := range files {
		if name == ManifestName {
			continue
		}
		if !listed[name] {
			return fmt.Errorf("证据目录包含清单未记录的文件: %s", name)
		}
	}
	return nil
}

// validatePackageName 只接受证据目录下的单个文件名，拒绝目录穿越、线索/冒号
// （NTFS 备用数据流）与 Windows 非法字符。
func validatePackageName(name string) error {
	if name == "" || name == "." || name == ".." ||
		filepath.Base(name) != name || strings.ContainsAny(name, `\/:*?"<>|`) {
		return fmt.Errorf("非法证据文件名: %q", name)
	}
	for _, r := range name {
		if r < 0x20 {
			return fmt.Errorf("非法证据文件名（控制字符）: %q", name)
		}
	}
	return nil
}

func fileSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
