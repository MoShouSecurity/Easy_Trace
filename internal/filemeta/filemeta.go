// Package filemeta 提供"目标文件元数据"读取：SHA256、PE 安全目录状态、修改时间。
//
// 用途：需要判断**文件证据强度**的采集器复用（当前：persistence 深采补启动项目标文件；
// 将来：file 采集器的签名态）。
//
// 边界：只读文件本身（不执行、不加载、不读其它进程内存）。
//
// 已知重复（记账）：internal/collector/process 里有一份历史实现（PE 安全目录 +
// WinVerifyTrust + 缓存）。本轮为控制改动范围，只把 persistence 需要的三项抽到这里；
// 后续应把 process 的实现统一到本包（见 docs/开发任务清单.md）。
package filemeta

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"time"

	"easytrace/internal/safepath"
)

// PE 安全目录状态取值（与 process 包的 signatureState 语义一致）。
const (
	SigPresent = "present" // PE 安全目录存在（有数字签名目录）
	SigMissing = "missing" // PE 安全目录不存在
	SigUnknown = "unknown" // 非 PE / PE 头不可读
)

// maxPEOffsetBound 是对 e_lfanew 的防御上限（异常 PE 头不允许让我们 seek 到任意偏移）。
const maxPEOffsetBound = 1 << 20

// HashSHA256 流式计算文件 SHA256（小写十六进制）。
//
// maxBytes > 0 时只读前 maxBytes 字节并返回 truncated=true（不把大文件读穿）。
// 返回 (hash, size, truncated, err)；size 是实际读取的字节数。
func HashSHA256(path string, maxBytes int64) (string, int64, bool, error) {
	if _, err := safepath.ValidateLocalFilePath(path, "目标文件路径"); err != nil {
		return "", 0, false, err
	}
	f, err := os.Open(path)
	if err != nil {
		return "", 0, false, err
	}
	defer f.Close()

	var reader io.Reader = f
	truncated := false
	if maxBytes > 0 {
		info, err := f.Stat()
		if err == nil && info.Size() > maxBytes {
			truncated = true
			reader = io.LimitReader(f, maxBytes)
		}
	}
	h := sha256.New()
	n, err := io.Copy(h, reader)
	if err != nil {
		return "", n, truncated, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, truncated, nil
}

// SignatureState 只读 PE 头判断是否存在安全目录（**不调用 WinVerifyTrust**）。
//
// 语义提醒：missing 只表示"PE 安全目录不存在"，不等于"未签名"——catalog 签名、
// 自解压载体等都可能没有内嵌安全目录。调用方不得把 missing 叙述为"确认未签名"。
func SignatureState(path string) string {
	if _, err := safepath.ValidateLocalFilePath(path, "目标文件路径"); err != nil {
		return SigUnknown
	}
	f, err := os.Open(path)
	if err != nil {
		return SigUnknown
	}
	defer f.Close()

	var dos [64]byte
	if _, err := io.ReadFull(f, dos[:]); err != nil {
		return SigUnknown
	}
	if dos[0] != 'M' || dos[1] != 'Z' {
		return SigUnknown
	}
	lfanew := int64(binary.LittleEndian.Uint32(dos[0x3C:0x40]))
	if lfanew <= 0 || lfanew > maxPEOffsetBound {
		return SigUnknown
	}
	if _, err := f.Seek(lfanew, io.SeekStart); err != nil {
		return SigUnknown
	}
	var sig [4]byte
	if _, err := io.ReadFull(f, sig[:]); err != nil {
		return SigUnknown
	}
	if sig[0] != 'P' || sig[1] != 'E' || sig[2] != 0 || sig[3] != 0 {
		return SigUnknown
	}
	// COFF 头 20 字节；SizeOfOptionalHeader 在偏移 16。
	var coff [20]byte
	if _, err := io.ReadFull(f, coff[:]); err != nil {
		return SigUnknown
	}
	optSize := int(binary.LittleEndian.Uint16(coff[16:18]))
	if optSize < 2 || optSize > 4096 {
		return SigUnknown
	}
	opt := make([]byte, optSize)
	if _, err := io.ReadFull(f, opt); err != nil {
		return SigUnknown
	}

	// PE32 (0x10B)：NumberOfRvaAndSizes@92、DataDirectory@96；
	// PE32+ (0x20B)：Number@108、DataDirectory@112。SECURITY 是第 5 项（索引 4）。
	var numDirsOff, dataDirOff int
	switch binary.LittleEndian.Uint16(opt[0:2]) {
	case 0x10B:
		numDirsOff, dataDirOff = 92, 96
	case 0x20B:
		numDirsOff, dataDirOff = 108, 112
	default:
		return SigUnknown
	}
	if len(opt) < numDirsOff+4 {
		return SigUnknown
	}
	if numDirs := int(binary.LittleEndian.Uint32(opt[numDirsOff : numDirsOff+4])); numDirs < 5 {
		return SigMissing
	}
	entry := dataDirOff + 4*8
	if len(opt) < entry+8 {
		return SigUnknown
	}
	va := binary.LittleEndian.Uint32(opt[entry : entry+4])
	size := binary.LittleEndian.Uint32(opt[entry+4 : entry+8])
	if va == 0 || size == 0 {
		return SigMissing
	}
	return SigPresent
}

// ModTime 返回文件最近修改时间（UTC 格式由调用方决定）。
func ModTime(path string) (time.Time, error) {
	if _, err := safepath.ValidateLocalFilePath(path, "目标文件路径"); err != nil {
		return time.Time{}, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}, fmt.Errorf("stat %s: %w", path, err)
	}
	return info.ModTime(), nil
}
