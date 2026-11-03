// Package safepath 校验路径的既有父目录链：拒绝符号链接、Windows junction
// （重解析点）与非目录组件。
//
// 用途有两类：
//   - 输出路径（report / analyze / catch 等）：防止把新建文件写进链接指向的
//     任意位置，绕过"仅写本地盘符"的边界；
//   - 源路径（痕迹留存）：防止通过父目录链接把链接目标处的文件当成本地证据复制。
//
// 只检查**已存在的父目录**：缺失的父目录留给 Mkdir/OpenFile 产生原生错误。
// 最终组件不在此检查——调用方用排他创建（O_EXCL）拒绝已存在的最终条目。
package safepath

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// LocalDrivePath 归一一个候选路径；不是“本地盘符绝对路径”就返回 false。
//
// 只接受 C:\... / D:\... 这种本地盘符路径。刻意拒绝 UNC（\\server\share\...）
// 与 NT/设备形式（\SystemRoot\...、\??\C:\...、\\.\...）：打开/写入这些路径会
// 让“零网络”工具发起 SMB 或设备 I/O，也绕过“只写本地可移动/固定卷”的边界。
//
// 判定不依赖 filepath.VolumeName（它会把 \SystemRoot\... 误当成 UNC 卷标）。
func LocalDrivePath(p string) (string, bool) {
	if len(p) < 3 || p[1] != ':' || (p[2] != '\\' && p[2] != '/') || !isDriveLetter(p[0]) {
		return "", false
	}
	return filepath.Clean(p), true
}

func isDriveLetter(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

// RequireLocalDrivePath 把 path 转成绝对路径后要求它是本地盘符路径，
// 且该盘符确实不是映射的网络驱动器。必须在任何 Lstat/ReadDir/Open 之前调用，
// 避免校验动作本身触发 SMB。
func RequireLocalDrivePath(path, label string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("解析%s失败: %w", label, err)
	}
	abs = filepath.Clean(abs)
	if _, ok := LocalDrivePath(abs); !ok {
		return "", fmt.Errorf("%s只接受本地盘符路径（如 C:\\...），拒绝 UNC/NT/设备路径: %s", label, path)
	}
	if err := checkLocalVolume(abs, label); err != nil {
		return "", err
	}
	return abs, nil
}

// RequireLocalDir 校验一个只读输入目录：本地盘符绝对路径、盘符不是网络映射、
// 父链无链接/重解析点，且最终组件本身是普通目录（不跟随 junction/符号链接）。
// 必须在 os.ReadDir 之前调用——对 UNC 路径的目录操作本身就会发起 SMB。
func RequireLocalDir(path, label string) (string, error) {
	abs, err := RequireLocalDrivePath(path, label)
	if err != nil {
		return "", err
	}
	if err := RejectUnsafeParents(abs, label); err != nil {
		return "", err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return "", fmt.Errorf("读取%s失败 %s: %w", label, path, err)
	}
	if !info.IsDir() || IsUnsafeParent(info) {
		return "", fmt.Errorf("%s必须是普通目录，拒绝链接、重解析点或非目录: %s", label, path)
	}
	return abs, nil
}

// ValidateLocalFilePath 校验一个将要只读打开的文件：本地盘符绝对路径、盘符不是
// 网络映射、父链无链接/重解析点。最终组件不存在时返回 nil（让 os.Open 产生准确的
// “文件不存在”错误）；存在但不是普通文件/是链接或重解析点时拒绝。
//
// 这是“读取前”的最后一道边界，不能只依赖采集结果里的路径字符串——注册表命令、
// 进程映像路径和证据候选都可能指向远程/设备位置。
func ValidateLocalFilePath(path, label string) (string, error) {
	abs, err := RequireLocalDrivePath(path, label)
	if err != nil {
		return "", err
	}
	if err := RejectUnsafeParents(abs, label); err != nil {
		return "", err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return abs, nil
		}
		return "", fmt.Errorf("读取%s失败 %s: %w", label, path, err)
	}
	if info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 || !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s必须是普通文件，拒绝链接、重解析点或非文件: %s", label, path)
	}
	return abs, nil
}

// RejectUnsafeParents 从 path 的父目录开始逐级 Lstat 到卷根（不含卷根本身），
// 发现符号链接、重解析点或非目录组件即返回错误。label 用于错误文案
// （如"输出路径"/"源文件路径"），保持调用方既有的用户可见措辞。
//
// 调用方必须先确认 path 是本地盘符路径（见 RequireLocalDrivePath）；本函数不负责
// 识别 UNC，且对 UNC 路径做 Lstat 本身就可能触发网络访问。
func RejectUnsafeParents(path, label string) error {
	root := filepath.VolumeName(path) + string(os.PathSeparator)
	for current := filepath.Dir(path); current != root; {
		info, err := os.Lstat(current)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("检查%s失败 %s: %w", label, current, err)
			}
		} else if IsUnsafeParent(info) {
			return fmt.Errorf("%s包含不安全的链接、重解析点或非目录组件: %s", label, current)
		}

		next := filepath.Dir(current)
		if next == current {
			break
		}
		current = next
	}
	return nil
}

// IsUnsafeParent 识别普通符号链接与 Windows junction。
// Go 把现代 junction 暴露为 ModeIrregular、旧式 junction 暴露为 ModeSymlink；
// 普通文件在"只允许目录"的链里同样不安全。
func IsUnsafeParent(info fs.FileInfo) bool {
	return info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 || !info.IsDir()
}
