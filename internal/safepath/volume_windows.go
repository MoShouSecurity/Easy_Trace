//go:build windows

package safepath

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	kernel32          = syscall.NewLazyDLL("kernel32.dll")
	procGetDriveTypeW = kernel32.NewProc("GetDriveTypeW")
)

// GetDriveTypeW 返回值（Windows SDK winbase.h）。
const (
	driveUnknown   = 0
	driveNoRootDir = 1
	driveRemote    = 4
)

// checkLocalVolume 拒绝映射的网络驱动器与不存在的盘符根。
// 仅靠路径形状无法区分 C:\ 与 Z:\（后者可能映射到 \\server\share）；
// 任一文件操作前必须先确认盘符类型，否则“零网络”边界会被 SMB 读取绕过。
func checkLocalVolume(path, label string) error {
	if len(path) < 3 {
		return fmt.Errorf("%s不是有效的盘符路径: %s", label, path)
	}
	root, err := syscall.UTF16PtrFromString(path[:3]) // "C:\"
	if err != nil {
		return fmt.Errorf("解析%s盘符失败: %w", label, err)
	}
	ret, _, _ := procGetDriveTypeW.Call(uintptr(unsafe.Pointer(root)))
	switch uint32(ret) {
	case driveRemote:
		return fmt.Errorf("%s位于映射的网络驱动器，拒绝访问（离线工具不读取网络位置）: %s", label, path)
	case driveUnknown, driveNoRootDir:
		return fmt.Errorf("%s所在盘符不可用，拒绝访问: %s", label, path)
	}
	return nil
}
