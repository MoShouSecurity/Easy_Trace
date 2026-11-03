//go:build !windows

package privilege

// detectImpl 非 Windows 平台：Unsupported，返回零值（保持跨平台编译）。
func detectImpl() PrivilegeInfo {
	return PrivilegeInfo{}
}
