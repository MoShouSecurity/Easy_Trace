//go:build windows

package privilege

import (
	"syscall"
	"unsafe"
)

// Token 查询权限（只读，无提权操作）。
const (
	tokenQuery = 0x0008 // TOKEN_QUERY

	// TOKEN_INFORMATION_CLASS
	tokenElevation = 20 // TokenElevation → TOKEN_ELEVATION{TokenIsElevated DWORD}
)

// BUILTIN\Administrators SID（S-1-5-32-544）。
const (
	securityNtAuthority = 5   // SECURITY_NT_AUTHORITY
	builtinDomainRID    = 32  // SECURITY_BUILTIN_DOMAIN_RID
	aliasRIDAdmins      = 544 // DOMAIN_ALIAS_RID_ADMINS
)

var (
	kernel32                     = syscall.NewLazyDLL("kernel32.dll")
	advapi32                     = syscall.NewLazyDLL("advapi32.dll")
	procOpenProcessToken         = advapi32.NewProc("OpenProcessToken")
	procGetTokenInformation      = advapi32.NewProc("GetTokenInformation")
	procCheckTokenMembership     = advapi32.NewProc("CheckTokenMembership")
	procAllocateAndInitializeSid = advapi32.NewProc("AllocateAndInitializeSid")
	procFreeSid                  = advapi32.NewProc("FreeSid")
	procCloseHandle              = kernel32.NewProc("CloseHandle")
)

// detectImpl 只读当前进程 Token：OpenProcessToken(GetCurrentProcess, TOKEN_QUERY)
// → GetTokenInformation(TokenElevation) → CheckTokenMembership(Administrators SID)。
// 任一查询失败保持该字段为 false（不误报管理员状态）。
func detectImpl() PrivilegeInfo {
	info := PrivilegeInfo{}

	// GetCurrentProcess 伪句柄 (-1)，无需打开进程
	var hToken uintptr
	r1, _, _ := procOpenProcessToken.Call(^uintptr(0), tokenQuery, uintptr(unsafe.Pointer(&hToken)))
	if r1 == 0 {
		return info
	}
	defer procCloseHandle.Call(hToken)

	// TokenElevation：TOKEN_ELEVATION{ TokenIsElevated DWORD }
	var elev struct{ TokenIsElevated uint32 }
	var n uint32
	r1, _, _ = procGetTokenInformation.Call(hToken, tokenElevation,
		uintptr(unsafe.Pointer(&elev)), unsafe.Sizeof(elev), uintptr(unsafe.Pointer(&n)))
	if r1 != 0 {
		info.IsElevated = elev.TokenIsElevated != 0
	}

	// 管理员组成员：CheckTokenMembership 对 split token 的过滤版本自动回退
	// 到 linked token，与"账户是否属于 Administrators"语义一致。
	if sid, err := builtinAdminsSID(); err == nil {
		defer procFreeSid.Call(sid)
		var member int32
		r1, _, _ = procCheckTokenMembership.Call(hToken, sid, uintptr(unsafe.Pointer(&member)))
		if r1 != 0 {
			info.IsAdminGroupMember = member != 0
		}
	}
	return info
}

// builtinAdminsSID 分配 BUILTIN\Administrators 的 SID（调用方负责 FreeSid）。
func builtinAdminsSID() (uintptr, error) {
	// SID_IDENTIFIER_AUTHORITY = {0,0,0,0,0,5}（SECURITY_NT_AUTHORITY）
	authority := [6]byte{0, 0, 0, 0, 0, securityNtAuthority}
	var sid uintptr
	r1, _, e := procAllocateAndInitializeSid.Call(
		uintptr(unsafe.Pointer(&authority)), 2, // 2 个子授权
		builtinDomainRID, aliasRIDAdmins,
		0, 0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&sid)))
	if r1 == 0 {
		return 0, e
	}
	return sid, nil
}
