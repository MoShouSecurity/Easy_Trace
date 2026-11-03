package execution

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"syscall"
	"unsafe"
)

// 注册表常量与句柄（advapi32；只申请 KEY_READ，不申请写权限）。
const (
	keyRead          = 0x20019
	errorSuccess     = 0
	errorMoreData    = 234
	errorNoMoreItems = 259

	hkeyCurrentUser  = 0x80000001
	hkeyLocalMachine = 0x80000002
	hkeyUsers        = 0x80000003
)

var (
	advapi32 = syscall.NewLazyDLL("advapi32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	procRegOpenKeyExW          = advapi32.NewProc("RegOpenKeyExW")
	procRegCloseKey            = advapi32.NewProc("RegCloseKey")
	procRegEnumKeyExW          = advapi32.NewProc("RegEnumKeyExW")
	procRegEnumValueW          = advapi32.NewProc("RegEnumValueW")
	procLookupAccountNameW     = advapi32.NewProc("LookupAccountNameW")
	procConvertSidToStringSidW = advapi32.NewProc("ConvertSidToStringSidW")
	procLocalFree              = kernel32.NewProc("LocalFree")
)

// regValue 是单个注册表值（数据已复制，关闭键后仍可用）。
type regValue struct {
	name string
	typ  uint32
	data []byte
}

// openKey 以只读方式打开 root 下的相对路径。
func openKey(root uintptr, path string) (uintptr, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, fmt.Errorf("注册表路径编码失败（%s）: %w", path, err)
	}
	var h uintptr
	ret, _, _ := procRegOpenKeyExW.Call(root,
		uintptr(unsafe.Pointer(p)), 0, keyRead, uintptr(unsafe.Pointer(&h)))
	if ret != errorSuccess {
		return 0, fmt.Errorf("打开注册表键失败（%s）: %w", path, syscall.Errno(ret))
	}
	return h, nil
}

func closeKey(h uintptr) {
	if h != 0 {
		procRegCloseKey.Call(h)
	}
}

// enumSubKeys 枚举子键名（注册表顺序通常已排序，调用方仍应显式排序）。
func enumSubKeys(h uintptr) ([]string, error) {
	buf := make([]uint16, 512)
	var out []string
	for i := uint32(0); ; {
		n := uint32(len(buf))
		ret, _, _ := procRegEnumKeyExW.Call(h, uintptr(i),
			uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)),
			0, 0, 0, 0)
		switch ret {
		case errorNoMoreItems:
			return out, nil
		case errorMoreData:
			// n 是需要的字符数（不含 NUL）；放大后重试同一个索引。
			// 若 n 没有超过当前缓冲（异常返回值），直接报错，避免死循环。
			if n == 0 || n > 4096 || n+1 <= uint32(len(buf)) {
				return out, fmt.Errorf("子键名长度异常（%d）", n)
			}
			buf = make([]uint16, n+1)
			continue
		case errorSuccess:
		default:
			return out, syscall.Errno(ret)
		}
		out = append(out, syscall.UTF16ToString(buf[:n]))
		i++
	}
}

// enumValues 枚举键下所有值（名称 + 类型 + 数据副本）。
//
// 数据缓冲 16 KiB 起步：本模块关心的 UserAssist/BAM/RecentDocs 值都远小于此；
// 遇到更大的值会按需扩容一次，超过 1 MiB 则返回错误而不是无限重试。
func enumValues(h uintptr) ([]regValue, error) {
	nameBuf := make([]uint16, 512)
	dataBuf := make([]byte, 16<<10)
	var out []regValue
	for i := uint32(0); ; {
		nameLen := uint32(len(nameBuf))
		dataLen := uint32(len(dataBuf))
		var typ uint32
		ret, _, _ := procRegEnumValueW.Call(h, uintptr(i),
			uintptr(unsafe.Pointer(&nameBuf[0])), uintptr(unsafe.Pointer(&nameLen)),
			0, uintptr(unsafe.Pointer(&typ)),
			uintptr(unsafe.Pointer(&dataBuf[0])), uintptr(unsafe.Pointer(&dataLen)))
		switch ret {
		case errorNoMoreItems:
			return out, nil
		case errorMoreData:
			// 先判断是数据不足还是值名太长；两者都会返回 ERROR_MORE_DATA。
			if dataLen > uint32(len(dataBuf)) {
				if dataLen > 1<<20 {
					return out, fmt.Errorf("注册表值数据长度异常（%d 字节）", dataLen)
				}
				dataBuf = make([]byte, dataLen)
				continue
			}
			if nameLen >= uint32(len(nameBuf)) && nameLen <= 4096 {
				nameBuf = make([]uint16, nameLen+1)
				continue
			}
			return out, fmt.Errorf("注册表值枚举异常（name=%d, data=%d）", nameLen, dataLen)
		case errorSuccess:
		default:
			return out, syscall.Errno(ret)
		}
		data := append([]byte(nil), dataBuf[:dataLen]...)
		out = append(out, regValue{
			name: syscall.UTF16ToString(nameBuf[:nameLen]),
			typ:  typ,
			data: data,
		})
		i++
	}
}

// errnoOf 提取 syscall.Errno（支持被 fmt.Errorf("%w") 包装）。
func errnoOf(err error) syscall.Errno {
	var e syscall.Errno
	if errors.As(err, &e) {
		return e
	}
	return 0
}

// isNotFound 判断键/值不存在（这是"该痕迹没有"的正常路径，不是失败）。
func isNotFound(err error) bool {
	switch errnoOf(err) {
	case 2, 3, 1018: // ERROR_FILE_NOT_FOUND / ERROR_PATH_NOT_FOUND / ERROR_KEY_DELETED
		return true
	}
	return false
}

// isAccessDenied 判断权限不足（普通用户读其他用户/系统 BAM 时的预期结果）。
func isAccessDenied(err error) bool {
	return errnoOf(err) == 5 // ERROR_ACCESS_DENIED
}

// currentUserName 返回当前用户名；优先 USERNAME 环境变量。
func currentUserName() string {
	if n := strings.TrimSpace(os.Getenv("USERNAME")); n != "" {
		return n
	}
	return "current"
}

// currentUserSID 通过 LookupAccountNameW + ConvertSidToStringSidW 取当前用户 SID。
// 失败返回空串（只影响 HKU 去重与标签，不影响采集）。
func currentUserSID() string {
	name := currentUserName()
	if name == "" || name == "current" {
		return ""
	}
	p, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return ""
	}
	var sid [68]byte // SID 最大 68 字节（8 + 15 × 4）
	sidLen := uint32(len(sid))
	var domain [256]uint16
	domainLen := uint32(len(domain))
	var use uint32
	ret, _, _ := procLookupAccountNameW.Call(0,
		uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&sid[0])), uintptr(unsafe.Pointer(&sidLen)),
		uintptr(unsafe.Pointer(&domain[0])), uintptr(unsafe.Pointer(&domainLen)),
		uintptr(unsafe.Pointer(&use)))
	if ret == 0 {
		return ""
	}
	var strPtr *uint16
	ret, _, _ = procConvertSidToStringSidW.Call(
		uintptr(unsafe.Pointer(&sid[0])), uintptr(unsafe.Pointer(&strPtr)))
	if ret == 0 || strPtr == nil {
		return ""
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(strPtr)))
	return utf16PtrToString(strPtr)
}

// userHive 是一个用户注册表配置单元（HKCU 或 HKU 下的一个 SID）。
type userHive struct {
	root uintptr
	base string // 相对 root 的前缀：HKCU 为 ""，HKU 为 SID
	user string // 实体里的 user 标签：当前用户名或 SID
}

// userHives 返回当前用户（HKCU）+ HKEY_USERS 下所有本地/域用户 SID 的配置单元。
//
// 只纳入 S-1-5-21-*（真实用户）；SYSTEM/服务账户没有 UserAssist/RecentDocs。
// 当前用户的 SID 已在 HKCU 中读取，从 HKU 跳过，避免同一痕迹出现两次。
// 其他用户的配置单元在普通用户下通常不可读：这是预期权限边界，只写 debug 日志。
func userHives() ([]userHive, []string) {
	hives := []userHive{{root: hkeyCurrentUser, user: currentUserName()}}
	currentSID := currentUserSID()
	if currentSID == "" {
		// 无法判断哪个 HKU SID 是当前用户；宁可只读 HKCU，也不输出重复事实。
		debugf("current_user_sid_unavailable: 跳过 HKU 其他用户配置单元")
		return hives, nil
	}
	sids, err := enumSubKeys(hkeyUsers)
	if err != nil {
		if isAccessDenied(err) {
			debugf("enum_hkey_users_denied: %v", err)
			return hives, nil
		}
		return hives, []string{"枚举 HKEY_USERS 失败：" + err.Error()}
	}
	sort.Strings(sids)
	for _, sid := range sids {
		if !strings.HasPrefix(sid, "S-1-5-21-") || sid == currentSID {
			continue
		}
		hives = append(hives, userHive{root: hkeyUsers, base: sid, user: sid})
	}
	return hives, nil
}

// joinReg 拼接注册表相对路径。
func joinReg(base, sub string) string {
	if base == "" {
		return sub
	}
	return base + `\` + sub
}

// utf16PtrToString 从 *uint16 指针读取字符串（直到 NUL，带防御上限）。
func utf16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	var units []uint16
	for i := 0; i < 4096; i++ {
		c := *(*uint16)(unsafe.Add(unsafe.Pointer(p), uintptr(i)*2))
		if c == 0 {
			break
		}
		units = append(units, c)
	}
	return syscall.UTF16ToString(units)
}
