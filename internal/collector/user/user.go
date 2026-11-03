// Package user 实现 User Collector（Task 7）。
//
// 通过 NETAPI32 枚举本地用户（含当前登录用户），输出 user 实体
// （username/sid/groups/enabled/last_login）。只采集事实，不修改账户、不采集密码。
package user

import (
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	"easytrace/internal/collector"
	"easytrace/internal/collector/runtime"
	"easytrace/internal/model"
)

// ---- Windows API 句柄（懒加载，零外部依赖） ----
var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")
	netapi32 = syscall.NewLazyDLL("netapi32.dll")

	procNetUserEnum            = netapi32.NewProc("NetUserEnum")
	procNetUserGetLocalGroups  = netapi32.NewProc("NetUserGetLocalGroups")
	procNetApiBufferFree       = netapi32.NewProc("NetApiBufferFree")
	procLookupAccountNameW     = advapi32.NewProc("LookupAccountNameW")
	procConvertSidToStringSidW = advapi32.NewProc("ConvertSidToStringSidW")
	procLocalFree              = kernel32.NewProc("LocalFree")
)

// 常量
const (
	filterNormalAccount = 0x0002 // FILTER_NORMAL_ACCOUNT
	maxPreferredLength  = 0xFFFFFFFF
	lgIncludeIndirect   = 0x0001 // LG_INCLUDE_INDIRECT

	ufAccountDisable = 0x0002 // UF_ACCOUNTDISABLE
)

// userInfo2 对应 USER_INFO_2（Windows x64 共 152 字节）。
//
// 注意两处与直觉不同的地方：
//   - usri2_last_logon / usri2_last_logoff / usri2_acct_expires 是 **DWORD**
//     （1970-01-01 起的秒数），不是 FILETIME；按 int64 读取会连带读错后续字段。
//   - usri2_logon_hours 是 PBYTE 指针，必须占一个指针槽；漏掉它会让
//     usri2_bad_pw_count / usri2_num_logons / usri2_logon_server 整体错位。
//     末尾的 usri2_country_code / usri2_code_page 也属于结构体（影响总大小）。
//
// 布局由 user_test.go 的偏移断言锁定（amd64）。
type userInfo2 struct {
	Name         *uint16
	Password     *uint16
	PasswordAge  uint32
	Priv         uint32
	HomeDir      *uint16
	Comment      *uint16
	Flags        uint32
	ScriptPath   *uint16
	AuthFlags    uint32
	FullName     *uint16
	UsrComment   *uint16
	Params       *uint16
	Workstations *uint16
	LastLogon    uint32 // 1970 起的秒数
	LastLogoff   uint32
	AcctExpires  uint32
	MaxStorage   uint32
	UnitsPerWeek uint32
	LogonHours   *byte
	BadPwCount   uint32
	NumLogons    uint32
	LogonServer  *uint16
	CountryCode  uint32
	CodePage     uint32
}

// localGroupUsersInfo0 对应 LOCALGROUP_USERS_INFO_0。
type localGroupUsersInfo0 struct {
	Name *uint16
}

// userEntry 是单个用户的中间结构（内部结构，供测试注入）。
type userEntry struct {
	username  string
	sid       string
	groups    []string
	enabled   bool
	lastLogin string
}

// Collector 实现 user 采集。getEntries 可注入以便测试；nil 时使用真实 Windows API。
type Collector struct {
	getEntries func() ([]userEntry, error)
	rt         *runtime.Runtime
}

// New 创建使用真实 Windows API 的 User Collector，绑定调用方注入的 Runtime。
// Collector 不在内部创建 Runtime（架构收口，Step 2.2）；rt 必传，nil 视为编程错误。
func New(rt *runtime.Runtime) *Collector {
	if rt == nil {
		panic("user: New 必须传入 runtime.Runtime（禁止 Collector 内部创建）")
	}
	return &Collector{rt: rt}
}

// NewWithEntries 创建使用自定义数据源的 User Collector（用于测试）。
func NewWithEntries(rt *runtime.Runtime, f func() ([]userEntry, error)) *Collector {
	c := New(rt)
	c.getEntries = f
	return c
}

// Runtime 返回绑定的行为控制 Runtime（供注入一致性校验）。
func (c *Collector) Runtime() *runtime.Runtime { return c.rt }

// Name 实现 collector.Collector 接口。
func (c *Collector) Name() string { return "user" }

// Collect 实现 collector.Collector 接口：输出 user 实体。
//
// Step 5.3 行为门卫：先经 rt.Allow("user","UserQuery") 检查——被拒则
// 不执行任何用户枚举 API，返回空结果并记录 deny 行为事件（不视为错误）。
// 容错遵循"能采多少采多少"：单用户 SID/组查询失败降级为空字段，枚举失败只记录
// 内部错误日志（协议 v0.2 未定义 collection_error，本 Step 只做内部日志）。
func (c *Collector) Collect() (*collector.Result, error) {
	if !c.rt.Allow("user", "UserQuery", "local_users") {
		debugf("user_query_denied mode=%s", c.rt.Mode())
		return &collector.Result{}, nil
	}
	getEntries := c.getEntries
	if getEntries == nil {
		getEntries = collectUsers
	}
	entries, err := getEntries()
	if err != nil {
		// 部分失败：记录内部错误（含 collector/capability/operation/error），保留已采集项。
		debugf("collection_error collector=user capability=UserQuery operation=collectUsers error=%v", err)
	}

	res := &collector.Result{}
	for _, ue := range entries {
		id := "user_" + ue.sid
		if id == "user_" {
			id = "user_" + ue.username
		}
		e := model.NewEntity("user", id, model.UserData{
			Username:  ue.username,
			SID:       ue.sid,
			Groups:    ue.groups,
			Enabled:   ue.enabled,
			LastLogin: ue.lastLogin,
		})
		res.Entities = append(res.Entities, e)
	}
	if err != nil {
		// 与 network / service / persistence 同一失败语义：保留已采结果，
		// 但显式标记不完整，由 CLI/Pipeline 计入失败并以非零退出。
		return res, fmt.Errorf("user 采集不完整: %w", err)
	}
	return res, nil
}

// debugf 输出采集阶段/内部错误日志到 stderr（不污染 stdout 的 JSONL 流）。
func debugf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[user] "+format+"\n", args...)
}

// collectUsers 通过 NETAPI32 枚举本地用户（USER_INFO_2）。
func collectUsers() ([]userEntry, error) {
	var buf unsafe.Pointer
	var entriesRead, totalEntries, resumeHandle uint32
	ret, _, _ := procNetUserEnum.Call(0, 2 /*level*/, filterNormalAccount,
		uintptr(unsafe.Pointer(&buf)), maxPreferredLength,
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&totalEntries)),
		uintptr(unsafe.Pointer(&resumeHandle)))
	if ret != 0 {
		return nil, fmt.Errorf("NetUserEnum: ret=%d", ret)
	}
	if buf != nil {
		defer procNetApiBufferFree.Call(uintptr(buf))
	}

	entries := make([]userEntry, 0, entriesRead)
	items := unsafe.Slice((*userInfo2)(buf), entriesRead)
	for i := range items {
		item := &items[i]
		name := utf16PtrToString(item.Name)
		if name == "" {
			continue
		}
		ue := userEntry{
			username:  name,
			enabled:   item.Flags&ufAccountDisable == 0,
			lastLogin: unixSecondsToString(item.LastLogon),
		}
		ue.sid = lookupSID(name)
		ue.groups = userGroups(name)
		entries = append(entries, ue)
	}
	return entries, nil
}

// lookupSID 通过 LookupAccountNameW + ConvertSidToStringSidW 获取用户 SID。
func lookupSID(username string) string {
	var sid [256]byte
	sidLen := uint32(len(sid))
	var domain [256]uint16
	domainLen := uint32(len(domain))
	var use uint32
	ret, _, _ := procLookupAccountNameW.Call(0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(username))),
		uintptr(unsafe.Pointer(&sid[0])), uintptr(unsafe.Pointer(&sidLen)),
		uintptr(unsafe.Pointer(&domain[0])), uintptr(unsafe.Pointer(&domainLen)),
		uintptr(unsafe.Pointer(&use)))
	if ret == 0 {
		return ""
	}
	var strPtr *uint16
	ret, _, _ = procConvertSidToStringSidW.Call(uintptr(unsafe.Pointer(&sid[0])),
		uintptr(unsafe.Pointer(&strPtr)))
	if ret == 0 || strPtr == nil {
		return ""
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(strPtr)))
	return utf16PtrToString(strPtr)
}

// userGroups 获取用户所属本地组（含间接组，失败返回空）。
func userGroups(username string) []string {
	var buf unsafe.Pointer
	var entriesRead, totalEntries uint32
	ret, _, _ := procNetUserGetLocalGroups.Call(0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(username))),
		0, lgIncludeIndirect,
		uintptr(unsafe.Pointer(&buf)), maxPreferredLength,
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&totalEntries)))
	if ret != 0 || buf == nil {
		return nil
	}
	defer procNetApiBufferFree.Call(uintptr(buf))

	items := unsafe.Slice((*localGroupUsersInfo0)(buf), entriesRead)
	groups := make([]string, 0, entriesRead)
	for i := range items {
		if name := utf16PtrToString(items[i].Name); name != "" {
			groups = append(groups, name)
		}
	}
	return groups
}

// unixSecondsToString 将 USER_INFO_2 的登录时间（1970 起的秒数）转为 ISO8601。
// 0 表示从未登录（MSDN：值 0 表示用户从未登录）→ 输出空串，不伪造时间。
func unixSecondsToString(sec uint32) string {
	if sec == 0 {
		return ""
	}
	return time.Unix(int64(sec), 0).UTC().Format(time.RFC3339)
}

// utf16PtrToString 从 *uint16 指针读取字符串（直到 NUL，带防御上限）。
func utf16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	var chars []uint16
	for i := 0; i < 4096; i++ {
		c := *(*uint16)(unsafe.Add(unsafe.Pointer(p), uintptr(i)*2))
		if c == 0 {
			break
		}
		chars = append(chars, c)
	}
	return syscall.UTF16ToString(chars)
}
