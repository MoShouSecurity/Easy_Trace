// Package privilege 检测当前进程的权限运行状态（Step 10.1 采集环境信息）。
//
// 用途：提醒用户采集权限状态、告知管理员权限可获得的更多采集信息、
// 在报告中记录采集完整度。权限状态属于采集环境，不是安全发现——
// 禁止生成风险评分，禁止据此判定"非管理员 = 风险"。
//
// 安全边界：只读取当前进程 Token（TOKEN_QUERY），
// 禁止注册表 / WMI / 外部程序 / ShellExecute(runas) / CreateProcess(runas)
// / 自动提权 / 自动重启 / 弹 UAC / 修改系统配置。
package privilege

// PrivilegeInfo 描述当前进程的权限状态。
//
//	IsElevated         当前 Easy_Trace.exe 是否正以管理员权限运行
//	                   （TokenElevation，不是"账户是否属于 Administrators"）
//	IsAdminGroupMember 当前账户是否属于 Administrators 组
//
// 语义示例（管理员账户）：
//   - 普通启动：IsAdminGroupMember=true, IsElevated=false
//   - 右键"以管理员身份运行"：IsAdminGroupMember=true, IsElevated=true
type PrivilegeInfo struct {
	IsElevated         bool
	IsAdminGroupMember bool
}

// detectFn 可注入（测试用）；detectImpl 为平台实现。
var detectFn = detectImpl

// Detect 返回当前进程权限状态。
//
// Windows：OpenProcessToken + GetTokenInformation(TokenElevation)
// + CheckTokenMembership(BUILTIN\Administrators)。
// 非 Windows 平台返回零值（Unsupported）。任何查询失败保持该字段为 false
// （不误报管理员状态，宁可保守）。
func Detect() PrivilegeInfo {
	return detectFn()
}
