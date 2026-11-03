package runtime

import "fmt"

// CollectionMode 定义采集运行模式（Step 2.2 冻结：Basic/Deep/Forensic）。
//
// 模式决定采集运行时被授予的能力（见 capability.go），
// Collector 不自行决定能力，只能通过 Runtime.Allow 请求。
type CollectionMode string

const (
	// Basic 默认运行模式：最低权限事实采集。
	// 只授予基础查询能力（网络连接表/注册表/服务/任务/用户枚举），
	// 拒绝一切敏感行为（读进程内存/读文件/验签/哈希/任意外部命令）。
	Basic CollectionMode = "basic"

	// Deep 人工确认模式：在 Basic 基础上允许补充证据采集
	// （文件读取、哈希、命令行、签名验证）。
	Deep CollectionMode = "deep"

	// Forensic 取证模式：最大化采集（当前授予全部能力，
	// 后续扩展：事件日志、原始磁盘、更多证据源）。
	Forensic CollectionMode = "forensic"
)

// String 实现 fmt.Stringer。
func (m CollectionMode) String() string {
	switch m {
	case Basic:
		return "basic"
	case Deep:
		return "deep"
	case Forensic:
		return "forensic"
	}
	return fmt.Sprintf("mode(%s)", string(m))
}
