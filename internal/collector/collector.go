// Package collector 定义采集模块的统一接口（Task 8 Pipeline 将基于它调度）。
package collector

import "easytrace/internal/model"

// Collector 是采集模块的统一接口。
// 所有采集模块（host/process/network/...）实现本接口：
// 只采集事实（Collector only collects facts），不输出 Finding。
type Collector interface {
	// Name 返回模块名（host / process / network / ...）。
	Name() string
	// Collect 执行一次采集，返回实体与关系。
	Collect() (*Result, error)
}

// Result 是一次采集的全部输出（Entity + EntityUpdate + Relation + DeepFailures）。
// 调用方负责将输出写入 JSONL 或存储层（Development Rule #3）。
// DeepFailures 不是协议数据（不写 JSONL / 不落库），仅供 CLI 层输出精确失败原因。
type Result struct {
	Entities      []*model.Entity
	EntityUpdates []*model.EntityUpdate
	Relations     []*model.Relation
	// DeepFailures 深采动作失败分类（Step 11.5：inspect 错误原因准确分类）。
	// 仅 process 模块深采/元数据路径填充；无失败时为空。
	DeepFailures []DeepFailure
}

// DeepFailure 描述单个深采动作的失败分类（Step 11.5）。
//
// 现场环境差异（权限不足 / 进程已退出 / 文件不存在 / 安全软件拦截）必须区分，
// 禁止笼统提示"目标进程可能已退出"。Reason 取 Reason* 常量。
type DeepFailure struct {
	EntityID string // 目标实体（process_<pid>）
	Field    string // command_line / hash_sha256 / signature_state / process_metadata
	Reason   string // 失败原因分类（Reason* 常量）
	Detail   string // 原始错误信息（日志/展示用）
}

// 深采失败原因分类常量（Step 11.5）。
const (
	ReasonAccessDenied       = "access_denied"         // 权限不足（ERROR_ACCESS_DENIED / E_ACCESSDENIED）
	ReasonProcessExited      = "process_exited"        // 进程不存在（ERROR_INVALID_PARAMETER）
	ReasonFileNotFound       = "file_not_found"        // 文件不存在
	ReasonHashFailed         = "hash_failed"           // 哈希计算失败（读取中断等）
	ReasonFileTooLarge       = "file_too_large"        // 文件超过哈希上限，未计算哈希
	ReasonWinVerifyTrustFail = "winverifytrust_failed" // WinVerifyTrust 验证失败
	ReasonAPIFailed          = "api_failed"            // Windows API 调用失败（其它错误码）
	ReasonQueryFailed        = "query_failed"          // 查询失败（其它原因）
	ReasonUnsafePath         = "unsafe_path"           // 路径不是本地普通文件（UNC/映射盘/链接/重解析点）
)
