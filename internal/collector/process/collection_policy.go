package process

import (
	"path/filepath"
	"strings"
	"time"
)

// 本文件实现 Collection Policy（Step 1.5）——采集策略层，决定"哪些进程值得花成本
// 深采 / 真实验签 / 计算哈希 / 读命令行"。
//
// 只输出采集计划（CollectionPlan），不判断恶意、不产 risk_score/severity/finding
// （风险评分归 Analyzer 阶段，Development Rule #6）。
//
// 目录处理原则：禁止目录白名单跳过（C:\Windows\System32 等仍采集）；正常微软签名
// 文件（signature_state=present）降低采集等级，异常文件（missing/伪装/父异常）提升。

// protectedProcessNames 系统关键进程：禁止 PEB 读取（深采命令行），
// 允许基础信息与签名状态（Step 1.5 §六）。key 全小写，查找时 ToLower。
var protectedProcessNames = map[string]bool{
	"system":       true, // 内核
	"idle":         true,
	"csrss.exe":    true,
	"wininit.exe":  true,
	"services.exe": true,
	"lsass.exe":    true,
}

// spoofedNames 常见系统进程名伪装特征（svchost1.exe / winupdate.exe 等）。
var spoofedNames = []string{
	"svchost", "winupdate", "winlogon", "lsass", "csrss",
	"explorer", "services", "smss", "taskhost", "conhost",
}

// officeSpawnShellParents office → shell 的父进程（父进程异常判定）。
var officeSpawnShellParents = map[string]bool{
	"winword.exe": true, "excel.exe": true, "powerpnt.exe": true,
	"outlook.exe": true,
}

// browserSpawnShellParents browser → cmd 的父进程（父进程异常判定）。
var browserSpawnShellParents = map[string]bool{
	"chrome.exe": true, "msedge.exe": true, "firefox.exe": true,
	"iexplore.exe": true, "brave.exe": true,
}

// shellSpawnChildren 由 office/browser 派生时值得深采的脚本宿主 / 加载器。
var shellSpawnChildren = map[string]bool{
	"powershell.exe": true, "cmd.exe": true, "rundll32.exe": true,
	"mshta.exe": true, "wscript.exe": true, "cscript.exe": true,
	"regsvr32.exe": true, "wmic.exe": true, "forfiles.exe": true,
}

// commandLineTriggerNames 是 Deep 模式下**只看命令行**的解释器 / LOLBin 名单。
//
// 背景：command_line 只在 Deep 且策略命中时采集。普通 System32\powershell.exe
// 由 explorer 或计划任务拉起时，路径不在用户目录、名字不伪装、父进程也不是
// Office/浏览器——原策略不会读它的命令行，7 条命令行规则就永远看不到
// `-EncodedCommand`、`IEX (New-Object Net.WebClient)` 等特征。
//
// 命中的进程只设置 NeedCommandLine（不触发 PE Inspect / Hash / 验签），
// 仍受 protectedProcessNames 排除；Basic 模式不会走到这里。
// 与 shellSpawnChildren 有重叠，但后者只用于"父进程异常"判定。
var commandLineTriggerNames = map[string]bool{
	"powershell.exe": true,
	"pwsh.exe":       true,
	"cmd.exe":        true,
	"wscript.exe":    true,
	"cscript.exe":    true,
	"mshta.exe":      true,
	"rundll32.exe":   true,
	"regsvr32.exe":   true,
	"wmic.exe":       true,
	"forfiles.exe":   true,
	"certutil.exe":   true,
	"bitsadmin.exe":  true,
	"msiexec.exe":    true,
}

// userDirMarkers 命中即认为进程位于用户可写目录（高风险取证价值区）。
// 注意：与 lowerPath（已 ToLower）比较，故全部用小写。
var userDirMarkers = []string{
	`\users\`, `\appdata\`, `\temp\`, `\public\`,
	`\downloads\`, `\desktop\`,
}

// CollectionPlan 是针对单个进程的采集计划（输出到深采执行层）。
// 不判断恶意、不含风险分数；Reasons 记录事实命中原因。
// 两阶段评估（Step 1.6 §二）：
//
//	Stage 1（无需读文件，planCollection）：基础事实 → 定 NeedPEInspect
//	Stage 2（PE Inspect 后，enrichEntries 内二次评估）：签名状态 + 文件时间 → 定
//	  NeedSignatureVerify / NeedHash / NeedCommandLine（recent_file 等）
type CollectionPlan struct {
	NeedPEInspect       bool     // 需要读取 PE 头（signature_state + last_write_time）
	NeedSignatureVerify bool     // 需要真实签名验证（WinVerifyTrust，missing 时）
	NeedHash            bool     // 需要计算文件 SHA256
	NeedCommandLine     bool     // 需要读命令行（PEB，系统进程禁止）
	Reasons             []string // 事实命中原因（user_dir/unsigned/name_spoof/recent_file/...）
}

// NeedsWork 是否有任何深采动作需要执行。
func (p CollectionPlan) NeedsWork() bool {
	return p.NeedPEInspect || p.NeedSignatureVerify || p.NeedHash || p.NeedCommandLine
}

// planCollection 评估给定进程的采集计划（Stage 1：不读取任何文件）。
// parentName 为父进程名（可空，用于 office/browser→shell 判定）。
// 基础阶段 signature_state 恒为 unknown，unsigned/recent_file 由 Stage 2 补充。
// 纯函数，可单测（Step 1.6 §六测试 2/3）。
func planCollection(entry procEntry, parentName string) CollectionPlan {
	var plan CollectionPlan

	// 1) 系统关键进程：禁止 PEB 读取（NeedCommandLine=false），
	//    基础信息与签名状态仍采集；不做任何深采动作。
	if protectedProcessNames[strings.ToLower(entry.name)] {
		return plan
	}

	lowerPath := strings.ToLower(entry.path)
	if entry.path != "" && isAbsPath(lowerPath) {
		for _, m := range userDirMarkers {
			if strings.Contains(lowerPath, m) {
				plan.Reasons = append(plan.Reasons, "user_dir")
				plan.NeedPEInspect = true
				break
			}
		}
	}

	// 2) 名字伪装：svchost1.exe / winupdate.exe 等 → 需要 PE Inspect 确认
	if isNameSpoof(entry.name) {
		plan.Reasons = append(plan.Reasons, "name_spoof")
		plan.NeedPEInspect = true
	}

	// 3) 父进程异常：office/browser 派生 shell → 需要 PE Inspect 确认
	if parentName != "" {
		pn := strings.ToLower(parentName)
		if shellSpawnChildren[strings.ToLower(entry.name)] &&
			(officeSpawnShellParents[pn] || browserSpawnShellParents[pn]) {
			plan.Reasons = append(plan.Reasons, "suspicious_parent")
			plan.NeedPEInspect = true
		}
	}

	// 4) 解释器 / LOLBin：无论父进程为何，Deep 下读取其命令行。
	//    这一步只读命令行，不额外读 PE/哈希；用于让命令行特征规则
	//    覆盖 explorer / 计划任务拉起的普通 System32 解释器。
	if commandLineTriggerNames[strings.ToLower(entry.name)] {
		plan.Reasons = append(plan.Reasons, "interpreter")
		plan.NeedCommandLine = true
	}

	// 深采：有 PE Inspect 需求才计算哈希（哈希与验签属于文件深采）；
	// 命令行需求独立成立（interpreter 触发不升级为文件深采）。
	if len(plan.Reasons) > 0 {
		if plan.NeedPEInspect {
			plan.NeedHash = true
		}
		plan.NeedCommandLine = true
	}
	return plan
}

// recentFileThresholdDays 文件最近修改时间阈值（天）——近 N 天内修改视为 recent_file。
const recentFileThresholdDays = 7

// isRecentFile 判断文件最近修改时间是否异常（近 recentFileThresholdDays 天内）。
// lastWriteTime 为 ISO8601 字符串（PE Inspect 阶段填充），空视为不可判定（false）。
func isRecentFile(lastWriteTime string) bool {
	if lastWriteTime == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, lastWriteTime)
	if err != nil {
		return false
	}
	return time.Since(t) <= recentFileThresholdDays*24*time.Hour
}

// isNameSpoof 判断进程名是否形如常见系统进程名的伪装变体
// （svchost1.exe / winupdate.exe / lsass.exe 但路径异常等）。
func isNameSpoof(name string) bool {
	lower := strings.ToLower(strings.TrimSuffix(name, ".exe"))
	for _, base := range spoofedNames {
		if lower == base {
			continue // 原名不算伪装
		}
		if strings.HasPrefix(lower, base) && len(lower) > len(base) {
			return true // svchost1 / svchostx ...
		}
	}
	return false
}

// isAbsPath 简化绝对路径判断（Windows 盘符路径 / UNC）。
func isAbsPath(p string) bool {
	if len(p) >= 2 && p[1] == ':' {
		return true
	}
	if strings.HasPrefix(p, `\\`) {
		return true
	}
	return filepath.IsAbs(p)
}
