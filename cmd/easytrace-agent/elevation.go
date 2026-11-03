package main

import (
	"fmt"
	"io"

	"easytrace/internal/platform/privilege"
)

// exitNotElevated 与命令失败（1）和用法错误（2）分开：门禁在解析参数、
// 打开数据库或接触主机之前拒绝执行，调用方可以据此区分“未提权，未执行”。
const exitNotElevated = 3

// elevationExemptVerbs 是不接触主机、也不需要管理员权限的入口。
// verify 必须保留在豁免列表中：build.ps1 会在普通 shell 中运行它做构建自检。
var elevationExemptVerbs = map[string]bool{
	"help":    true,
	"-h":      true,
	"--help":  true,
	"version": true,
	"verify":  true,
}

// elevationGatedVerbs 与 runCLI 的 switch 保持一致。新增命令时必须在这里分类，
// 否则未知命令仍由 runCLI 报“未知命令”，不会被误当成需要管理员的有效命令。
var elevationGatedVerbs = map[string]bool{
	"test":        true,
	"collect":     true,
	"snapshot":    true,
	"rules":       true,
	"analyze":     true,
	"investigate": true,
	"inspect":     true,
	"report":      true,
	"catch":       true,
	"whitelist":   true,
	"audit":       true,
}

// isHelpToken 覆盖 Go flag 包接受的三种帮助写法。
func isHelpToken(arg string) bool {
	return arg == "-h" || arg == "--help" || arg == "-help"
}

// isSubcommandHelp 只检查固定的帮助位置，不把任意位置的 -h 当成豁免：
// 例如 collect --db -h 中的 -h 是 --db 的值，不应绕过门禁。
// test 不使用 flag 解析参数，test -h 仍会执行 runTest，因此不在此豁免。
func isSubcommandHelp(verb string, args []string) bool {
	if verb != "test" && len(args) == 2 && isHelpToken(args[1]) {
		return true
	}
	// rules/snapshot/whitelist 的第一个参数是动作，第二个才是该动作的 flag。
	switch verb {
	case "rules", "snapshot", "whitelist":
		return len(args) == 3 && isHelpToken(args[2])
	default:
		return false
	}
}

// checkElevationGate 是纯决策函数，便于在不接触真实主机的情况下测试全部分支。
// 返回 blocked=true 时，调用方必须直接返回 code，不得继续执行 runCLI。
func checkElevationGate(args []string, elevated bool, stderr io.Writer) (blocked bool, code int) {
	if len(args) == 0 {
		return false, 0
	}
	verb := args[0]
	if elevationExemptVerbs[verb] || !elevationGatedVerbs[verb] || isSubcommandHelp(verb, args) || elevated {
		return false, 0
	}
	fmt.Fprintln(stderr, "Easy_Trace 需要管理员权限才能运行此命令。")
	fmt.Fprintln(stderr, "请右键 Easy_Trace.exe，选择“以管理员身份运行”；或在已以管理员身份运行的 PowerShell / cmd 中执行。")
	fmt.Fprintln(stderr, "本次未执行任何采集、数据库或文件操作。help、version、verify 不需要管理员权限。")
	return true, exitNotElevated
}

// runMainWith 是带权限结果注入的生产入口包装，供离线测试使用。
// 未通过门禁时不会调用 runCLI，也不会写操作留痕。
func runMainWith(args []string, stdin io.Reader, stderr io.Writer, elevated bool) int {
	if blocked, code := checkElevationGate(args, elevated, stderr); blocked {
		return code
	}
	return runCLI(args, stdin, stderr)
}

// runMain 是实际的 CLI 入口。只读取当前进程 Token，不自动提权、不弹 UAC、
// 不重启自身；要求操作者先以管理员身份启动工具。
func runMain(args []string, stdin io.Reader, stderr io.Writer) int {
	return runMainWith(args, stdin, stderr, privilege.Detect().IsElevated)
}
