// Command easytrace-agent 是 Easy_Trace 的 DFIR 命令行应急响应工具入口。
//
// Easy_Trace 定位：专业 Windows 主机调查与应急响应命令行工具（Step 10）。
// 现场工作流：collect（采集建快照）→ analyze（离线分析）→ investigate（查看线索）
// → inspect（目标深采）→ report（输出报告）。
//
// 安全边界：不联网、不执行外部程序、不自动处置、不常驻。
// 采集逻辑从 Task 1 起逐步加入，协议层见 docs/protocol-spec-v0.2.md（冻结）。
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"easytrace/internal/schema"
)

// cliVersion 是 Easy_Trace 产品版本（展示用）。
const cliVersion = "v0.1.0"

// usage 打印全部命令用法到 w（Step 10 最终命令集）。
func usage(w io.Writer) {
	fmt.Fprintln(w, "Easy_Trace "+cliVersion+" — Windows DFIR 应急响应命令行工具")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "用法: Easy_Trace <command> [options]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "命令:")
	fmt.Fprintln(w, "  collect      采集主机信息并创建快照（--module all 默认；--module file 需 --path + --mode deep）")
	fmt.Fprintln(w, "  analyze      分析快照输出调查线索（默认人类可读，-jsonl 输出 JSONL）")
	fmt.Fprintln(w, "  investigate  查看单条调查线索详情（-id <finding_id>）")
	fmt.Fprintln(w, "  inspect      对目标进程补充深采证据（-pid <pid>，需确认）")
	fmt.Fprintln(w, "  report       生成应急响应报告（report/report.html + findings.json + summary.txt）")
	fmt.Fprintln(w, "  catch        痕迹留存：只读复制命中项指向的文件到新证据目录（catch；配套 report -zip --evidence）")
	fmt.Fprintln(w, "  snapshot     导入/列出/查看/比较 SQLite 快照")
	fmt.Fprintln(w, "  rules        列出/校验本地规则（rules list / rules validate，只读，不访问数据库）")
	fmt.Fprintln(w, "  verify       自校验构建产物（SHA256 清单；--write-manifest 生成清单）")
	fmt.Fprintln(w, "  audit        列出本机操作留痕（-n <N> 最近 N 条，-jsonl 机器可读）")
	fmt.Fprintln(w, "  whitelist    白名单：已确认正常的命中不再出现在报告正文（whitelist add|list|remove）")
	fmt.Fprintln(w, "  version      输出协议版本")
	fmt.Fprintln(w, "  test         输出协议示例数据到 stdout")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "常用参数: 需要数据库的子命令支持 --db <path>（默认 easytrace.db；rules/verify/audit/version/test 不访问数据库）")
	fmt.Fprintln(w, "规则来源: 默认使用**内嵌规则包**；--rules / -r <dir> 覆盖为外部规则目录")
	fmt.Fprintln(w, "运行要求: 除 help / version / verify 外需以管理员身份运行；未提权退出码 3")
}

func main() {
	os.Exit(runMain(os.Args[1:], os.Stdin, os.Stderr))
}

// runCLI 是不带权限门禁的执行核心，供已有单元测试直接调用；生产入口必须经过
// runMain。新增子命令时还要在 elevation.go 中分类，避免遗漏管理员门禁。
//
// runCLI 解析命令行参数并执行，返回进程退出码（Step 10.2 可测性重构：
// stdin：仅无参数分支（双击误操作）用于等待按键；stdin EOF / 管道 /
// 重定向时 Read 立即返回，不阻塞。正常命令绝不读 stdin。
// stderr：全部提示输出（usage / 未知命令 / 子命令错误）的唯一通道。
func runCLI(args []string, stdin io.Reader, stderr io.Writer) int {
	if len(args) < 1 {
		// 无参数 = 通常来自双击误操作：打印用法 + 引导 + 等待按键，
		// 避免控制台窗口一闪而过。cmd 里正常调用都带子命令，不受影响。
		usage(stderr)
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "本程序是命令行工具，请在 cmd 或 PowerShell 中运行:")
		fmt.Fprintln(stderr, "  Easy_Trace <command> [options]")
		fmt.Fprintln(stderr, "例如: Easy_Trace collect / analyze / report")
		fmt.Fprintln(stderr)
		fmt.Fprint(stderr, "按任意键关闭窗口...")
		var b [1]byte
		stdin.Read(b[:])
		fmt.Fprintln(stderr)
		return 2
	}
	// 各子命令统一"执行 → 报错 → 留痕"：错误文案与历史一致（"<verb> 失败: ..."），
	// 留痕只在 CLI 入口记录，直接调用内部函数（单元测试）不留痕。
	verb := args[0]
	var runErr error
	switch verb {
	case "-h", "--help", "help":
		// 帮助请求：打印用法并正常退出（usage 输出到 stderr 与其它提示一致）
		usage(stderr)
		return 0
	case "test":
		runErr = runTest()
	case "collect":
		runErr = runCollect(args[1:])
	case "snapshot":
		runErr = runSnapshot(args[1:])
	case "rules":
		runErr = runRules(args[1:])
	case "analyze":
		runErr = runAnalyze(args[1:])
	case "investigate":
		runErr = runInvestigate(args[1:])
	case "inspect":
		runErr = runInspect(args[1:])
	case "report":
		runErr = runReport(args[1:])
	case "catch":
		runErr = runCatch(args[1:])
	case "verify":
		runErr = runVerify(args[1:])
	case "whitelist":
		runErr = runWhitelist(args[1:])
	case "audit":
		runErr = runAudit(args[1:])
	case "version":
		fmt.Println(schema.Version)
	default:
		fmt.Fprintf(stderr, "未知命令: %q\n", args[0])
		usage(stderr)
		return 2
	}
	code := 0
	if runErr != nil {
		// 子命令 -h/--help：flag.ContinueOnError 以 flag.ErrHelp 返回，usage 已由
		// flag 包打印。这不是失败，也不留痕（帮助请求不接触主机或数据）。
		if errors.Is(runErr, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, verb+" 失败:", runErr)
		code = 1
	}
	recordAudit(verb, args[1:], code, runErr, stderr)
	return code
}
