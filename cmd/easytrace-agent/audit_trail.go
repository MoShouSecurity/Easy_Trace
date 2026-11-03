package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"easytrace/internal/audit"
	"easytrace/internal/integrity"
)

// auditEnvVar 控制操作留痕的位置（设计原则 P8）：
//
//	未设置     → 与可执行文件同目录的 easytrace-audit.log
//	=off      → 关闭留痕（只读介质 / 自动化测试；关闭后本机不再有操作记录）
//	=<path>   → 写入指定文件
const auditEnvVar = "EASYTRACE_AUDIT_LOG"

// auditLogPathOverride 是测试注入口（与 stepTimeout 同风格，避免测试写真实文件）。
var auditLogPathOverride string

// resolveAuditPath 解析留痕文件路径；enabled=false 表示明确关闭或无法定位。
func resolveAuditPath() (string, bool) {
	if p := auditLogPathOverride; p != "" {
		return p, true
	}
	if v := strings.TrimSpace(os.Getenv(auditEnvVar)); v != "" {
		if strings.EqualFold(v, "off") {
			return "", false
		}
		return v, true
	}
	p, err := audit.DefaultPath()
	if err != nil {
		return "", false
	}
	return p, true
}

// auditFlags 描述一个命令允许记录的参数白名单。
type auditFlags struct {
	str   []string
	bools []string
	// multi 是允许重复出现、需要按顺序拼接的字符串参数（如 collect --path/--key）。
	// 只保留最后一个值会丢掉采集范围，事后无法还原。
	multi []string
}

// auditParamSpec 是**逐命令白名单**：只记录可核对的路径/ID/枚举，不记录任何采集数据，
// 也不整体落盘命令行，避免把无关或敏感内容写进留痕。
var auditParamSpec = map[string]auditFlags{
	// collect 的参数决定“采集了哪台主机的哪些范围”（目录、注册表键、PID、事件日志
	// 输出目录、各项上限），属于必须可还原的操作范围。
	"collect": {
		str:   []string{"module", "mode", "db", "pid", "evtx", "recent-hours", "max-files", "depth", "max-values"},
		multi: []string{"path", "key"},
	},
	// snapshot 的 import/show/diff 各有独立开关（mode/from/to），不记录就无法知道
	// 导入模式或比较的是哪两个快照。
	"snapshot":    {str: []string{"db", "mode", "from", "to"}},
	"rules":       {str: []string{"rules"}},
	"analyze":     {str: []string{"db", "snapshot", "rules", "output", "severity", "rule", "entity"}, bools: []string{"jsonl", "silent", "summary"}},
	"investigate": {str: []string{"db", "id", "rules"}},
	"inspect":     {str: []string{"db", "pid", "module", "mode"}},
	"report":      {str: []string{"db", "snapshot", "rules", "output", "events", "evidence", "whitelist"}, bools: []string{"zip", "no-whitelist"}},
	// catch 会**第二次接触主机**（只读复制命中项指向的文件），属必须可追溯的动作：
	// 记下快照、规则来源、证据目录与留存范围下限。白名单参数已废弃（catch 从不
	// 读取白名单），不再记录。
	"catch": {str: []string{"db", "snapshot", "rules", "out", "min-severity"}},
	// whitelist 是**配置变更**（抑制谁、为什么），因此 rule/entity/reason 都要留痕——
	// 白名单的价值在于可审计，留痕里必须有"谁在什么时候抑制了什么、理由是什么"。
	"whitelist": {str: []string{"db", "rule", "entity", "reason", "whitelist"}},
	"verify":    {str: []string{"manifest", "exe", "rules"}, bools: []string{"write-manifest"}},
}

// auditFlagAliases 把简写归一到清单里的规范名，避免同一次调用出现两个键。
var auditFlagAliases = map[string]string{"r": "rules", "o": "output", "m": "manifest", "f": "file", "w": "whitelist"}

// auditVerbAliases 覆盖个别命令与全局简写不一致的情况：catch 的 -o 是 --out，
// 不是 --output；沿用全局表会让 `catch -o <dir>` 完全落不进留痕。
var auditVerbAliases = map[string]map[string]string{
	"catch": {"o": "out"},
}

// auditActionVerbs 是带子命令的 verb：第一个位置参数是动作（snapshot import /
// whitelist remove …）。不记录动作就无法区分 `whitelist add` 与 `whitelist remove`。
var auditActionVerbs = map[string]bool{"snapshot": true, "rules": true, "whitelist": true}

// auditParams 按白名单从子命令参数里提取可核对参数；未知参数一律忽略。
func auditParams(verb string, args []string) map[string]string {
	spec, ok := auditParamSpec[verb]
	if !ok {
		return nil
	}
	isStr := map[string]bool{}
	for _, name := range spec.str {
		isStr[name] = true
	}
	isBool := map[string]bool{}
	for _, name := range spec.bools {
		isBool[name] = true
	}
	isMulti := map[string]bool{}
	for _, name := range spec.multi {
		isMulti[name] = true
		isStr[name] = true
	}

	params := map[string]string{}
	// 子命令动作（snapshot/rules/whitelist）固定是第一个位置参数。
	if auditActionVerbs[verb] && len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		params["action"] = args[0]
	}
	for i := 0; i < len(args); i++ {
		token := args[i]
		if len(token) < 2 || token[0] != '-' {
			continue
		}
		name := strings.TrimLeft(token, "-")
		value := ""
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			name, value = name[:eq], name[eq+1:]
		}
		if canonical, ok := auditVerbAliases[verb][name]; ok {
			name = canonical
		} else if canonical, ok := auditFlagAliases[name]; ok {
			name = canonical
		}
		switch {
		case isBool[name]:
			if value == "" {
				value = "true"
			}
			params[name] = value
		case isStr[name]:
			// 与 Go flag 的解析语义一致：非 bool 参数总是消费下一个 token，
			// 即使它本身以 '-' 开头（`--output -weird` 的值就是 "-weird"）。
			if value == "" && i+1 < len(args) {
				i++
				value = args[i]
			}
			if value != "" {
				if isMulti[name] && params[name] != "" {
					params[name] += "," + value
				} else {
					params[name] = value
				}
			}
		}
	}
	if len(params) == 0 {
		return nil
	}
	return params
}

// operatorLabel 返回尽力而为的操作者标识（USERDOMAIN\USERNAME）。它不是身份认证，
// 只是当时的登录上下文；缺失时留空。
func operatorLabel() string {
	user := strings.TrimSpace(os.Getenv("USERNAME"))
	domain := strings.TrimSpace(os.Getenv("USERDOMAIN"))
	switch {
	case user == "":
		return ""
	case domain == "":
		return user
	default:
		return domain + `\` + user
	}
}

var (
	exeSelfHashOnce sync.Once
	exeSelfHash     string
)

// runningExeHash 返回当前可执行文件的 SHA256（进程内只算一次），失败则为空。
// 把二进制哈希写进留痕，让"哪一份 exe 做了这些动作"可事后核对。
func runningExeHash() string {
	exeSelfHashOnce.Do(func() {
		exe, err := os.Executable()
		if err != nil {
			return
		}
		if h, err := integrity.HashFile(exe); err == nil {
			exeSelfHash = h
		}
	})
	return exeSelfHash
}

// truncateDetail 限制错误详情长度，避免把超长文本写进留痕。
func truncateDetail(s string) string {
	const max = 200
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max]) + "…"
}

// recordAudit 在 CLI 入口为一次命令调用追加留痕。
//
// 留痕失败只向 stderr 警告，**不改变命令退出码**：命令本身可能已经成功（例如采集
// 已完成），不应因为在只读介质上写不了日志而报失败——但操作者必须看到这行警告。
func recordAudit(verb string, args []string, code int, execErr error, stderr io.Writer) {
	if verb == "" || verb == "audit" || verb == "-h" || verb == "--help" || verb == "help" {
		return
	}
	path, enabled := resolveAuditPath()
	if !enabled {
		return
	}
	result := "ok"
	if execErr != nil || code != 0 {
		result = "failed"
	}
	detail := ""
	if execErr != nil {
		detail = execErr.Error()
	}
	entry := audit.Entry{
		Operator:    operatorLabel(),
		Verb:        verb,
		Result:      result,
		ToolVersion: cliVersion,
		ExeSHA256:   runningExeHash(),
		Params:      auditParams(verb, args),
		Detail:      truncateDetail(detail),
	}
	if _, err := audit.Append(path, entry); err != nil {
		fmt.Fprintf(stderr, "警告: 操作留痕写入失败（%s）: %v\n", path, err)
	}
}
