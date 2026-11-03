package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"easytrace/internal/audit"
)

// runAudit 处理 audit 子命令：列出本机操作留痕（只读，不产生新的留痕）。
//
//	easytrace audit [-f|--file <path>] [-n <N>] [-jsonl]
//
// 默认读取与可执行文件同目录的 easytrace-audit.log；-n 控制显示最近多少条（0=全部）。
// 留痕文件里有无法解析的行时，仍会列出其余记录，但返回非零退出码——"少了几条"
// 不能被当成完整记录。
func runAudit(args []string) error {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	file := fs.String("f", "", "留痕文件路径（默认与可执行文件同目录的 "+audit.DefaultFileName+"）")
	fs.StringVar(file, "file", "", "留痕文件路径别名（-f 同义）")
	limit := fs.Int("n", 20, "显示最近 N 条（0=全部）")
	jsonl := fs.Bool("jsonl", false, "以 JSONL 输出（默认人类可读）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("用法: audit [-f <file>] [-n <N>] [-jsonl]")
	}

	path := *file
	if path == "" {
		resolved, enabled := resolveAuditPath()
		if !enabled {
			return fmt.Errorf("操作留痕已关闭（%s=off），没有可列出的记录", auditEnvVar)
		}
		path = resolved
	}

	entries, corrupt, err := audit.List(path, *limit)
	if err != nil {
		return fmt.Errorf("读取留痕失败: %w", err)
	}
	if *jsonl {
		if err := writeAuditJSONL(os.Stdout, entries); err != nil {
			return err
		}
	} else {
		writeAuditText(os.Stdout, path, entries)
	}
	if len(corrupt) > 0 {
		return fmt.Errorf("留痕文件有 %d 行无法解析（行号: %s）", len(corrupt), joinInts(corrupt))
	}
	// 哈希链只能发现“按原样修改/删除后重新拼接”的痕迹，不是签名；
	// 旧版本写入的记录没有 hash 字段，同样会出现在这里（如实说明，不假装验证通过）。
	broken, err := audit.Verify(path)
	if err != nil {
		return fmt.Errorf("校验留痕哈希链失败: %w", err)
	}
	if len(broken) > 0 {
		return fmt.Errorf("留痕哈希链校验失败：%d 行与记录不符（行号: %s）；文件可能被修改，或含旧版本无 hash 记录", len(broken), joinInts(broken))
	}
	return nil
}

// writeAuditText 打印人类可读的留痕列表（字段固定、按序号升序）。
func writeAuditText(w io.Writer, path string, entries []audit.Entry) {
	fmt.Fprintln(w, "Easy_Trace audit")
	fmt.Fprintf(w, "File: %s\n", path)
	fmt.Fprintln(w)
	if len(entries) == 0 {
		fmt.Fprintln(w, "Total: 0 entries（文件不存在或还没有记录）")
		return
	}
	fmt.Fprintf(w, "%-5s %-22s %-22s %-12s %s\n", "SEQ", "TIME(UTC)", "OPERATOR", "VERB", "RESULT")
	for _, e := range entries {
		operator := e.Operator
		if operator == "" {
			operator = "-"
		}
		result := e.Result
		if e.Detail != "" {
			result += " (" + e.Detail + ")"
		}
		fmt.Fprintf(w, "%-5d %-22s %-22s %-12s %s\n", e.Seq, e.TimeUTC, operator, e.Verb, result)
	}
	fmt.Fprintf(w, "\nTotal: %d entries\n", len(entries))
}

// writeAuditJSONL 以 JSONL 输出留痕（一行一条，字段顺序固定）。
func writeAuditJSONL(w io.Writer, entries []audit.Entry) error {
	for _, e := range entries {
		line, err := json.Marshal(e)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, string(line)); err != nil {
			return err
		}
	}
	return nil
}

// joinInts 把行号列表渲染成 "1, 5, 9"。
func joinInts(values []int) string {
	parts := make([]string, 0, len(values))
	for _, v := range values {
		parts = append(parts, fmt.Sprintf("%d", v))
	}
	return strings.Join(parts, ", ")
}
