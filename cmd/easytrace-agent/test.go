package main

import (
	"fmt"
	"os"
	"time"

	"easytrace/internal/model"
	"easytrace/internal/output"
	"easytrace/internal/protocol"
	"easytrace/internal/schema"
)

// runTest 输出一组覆盖 entity / relation / finding 三类消息的示例数据。
// 所有消息先过协议校验再输出，保证 result.jsonl 每行都合法。
func runTest() error {
	w := output.NewWriter(os.Stdout)
	defer w.Close()

	now := time.Now().UTC()

	// 1) entity: host（Task 1 的数据形态）
	host := model.NewEntity("host", "host_PC-001", model.HostData{
		Hostname:     "PC-001",
		OSVersion:    "Windows 11 Pro",
		OSBuild:      "22631",
		Architecture: "x64",
		Username:     "sec",
		CurrentTime:  now.Format(time.RFC3339),
	})
	if err := writeValid(w, host); err != nil {
		return err
	}

	// 2) entity: process ×2（Task 2 的数据形态）
	proc1 := model.NewEntity("process", "process_100", model.ProcessData{
		PID:         100,
		Name:        "winword.exe",
		Path:        `C:\Program Files\Microsoft Office\winword.exe`,
		ParentPID:   812,
		CommandLine: `"C:\Program Files\Microsoft Office\winword.exe" /safe`,
		Username:    "sec",
		Session:     1,
		Windowed:    true,
		Signed:      true,
	})
	proc2 := model.NewEntity("process", "process_200", model.ProcessData{
		PID:         200,
		Name:        "powershell.exe",
		Path:        `C:\Windows\System32\powershell.exe`,
		ParentPID:   100,
		CommandLine: "powershell -enc SQBFAFgA...",
		Username:    "sec",
		Session:     1,
		Windowed:    false,
		Signed:      true,
	})
	if err := writeValid(w, proc1); err != nil {
		return err
	}
	if err := writeValid(w, proc2); err != nil {
		return err
	}

	// 3) relation: spawn（winword.exe 启动 powershell.exe）
	rel := model.NewRelation("rel_0001", "process_100", "process_200", "spawn",
		map[string]string{"command": "powershell -enc SQBFAFgA..."})
	if err := writeValid(w, rel); err != nil {
		return err
	}

	// 4) finding: 示例判定结果
	find := model.NewFinding(
		"finding_0001",
		"R-201",
		"疑似远控（弱信号组合）",
		"未签名进程 + 公网外联 + 启动项",
		"critical",
		"process_200",
		[]string{"ip_45_33_32_156", "registry_run_1"},
		[]string{"未签名", "外联 45.33.32.156:443", "Run 键启动项"},
		[]string{"联动取证: 进程dump", "核查启动项来源"},
	)
	if err := writeValid(w, find); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "schema_version=%s: 输出 3 条 entity, 1 条 relation, 1 条 finding\n",
		schema.Version)
	return nil
}

// writeValid 先按协议校验，通过后写入 JSONL。
func writeValid(w *output.Writer, v any) error {
	switch t := v.(type) {
	case *model.Entity:
		if err := protocol.ValidateEntity(t); err != nil {
			return err
		}
	case *model.Relation:
		if err := protocol.ValidateRelation(t); err != nil {
			return err
		}
	case *model.Finding:
		if err := protocol.ValidateFinding(t); err != nil {
			return err
		}
	default:
		return fmt.Errorf("不支持的消息类型 %T", v)
	}
	return w.Write(v)
}
