package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"easytrace/internal/integrity"
	"easytrace/internal/rulelint"
)

// runVerify 处理 verify 子命令（设计原则 P8「自身可信」，离线自校验）：
//
//	easytrace verify [-m|--manifest <file>] [-exe <file>] [-r|--rules <dir>]
//	easytrace verify --write-manifest [-m <file>] [-exe <file>] [-r|--rules <dir>]
//
// 默认校验"当前运行的可执行文件 + 规则目录"与清单是否一致；--write-manifest 用
// 当前文件重新生成清单（构建后调用，见 build.ps1）。
//
// 除清单比对外，还会扫描**成品 exe 字节**是否含"高危连续字串"（见 writeHighRiskScan）：
// 这类特征会被杀软启发式拦截，导致生成的 exe 被拒绝执行，直接破坏"单 exe 交付"。
//
// 边界：清单未签名，只能发现"文件与清单不一致"，不能替代代码签名；不联网、不执行
// 外部程序。exit code：全部一致 0；任一条不一致/缺失/多出、或成品含高危字串 1。
func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	manifestPath := fs.String("m", "", "自校验清单路径（默认与可执行文件同目录的 "+integrity.ManifestName+"）")
	fs.StringVar(manifestPath, "manifest", "", "自校验清单路径别名（-m 同义）")
	exePath := fs.String("exe", "", "被校验的可执行文件（默认当前运行的 exe；也可指向待分发的副本）")
	rulesDir := fs.String("r", "", "规则目录（可选）：留空**只校验 exe**（内嵌规则已含在 exe 哈希内）；指定则把该目录下的规则一并纳入清单")
	fs.StringVar(rulesDir, "rules", "", "规则目录别名（-r 同义）")
	write := fs.Bool("write-manifest", false, "为当前 exe + 规则重新生成清单（会覆盖同名清单）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("用法: verify [--write-manifest] [-m <manifest>] [-exe <exe>] [-r <rules_dir>]")
	}

	exe := *exePath
	if exe == "" {
		actual, err := os.Executable()
		if err != nil {
			return fmt.Errorf("无法定位当前可执行文件（可用 -exe 显式指定）: %w", err)
		}
		exe = actual
	}
	manifest := *manifestPath
	if manifest == "" {
		manifest = filepath.Join(filepath.Dir(exe), integrity.ManifestName)
	}

	if *write {
		m, err := integrity.Build(exe, *rulesDir)
		if err != nil {
			return err
		}
		if err := integrity.Save(manifest, m); err != nil {
			return err
		}
		writeVerifyWritten(os.Stdout, manifest, exe, *rulesDir, m)
		return nil
	}

	m, err := integrity.Load(manifest)
	if err != nil {
		return fmt.Errorf("%w（构建后可先用 verify --write-manifest 生成）", err)
	}
	results, err := integrity.Verify(m, exe, *rulesDir)
	if err != nil {
		return err
	}
	resultsBad := writeVerifyResults(os.Stdout, manifest, exe, *rulesDir, results)
	highRiskBad := writeHighRiskScan(os.Stdout, exe)
	if resultsBad+highRiskBad > 0 {
		return fmt.Errorf("自校验未通过：清单不一致 %d/%d 项，高危字串自检 %d 项（见上。清单未签名，仅能发现与清单的差异）",
			resultsBad, len(results), highRiskBad)
	}
	return nil
}

// writeHighRiskScan 扫描**成品 exe 字节**里是否含"高危连续字串"，返回异常条数（0 或 1）。
//
// 为什么放在 verify：内置规则或源码里一旦出现完整的高危工具名，成品会被杀软启发式拦截
// （fork/exec … Access is denied），直接破坏"单 exe 交付"这一目标。而"规则文件干净"不等于
// "成品干净"——源码字面量、编译期常量拼接、只读数据段里两个字面量恰好相邻，都会让成品
// 重新带上该特征。只有对着成品字节下结论，才能真正覆盖这条链路。
//
// 标记表只有一份（internal/rulelint.Markers），规则目录扫描与之共用，避免多处维护漂移。
// 读不到 exe 不算这里的失败项：清单比对那一节已如实报 unreadable，这里只提示。
func writeHighRiskScan(w io.Writer, exe string) int {
	b, err := os.ReadFile(exe)
	if err != nil {
		fmt.Fprintf(w, "%-10s 高危字串自检：跳过（无法读取可执行文件）\n", "SKIP")
		return 0
	}
	hits := rulelint.FindMarkers(b)
	if len(hits) == 0 {
		fmt.Fprintf(w, "%-10s 高危字串自检：成品不含连续高危工具名（标记 %d 条）\n", "OK", len(rulelint.Markers()))
		return 0
	}
	fmt.Fprintf(w, "%-10s 高危字串自检：成品含连续高危工具名 %v\n", "FAIL", hits)
	fmt.Fprintln(w, "           这类连续特征会被杀软启发式拦截（生成的 exe 被拒绝执行）。")
	fmt.Fprintln(w, "           改法：把该名字拆成两段，用两条 contains 以 AND 组合（语义等价）；见 docs/rules.md「规则作者须知」。")
	return 1
}

// rulesLabel 描述本次校验的规则范围：留空表示"只校验 exe"——内嵌规则已含在 exe 哈希内。
func rulesLabel(rulesDir string) string {
	if strings.TrimSpace(rulesDir) == "" {
		return "(none — embedded rules covered by exe hash)"
	}
	return rulesDir
}

// writeVerifyWritten 打印"已生成清单"的结果。
func writeVerifyWritten(w io.Writer, manifest, exe, rulesDir string, m *integrity.Manifest) {
	fmt.Fprintln(w, "Easy_Trace verify --write-manifest")
	fmt.Fprintf(w, "Manifest: %s\n", manifest)
	fmt.Fprintf(w, "Executable: %s\n", exe)
	fmt.Fprintf(w, "Rules dir: %s\n", rulesLabel(rulesDir))
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Entries: %d\n", len(m.Entries))
	fmt.Fprintln(w, "Note: 清单未签名——只能发现「与清单不一致」，不能替代代码签名（仅分发场景需要）。")
}

// writeVerifyResults 打印逐条比对结果，返回异常条数。
func writeVerifyResults(w io.Writer, manifest, exe, rulesDir string, results []integrity.Result) int {
	fmt.Fprintln(w, "Easy_Trace verify")
	fmt.Fprintf(w, "Manifest: %s\n", manifest)
	fmt.Fprintf(w, "Executable: %s\n", exe)
	fmt.Fprintf(w, "Rules dir: %s\n", rulesLabel(rulesDir))
	fmt.Fprintln(w)

	bad := 0
	for _, r := range results {
		if r.OK() {
			fmt.Fprintf(w, "%-10s %s\n", "OK", r.Label)
			continue
		}
		bad++
		fmt.Fprintf(w, "%-10s %s\n", strings.ToUpper(r.Status), r.Label)
		if r.Want != "" {
			fmt.Fprintf(w, "           manifest: %s\n", r.Want)
		}
		if r.Got != "" {
			fmt.Fprintf(w, "           actual:   %s\n", r.Got)
		}
	}
	fmt.Fprintln(w)
	if bad == 0 {
		fmt.Fprintf(w, "Verified: %d/%d entries match\n", len(results), len(results))
	} else {
		fmt.Fprintf(w, "Verified: %d/%d entries match, %d mismatched\n", len(results)-bad, len(results), bad)
	}
	return bad
}
