package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"easytrace/internal/analyzer"
)

// runRules handles read-only local rule-pack commands:
//
//	easytrace rules list [-r|--rules <dir>]
//	easytrace rules validate [-r|--rules <dir>]
//
// Both commands only load local YAML files through FileRuleProvider. They do
// not open SQLite, collect host data, or modify the rule pack.
func runRules(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法: rules <list|validate> [-r <rules_dir>]")
	}

	switch args[0] {
	case "list":
		rules, source, err := loadLocalRules("list", args[1:])
		if err != nil {
			return err
		}
		writeRulesList(os.Stdout, rules, source)
		return nil
	case "validate":
		rules, source, err := loadLocalRules("validate", args[1:])
		if err != nil {
			return err
		}
		writeRulesValidate(os.Stdout, rules, source)
		return nil
	default:
		return fmt.Errorf("未知 rules 子命令: %q（可用: list, validate）", args[0])
	}
}

func loadLocalRules(command string, args []string) ([]*analyzer.Rule, string, error) {
	fs := flag.NewFlagSet("rules "+command, flag.ContinueOnError)
	rulesDir := fs.String("r", "", "规则目录；留空使用**内嵌规则包**（单 exe 即可用），指定则覆盖")
	fs.StringVar(rulesDir, "rules", "", "规则目录别名（-r 同义；留空用内嵌规则包）")
	if err := fs.Parse(args); err != nil {
		return nil, "", err
	}
	if fs.NArg() != 0 {
		return nil, "", fmt.Errorf("用法: rules %s [-r <rules_dir>]", command)
	}
	return loadRules(*rulesDir)
}

// writeRulesList prints enabled rules in the provider's stable rule_id order.
func writeRulesList(w io.Writer, rules []*analyzer.Rule, source string) {
	fmt.Fprintln(w, "Rules")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Pack: %s\n", source)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%-40s %-8s %-12s %-14s %s\n", "RULE ID", "SEVERITY", "TARGET", "CATEGORY", "SOURCE")
	for _, rule := range rules {
		fmt.Fprintf(w, "%-40s %-8s %-12s %-14s %s\n", rule.RuleID, rule.Severity, rule.Target, ruleCategory(rule.Source), rule.Source)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Total rules: %d\n", len(rules))
}

// writeRulesValidate reports the result of loading and validating a local rule
// pack. Rules that depend on deep collection are listed explicitly so a Basic
// snapshot is not mistaken for evidence that those indicators were checked.
func writeRulesValidate(w io.Writer, rules []*analyzer.Rule, source string) {
	fmt.Fprintln(w, "Rule pack validation passed.")
	fmt.Fprintf(w, "Pack: %s\n", source)
	fmt.Fprintf(w, "Rules: %d\n", len(rules))
	fmt.Fprintf(w, "Files: %d\n", len(distinctRuleFiles(rules)))

	var deepRules []string
	for _, rule := range rules {
		if ruleNeedsDeepCollection(rule) {
			deepRules = append(deepRules, rule.RuleID)
		}
	}
	if len(deepRules) == 0 {
		fmt.Fprintln(w, "Deep collection required: none")
		return
	}
	fmt.Fprintln(w, "Deep collection required:")
	for _, ruleID := range deepRules {
		fmt.Fprintln(w, "  - "+ruleID)
	}
}

func distinctRuleFiles(rules []*analyzer.Rule) []string {
	seen := make(map[string]bool, len(rules))
	for _, rule := range rules {
		if rule.Source != "" {
			seen[rule.Source] = true
		}
	}
	files := make([]string, 0, len(seen))
	for source := range seen {
		files = append(files, source)
	}
	sort.Strings(files)
	return files
}

func ruleCategory(source string) string {
	parts := strings.Split(filepath.ToSlash(source), "/")
	if len(parts) > 1 && parts[0] != "" && parts[0] != "." {
		return parts[0]
	}
	return "root"
}

// ruleNeedsDeepCollection 委托给 analyzer 的唯一名单（避免两处硬编码漂移）。
func ruleNeedsDeepCollection(rule *analyzer.Rule) bool {
	return analyzer.RuleNeedsDeepCollection(rule)
}
