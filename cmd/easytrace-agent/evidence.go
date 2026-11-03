package main

import (
	"strings"

	"easytrace/internal/analyzer"
)

// 本文件实现 Finding 的统一证据摘要（Step 12.1）：
//
//   - Process 实体: 一行 Process（PID / Image / CommandLine）+ 一行 File（Path / Hash / Signer）
//   - Persistence 实体: 一行 File（Path / Hash / Signer）+ 一行 Command
//   - Network 实体: 一行 Network（Protocol / Local / State / PID）
//   - 父/子进程、进程关联的网络连接、持久化关联、缺失字段各一行，随附上下文
//
// 原则：字段缺失显式标注 Unavailable，绝不猜测；每个字段只出现一次，
// 保持单行简洁，回答"证据在哪里"而不展开大段解释。

// evidenceSummary 从 FindingContext 生成统一证据摘要行（每行一条）。
// ctx 为 nil 时返回 nil（调用方回退到 Finding.Evidence 原始证据）。
func evidenceSummary(ctx *analyzer.FindingContext) []string {
	if ctx == nil {
		return nil
	}

	var out []string
	switch ctx.EntityType {
	case "process":
		if ctx.Process == nil {
			return nil
		}
		proc := ctx.Process
		out = append(out, "Process: PID "+avail(proc, "pid")+" / Image "+avail(proc, "path")+
			" / CommandLine "+avail(proc, "command_line"))
		out = append(out, "File: Path "+avail(proc, "path")+" / Hash "+avail(proc, "hash_sha256")+
			" / Signer "+signerLabel(proc["signature_state"], proc["signature_valid"], proc["publisher"]))
		if v := ctx.ParentProcess; v != nil && v["name"] != "" {
			line := "Parent: " + v["name"]
			if pid := v["pid"]; pid != "" {
				line += " (PID " + pid + ")"
			}
			out = append(out, line)
		}
		for _, c := range ctx.ChildProcesses {
			line := "Child: " + avail(c, "name")
			if pid := c["pid"]; pid != "" && pid != "0" {
				line += " (PID " + pid + ")"
			}
			out = append(out, line)
		}
		for _, n := range ctx.NetworkConns {
			line := "Network: " + avail(n, "remote_ip")
			if port := n["remote_port"]; port != "" {
				line += ":" + port
			}
			if st := n["state"]; st != "" {
				line += " (" + st + ")"
			}
			out = append(out, line)
		}
		for _, p := range ctx.PersistenceRefs {
			out = append(out, "Persistence: "+avail(p, "type")+" — "+avail(p, "location"))
		}
	case "persistence":
		// EntityData 是当前上下文；Process 保留给旧调用方/旧测试兼容。
		facts := ctx.EntityData
		if facts == nil {
			facts = ctx.Process
		}
		if facts == nil {
			return nil
		}
		// persistence 等文件型实体：无哈希/签名数据，显式 Unavailable。
		out = append(out, "File: Path "+avail(facts, "path")+" / Hash Unavailable / Signer Unavailable")
		if cmd := facts["command"]; cmd != "" {
			out = append(out, "Command: "+cmd)
		}
	case "network":
		if ctx.Network == nil {
			return nil
		}
		// 仅展示 network 实体自身采集到的事实；不从 PID 推断进程身份，
		// 也不把监听端口误写成远程连接。
		out = append(out, "Network: Protocol "+avail(ctx.Network, "protocol")+
			" / Local "+endpointLabel(ctx.Network["local_ip"], ctx.Network["local_port"])+
			" / State "+avail(ctx.Network, "state")+
			" / PID "+avail(ctx.Network, "pid"))
	default:
		return nil
	}

	if len(ctx.MissingEvidence) > 0 {
		out = append(out, "Missing: "+strings.Join(ctx.MissingEvidence, ", "))
	}
	return out
}

// avail 字段值，缺失时显式标注 Unavailable（不猜测）。
func avail(m map[string]string, k string) string {
	if v := m[k]; v != "" {
		return v
	}
	return "Unavailable"
}

// endpointLabel 格式化采集到的 IP/端口；IPv6 加方括号避免地址与端口歧义。
// 缺失字段逐项标注，不能以本地监听事实推断远程端点。
func endpointLabel(ip, port string) string {
	switch {
	case ip == "" && port == "":
		return "Unavailable"
	case ip == "":
		return "IP Unavailable / Port " + port
	case port == "":
		return ip + " / Port Unavailable"
	}
	if strings.Contains(ip, ":") && !strings.HasPrefix(ip, "[") {
		ip = "[" + ip + "]"
	}
	return ip + ":" + port
}

// signerLabel 区分 PE 目录事实与完整验签；旧快照缺失 valid 时不猜测结论。
// false 既可能是信任未通过，也可能是操作失败，不能由此判为 unsigned。
func signerLabel(state, valid, publisher string) string {
	if valid == "true" {
		if publisher != "" {
			return publisher + " (signature verified)"
		}
		return "Signature verified (publisher unavailable)"
	}
	label := "Unavailable"
	switch state {
	case "present":
		label = "PE signature directory present (unverified)"
	case "missing":
		label = "PE signature directory missing (not a trust verdict)"
	}
	if valid == "false" {
		return "Signature verification not confirmed / " + label
	}
	return label
}
