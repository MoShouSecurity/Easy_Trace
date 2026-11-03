package analyzer

import (
	"net"
	"strings"
)

// isOutboundConnection 判断一个 network 实体是否代表「对外连接」。
//
// 采集器对所有有 PID 的端点都生成 network_connect 关系（包括 LISTENING、回环、
// UDP 未连接的 0.0.0.0:0）。这是正确的事实留存，但**不能**直接当作“进程联网”：
// 用户目录里的正常程序监听 8080 不是对外连接。检测侧（process.user_path.network、
// 关系传导）必须只看真正发起的连接。
//
// 判据（全部来自实体事实，不推断）：
//   - state 不是 LISTENING（TCP 监听；UDP 端点没有 state）；
//   - remote_ip 非空，且不是未指定地址（0.0.0.0 / ::）；
//   - remote_ip 不是回环（127.0.0.0/8、::1、IPv4-mapped 回环）；
//   - remote_port 非 0（未连接套接字的占位值）。
func isOutboundConnection(data map[string]any) bool {
	if strings.EqualFold(strings.TrimSpace(stringify(data["state"])), "LISTENING") {
		return false
	}

	remote := strings.TrimSpace(stringify(data["remote_ip"]))
	if remote == "" {
		return false
	}
	if ip := parseIPFact(remote); ip != nil {
		if ip.IsUnspecified() || ip.IsLoopback() {
			return false
		}
	}

	port := strings.TrimSpace(stringify(data["remote_port"]))
	if port == "" || port == "0" {
		return false
	}
	return true
}

// parseIPFact 解析实体里的 IP 文本（兼容 IPv6 方括号与 zone 后缀）。
func parseIPFact(s string) net.IP {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	if i := strings.LastIndexByte(s, '%'); i >= 0 {
		s = s[:i]
	}
	return net.ParseIP(s)
}
