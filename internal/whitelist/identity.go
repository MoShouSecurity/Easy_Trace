package whitelist

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// identityFields 定义每类实体用于“稳定身份”的字段。
//
// 为什么不能继续只用 (rule_id, entity_id)：entity_id 里有大量不稳定成分——
// process_<pid> 会被系统复用，network 是序号，file 在基础采集下也是序号。
// 同一 ID 在下一次采集时可能指向完全不同的对象，按 ID 抑制会静默隐藏真正的
// 新线索。这里改用实体自身可复核的事实（路径/名称/哈希等）做指纹；PID、
// 采集序号、连接状态这类易变字段刻意排除。
//
// 字段顺序固定，且值为空时也参与计算：同一实体在两次采集里字段缺失与否不同，
// 指纹即不同（宁可多报，也不误抑制）。
var identityFields = map[string][]string{
	"host":        {"hostname"},
	"process":     {"name", "path", "hash_sha256"},
	"network":     {"protocol", "local_ip", "local_port", "remote_ip", "remote_port"},
	"persistence": {"type", "location", "name", "command", "path", "user"},
	"service":     {"service_name", "binary_path"},
	"task":        {"task_name", "command"},
	"driver":      {"name", "path"},
	"user":        {"sid", "username"},
	"file":        {"path", "hash_sha256"},
	"registry":    {"key", "name"},
	"event":       {"channel", "event_id", "record_id", "time_created", "computer", "provider"},
	// prefetch：path（.pf 文件路径）+ prefetch_hash 在同一主机上稳定；executable_name
	// 单独使用会与同名的不同副本混淆，因此与 path 一起参与指纹。
	"prefetch": {"path", "prefetch_hash"},
	// execution：source 区分"运行/打开/历史"；user + name/path/command 是痕迹本身。
	// 运行次数、出现次数与时间会变化，刻意不参与身份指纹。
	"execution": {"source", "user", "name", "path", "command"},
}

// IdentityFields 返回某实体类型的稳定身份字段（只读副本）。
func IdentityFields(entityType string) []string {
	fields, ok := identityFields[entityType]
	if !ok {
		return nil
	}
	return append([]string(nil), fields...)
}

// EntityIdentity 由实体 data JSON 计算稳定身份（SHA256 hex）。
//
// 返回 false 表示实体类型未知或 data 不是合法 JSON；调用方必须按“无法匹配”
// 处理，绝不能退化成只按 entity_id 抑制。
func EntityIdentity(entityType, dataJSON string) (string, bool) {
	fields, ok := identityFields[entityType]
	if !ok {
		return "", false
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(dataJSON), &data); err != nil {
		return "", false
	}
	var b strings.Builder
	b.WriteString(entityType)
	for _, field := range fields {
		b.WriteByte(0)
		b.WriteString(field)
		b.WriteByte('=')
		v, present := data[field]
		if !present {
			// 与“字段存在但为 null”区分开；真实字符串值会被 JSON 引号包裹，
			// 不会与这个标记碰撞。
			b.WriteString("~missing~")
			continue
		}
		b.WriteString(canonicalIdentityValue(field, v))
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:]), true
}

// canonicalIdentityValue 把字段值编码成无歧义、可复现的字符串。
// 路径/注册表键/通道/协议在 Windows 上大小写不敏感，统一小写；
// 其余字符串保留原样（命令参数大小写可能有意义）。
func canonicalIdentityValue(field string, v any) string {
	switch x := v.(type) {
	case nil:
		return "n:null"
	case string:
		s := strings.TrimSpace(x)
		switch field {
		case "path", "binary_path", "location", "key", "channel", "protocol":
			s = strings.ToLower(s)
		}
		encoded, err := json.Marshal(s)
		if err != nil {
			return "s:!unencodable"
		}
		return "s:" + string(encoded)
	default:
		encoded, err := json.Marshal(x)
		if err != nil {
			return "j:!unencodable"
		}
		return "j:" + string(encoded)
	}
}

// EvidenceHashOf 读取实体 data 里已存在的 SHA256（process/file 深采字段）。
// 没有该字段时返回空字符串；绝不临时读取主机文件计算哈希。
func EvidenceHashOf(dataJSON string) string {
	var raw struct {
		HashSHA256 string `json:"hash_sha256"`
	}
	if err := json.Unmarshal([]byte(dataJSON), &raw); err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(raw.HashSHA256))
}

func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
