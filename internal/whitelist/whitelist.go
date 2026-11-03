// Package whitelist 实现"按 (rule_id, entity_id) 抑制已确认命中的线索"（V1.0 设计项）。
//
// 设计见 docs/设计-白名单.md。三条不可动摇的底线：
//  1. **只影响报告层**：被抑制的线索仍然存在于快照与 findings.json 里，只是不再打扰读者；
//  2. **可审计**：每条必须有人类可读的 reason 与加入时间/操作者；缺 reason 一律报错；
//  3. **绝不静默**：文件损坏、条目非法、字段缺失都显式报错，而不是"那就当没有白名单"。
//
// 为什么用 JSON 而不是 YAML（设计稿原写 whitelist.yaml）：本文件以**机器写、机器读**为主
// （whitelist add/remove），JSON 的转义交给 encoding/json 即可，不必自己实现 YAML 序列化
// 再担心与极简解析器往返不一致；规则文件仍用 YAML，因为那是人手写的。
package whitelist

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// FileName 是白名单默认文件名（与 easytrace.db 同目录）。
const FileName = "whitelist.json"

// Entry 是一条白名单条目：抑制"这条规则在这个实体上"的命中。
//
// EntityType/Hostname/Identity/EvidenceHash 是**范围与稳定身份**（新增，均可选）：
//   - Hostname 记录加入时的快照主机；只在同一主机上抑制；
//   - EntityType + Identity 记录实体自身的稳定指纹（见 identity.go），避免
//     PID/序号复用后抑制到另一个对象；
//   - EvidenceHash 是实体 data 里已有的 sha256（深采才有；不临时读主机）。
//
// 旧文件里没有这些字段的条目仍按 rule_id + entity_id 匹配（向后兼容），但存在
// entity_id 复用风险；whitelist add 现在会从 --db 的快照里自动补齐这些范围。
type Entry struct {
	RuleID       string `json:"rule_id"`
	EntityID     string `json:"entity_id"`
	Reason       string `json:"reason"`
	AddedAt      string `json:"added_at"`
	AddedBy      string `json:"added_by,omitempty"`
	EntityType   string `json:"entity_type,omitempty"`
	Hostname     string `json:"hostname,omitempty"`
	Identity     string `json:"identity,omitempty"`
	EvidenceHash string `json:"evidence_hash,omitempty"`
}

// File 是白名单文件的整体结构。
type File struct {
	Entries []Entry `json:"entries"`
}

// Load 读取白名单。
//
// **文件不存在**返回空表且不报错（还没建白名单是正常状态）；**文件存在但损坏/条目非法**一律报错
// ——静默当空会让使用者以为"白名单生效了"，实际什么都没抑制。
func Load(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &File{}, nil
		}
		return nil, fmt.Errorf("读取白名单失败 %s: %w", path, err)
	}
	var f File
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("白名单格式非法 %s（应为 {\"entries\":[...]}）: %w", path, err)
	}
	if err := f.validate(); err != nil {
		return nil, fmt.Errorf("白名单条目非法 %s: %w", path, err)
	}
	return &f, nil
}

func (f *File) validate() error {
	seen := map[string]bool{}
	for i, e := range f.Entries {
		where := fmt.Sprintf("第 %d 条", i+1)
		if strings.TrimSpace(e.RuleID) == "" {
			return fmt.Errorf("%s 缺 rule_id", where)
		}
		if strings.TrimSpace(e.EntityID) == "" {
			return fmt.Errorf("%s（%s）缺 entity_id", where, e.RuleID)
		}
		// reason 必填：白名单的价值在于可审计，没有理由的抑制等于静默隐藏。
		if strings.TrimSpace(e.Reason) == "" {
			return fmt.Errorf("%s（%s/%s）缺 reason（抑制必须写明理由）", where, e.RuleID, e.EntityID)
		}
		if e.Identity != "" && !isSHA256Hex(strings.ToLower(strings.TrimSpace(e.Identity))) {
			return fmt.Errorf("%s（%s/%s）identity 必须是 64 位 SHA256 hex", where, e.RuleID, e.EntityID)
		}
		if e.EvidenceHash != "" && !isSHA256Hex(strings.ToLower(strings.TrimSpace(e.EvidenceHash))) {
			return fmt.Errorf("%s（%s/%s）evidence_hash 必须是 64 位 SHA256 hex", where, e.RuleID, e.EntityID)
		}
		key := key(e.RuleID, e.EntityID)
		if seen[key] {
			return fmt.Errorf("%s 重复：%s / %s", where, e.RuleID, e.EntityID)
		}
		seen[key] = true
	}
	return nil
}

func key(ruleID, entityID string) string { return ruleID + "\x00" + entityID }

// BackupSuffix 是 Save 保留上一版白名单的后缀（配置损坏时可人工回退）。
const BackupSuffix = ".bak"

// Save 把白名单写回磁盘（0600：其中可能含环境信息）。
//
// 白名单是**配置**不是证据，因此允许覆盖同名文件；写入内容整体重建，不会残留旧条目。
// 但覆盖必须原子：先写同目录临时文件并 fsync，再 rename 替换。直接 WriteFile 在
// 写到一半崩溃/断电时会留下半截 JSON，下一次 report 会因白名单损坏而全体失败。
// 旧内容同时保留为 <path>.bak（只在内容变化时更新），便于回退与事后核对。
func (f *File) Save(path string) error {
	if err := f.validate(); err != nil {
		return err
	}
	sort.Slice(f.Entries, func(i, j int) bool {
		if f.Entries[i].RuleID != f.Entries[j].RuleID {
			return f.Entries[i].RuleID < f.Entries[j].RuleID
		}
		return f.Entries[i].EntityID < f.Entries[j].EntityID
	})
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化白名单失败: %w", err)
	}
	b = append(b, '\n')

	old, readErr := os.ReadFile(path)
	switch {
	case readErr == nil:
		if !bytes.Equal(old, b) {
			if err := writeAtomic(path+BackupSuffix, old); err != nil {
				return fmt.Errorf("备份旧白名单失败 %s: %w", path+BackupSuffix, err)
			}
		}
	case os.IsNotExist(readErr):
		// 首次创建：没有旧版本可备份。
	default:
		return fmt.Errorf("读取旧白名单失败 %s: %w", path, readErr)
	}
	if err := writeAtomic(path, b); err != nil {
		return fmt.Errorf("写入白名单失败 %s: %w", path, err)
	}
	return nil
}

// writeAtomic 写同目录临时文件 → fsync → rename 覆盖目标。
// 临时文件用 O_EXCL（os.CreateTemp 保证），失败时清理，不触碰目标文件。
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".whitelist-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	closed := false
	cleanup := true
	defer func() {
		if !closed {
			_ = tmp.Close()
		}
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	closed = true
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

// Lookup 判断 (ruleID, entityID) 是否被抑制（不看范围/指纹；用于增删查重）。
func (f *File) Lookup(ruleID, entityID string) (Entry, bool) {
	for _, e := range f.Entries {
		if e.RuleID == ruleID && e.EntityID == entityID {
			return e, true
		}
	}
	return Entry{}, false
}

// LookupScoped 在 (ruleID, entityID) 之外，还要求条目自带的范围/稳定身份与
// 当前实体一致；旧条目（对应字段为空）不施加该限制，保持向后兼容。
//
// 传入的 identity/evidenceHash 为空表示“当前快照无法证明身份”，此时带相应
// 指纹的条目不会匹配——宁可多报，也不能把无法核对的命中原样抑制掉。
func (f *File) LookupScoped(ruleID, entityID, entityType, hostname, identity, evidenceHash string) (Entry, bool) {
	for _, e := range f.Entries {
		if e.RuleID != ruleID || e.EntityID != entityID {
			continue
		}
		if e.EntityType != "" && !strings.EqualFold(strings.TrimSpace(e.EntityType), strings.TrimSpace(entityType)) {
			continue
		}
		if e.Hostname != "" && !strings.EqualFold(strings.TrimSpace(e.Hostname), strings.TrimSpace(hostname)) {
			continue
		}
		if e.Identity != "" && !strings.EqualFold(strings.TrimSpace(e.Identity), strings.TrimSpace(identity)) {
			continue
		}
		if e.EvidenceHash != "" && !strings.EqualFold(strings.TrimSpace(e.EvidenceHash), strings.TrimSpace(evidenceHash)) {
			continue
		}
		return e, true
	}
	return Entry{}, false
}

// Add 追加一条；已存在（同 rule+entity）时报错，避免"以为改了其实没改"。
func (f *File) Add(e Entry) error {
	if strings.TrimSpace(e.RuleID) == "" || strings.TrimSpace(e.EntityID) == "" {
		return fmt.Errorf("必须同时给 --rule 与 --entity")
	}
	if strings.TrimSpace(e.Reason) == "" {
		return fmt.Errorf("必须给 --reason（抑制必须写明理由，便于日后审计）")
	}
	if _, ok := f.Lookup(e.RuleID, e.EntityID); ok {
		return fmt.Errorf("该条目已存在：%s / %s（如需改动请先 remove）", e.RuleID, e.EntityID)
	}
	f.Entries = append(f.Entries, e)
	return nil
}

// Remove 删除一条；不存在返回 false。
func (f *File) Remove(ruleID, entityID string) bool {
	for i, e := range f.Entries {
		if e.RuleID == ruleID && e.EntityID == entityID {
			f.Entries = append(f.Entries[:i], f.Entries[i+1:]...)
			return true
		}
	}
	return false
}
