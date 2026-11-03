package collector

import (
	"strconv"
	"strings"

	"easytrace/internal/model"
)

// RelationIDAllocator 在多个采集器合并为一份事件流时隔离 relation_id。
//
// 采集器各自从 rel_0001 起编号（协议 v0.2 §2），单独采集时不会冲突；但
// `collect --module all` 会把 process / network / service 等模块的结果合并，
// 跨模块重名会违反 (snapshot_id, relation_id) 唯一约束。协议规定 relation_id
// 只需在事件流内唯一，因此合并层负责改名：
//
//	首次出现的 ID 原样保留；
//	冲突时依次尝试 <id>_<module>、<id>_<module>2、<id>_<module>3 …
//
// 改名只影响 relation_id，source_id / target_id 不变（analyzer 与报告依赖后者）。
// 分配器永不丢弃 relation：每个输入的 relation 都会得到一个唯一 ID。
type RelationIDAllocator struct {
	used map[string]struct{}
}

// NewRelationIDAllocator 创建空的分配器。
func NewRelationIDAllocator() *RelationIDAllocator {
	return &RelationIDAllocator{used: make(map[string]struct{})}
}

// Allocate 返回 rel 的唯一 relation_id，并在冲突时就地改写 rel.RelationID。
// 返回的 renamed 表示是否发生了改名；rel 为 nil 时返回空串。
//
// module 来自 Collector.Name()（host / process / network / ...），仅用于生成
// 可读后缀，会统一转小写；为空时使用 "module"。
func (a *RelationIDAllocator) Allocate(module string, rel *model.Relation) (id string, renamed bool) {
	if rel == nil {
		return "", false
	}
	original := rel.RelationID
	if _, exists := a.used[original]; !exists {
		a.used[original] = struct{}{}
		return original, false
	}

	suffix := strings.ToLower(strings.TrimSpace(module))
	if suffix == "" {
		suffix = "module"
	}
	candidate := original + "_" + suffix
	if _, exists := a.used[candidate]; exists {
		for n := 2; ; n++ {
			candidate = original + "_" + suffix + strconv.Itoa(n)
			if _, exists := a.used[candidate]; !exists {
				break
			}
		}
	}
	a.used[candidate] = struct{}{}
	rel.RelationID = candidate
	return candidate, true
}
