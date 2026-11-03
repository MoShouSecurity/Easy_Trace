// Package pipeline 实现 Collector Pipeline（Task 8）。
//
// 按注册顺序依次执行多个 Collector，合并各模块的 Entity/Relation/Finding；
// 单模块失败不中断其余模块，错误以列表形式返回。
package pipeline

import (
	"errors"
	"fmt"
	"time"

	"easytrace/internal/collector"
)

// ModuleStat 记录单个模块的执行统计。
type ModuleStat struct {
	Name          string
	Entities      int
	EntityUpdates int
	Relations     int
	Duration      time.Duration
	Err           error
}

// Result 是 Pipeline 的合并结果 + 各模块统计。
type Result struct {
	collector.Result
	Stats []ModuleStat
}

// Pipeline 顺序执行一组 Collector。
type Pipeline struct {
	collectors []collector.Collector
}

// New 创建 Pipeline（按传入顺序执行）。
func New(collectors ...collector.Collector) *Pipeline {
	return &Pipeline{collectors: collectors}
}

// Add 追加 Collector。
func (p *Pipeline) Add(c collector.Collector) *Pipeline {
	p.collectors = append(p.collectors, c)
	return p
}

// Run 依次执行所有 Collector 并合并结果。
// 单模块失败记录到对应 Stat.Err 并继续；返回合并结果（可为空）与是否全部成功。
// 注：Collector 只产 Entity/Relation（Development Rule #1），Finding 由后续 Analyzer 阶段负责。
func (p *Pipeline) Run() (*Result, bool) {
	res := &Result{}
	seenEntity := map[string]bool{}
	// relation_id 只在事件流内唯一：采集器各自从 rel_0001 起编号，合并时由
	// 分配器确定性改名（冲突不丢弃，否则会静默丢事实）。
	relIDs := collector.NewRelationIDAllocator()

	allOK := true
	for _, c := range p.collectors {
		stat := ModuleStat{Name: c.Name()}
		start := time.Now()
		r, err := c.Collect()
		stat.Duration = time.Since(start)
		if err != nil {
			stat.Err = err
			allOK = false
		}
		if r == nil {
			if stat.Err == nil {
				stat.Err = fmt.Errorf("%s: Collect 返回空结果", c.Name())
			}
			allOK = false
			res.Stats = append(res.Stats, stat)
			continue
		}
		for _, e := range r.Entities {
			if e == nil {
				stat.Err = errors.Join(stat.Err, fmt.Errorf("%s: 含空 entity", c.Name()))
				allOK = false
				continue
			}
			if !seenEntity[e.EntityID] {
				seenEntity[e.EntityID] = true
				res.Entities = append(res.Entities, e)
			}
		}
		for _, u := range r.EntityUpdates {
			// entity_update 不按 id 去重：同一实体可有多条补充（补充链语义，协议 §1.2）
			res.EntityUpdates = append(res.EntityUpdates, u)
		}
		for _, rl := range r.Relations {
			if rl == nil {
				stat.Err = errors.Join(stat.Err, fmt.Errorf("%s: 含空 relation", c.Name()))
				allOK = false
				continue
			}
			relIDs.Allocate(c.Name(), rl)
			res.Relations = append(res.Relations, rl)
		}
		// 深采失败分类一并合并（Step 11.5：inspect 错误原因分类数据源）
		res.DeepFailures = append(res.DeepFailures, r.DeepFailures...)
		stat.Entities = len(r.Entities)
		stat.EntityUpdates = len(r.EntityUpdates)
		stat.Relations = len(r.Relations)
		res.Stats = append(res.Stats, stat)
	}
	return res, allOK
}

// Collectors 返回已注册的 Collector（按执行顺序）。
func (p *Pipeline) Collectors() []collector.Collector {
	return p.collectors
}
