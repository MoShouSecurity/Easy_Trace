package runtime

import "time"

// capabilityField 将能力名映射到 Capability 字段。
// 未注册的能力名一律拒绝（deny by default）。
var capabilityField = map[string]func(Capability) bool{
	"ReadProcessMemory": func(c Capability) bool { return c.ReadProcessMemory },
	"ReadFile":          func(c Capability) bool { return c.ReadFile },
	"HashFile":          func(c Capability) bool { return c.HashFile },
	"VerifySignature":   func(c Capability) bool { return c.VerifySignature },
	"NetworkQuery":      func(c Capability) bool { return c.NetworkQuery },
	"RegistryQuery":     func(c Capability) bool { return c.RegistryQuery },
	"ServiceQuery":      func(c Capability) bool { return c.ServiceQuery },
	"TaskQuery":         func(c Capability) bool { return c.TaskQuery },
	"DriverQuery":       func(c Capability) bool { return c.DriverQuery },
	"ExternalCommand":   func(c Capability) bool { return c.ExternalCommand },
	"UserQuery":         func(c Capability) bool { return c.UserQuery },
	"EventQuery":        func(c Capability) bool { return c.EventQuery },
	"PrefetchQuery":     func(c Capability) bool { return c.PrefetchQuery },
}

// Runtime 是全局采集行为控制中心（Collector Behavior Layer）：
//   - 持有当前 CollectionMode 与被授予的 Capability
//   - Allow() 为 Collector 提供"该能力是否被授权"的判定（deny by default）
//   - 记录全部行为事件（BehaviorLogger），可开启实时 [behavior] 输出
//
// 职责边界：只治理"怎么采"，不做任何安全判断 / 评分 / 威胁识别
// （那些属于 Analyzer，见开发规则 2 / 6）。
type Runtime struct {
	mode   CollectionMode
	caps   Capability
	logger *BehaviorLogger
}

// New 创建绑定指定模式的行为控制 Runtime。
func New(mode CollectionMode) *Runtime {
	return &Runtime{
		mode:   mode,
		caps:   Capabilities(mode),
		logger: NewBehaviorLogger(false), // 默认只收集事件，不实时输出（低噪声）
	}
}

// NewWithCapabilities 创建自定义能力集合的 Runtime。
// 生产路径请使用 New(mode) 走冻结的模式映射（Step 2.2）；此入口用于测试
// 验证门卫行为（如构造拒绝特定能力的 Runtime）与特殊嵌入场景。
func NewWithCapabilities(mode CollectionMode, caps Capability) *Runtime {
	return &Runtime{mode: mode, caps: caps, logger: NewBehaviorLogger(false)}
}

// Mode 返回当前采集模式。
func (r *Runtime) Mode() CollectionMode { return r.mode }

// Capabilities 返回当前被授予的能力集合。
func (r *Runtime) Capabilities() Capability { return r.caps }

// Logger 返回行为日志器（供测试断言与未来结构化输出）。
func (r *Runtime) Logger() *BehaviorLogger { return r.logger }

// Allow 判定 collector 请求的 capability 是否被当前模式授权。
// collector 是模块名（process/network/...），target 是行为对象描述（如 "pid:1234"）。
// 每次判定都会被记录为一条行为事件。
func (r *Runtime) Allow(collector, capability, target string) bool {
	check, ok := capabilityField[capability]
	allowed := ok && check(r.caps)
	r.logger.Record(BehaviorEvent{
		Timestamp:  time.Now(),
		Collector:  collector,
		Capability: capability,
		Target:     target,
		Mode:       r.mode,
		Result:     resultString(allowed),
	})
	return allowed
}

// AllowFn 返回绑定 collector 名的 Allow 函数（便于传入采集实现）。
func (r *Runtime) AllowFn(collector string) func(capability, target string) bool {
	return func(capability, target string) bool {
		return r.Allow(collector, capability, target)
	}
}

func resultString(allowed bool) string {
	if allowed {
		return "allow"
	}
	return "deny"
}
