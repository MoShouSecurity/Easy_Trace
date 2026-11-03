package runtime

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// BehaviorEvent 是一次采集行为（或行为请求）的记录。
// 只描述"采集方请求了什么能力、被授予与否"，不做任何安全判断。
// 字段对应 Step 2.2 冻结格式：time/collector/capability/target/mode/result。
type BehaviorEvent struct {
	Timestamp  time.Time
	Collector  string
	Capability string
	Target     string
	Mode       CollectionMode
	Result     string // allow / deny
}

// BehaviorLogger 记录采集行为事件。
// 默认只收集事件队列（供测试断言与未来结构化输出 / collection_error 上报），
// 不实时输出（低噪声）；EnableOutput 可开启 [behavior] 行实时输出。
type BehaviorLogger struct {
	mu      sync.Mutex
	enabled bool
	out     io.Writer
	events  []BehaviorEvent
}

// NewBehaviorLogger 创建行为日志器；默认不实时输出。
func NewBehaviorLogger(enabled bool) *BehaviorLogger {
	return &BehaviorLogger{enabled: enabled, out: os.Stderr}
}

// EnableOutput 开启实时 [behavior] 行输出（开发诊断用）。
func (l *BehaviorLogger) EnableOutput() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.enabled = true
}

// SetOutput 重定向行为日志输出（测试断言 / 嵌入场景）；nil 恢复 stderr。
func (l *BehaviorLogger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if w == nil {
		w = os.Stderr
	}
	l.out = w
}

// Record 追加一条行为事件；启用实时输出时同步输出 [behavior] 日志行。
func (l *BehaviorLogger) Record(e BehaviorEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, e)
	if l.enabled {
		fmt.Fprintf(l.out, "[behavior] time=%s collector=%s capability=%s target=%s mode=%s result=%s\n",
			e.Timestamp.Format(time.RFC3339Nano), e.Collector, e.Capability, e.Target, e.Mode, e.Result)
	}
}

// Events 返回已记录的全部行为事件（副本，按记录顺序）。
func (l *BehaviorLogger) Events() []BehaviorEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]BehaviorEvent, len(l.events))
	copy(out, l.events)
	return out
}

// Enabled 返回是否实时输出行为日志。
func (l *BehaviorLogger) Enabled() bool { return l.enabled }
