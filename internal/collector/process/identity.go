package process

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"easytrace/internal/model"
)

// ValidateInspectIdentity 要求可核验的进程身份；旧秒级快照只读使用，不再追加深采。
func ValidateInspectIdentity(data model.ProcessData) error {
	if data.PID == 0 || !filepath.IsAbs(data.Path) || strings.HasSuffix(data.Path, `\`) ||
		strings.HasSuffix(data.Path, "/") || filepath.Clean(data.Path) == filepath.VolumeName(data.Path) {
		return fmt.Errorf("进程身份缺少 PID 或完整绝对路径，请重新 Basic collect 后再 inspect")
	}
	created, err := time.Parse(time.RFC3339Nano, data.CreationTime)
	if err != nil || created.IsZero() {
		return fmt.Errorf("进程创建时间不可核验，请重新 Basic collect 后再 inspect")
	}
	dot := strings.IndexByte(data.CreationTime, '.')
	digits := 0
	if dot >= 0 {
		for i := dot + 1; i < len(data.CreationTime) && data.CreationTime[i] >= '0' && data.CreationTime[i] <= '9'; i++ {
			digits++
		}
	}
	if digits < 7 || digits > 9 || created.Nanosecond()%100 != 0 {
		return fmt.Errorf("进程创建时间精度不足（需要 100ns），请重新 Basic collect 后再 inspect")
	}
	return nil
}

// MatchInspectIdentity 同时比较 PID、路径与创建时间，不把相同路径当成相同进程。
func MatchInspectIdentity(expected, actual model.ProcessData) error {
	if err := ValidateInspectIdentity(expected); err != nil {
		return err
	}
	if err := ValidateInspectIdentity(actual); err != nil {
		return err
	}
	before, _ := time.Parse(time.RFC3339Nano, expected.CreationTime)
	after, _ := time.Parse(time.RFC3339Nano, actual.CreationTime)
	if expected.PID != actual.PID || canonPath(expected.Path) != canonPath(actual.Path) || !before.Equal(after) {
		return fmt.Errorf("进程身份不一致，PID 可能已复用；未保存补证，请重新 Basic collect 后再 inspect")
	}
	return nil
}

// WithExpectedIdentity 仅用于已确认的定向补证，不改变普通 Basic/Deep 的查询范围。
func (c *Collector) WithExpectedIdentity(expected model.ProcessData) *Collector {
	c.expected = &expected
	return c
}

// checkLiveIdentity 只做有限权限查询。前后检查不等价于全流程持有同一进程/文件句柄。
func (c *Collector) checkLiveIdentity() error {
	path, reason := queryProcessPathFn(c.pidFilter)
	if reason != "" {
		return fmt.Errorf("目标身份路径查询失败: %s（未保存补证）", reason)
	}
	created, reason := queryCreationTimeFn(c.pidFilter)
	if reason != "" {
		return fmt.Errorf("目标身份创建时间查询失败: %s（未保存补证）", reason)
	}
	return MatchInspectIdentity(*c.expected, model.ProcessData{
		PID: c.pidFilter, Path: path, CreationTime: created,
	})
}
