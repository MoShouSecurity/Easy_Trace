package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"easytrace/internal/collector"
	"easytrace/internal/storage"
)

// collectUI 负责 collect 的终端展示。
//
// 设计边界：
//   - 只在 stdout 是终端时启用“人类可读模式”，此时不再把 JSONL 打到屏幕；
//     JSONL 仍写入临时文件并导入 SQLite，不改变数据链路。
//   - stdout 被重定向/管道时保持原 JSONL 输出，自动化不受影响。
//   - 进度以模块为单位；单个模块内部的细粒度计数由后续 ProgressReporter 扩展。
type collectUI struct {
	out         io.Writer
	total       int
	human       bool // stdout 是终端：隐藏 JSONL，输出摘要
	interactive bool // stderr 也是终端：显示 spinner/进度条

	mu        sync.Mutex
	completed int
	index     int
	name      string
	frame     int
	stop      chan struct{}
	done      chan struct{}
	entities  int
	updates   int
	relations int
}

func newCollectUI(out io.Writer, total int, human, interactive bool) *collectUI {
	return &collectUI{out: out, total: total, human: human, interactive: interactive}
}

func (u *collectUI) header(mode, dbPath string) {
	if u.human {
		fmt.Fprintf(u.out, "Easy_Trace collect  mode=%s  ->  %s\n\n", mode, dbPath)
		return
	}
	fmt.Fprintln(u.out, "Collection started")
	fmt.Fprintln(u.out)
}

func (u *collectUI) startModule(i int, name string) {
	u.mu.Lock()
	u.stopSpinnerLocked()
	u.index = i
	u.name = name
	u.frame = 0
	u.completed = i
	if !u.interactive {
		fmt.Fprintf(u.out, "[%d/%d] %s\n", i+1, u.total, name)
		u.mu.Unlock()
		return
	}
	stop, done := make(chan struct{}), make(chan struct{})
	u.stop, u.done = stop, done
	u.mu.Unlock()
	go u.spin(stop, done)
}

func (u *collectUI) spin(stop, done chan struct{}) {
	defer close(done)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	frames := []string{"|", "/", "-", "\\"}
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			u.mu.Lock()
			if u.total <= 1 {
				// 单模块没有可靠的阶段总数：只显示 spinner，不伪造百分比。
				fmt.Fprintf(u.out, "\r[1/1] %-16s %s working...",
					shortName(u.name, 16), frames[u.frame%len(frames)])
			} else {
				pct := u.percentLocked()
				fmt.Fprintf(u.out, "\r[%d/%d] %-16s [%s] %3d%% %s",
					u.index+1, u.total, shortName(u.name, 16), progressBar(pct, 12), pct, frames[u.frame%len(frames)])
			}
			u.frame++
			u.mu.Unlock()
		}
	}
}

func (u *collectUI) finishModule(res *collector.Result, err error, dur time.Duration, unit string) {
	u.mu.Lock()
	u.stopSpinnerLocked()
	done := u.done
	u.done = nil
	u.mu.Unlock()
	if done != nil {
		<-done
	}

	u.mu.Lock()
	defer u.mu.Unlock()
	u.completed = u.index + 1
	if u.human && u.interactive {
		u.clearLineLocked()
	}

	if !u.human {
		if err != nil {
			fmt.Fprintf(u.out, "      Failed: %v（有效部分结果仍保留）\n", err)
		}
		if res != nil {
			fmt.Fprintf(u.out, "      %d %s\n\n", len(res.Entities), unit)
		}
		return
	}

	status := "OK"
	if err != nil {
		status = "FAIL"
	}
	parts := make([]string, 0, 3)
	if res != nil {
		parts = append(parts, fmt.Sprintf("%d %s", len(res.Entities), unit))
		if len(res.EntityUpdates) > 0 {
			parts = append(parts, fmt.Sprintf("%d updates", len(res.EntityUpdates)))
		}
		if len(res.Relations) > 0 {
			parts = append(parts, fmt.Sprintf("%d relations", len(res.Relations)))
		}
		u.entities += len(res.Entities)
		u.updates += len(res.EntityUpdates)
		u.relations += len(res.Relations)
	}
	line := fmt.Sprintf("[%d/%d] %-16s %-4s", u.completed, u.total, shortName(u.name, 16), status)
	if len(parts) > 0 {
		line += "  " + strings.Join(parts, ", ")
	}
	if dur > 0 {
		line += "  " + dur.Round(time.Millisecond).String()
	}
	fmt.Fprintln(u.out, line)
	if err != nil {
		fmt.Fprintf(u.out, "       %v\n", err)
	}
}

func (u *collectUI) summary(meta *storage.SnapshotMeta, mode, dbPath string, failed int) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.stopSpinnerLocked()
	state := "complete"
	if failed > 0 {
		state = fmt.Sprintf("%d incomplete", failed)
	}
	fmt.Fprintln(u.out)
	fmt.Fprintln(u.out, "Summary")
	fmt.Fprintf(u.out, "  modules:   %d/%d (%s)\n", u.completed, u.total, state)
	fmt.Fprintf(u.out, "  entities:  %d\n", u.entities)
	fmt.Fprintf(u.out, "  updates:   %d\n", u.updates)
	fmt.Fprintf(u.out, "  relations: %d\n", u.relations)
	fmt.Fprintf(u.out, "  mode:      %s\n", mode)
	if meta != nil && meta.SnapshotID != "" {
		fmt.Fprintf(u.out, "  snapshot:  %s\n", meta.SnapshotID)
	}
	fmt.Fprintf(u.out, "  database:  %s\n", dbPath)
}

func (u *collectUI) close() {
	u.mu.Lock()
	u.stopSpinnerLocked()
	u.mu.Unlock()
}

func (u *collectUI) stopSpinnerLocked() {
	if u.stop != nil {
		close(u.stop)
		u.stop = nil
	}
}

func (u *collectUI) clearLineLocked() {
	fmt.Fprintf(u.out, "\r%s\r", strings.Repeat(" ", 80))
}

func (u *collectUI) percentLocked() int {
	if u.total <= 0 {
		return 0
	}
	pct := u.completed * 100 / u.total
	if pct < 0 {
		return 0
	}
	if pct > 100 {
		return 100
	}
	return pct
}

func progressBar(pct, width int) string {
	if width <= 0 {
		return ""
	}
	filled := pct * width / 100
	if filled < 0 {
		filled = 0
	}
	if filled > width {
		filled = width
	}
	return strings.Repeat("#", filled) + strings.Repeat("-", width-filled)
}

func shortName(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "~"
}

// stdoutIsTerminal/stderrIsTerminal 用于选择展示模式；不依赖第三方 term 库。
// 声明为变量便于测试注入终端/非终端场景。
var (
	stdoutIsTerminalFn = func() bool { return fileIsTerminal(os.Stdout) }
	stderrIsTerminalFn = func() bool { return fileIsTerminal(os.Stderr) }
)

func stdoutIsTerminal() bool { return stdoutIsTerminalFn() }
func stderrIsTerminal() bool { return stderrIsTerminalFn() }

func fileIsTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err == nil && info.Mode()&os.ModeCharDevice != 0 {
		return true
	}
	// git-bash / MSYS 的 pty 有时不会在 Stat 里体现为字符设备；直接问控制台。
	var mode uint32
	return syscall.GetConsoleMode(syscall.Handle(f.Fd()), &mode) == nil
}
