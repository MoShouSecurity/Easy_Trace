// Package output 提供 JSONL 输出器。
//
// 职责单一：任何对象 → json.Marshal → 一行 + '\n' → 立即 Flush。
// 采集模块不得直接写文件，一律通过本包输出（Easy_Trace Development Rules #3）。
package output

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
)

// Writer 按 JSONL 格式逐行序列化并输出数据。
type Writer struct {
	w *bufio.Writer
	f *os.File // 非 nil 时 Close 会同步关闭该文件
}

// NewWriter 创建写入 w 的 JSONL Writer（不负责关闭 w，调用方管理）。
func NewWriter(w io.Writer) *Writer {
	return &Writer{w: bufio.NewWriter(w)}
}

// NewFileWriter 创建写入指定路径文件的 JSONL Writer（文件由本 Writer 管理）。
func NewFileWriter(path string) (*Writer, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &Writer{w: bufio.NewWriter(f), f: f}, nil
}

// Write 将 data 序列化为一行 JSON 并输出。
// 每次调用立即 Flush，保证下游（GUI/管道/落库）实时消费。
func (w *Writer) Write(data any) error {
	line, err := json.Marshal(data)
	if err != nil {
		return err
	}
	if _, err := w.w.Write(line); err != nil {
		return err
	}
	if err := w.w.WriteByte('\n'); err != nil {
		return err
	}
	return w.w.Flush()
}

// Close 关闭由本 Writer 创建的底层文件（NewWriter 创建的 writer 为 no-op）。
func (w *Writer) Close() error {
	if w.f != nil {
		return w.f.Close()
	}
	return nil
}
