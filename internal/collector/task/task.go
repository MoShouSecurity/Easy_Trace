// Package task 实现 Scheduled Task Collector（Task 6）。
//
// 采集计划任务，只读解析 C:\Windows\System32\Tasks\ 下的任务 XML（零外部命令、
// 零外部程序依赖，Step 11.4）。单个子目录/文件失败只记录内部错误并继续采集
// 其它目录；只有根目录不可访问才认为 Task Collector 整体不可用，且错误必须
// 区分 Access denied / File not found / Invalid path / Other filesystem error，
// 绝不转换成"没有任务"。只采集事实，不禁用/删除/运行任务。
package task

import (
	"crypto/sha1"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"unicode/utf16"

	"easytrace/internal/collector"
	"easytrace/internal/collector/runtime"
	"easytrace/internal/model"
)

// tasksRoot 计划任务 XML 存储目录（非管理员下不可枚举）。
const tasksRoot = `C:\Windows\System32\Tasks`

// maxTaskXMLBytes 单个任务 XML 的最大读取字节数（Step 11.4：4MB 上限，
// 防异常超大文件；超限跳过该任务并明确记录，不 panic）。
const maxTaskXMLBytes = 4 * 1024 * 1024

// XML 预处理正则（任务文件是 UTF-16LE 编码 + xmlns 命名空间）。
var (
	xmlDeclRe = regexp.MustCompile(`<\?xml[^>]*\?>`)
	xmlnsRe   = regexp.MustCompile(`\sxmlns(?::\w+)?="[^"]*"`)
)

// taskItem 是单个任务的中间结构（内部结构，供测试注入）。
type taskItem struct {
	name    string
	path    string
	author  string
	command string
	trigger string
	enabled bool
}

// taskXML 对应计划任务 XML 的解析结构（带 xmlns 命名空间，Go 按本地名匹配）。
type taskXML struct {
	RegistrationInfo struct {
		Author string `xml:"Author"`
		URI    string `xml:"URI"`
	} `xml:"RegistrationInfo"`
	Triggers struct {
		Any []struct {
			XMLName xml.Name
		} `xml:",any"`
	} `xml:"Triggers"`
	Actions struct {
		Exec struct {
			Command   string `xml:"Command"`
			Arguments string `xml:"Arguments"`
		} `xml:"Exec"`
	} `xml:"Actions"`
	Settings struct {
		Enabled *bool `xml:"Enabled"` // 缺省时任务视为启用
	} `xml:"Settings"`
}

// Collector 实现 task 采集。getItems 可注入以便测试；nil 时使用真实文件系统扫描。
type Collector struct {
	getItems func() ([]taskItem, error)
	rt       *runtime.Runtime
}

// New 创建使用真实文件系统扫描的 Task Collector，绑定调用方注入的 Runtime。
// Collector 不在内部创建 Runtime（架构收口，Step 2.2）；rt 必传，nil 视为编程错误。
func New(rt *runtime.Runtime) *Collector {
	if rt == nil {
		panic("task: New 必须传入 runtime.Runtime（禁止 Collector 内部创建）")
	}
	return &Collector{rt: rt}
}

// NewWithItems 创建使用自定义数据源的 Task Collector（用于测试）。
func NewWithItems(rt *runtime.Runtime, f func() ([]taskItem, error)) *Collector {
	c := New(rt)
	c.getItems = f
	return c
}

// Runtime 返回绑定的行为控制 Runtime（供注入一致性校验）。
func (c *Collector) Runtime() *runtime.Runtime { return c.rt }

// Name 实现 collector.Collector 接口。
func (c *Collector) Name() string { return "task" }

// Collect 实现 collector.Collector 接口：输出 scheduled_task 实体。
//
// Step 5.2 行为门卫：先经 rt.Allow("task","TaskQuery") 检查——被拒则
// 不执行任何任务枚举，返回空结果并记录 deny 行为事件。
// 采集实现只读扫描 System32\Tasks 下的任务 XML（零外部命令）。
// 根目录不可访问（非管理员）时按错误分类记录内部错误（collection_error），
// 返回错误和已获得的结果，绝不把"目录不可读"转换成"没有任务"。
//
// 说明：execute 关系到 Task 8 Pipeline（按命令路径匹配运行中的 process）再生成；
// 静态采集无任务运行实例的 PID，本阶段只输出实体。
func (c *Collector) Collect() (*collector.Result, error) {
	if !c.rt.Allow("task", "TaskQuery", "scheduled_tasks") {
		debugf("task_query_denied mode=%s", c.rt.Mode())
		return &collector.Result{}, nil
	}
	getItems := c.getItems
	if getItems == nil {
		getItems = scanTasksXML
	}
	items, err := getItems()
	if err != nil {
		// 部分失败：记录内部错误（含分类：Access denied / File not found / ...），保留已采集项。
		debugf("collection_error collector=task capability=TaskQuery operation=scanTasksXML error=%v", err)
	}

	res := &collector.Result{}
	for _, it := range items {
		id := "task_" + hashPath(it.path)
		e := model.NewEntity("task", id, model.TaskData{
			TaskName: it.name,
			Path:     it.path,
			Author:   it.author,
			Command:  it.command,
			Trigger:  it.trigger,
			Enabled:  it.enabled,
		})
		res.Entities = append(res.Entities, e)
	}
	return res, err
}

// debugf 输出采集阶段/内部错误日志到 stderr（不污染 stdout 的 JSONL 流）。
func debugf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[task] "+format+"\n", args...)
}

// walkTasksDir 可注入的目录遍历实现（测试模拟子目录 Access Denied / 根目录失败）。
var walkTasksDir = filepath.WalkDir

// scanTasksXML 递归扫描 System32\Tasks（管理员可读；非管理员根目录不可枚举）。
//
// 注意：任务在该目录下是**无扩展名**文件——文件名即任务路径，内容才是 XML。
// 因此不能按扩展名筛选，必须逐个尝试解析。
// 零外部命令，只读文件系统。
//
// Step 11.4 容错：单个子目录失败只记录分类错误并继续采集其它目录；
// 只有根目录不可访问才整体失败——错误保留原始 errno 与分类
// （Access denied / File not found / Invalid path / Other filesystem error），
// 绝不转换成"没有任务"。
func scanTasksXML() ([]taskItem, error) {
	return scanTasksXMLRoot(tasksRoot)
}

// scanTasksXMLRoot 对指定根目录执行任务 XML 扫描（root 可注入，供测试）。
func scanTasksXMLRoot(root string) ([]taskItem, error) {
	var items []taskItem
	candidates := 0
	err := walkTasksDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if filepath.Clean(path) == filepath.Clean(root) {
				return err // 根目录不可读 → 整体失败（错误含原始 errno）
			}
			// 子目录/文件失败：记录分类错误，继续采集其它目录
			debugf("walk_error path=%s class=%s error=%v", path, walkErrClass(err), err)
			return nil
		}
		if d.IsDir() {
			return nil
		}
		// System32\Tasks 下每个计划任务都是无扩展名文件：文件名即任务路径
		// （例如 Microsoft\Windows\Defrag\ScheduledDefrag），内容才是 XML。
		// 按扩展名过滤会导致真实主机上恒为 0 条，这里逐个尝试解析；
		// 解析失败即视为非任务文件跳过（目录里可能存在其它附属文件）。
		candidates++
		if it, ok := parseTaskFile(path); ok {
			items = append(items, it)
		}
		return nil
	})
	if err != nil {
		return items, fmt.Errorf("scanTasksXML(%s): %s: %w", root, walkErrClass(err), err)
	}
	// 诊断：区分"目录里没有候选文件"与"有文件但都解析失败"，
	// 避免 0 条被误读为"主机没有计划任务"。
	debugf("task_scan files=%d parsed=%d", candidates, len(items))
	return items, nil
}

// walkErrClass 将目录遍历错误分类（Step 11.4：错误信息必须区分
// Access denied / File not found / Invalid path / Other filesystem error）。
func walkErrClass(err error) string {
	if err == nil {
		return ""
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case 5: // ERROR_ACCESS_DENIED
			return "Access denied"
		case 2, 3: // ERROR_FILE_NOT_FOUND / ERROR_PATH_NOT_FOUND
			return "File not found"
		case 87: // ERROR_INVALID_PARAMETER
			return "Invalid path"
		}
	}
	if os.IsPermission(err) {
		return "Access denied"
	}
	if os.IsNotExist(err) {
		return "File not found"
	}
	return "Other filesystem error"
}

// parseTaskFile 读取并解析单个任务 XML 文件（Step 11.4：4MB 读取上限，
// 超限记录 "XML exceeds read limit" 并跳过该任务，不 panic）。
func parseTaskFile(path string) (taskItem, bool) {
	data, err := readTaskXML(path)
	if err != nil {
		debugf("parse_task_file_failed path=%s error=%v", path, err)
		return taskItem{}, false
	}
	return parseTaskXML(path, data)
}

// readTaskXML 读取任务 XML，限制最大字节数（io.LimitReader，等价防超限分配）。
// 超过 maxTaskXMLBytes 返回明确错误（含 "XML exceeds read limit"），不 panic。
func readTaskXML(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxTaskXMLBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxTaskXMLBytes {
		return nil, fmt.Errorf("XML exceeds read limit (%d bytes > %d)", len(data), maxTaskXMLBytes)
	}
	return data, nil
}

// parseTaskXML 解析任务 XML 内容（path 用于推导任务名）。
func parseTaskXML(path string, data []byte) (taskItem, bool) {
	data = sanitizeXML(data)
	var tx taskXML
	if err := xml.Unmarshal(data, &tx); err != nil {
		// 错误可能包含 XML 中的标签名，只记录分类，避免输出任务内容。
		debugf("parse_task_xml_failed path=%s class=Invalid XML", path)
		return taskItem{}, false
	}

	// 任务名 = 文件名（去 .xml）
	name := strings.TrimSuffix(filepath.Base(path), ".xml")

	// 任务路径 = URI（\Microsoft\Windows\...）；无 URI 用 \文件名
	taskPath := tx.RegistrationInfo.URI
	if taskPath == "" {
		taskPath = `\` + name
	}

	// 触发器类型：取第一个触发器元素名
	trigger := ""
	if len(tx.Triggers.Any) > 0 {
		trigger = triggerName(tx.Triggers.Any[0].XMLName.Local)
	}

	// 启用状态：Settings.Enabled 缺省视为启用
	enabled := true
	if tx.Settings.Enabled != nil {
		enabled = *tx.Settings.Enabled
	}

	// 命令：Command + Arguments
	cmd := tx.Actions.Exec.Command
	if args := strings.TrimSpace(tx.Actions.Exec.Arguments); args != "" {
		cmd = cmd + " " + args
	}

	return taskItem{
		name:    name,
		path:    taskPath,
		author:  tx.RegistrationInfo.Author,
		command: cmd,
		trigger: trigger,
		enabled: enabled,
	}, true
}

// sanitizeXML 预处理任务 XML：UTF-16LE → UTF-8、去掉 XML 声明与 xmlns 属性。
func sanitizeXML(data []byte) []byte {
	data = utf16ToUTF8(data)
	data = xmlDeclRe.ReplaceAll(data, nil)
	data = xmlnsRe.ReplaceAll(data, nil)
	return data
}

// utf16ToUTF8 将 UTF-16LE（带 BOM）转换为 UTF-8；非 UTF-16 原样返回。
func utf16ToUTF8(data []byte) []byte {
	if len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE {
		u16 := make([]uint16, (len(data)-2)/2)
		for i := range u16 {
			u16[i] = uint16(data[2+i*2]) | uint16(data[3+i*2])<<8
		}
		return []byte(string(utf16.Decode(u16)))
	}
	return data
}

// triggerName 将触发器元素名转为小写 snake_case（SessionStateChangeTrigger -> session_state_change）。
func triggerName(elem string) string {
	s := strings.TrimSuffix(elem, "Trigger")
	var b strings.Builder
	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			b.WriteByte('_')
		}
		b.WriteRune(r)
	}
	return strings.ToLower(b.String())
}

// hashPath 计算任务路径的 SHA1（entity_id 用，协议规则 task_<sha1(path)>）。
func hashPath(p string) string {
	sum := sha1.Sum([]byte(p))
	return fmt.Sprintf("%x", sum[:8])
}
