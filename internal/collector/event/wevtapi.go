package event

// wevtapi.go 用系统自带的 wevtapi.dll 查询并渲染事件（日志采集阶段 B）。
//
// 为什么不用 wevtutil.exe：需要 CreateProcess 起外部程序，与本项目"不执行外部程序"
// 的边界冲突（Task 模块当初正因此弃用 schtasks）。wevtapi.dll 随系统提供，懒加载
// 调用与现有 kernel32/advapi32/iphlpapi/ntdll 模式一致。
//
// 只读：EvtQuery 查询 + EvtNext 取句柄 + EvtRender 渲染成 XML + EvtClose 释放。
// 不导出、不清除日志、不修改通道配置、不订阅实时事件。

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	wevtapi        = syscall.NewLazyDLL("wevtapi.dll")
	procEvtQuery   = wevtapi.NewProc("EvtQuery")
	procEvtNext    = wevtapi.NewProc("EvtNext")
	procEvtRender  = wevtapi.NewProc("EvtRender")
	procEvtClose   = wevtapi.NewProc("EvtClose")
	procEvtExtStat = wevtapi.NewProc("EvtGetExtendedStatus")
)

const (
	// evtQueryChannelPath：Path 参数是通道名（而不是日志文件路径）。
	evtQueryChannelPath = 0x1
	// evtQueryReverseDirection：先返回最新的事件。排查场景优先看最近发生的事。
	evtQueryReverseDirection = 0x100
	// evtRenderEventXml：把事件渲染成完整的 Event XML。
	evtRenderEventXml = 1

	// evtNextBatch 是每次 EvtNext 最多取回的事件数。
	evtNextBatch = 64
	// evtNextTimeoutMS 是 EvtNext 的等待上限。查询结果是快照，正常很快就取完；
	// 给它一个有限的等待，避免 0 超时下把"暂时没有"当成"已经取完"。
	evtNextTimeoutMS = 1000

	errorInsufficientBuffer = 122  // ERROR_INSUFFICIENT_BUFFER
	errorNoMoreItems        = 259  // ERROR_NO_MORE_ITEMS
	errorTimeout            = 1460 // ERROR_TIMEOUT
)

// queryResult 是一次通道查询的结果。
//
// Failed 单独计数：个别事件渲染失败不能静默丢掉（"少了几条"必须能被说出来）。
type queryResult struct {
	XML      []string // EvtRender 输出的 Event XML，最多 limit 条（按时间倒序）
	More     bool     // 是否还有超出 limit 的匹配事件（超限必须显式说明）
	Rendered int      // 成功渲染的条数
	Failed   int      // 渲染失败被跳过的条数
}

// buildEventXPath 生成"按事件 ID 白名单选取"的 XPath。
//
// 只选事件 ID，不带其它条件：通道白名单 + 事件 ID 白名单是唯一的选择口径
// （设计 §3.2：一期固定，不做配置项）。
func buildEventXPath(ids []uint32) string {
	if len(ids) == 0 {
		return ""
	}
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, fmt.Sprintf("EventID=%d", id))
	}
	cond := parts[0]
	for _, p := range parts[1:] {
		cond += " or " + p
	}
	return "*[System[(" + cond + ")]]"
}

// queryChannelEvents 在单个通道上查询白名单事件，返回最多 limit 条 Event XML。
//
// More=true 表示"还有更多匹配事件被上限截断"——调用方必须把这件事显式说出来，
// 不允许静默截断。
func queryChannelEvents(channel string, ids []uint32, limit int) (queryResult, error) {
	var res queryResult
	if limit <= 0 {
		res.More = true
		return res, nil
	}
	xpath := buildEventXPath(ids)
	if xpath == "" {
		return res, fmt.Errorf("通道 %s 没有配置事件 ID 白名单", channel)
	}
	cp, err := syscall.UTF16PtrFromString(channel)
	if err != nil {
		return res, err
	}
	qp, err := syscall.UTF16PtrFromString(xpath)
	if err != nil {
		return res, err
	}
	// EvtQuery(Session, Path, Query, Flags) → EVT_HANDLE（0 = 失败）。
	h, _, lastErr := procEvtQuery.Call(0,
		uintptr(unsafe.Pointer(cp)), uintptr(unsafe.Pointer(qp)),
		uintptr(evtQueryChannelPath|evtQueryReverseDirection))
	if h == 0 {
		errno, _ := lastErr.(syscall.Errno)
		return res, fmt.Errorf("EvtQuery 失败 通道=%s (win32=%d)%s",
			channel, uintptr(errno), evtExtendedStatus())
	}
	defer procEvtClose.Call(h)

	for {
		batch := make([]uintptr, evtNextBatch)
		var returned uint32
		// EvtNext(ResultSet, EventArraySize, EventArray, Timeout, Flags, Returned) → BOOL
		ret, _, lastErr := procEvtNext.Call(h,
			uintptr(len(batch)), uintptr(unsafe.Pointer(&batch[0])),
			uintptr(evtNextTimeoutMS), 0, uintptr(unsafe.Pointer(&returned)))
		if ret == 0 {
			errno, _ := lastErr.(syscall.Errno)
			if returned == 0 {
				if uintptr(errno) == errorNoMoreItems || uintptr(errno) == errorTimeout {
					return res, nil
				}
				return res, fmt.Errorf("EvtNext 失败 通道=%s (win32=%d)%s",
					channel, uintptr(errno), evtExtendedStatus())
			}
			// 非 0 返回但带回了若干事件（部分返回）：照常处理，不丢。
		}
		for i := 0; i < int(returned); i++ {
			if len(res.XML) >= limit {
				// 已经取满上限：先释放本批剩余句柄，再明确报告"还有更多"。
				res.More = true
				procEvtClose.Call(batch[i])
				continue
			}
			x, rerr := renderEventXML(batch[i])
			procEvtClose.Call(batch[i])
			if rerr != nil {
				res.Failed++
				continue
			}
			res.XML = append(res.XML, x)
			res.Rendered++
		}
		if res.More {
			return res, nil
		}
	}
}

// renderEventXML 把单个事件句柄渲染成完整 Event XML。
//
// EvtRender 的 BufferSize 单位是**字节**（BufferUsed 也是字节）。这里仍带一次
// 重试：万一缓冲区不够（ERROR_INSUFFICIENT_BUFFER），按 EvtRender 回写的实际
// 需求重来，不猜。
func renderEventXML(h uintptr) (string, error) {
	var used, props uint32
	// 先探一次需要多大。
	procEvtRender.Call(0, h, uintptr(evtRenderEventXml), 0, 0,
		uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
	if used == 0 {
		return "", fmt.Errorf("EvtRender 探测缓冲区失败")
	}
	size := used
	for attempt := 0; attempt < 3; attempt++ {
		buf := make([]uint16, size/2+2)
		var back, propCount uint32
		ret, _, lastErr := procEvtRender.Call(0, h, uintptr(evtRenderEventXml),
			uintptr(size), uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&back)), uintptr(unsafe.Pointer(&propCount)))
		if ret != 0 {
			return syscall.UTF16ToString(buf), nil
		}
		errno, _ := lastErr.(syscall.Errno)
		if uintptr(errno) == errorInsufficientBuffer && back > size {
			size = back
			continue
		}
		return "", fmt.Errorf("EvtRender 失败 (win32=%d)", uintptr(errno))
	}
	return "", fmt.Errorf("EvtRender 连续 3 次缓冲区不足")
}

// evtExtendedStatus 取 EvtGetExtendedStatus 的补充诊断（尽力而为）。
// 它比 GetLastError 更有诊断价值，例如通道不存在 / 访问被拒的具体说明。
func evtExtendedStatus() string {
	var buf [512]uint16
	var used uint32
	ret, _, _ := procEvtExtStat.Call(uintptr(len(buf)),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&used)))
	if ret != 0 || used == 0 {
		return ""
	}
	return ": " + syscall.UTF16ToString(buf[:used])
}
