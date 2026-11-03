// Package network 实现 Network Collector（Task 3）。
//
// 枚举 Windows TCP/UDP 连接（含监听），输出 network 实体与
// process --network_connect--> network 关系。只采集事实，不做 IP 恶意判断。
package network

import (
	"fmt"
	"net"
	"os"
	goruntime "runtime"
	"sort"
	"strings"
	"syscall"
	"unsafe"

	"easytrace/internal/collector"
	"easytrace/internal/collector/runtime"
	"easytrace/internal/model"
)

// ---- Windows API 句柄（懒加载，零外部依赖） ----
var (
	iphlpapi                = syscall.NewLazyDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = iphlpapi.NewProc("GetExtendedUdpTable")
)

// Table 类常量
const (
	tcpTableOwnerPidAll = 5  // TCP_TABLE_OWNER_PID_ALL
	udpTableOwnerPid    = 1  // UDP_TABLE_OWNER_PID
	afInet              = 2  // AF_INET
	afInet6             = 23 // AF_INET6

	errInsufficientBuffer = 122 // ERROR_INSUFFICIENT_BUFFER
)

// TCP 状态 → 字符串
var tcpStates = map[uint32]string{
	1: "CLOSED", 2: "LISTENING", 3: "SYN_SENT", 4: "SYN_RECV", 5: "ESTABLISHED",
	6: "FIN_WAIT1", 7: "FIN_WAIT2", 8: "CLOSE_WAIT", 9: "CLOSING", 10: "LAST_ACK",
	11: "TIME_WAIT", 12: "DELETE_TCB",
}

// connInfo 是单条连接/端点的中间结构（内部结构，供测试注入）。
type connInfo struct {
	proto      string // tcp / udp
	localIP    string
	localPort  uint16
	remoteIP   string
	remotePort uint16
	state      string // TCP 才有
	pid        uint32
}

// ---- MIB 结构 ----

// mibTCPRowOwnerPID 对应 MIB_TCPROW_OWNER_PID（IPv4）。
type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

// mibTCP6RowOwnerPID 对应 MIB_TCP6ROW_OWNER_PID（IPv6）。
type mibTCP6RowOwnerPID struct {
	LocalAddr   [16]byte
	LocalScope  uint32
	LocalPort   uint32
	RemoteAddr  [16]byte
	RemoteScope uint32
	RemotePort  uint32
	State       uint32
	OwningPid   uint32
}

// mibUDPRowOwnerPID 对应 MIB_UDPROW_OWNER_PID（IPv4）。
type mibUDPRowOwnerPID struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPid uint32
}

// mibUDP6RowOwnerPID 对应 MIB_UDP6ROW_OWNER_PID（IPv6）。
type mibUDP6RowOwnerPID struct {
	LocalAddr  [16]byte
	LocalScope uint32
	LocalPort  uint32
	OwningPid  uint32
}

// Collector 实现 network 采集。getConns 可注入以便测试；nil 时使用真实 Windows API。
type Collector struct {
	getConns func() ([]connInfo, error)
	rt       *runtime.Runtime
}

// New 创建使用真实 Windows API 的 Network Collector，绑定调用方注入的 Runtime。
// Collector 不在内部创建 Runtime（架构收口，Step 2.2）；rt 必传，nil 视为编程错误。
func New(rt *runtime.Runtime) *Collector {
	if rt == nil {
		panic("network: New 必须传入 runtime.Runtime（禁止 Collector 内部创建）")
	}
	return &Collector{rt: rt}
}

// NewWithConns 创建使用自定义数据源的 Network Collector（用于测试）。
func NewWithConns(rt *runtime.Runtime, f func() ([]connInfo, error)) *Collector {
	c := New(rt)
	c.getConns = f
	return c
}

// Runtime 返回绑定的行为控制 Runtime（供注入一致性校验）。
func (c *Collector) Runtime() *runtime.Runtime { return c.rt }

// debugf 输出采集阶段/内部错误日志到 stderr（不污染 stdout 的 JSONL 流）。
func debugf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[network] "+format+"\n", args...)
}

// Name 实现 collector.Collector 接口。
func (c *Collector) Name() string { return "network" }

// Collect 实现 collector.Collector 接口：返回 network 实体 + process connect 关系。
//
// Step 3 行为门卫：先经 rt.Allow("network","NetworkQuery") 检查——被拒则
// 不执行任何 Windows API，返回空结果并记录 deny 行为事件（不导致 Pipeline 失败，
// Collector 不自决能力）。TCP/UDP 四表独立容错："能采多少采多少"，单个表失败
// 不影响其它表结果；但只要有表失败就返回聚合错误（部分结果照常保留），
// 让 CLI/Pipeline 计入失败而不是把不完整采集当成成功。有 PID 的连接生成
// process --network_connect--> network 关系；无 PID 只保留实体。
func (c *Collector) Collect() (*collector.Result, error) {
	if !c.rt.Allow("network", "NetworkQuery", "tcp+udp") {
		debugf("network_query_denied mode=%s", c.rt.Mode())
		return &collector.Result{}, nil
	}
	getConns := c.getConns
	if getConns == nil {
		getConns = collectConnections
	}
	conns, err := getConns()
	if err != nil {
		// 部分/全部表失败：记录内部错误（含 collector/capability/operation/error），
		// 保留已采集的连接（TCP 失败 ≠ UDP 失败），但采集结果必须显式标记为不完整，
		// 由 CLI/Pipeline 计入失败——否则"少采了表"会静默变成"采到了空"。
		debugf("collection_error collector=network capability=NetworkQuery operation=collectConnections error=%v", err)
	}

	// 实体 ID 是索引型（network_%04d），必须先按内容稳定排序再编号，
	// 否则同一批连接会因 Windows API 返回顺序不同而得到不同 ID，跨快照无法复现。
	sort.SliceStable(conns, func(i, j int) bool {
		return connLess(conns[i], conns[j])
	})

	res := &collector.Result{}
	for i, ci := range conns {
		id := fmt.Sprintf("network_%04d", i+1)
		e := model.NewEntity("network", id, model.NetworkData{
			Protocol:   ci.proto,
			LocalIP:    ci.localIP,
			LocalPort:  ci.localPort,
			RemoteIP:   ci.remoteIP,
			RemotePort: ci.remotePort,
			State:      ci.state,
			PID:        ci.pid,
		})
		res.Entities = append(res.Entities, e)

		if ci.pid != 0 {
			rel := model.NewRelation(
				fmt.Sprintf("rel_%04d", i+1),
				fmt.Sprintf("process_%d", ci.pid),
				id,
				"network_connect",
				map[string]string{"protocol": ci.proto, "remote_ip": ci.remoteIP},
			)
			res.Relations = append(res.Relations, rel)
		}
	}
	if err != nil {
		return res, fmt.Errorf("network 采集不完整: %w", err)
	}
	return res, nil
}

// connLess 是全字段稳定排序键：proto → local → remote → pid → state。
// 所有字段都参与比较，保证同一批连接在任何 API 返回顺序下都得到相同编号。
func connLess(a, b connInfo) bool {
	if a.proto != b.proto {
		return a.proto < b.proto
	}
	if a.localIP != b.localIP {
		return a.localIP < b.localIP
	}
	if a.localPort != b.localPort {
		return a.localPort < b.localPort
	}
	if a.remoteIP != b.remoteIP {
		return a.remoteIP < b.remoteIP
	}
	if a.remotePort != b.remotePort {
		return a.remotePort < b.remotePort
	}
	if a.pid != b.pid {
		return a.pid < b.pid
	}
	return a.state < b.state
}

// collectConnections 枚举 TCP(IPv4+IPv6) 与 UDP(IPv4+IPv6) 连接。
// 单表失败跳过该表并聚合错误信息，不影响其它表；返回已采集的连接（可能非空）
// 与聚合错误（仅当存在失败表时非 nil）。UDP 无连接状态字段，不人为制造 state。
func collectConnections() ([]connInfo, error) {
	var all []connInfo
	var errs []string
	if rows, err := getTCPRows(afInet); err == nil {
		all = append(all, rows...)
	} else {
		errs = append(errs, fmt.Sprintf("GetExtendedTcpTable(af=%d): %v", afInet, err))
	}
	if rows, err := getTCPRows(afInet6); err == nil {
		all = append(all, rows...)
	} else {
		errs = append(errs, fmt.Sprintf("GetExtendedTcpTable(af=%d): %v", afInet6, err))
	}
	if rows, err := getUDPRows(afInet); err == nil {
		all = append(all, rows...)
	} else {
		errs = append(errs, fmt.Sprintf("GetExtendedUdpTable(af=%d): %v", afInet, err))
	}
	if rows, err := getUDPRows(afInet6); err == nil {
		all = append(all, rows...)
	} else {
		errs = append(errs, fmt.Sprintf("GetExtendedUdpTable(af=%d): %v", afInet6, err))
	}
	if len(errs) > 0 {
		return all, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return all, nil
}

// getTCPRows 枚举 TCP 连接表。
func getTCPRows(af uint32) ([]connInfo, error) {
	var size uint32
	ret, _, _ := procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)),
		1 /*bOrder*/, uintptr(af), tcpTableOwnerPidAll, 0)
	if ret != errInsufficientBuffer || size == 0 {
		return nil, fmt.Errorf("GetExtendedTcpTable(af=%d) size: ret=%d", af, ret)
	}
	buf := make([]byte, size)
	ret, _, _ = procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)), 1, uintptr(af), tcpTableOwnerPidAll, 0)
	goruntime.KeepAlive(buf)
	if ret != 0 {
		return nil, fmt.Errorf("GetExtendedTcpTable(af=%d): ret=%d", af, ret)
	}

	num := *(*uint32)(unsafe.Pointer(&buf[0]))
	var out []connInfo
	if af == afInet {
		rows := unsafe.Slice((*mibTCPRowOwnerPID)(unsafe.Pointer(&buf[4])), num)
		for _, r := range rows {
			out = append(out, connInfo{
				proto:      "tcp",
				localIP:    fmtIPv4(r.LocalAddr),
				localPort:  ntohs(r.LocalPort),
				remoteIP:   fmtIPv4(r.RemoteAddr),
				remotePort: ntohs(r.RemotePort),
				state:      tcpStates[r.State],
				pid:        r.OwningPid,
			})
		}
	} else {
		rows := unsafe.Slice((*mibTCP6RowOwnerPID)(unsafe.Pointer(&buf[4])), num)
		for _, r := range rows {
			out = append(out, connInfo{
				proto:      "tcp",
				localIP:    net.IP(r.LocalAddr[:]).String(),
				localPort:  ntohs(r.LocalPort),
				remoteIP:   net.IP(r.RemoteAddr[:]).String(),
				remotePort: ntohs(r.RemotePort),
				state:      tcpStates[r.State],
				pid:        r.OwningPid,
			})
		}
	}
	return out, nil
}

// getUDPRows 枚举 UDP 端点表。
func getUDPRows(af uint32) ([]connInfo, error) {
	var size uint32
	ret, _, _ := procGetExtendedUdpTable.Call(0, uintptr(unsafe.Pointer(&size)),
		1, uintptr(af), udpTableOwnerPid, 0)
	if ret != errInsufficientBuffer || size == 0 {
		return nil, fmt.Errorf("GetExtendedUdpTable(af=%d) size: ret=%d", af, ret)
	}
	buf := make([]byte, size)
	ret, _, _ = procGetExtendedUdpTable.Call(uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)), 1, uintptr(af), udpTableOwnerPid, 0)
	goruntime.KeepAlive(buf)
	if ret != 0 {
		return nil, fmt.Errorf("GetExtendedUdpTable(af=%d): ret=%d", af, ret)
	}

	num := *(*uint32)(unsafe.Pointer(&buf[0]))
	var out []connInfo
	if af == afInet {
		rows := unsafe.Slice((*mibUDPRowOwnerPID)(unsafe.Pointer(&buf[4])), num)
		for _, r := range rows {
			out = append(out, connInfo{
				proto:     "udp",
				localIP:   fmtIPv4(r.LocalAddr),
				localPort: ntohs(r.LocalPort),
				pid:       r.OwningPid,
			})
		}
	} else {
		rows := unsafe.Slice((*mibUDP6RowOwnerPID)(unsafe.Pointer(&buf[4])), num)
		for _, r := range rows {
			out = append(out, connInfo{
				proto:     "udp",
				localIP:   net.IP(r.LocalAddr[:]).String(),
				localPort: ntohs(r.LocalPort),
				pid:       r.OwningPid,
			})
		}
	}
	return out, nil
}

// fmtIPv4 将 MIB 中的 DWORD 地址格式化为点分十进制。
func fmtIPv4(a uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(a), byte(a>>8), byte(a>>16), byte(a>>24))
}

// ntohs 网络字节序 → 主机字节序（端口）。
func ntohs(p uint32) uint16 {
	return uint16(p>>8) | uint16(p<<8)
}
