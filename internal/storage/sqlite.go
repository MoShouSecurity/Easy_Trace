// Package storage 实现 Easy_Trace SQLite Snapshot 存储层（Step 6）。
//
// 使用 Windows 10+ 系统自带的 winsqlite3.dll（零第三方依赖、零 CGO），
// 与项目现有 syscall 懒加载 DLL 模式一致。本层只处理 JSON/SQLite/文件 I/O，
// 不引入任何外部程序执行、网络访问、进程内存读取等行为。
package storage

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"easytrace/internal/safepath"
)

// winsqlite3.dll 是 Windows 10 1607+ 系统自带的 SQLite 库（标准 SQLite C API）。
var winsqlite = syscall.NewLazyDLL("winsqlite3.dll")

var (
	procOpen         = winsqlite.NewProc("sqlite3_open_v2")
	procClose        = winsqlite.NewProc("sqlite3_close_v2")
	procExec         = winsqlite.NewProc("sqlite3_exec")
	procPrepare      = winsqlite.NewProc("sqlite3_prepare_v2")
	procStep         = winsqlite.NewProc("sqlite3_step")
	procBindText     = winsqlite.NewProc("sqlite3_bind_text")
	procBindInt64    = winsqlite.NewProc("sqlite3_bind_int64")
	procColumnText   = winsqlite.NewProc("sqlite3_column_text")
	procColumnInt64  = winsqlite.NewProc("sqlite3_column_int64")
	procColumnBytes  = winsqlite.NewProc("sqlite3_column_bytes")
	procFinalize     = winsqlite.NewProc("sqlite3_finalize")
	procErrMsg       = winsqlite.NewProc("sqlite3_errmsg")
	procLastInsertID = winsqlite.NewProc("sqlite3_last_insert_rowid")
	procBusyTimeout  = winsqlite.NewProc("sqlite3_busy_timeout")
)

// SQLite 结果码与常量
const (
	sqliteOK            = 0
	sqliteRow           = 100
	sqliteDone          = 101
	sqliteOpenReadOnly  = 0x0001
	sqliteOpenReadWrite = 0x0002
	sqliteOpenCreate    = 0x0004
)

// sqliteTransient 对应 SQLITE_TRANSIENT（-1 作为无符号全 1 位，64 位下 = 0xFFFF...FF）。
var sqliteTransient = ^uintptr(0)

// DB 是 SQLite 数据库连接句柄封装。
type DB struct {
	handle uintptr
	path   string
}

// Open 打开（不存在则创建）SQLite 数据库。
// 已存在的数据库正常打开，不覆盖已有数据。
func Open(path string) (*DB, error) {
	return openSQLite(path, sqliteOpenReadWrite|sqliteOpenCreate)
}

// OpenExisting 打开已存在的 SQLite 数据库（可读写），绝不创建新文件。
//
// 用于确实要写库的命令（inspect 追加补证、snapshot import）：拼错 --db 时
// 应立即失败，而不是留下一个空库并把错误延迟到“没有快照”。
func OpenExisting(path string) (*DB, error) {
	return openSQLite(path, sqliteOpenReadWrite)
}

// OpenReadOnly 以只读方式打开已存在的数据库。
//
// 所有读命令（analyze / report / investigate / catch / snapshot list|show|diff
// / whitelist）都必须用它，而不是 OpenExisting：
//   - 不创建文件、不建表：拼错 --db 不会留下空库；
//   - 不写 journal / WAL / 锁文件：可在只读介质（挂载的镜像、写保护 U 盘）上使用；
//   - 不会改变证据文件本身（取证完整性）。
func OpenReadOnly(path string) (*DB, error) {
	return openSQLite(path, sqliteOpenReadOnly)
}

func openSQLite(path string, flags uintptr) (*DB, error) {
	if path == "" {
		return nil, fmt.Errorf("storage: 数据库路径不能为空")
	}
	// 数据库也是读取入口：SQLite 打开 UNC/映射网络驱动器同样会发起 SMB。
	localPath, err := safepath.RequireLocalDrivePath(path, "数据库路径")
	if err != nil {
		return nil, fmt.Errorf("storage: %w", err)
	}
	path = localPath
	// 不创建时先做存在性检查：SQLite 对“文件不存在”和“父目录不存在”都只返回
	// SQLITE_CANTOPEN，无法给出可操作的提示。
	if flags&sqliteOpenCreate == 0 {
		info, statErr := os.Stat(path)
		if statErr != nil {
			if os.IsNotExist(statErr) {
				return nil, fmt.Errorf("storage: 数据库不存在: %s（只读命令不会创建新库；请检查 --db 路径，或先运行 collect / snapshot import）", path)
			}
			return nil, fmt.Errorf("storage: 无法访问数据库 %q: %w", path, statErr)
		}
		if info.IsDir() {
			return nil, fmt.Errorf("storage: 数据库路径是目录: %s", path)
		}
	}
	var db uintptr
	// 文件名按 UTF-8 传入（SQLite 内部处理）。
	fn := append([]byte(path), 0)
	ret, _, _ := procOpen.Call(uintptr(unsafe.Pointer(&fn[0])),
		uintptr(unsafe.Pointer(&db)), flags, 0)
	// **必须** KeepAlive：LazyProc.Call 是普通变参函数，不像 syscall.Syscall 带
	// //go:uintptrescapes，编译器**不保证**缓冲区活到调用结束。fn 此后不再被引用，
	// 若在调用进行中被 GC 回收，SQLite 读到的是已被复用的内存（2026-10-15 修正）。
	runtime.KeepAlive(fn)
	if ret != sqliteOK || db == 0 {
		if db != 0 {
			// 打开失败时可能仍返回句柄，先关闭避免泄漏。
			procClose.Call(db)
		}
		return nil, fmt.Errorf("storage: 无法打开数据库 %q: %s（sqlite3_open_v2 ret=%d）",
			path, openErrText(ret), ret)
	}
	d := &DB{handle: db, path: path}
	procBusyTimeout.Call(db, 5000) // 5s busy timeout，避免并发写锁死
	return d, nil
}

// openErrText 把 sqlite3_open_v2 的常见返回码翻译成人话（同时保留原始返回码供排查）。
func openErrText(ret uintptr) string {
	switch ret {
	case 14: // SQLITE_CANTOPEN
		return "路径不存在、不可写或非法。注意 shell 变量由 shell 先展开：" +
			"cmd.exe 用 %VAR%，PowerShell 用 $env:VAR；" +
			"不确定时直接用相对路径（例如 --db t.db）"
	case 8: // SQLITE_READONLY
		return "目标位置为只读"
	case 21: // SQLITE_MISUSE
		return "调用方式不正确"
	}
	return "打开失败"
}

// Close 关闭数据库连接。
func (d *DB) Close() error {
	if d.handle == 0 {
		return nil
	}
	procClose.Call(d.handle)
	d.handle = 0
	return nil
}

// Path 返回数据库文件路径。
func (d *DB) Path() string { return d.path }

// err 返回带 sqlite 错误消息的错误。
func (d *DB) err(op string, ret uintptr) error {
	msg := ""
	if p, _, _ := procErrMsg.Call(d.handle); p != 0 {
		msg = cString(p)
	}
	return fmt.Errorf("storage: %s ret=%d: %s", op, ret, msg)
}

// Exec 执行无参数 SQL（DDL / BEGIN / COMMIT / ROLLBACK）。
func (d *DB) Exec(sql string) error {
	var errmsg uintptr
	sqlBytes := append([]byte(sql), 0)
	ret, _, _ := procExec.Call(d.handle, uintptr(unsafe.Pointer(&sqlBytes[0])), 0, 0,
		uintptr(unsafe.Pointer(&errmsg)))
	runtime.KeepAlive(sqlBytes) // 见 Open 的说明：缓冲区必须活到调用结束
	if ret != sqliteOK {
		msg := ""
		if errmsg != 0 {
			msg = cString(errmsg)
		}
		return fmt.Errorf("storage: sqlite3_exec: %s", msg)
	}
	return nil
}

// LastInsertRowID 返回最近一次 INSERT 的自增 id。
func (d *DB) LastInsertRowID() int64 {
	id, _, _ := procLastInsertID.Call(d.handle)
	return int64(id)
}

// stmt 是预处理语句封装。
type stmt struct {
	db     *DB
	handle uintptr
}

// Prepare 预处理一条 SQL 语句。
func (d *DB) Prepare(sql string) (*stmt, error) {
	var s uintptr
	sqlBytes := append([]byte(sql), 0)
	ret, _, _ := procPrepare.Call(d.handle, uintptr(unsafe.Pointer(&sqlBytes[0])), ^uintptr(0),
		uintptr(unsafe.Pointer(&s)), 0)
	runtime.KeepAlive(sqlBytes) // 见 Open 的说明：缓冲区必须活到调用结束
	if ret != sqliteOK || s == 0 {
		return nil, d.err("prepare", ret)
	}
	return &stmt{db: d, handle: s}, nil
}

// BindInt 绑定 int64 参数（1-based）。
func (s *stmt) BindInt(idx int, v int64) error {
	ret, _, _ := procBindInt64.Call(s.handle, uintptr(idx), uintptr(v))
	if ret != sqliteOK {
		return s.db.err("bind_int64", ret)
	}
	return nil
}

// BindText 绑定字符串参数（1-based）。
// SQLITE_TRANSIENT：SQLite 在调用内拷贝数据。
func (s *stmt) BindText(idx int, v string) error {
	b := append([]byte(v), 0)
	ret, _, _ := procBindText.Call(s.handle, uintptr(idx),
		uintptr(unsafe.Pointer(&b[0])), uintptr(len(v)),
		uintptr(sqliteTransient))
	runtime.KeepAlive(b) // 见 Open 的说明：缓冲区必须活到调用结束
	if ret != sqliteOK {
		return s.db.err("bind_text", ret)
	}
	return nil
}

// Step 执行一步；返回是否有结果行。
func (s *stmt) Step() (bool, error) {
	ret, _, _ := procStep.Call(s.handle)
	switch ret {
	case sqliteDone:
		return false, nil
	case sqliteRow:
		return true, nil
	}
	return false, s.db.err("step", ret)
}

// ColumnText 读取文本列（UTF-8，复制为 Go string）。
//
// Step 11.3：先取 sqlite3_column_bytes 的真实长度再按精确长度复制，避免大字段
// （如 data_json）被 cString 的防御上限（1MB）静默截断。NULL 列返回空串。
func (s *stmt) ColumnText(idx int) string {
	n, _, _ := procColumnBytes.Call(s.handle, uintptr(idx))
	if n == 0 {
		// 长度为 0：可能是 NULL（column_text 返回 NULL 指针）或空串
		p, _, _ := procColumnText.Call(s.handle, uintptr(idx))
		if p == 0 {
			return ""
		}
		return cString(p)
	}
	p, _, _ := procColumnText.Call(s.handle, uintptr(idx))
	if p == 0 {
		return ""
	}
	// vet unsafeptr 兼容模式：uintptr → unsafe.Pointer 类型双关（与 cString 一致）
	ptr := *(*unsafe.Pointer)(unsafe.Pointer(&p))
	return string(unsafe.Slice((*byte)(ptr), int(n)))
}

// ColumnInt64 读取 int64 列。
func (s *stmt) ColumnInt64(idx int) int64 {
	v, _, _ := procColumnInt64.Call(s.handle, uintptr(idx))
	return int64(v)
}

// Close 释放语句。
func (s *stmt) Close() {
	if s.handle != 0 {
		procFinalize.Call(s.handle)
		s.handle = 0
	}
}

// cString 从 *byte 读取 UTF-8 C 字符串（直到 NUL，带防御上限）。
// ptr 是 SQLite 返回的 C 内存指针（sqlite3_column_text/errmsg），生命周期安全。
func cString(p uintptr) string {
	if p == 0 {
		return ""
	}
	// vet unsafeptr 误报绕过：uintptr → unsafe.Pointer 类型双关
	ptr := *(*unsafe.Pointer)(unsafe.Pointer(&p))
	var b []byte
	for i := 0; i < 1<<20; i++ { // 防御上限 1MB
		c := *(*byte)(unsafe.Add(ptr, uintptr(i)))
		if c == 0 {
			break
		}
		b = append(b, c)
	}
	return string(b)
}
