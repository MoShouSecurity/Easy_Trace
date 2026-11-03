// Package audit 实现 Easy_Trace 的「操作留痕」（设计原则 P8「自身可信」）：
// 把授权调查动作追加写入一个只增不改的本地 JSONL 文件，供事后核对
// "谁在什么时候做了什么、结果如何、用的是哪一份二进制"。
//
// 边界（如实说明，不得夸大）：
//   - operator 取自环境变量（USERDOMAIN\USERNAME），只是**尽力而为**的登录上下文，
//     不是身份认证——离线 CLI 无法证明操作者身份。
//   - 只记录 CLI 边界上的命令名与少量白名单参数，**不记录**采集到的数据、报告内容
//     或完整命令行；参数值只保留路径/ID 一类可核对信息。
//   - 只追加、不修改、不轮转；写入失败如实返回错误，由调用方决定是否影响退出码。
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultFileName 是与可执行文件同目录的默认留痕文件名。
const DefaultFileName = "easytrace-audit.log"

// Entry 是一条操作留痕。字段固定、顺序固定，便于用文本工具核对。
//
// PrevHash / Hash 组成哈希链：Hash = SHA256(本条 JSON，Hash 置空)，
// PrevHash = 上一条的 Hash。它不是签名（离线工具没有可信密钥），
// 但能发现“事后修改/删除其中一行、再原样追加”的痕迹。
type Entry struct {
	Seq         int               `json:"seq"`
	TimeUTC     string            `json:"time_utc"`
	Operator    string            `json:"operator,omitempty"`
	Verb        string            `json:"verb"`
	Result      string            `json:"result"`
	ToolVersion string            `json:"tool_version,omitempty"`
	ExeSHA256   string            `json:"exe_sha256,omitempty"`
	Params      map[string]string `json:"params,omitempty"`
	Detail      string            `json:"detail,omitempty"`
	PrevHash    string            `json:"prev_hash,omitempty"`
	Hash        string            `json:"hash,omitempty"`
}

// entryHash 计算一条留痕的链哈希（Hash 字段本身不参与计算）。
func entryHash(e Entry) (string, error) {
	e.Hash = ""
	line, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(line)
	return hex.EncodeToString(sum[:]), nil
}

// DefaultPath 返回默认留痕文件路径（与当前可执行文件同目录）。
func DefaultPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("无法定位可执行文件: %w", err)
	}
	return filepath.Join(filepath.Dir(exe), DefaultFileName), nil
}

// NextSeq 扫描留痕文件，返回"下一条应使用的序号"（最大已用序号 + 1）。
// 无法解析的行被跳过而不阻断追加——留痕宁可继续增长，也不能因为一行损坏而停摆；
// 损坏行由 List 明确报告。
func NextSeq(path string) (int, error) {
	seq, _, err := scanState(path)
	return seq, err
}

// scanState 返回下一条序号与最后一条可解析记录的链哈希（供追加时接链）。
func scanState(path string) (int, string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 1, "", nil
		}
		return 0, "", err
	}
	defer f.Close()

	max := 0
	lastHash := ""
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}
		if e.Seq > max {
			max = e.Seq
		}
		lastHash = e.Hash
	}
	if err := scanner.Err(); err != nil {
		return 0, "", err
	}
	return max + 1, lastHash, nil
}

// Verify 校验留痕哈希链与序号连续性，返回不匹配的行号（1 起）。
//
// 三类情况会出现在结果里：内容被改动（重算哈希不符）、链路断开
// （prev_hash 与上一行 hash 不一致）、序号不连续（缺号 / 重号 / 乱序。
// 留痕只追加不轮转，因此序号必须从 1 开始逐条 +1）。
// 升级前写入的旧记录没有 hash 字段，同样无法通过校验——这是如实反映，不是误报。
// 无法解析的行由 List 报告，这里跳过。
func Verify(path string) ([]int, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var broken []int
	prev := ""
	wantSeq := 1
	lineNo := 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}
		want, err := entryHash(e)
		if err != nil {
			return nil, err
		}
		if e.Hash != want || e.PrevHash != prev || e.Seq != wantSeq {
			broken = append(broken, lineNo)
		}
		// 断链后按实际值重新对齐，避免一行异常把后续所有行都标成断链。
		wantSeq = e.Seq + 1
		prev = e.Hash
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return broken, nil
}

// 留痕写入的互斥参数。Append 需要“扫最后一条 → 算序号/链哈希 → 追加”，
// 三个进程同时执行会拿到相同序号并接同一条父哈希，链随即断开。这里用同目录
// 的 `.lock` 排他创建文件做跨进程互斥（stdlib 在 Windows 上没有可用的文件锁）。
// 变量而非常量：测试把等待时间调小。
var (
	lockRetryDelay = 10 * time.Millisecond
	lockTimeout    = 2 * time.Second
	lockStaleAfter = 30 * time.Second
)

// acquireLock 获取留痕文件的跨进程写锁，返回释放函数。
//
// 进程崩溃会留下锁文件：超过 lockStaleAfter 未更新的锁视为陈旧并清除。
// 超时仍拿不到锁时返回错误——调用方（recordAudit）会警告，而不是静默丢失记录。
func acquireLock(path string) (func(), error) {
	lockPath := path + ".lock"
	deadline := time.Now().Add(lockTimeout)
	for {
		f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_, _ = fmt.Fprintf(f, "%d\n", os.Getpid())
			_ = f.Close()
			return func() { _ = os.Remove(lockPath) }, nil
		}
		if !os.IsExist(err) {
			return nil, err
		}
		if info, statErr := os.Stat(lockPath); statErr == nil &&
			time.Since(info.ModTime()) > lockStaleAfter {
			_ = os.Remove(lockPath)
			continue
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("留痕文件正被另一个进程写入（等待 %s 超时）: %s", lockTimeout, lockPath)
		}
		time.Sleep(lockRetryDelay)
	}
}

// Append 追加一条留痕：补全 Seq / TimeUTC 与哈希链后写入一行 JSON 并 fsync。
// 只追加（O_APPEND），绝不截断已有内容；目录不存在时明确报错，不自动创建目录。
func Append(path string, e Entry) (Entry, error) {
	if strings.TrimSpace(e.Verb) == "" {
		return Entry{}, fmt.Errorf("留痕缺少 verb")
	}
	release, err := acquireLock(path)
	if err != nil {
		return Entry{}, err
	}
	defer release()

	seq, lastHash, err := scanState(path)
	if err != nil {
		return Entry{}, fmt.Errorf("读取留痕序号失败: %w", err)
	}
	if e.Seq == 0 {
		e.Seq = seq
	}
	if e.TimeUTC == "" {
		e.TimeUTC = time.Now().UTC().Format(time.RFC3339)
	}
	e.PrevHash = lastHash
	e.Hash, err = entryHash(e)
	if err != nil {
		return Entry{}, fmt.Errorf("计算留痕哈希失败: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return Entry{}, err
	}
	line, err := json.Marshal(e)
	if err == nil {
		_, err = f.Write(append(line, '\n'))
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return Entry{}, err
	}
	return e, closeErr
}

// List 读取留痕文件，返回最近 limit 条（limit <= 0 表示全部）以及无法解析的行号。
// 损坏行不静默吞掉：由调用方据此给出非零退出码，避免"少了几条"被当成完整记录。
func List(path string, limit int) ([]Entry, []int, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	defer f.Close()

	var entries []Entry
	var corrupt []int
	lineNo := 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			corrupt = append(corrupt, lineNo)
			continue
		}
		entries = append(entries, e)
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	if limit > 0 && len(entries) > limit {
		entries = entries[len(entries)-limit:]
	}
	return entries, corrupt, nil
}
