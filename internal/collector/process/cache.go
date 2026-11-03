package process

import (
	"path/filepath"
	"strings"
)

// 本文件实现 Deep 生命周期缓存（Step 12.3）：
//
// 同一次运行内（当前进程生命周期），同一文件路径的敏感操作只执行一次：
//   - hash（SHA256 全文件读取）
//   - signature verification（WinVerifyTrust，打开文件并查系统证书存储）
//   - PE inspect（读文件头 + os.Stat）
//
// 目标：Deep/Forensic 模式下多个进程实例引用同一文件时（如数十个
// svchost.exe 实例共用 C:\Windows\System32\svchost.exe），不重复执行
// 相同的文件读取与验证，缩小安全软件的触发面。
//
// 约束：
//   - 缓存仅当前进程生命周期有效（包级 map，进程退出即释放）
//   - 不写 Snapshot / 不写 SQLite / 不影响证据模型
//   - Windows 文件路径大小写不敏感，缓存 key 统一规范化（见 canonPath）
//   - 单线程 CLI，无并发访问，无需锁
//   - 缓存包装调用底层实现注入点（*Impl），测试替换为 fake 后零真实
//     API 调用（真实 WinVerifyTrust 会触发 Windows 文件信誉/数字签名
//     安全警告，测试绝不允许走真实实现）

// 底层实现注入点（测试计数/替换用）：
//   - 产品路径：默认真实实现（verifyFileSignature / peInspect / hashFile）
//   - 测试路径：替换为 fake，缓存包装自动调用 fake，不触发真实 API
//   - 与 enrichEntries 的注入点（verifySignatureFn 等）分离：
//     mockEnrich 覆盖后者绕过缓存；缓存测试覆盖前者验证缓存逻辑。
var (
	hashFileImpl        = hashFile
	verifySignatureImpl = verifyFileSignature
	peInspectImpl       = peInspect
)

// canonPath 将文件路径规范化为缓存 key：
// filepath.Clean 统一分隔符并消除冗余段（Windows 上 '/'→'\'），
// ToLower 使 C:\Windows\a.exe 与 c:\windows\A.EXE 命中同一 key。
func canonPath(p string) string {
	return strings.ToLower(filepath.Clean(p))
}

// hashCacheEntry 缓存哈希结果（值 + 失败原因，Step 11.5）。
type hashCacheEntry struct {
	value  string
	reason string
}

// hashPathCache 按规范化路径缓存 SHA256（避免同一文件被多个进程重复计算）。
var hashPathCache = map[string]hashCacheEntry{}

// hashFileCached 计算文件 SHA256，带路径级缓存（Step 12.3：大小写不敏感）。
func hashFileCached(path string) (string, string) {
	if path == "" {
		return hashFileImpl(path)
	}
	key := canonPath(path)
	if r, ok := hashPathCache[key]; ok {
		debugf("hash_cache_hit path=%s", path)
		return r.value, r.reason
	}
	h, reason := hashFileImpl(path)
	hashPathCache[key] = hashCacheEntry{value: h, reason: reason}
	return h, reason
}

// sigCacheEntry 缓存一次验签结果（同一次运行内文件不变，结果确定）。
type sigCacheEntry struct {
	valid     bool
	publisher string
	reason    string
	status    SignatureStatus // 结果语义（Step 12.3 Follow-up，缓存不丢失）
	retCode   uintptr         // 原始返回码（失败 Detail 输出用）
}

// signatureVerifyCache 按规范化路径缓存 WinVerifyTrust 结果（Step 12.3）。
var signatureVerifyCache = map[string]sigCacheEntry{}

// verifyFileSignatureCached 带生命周期缓存的签名验证：
// 同一路径（忽略大小写）在同一次运行内只执行一次 WinVerifyTrust。
// 失败结果同样缓存（同一文件重复失败也是重复敏感操作）。
func verifyFileSignatureCached(path string) (signatureInfo, string) {
	if path == "" {
		return verifySignatureImpl(path)
	}
	key := canonPath(path)
	if e, ok := signatureVerifyCache[key]; ok {
		debugf("sig_cache_hit path=%s", path)
		return signatureInfo{valid: e.valid, publisher: e.publisher, status: e.status, retCode: e.retCode}, e.reason
	}
	info, reason := verifySignatureImpl(path)
	signatureVerifyCache[key] = sigCacheEntry{
		valid: info.valid, publisher: info.publisher, reason: reason,
		status: info.status, retCode: info.retCode,
	}
	return info, reason
}

// peCacheEntry 缓存一次 PE Inspect 结果（state + mtime，同一次运行内文件不变）。
type peCacheEntry struct {
	state signatureState
	mtime string
}

// peInspectCache 按规范化路径缓存 PE Inspect 结果（Step 12.3）。
var peInspectCache = map[string]peCacheEntry{}

// peInspectCached 带生命周期缓存的 PE Inspect：
// 同一路径（忽略大小写）只读一次文件头 + os.Stat。
func peInspectCached(path string) (signatureState, string) {
	if path == "" {
		return peInspectImpl(path)
	}
	key := canonPath(path)
	if e, ok := peInspectCache[key]; ok {
		debugf("pe_cache_hit path=%s", path)
		return e.state, e.mtime
	}
	state, mtime := peInspectImpl(path)
	peInspectCache[key] = peCacheEntry{state: state, mtime: mtime}
	return state, mtime
}

// resetProcessCaches 清空全部 Deep 生命周期缓存（仅测试用，
// 保证测试间无路径状态泄漏；真实运行无需调用）。
func resetProcessCaches() {
	hashPathCache = map[string]hashCacheEntry{}
	signatureVerifyCache = map[string]sigCacheEntry{}
	peInspectCache = map[string]peCacheEntry{}
}
