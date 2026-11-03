// 本文件承载**唯一的** WinVerifyTrust 验签实现（原 internal/collector/process 的实现
// 于 2026-10-14 迁入本包，process 只保留薄封装）。PE 安全目录的轻量检测见 filemeta.go
// 的 SignatureState（同样是唯一实现）。
//
// 语义边界（供 Analyzer/证据输出参考，禁止直接据此判定恶意）：
//   - unsigned：文件没有数字签名（自研/绿色软件常见，属事实，不是"恶意"的证据）
//   - invalid_signature：签名存在但损坏/摘要不匹配
//   - trust_evaluation_failed：签名存在但 Windows 信任策略拒绝/显式不信任
//   - verification_error：API 或文件级失败（不可读等），不代表任何签名结论
package filemeta

import (
	"errors"
	"os"
	goruntime "runtime"
	"syscall"
	"unsafe"

	"easytrace/internal/collector"
	"easytrace/internal/safepath"
)

// SignatureStatus 是 WinVerifyTrust 全量验证的结果语义（与 SignatureState 是两个层级：
// SignatureState 只看 PE 安全目录是否存在；SignatureStatus 表达验证结果的含义）。
type SignatureStatus string

const (
	SigStatusSigned            SignatureStatus = "signed"                  // 签名链验证通过
	SigStatusUnsigned          SignatureStatus = "unsigned"                // 无数字签名（TRUST_E_NOSIGNATURE）
	SigStatusInvalidSignature  SignatureStatus = "invalid_signature"       // 签名存在但无效（TRUST_E_BAD_DIGEST）
	SigStatusTrustFailed       SignatureStatus = "trust_evaluation_failed" // 信任评估失败
	SigStatusVerificationError SignatureStatus = "verification_error"      // API/文件级失败
)

// SignatureInfo 是真实签名验证结果（WinVerifyTrust）。内部结构（不进入协议/JSONL）。
type SignatureInfo struct {
	Valid     bool            // 签名链是否有效（= Status == SigStatusSigned）
	Publisher string          // 签名者名称（尽力而为，仅 Signed 时提取）
	Issuer    string          // 颁发者（V0.1 暂留空）
	Status    SignatureStatus // 结果语义（VerifySignature 总会设置，绝不保留零值）
	RetCode   uintptr         // WinVerifyTrust 原始返回码
}

// WinTrustFileInfo 对应 WINTRUST_FILE_INFO。
type WinTrustFileInfo struct {
	CbStruct       uint32
	PcwszFilePath  *uint16
	HFile          uintptr
	PgKnownSubject uintptr
}

// WINTRUST_DATA.dwProvFlags 的取值（wintrust.h）。
const (
	wtdRevocationCheckNone = 0x00000010 // WTD_REVOCATION_CHECK_NONE
	wtdCacheOnlyURLRetry   = 0x00001000 // WTD_CACHE_ONLY_URL_RETRY：只用本地缓存，不访问网络
)

// winTrustProvFlags 是验签固定使用的标志位：取证工具必须保持离线。
const winTrustProvFlags = wtdRevocationCheckNone | wtdCacheOnlyURLRetry

// WinTrustData 对应 WINTRUST_DATA。
//
// 布局必须与 Windows SDK 完全一致：cbStruct 之后紧跟 pPolicyCallbackData 与
// pSIPClientData 两个指针。漏掉这两个字段会让其后所有字段整体错位——API 会把
// dwUIChoice 读成 WTD_UI_ALL(1) 而不是 WTD_UI_NONE(2)，WinVerifyTrust 于是弹出
// "安全警告"对话框并阻塞；同时 pFile 也无法正确传入，验证结果无效。
// 布局由 signature_test.go 的 TestWinTrustDataLayout 固定。
type WinTrustData struct {
	CbStruct            uint32
	PPolicyCallbackData uintptr
	PSIPClientData      uintptr
	DwUIChoice          uint32
	FdwRevocationChecks uint32
	DwUnionChoice       uint32
	PFile               *WinTrustFileInfo
	DwStateAction       uint32
	HWVTStateData       uintptr
	PwszURLReference    *uint16
	DwProvFlags         uint32
	DwUIContext         uint32
}

// guid 对应 GUID。
type guid struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// WINTRUST_ACTION_GENERIC_VERIFY_V2 = {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
var actionGenericVerifyV2 = guid{0x00AAC56B, 0xCD44, 0x11d0,
	[8]byte{0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE}}

var (
	wintrust = syscall.NewLazyDLL("wintrust.dll")
	crypt32  = syscall.NewLazyDLL("crypt32.dll")

	procWinVerifyTrust                 = wintrust.NewProc("WinVerifyTrust")
	procWTHelperProvDataFromStateData  = wintrust.NewProc("WTHelperProvDataFromStateData")
	procWTHelperGetProvSignerFromChain = wintrust.NewProc("WTHelperGetProvSignerFromChain")
	procWTHelperGetProvCertFromChain   = wintrust.NewProc("WTHelperGetProvCertFromChain")
	procCertGetNameStringW             = crypt32.NewProc("CertGetNameStringW")
)

// cryptProviderCertOffset 是 CRYPT_PROVIDER_CERT 中 PCCERT_CONTEXT pCert 的偏移
// （64 位：cbStruct 4 字节 + 4 字节对齐填充，随后即为指针）。
//
// 说明：此处只按偏移取一个指针，不整体映射结构体——历史实现曾把
// CRYPT_PROVIDER_DATA / CRYPT_PROVIDER_SGNR 整体"凭记忆"映射（其中
// CRYPT_PROVIDER_SGNR 里根本不存在 pwszName 字段），导致读到无效指针并崩溃。
const cryptProviderCertOffset = unsafe.Sizeof(uint32(0)) + unsafe.Sizeof(uint32(0))

// WinVerifyTrust 返回码。
const (
	trustENoSignature         = 0x800B0100 // TRUST_E_NOSIGNATURE：无签名（状态，非失败）
	trustESubjectNotTrusted   = 0x800B0004 // TRUST_E_SUBJECT_NOT_TRUSTED
	trustEExplicitDistrust    = 0x800B0111 // TRUST_E_EXPLICIT_DISTRUST
	trustEBadDigest           = 0x80096010 // TRUST_E_BAD_DIGEST
	trustEProviderUnknown     = 0x800B0001 // TRUST_E_PROVIDER_UNKNOWN
	trustEProviderUnsupported = 0x800B0006 // TRUST_E_PROVIDER_UNSUPPORTED
	trustEFAil                = 0x800B010B // TRUST_E_FAIL
	trustEAccessDenied        = 0x80070005 // E_ACCESSDENIED
)

// ClassifyVerifyRet 把 WinVerifyTrust 返回码分类为（结果语义, 失败原因）。
// 失败原因仅对 verification_error 非空；签名状态类不是操作失败。
func ClassifyVerifyRet(ret uintptr) (SignatureStatus, string) {
	switch ret {
	case 0:
		return SigStatusSigned, ""
	case trustENoSignature:
		return SigStatusUnsigned, ""
	case trustEBadDigest:
		return SigStatusInvalidSignature, ""
	case trustESubjectNotTrusted, trustEExplicitDistrust:
		return SigStatusTrustFailed, ""
	case trustEAccessDenied:
		return SigStatusVerificationError, collector.ReasonAccessDenied
	}
	return SigStatusVerificationError, collector.ReasonWinVerifyTrustFail
}

// VerifySignature 真实签名验证（WinVerifyTrust + 签名者提取）。
//
//   - Status 总会被设置为明确值（绝不保留零值——零值会被误读为 signed）
//   - RetCode 保留原始返回码
//   - Valid = (Status == signed)；消费方必须看 Status 而非只看 bool
//   - 失败时返回分类原因（File not found / Access denied / WinVerifyTrust failed），
//     绝不把"文件不可读"误报为"验证失败"
func VerifySignature(path string) (SignatureInfo, string) {
	info := SignatureInfo{}
	if path == "" {
		info.Status = SigStatusVerificationError
		return info, ""
	}
	// 先确认是本地普通文件：验签会打开文件，不能让 UNC/映射盘/链接成为读取入口。
	if _, err := safepath.ValidateLocalFilePath(path, "验签目标路径"); err != nil {
		info.Status = SigStatusVerificationError
		return info, collector.ReasonUnsafePath
	}
	// 再做文件级预检，避免把文件不可读误报为 WinVerifyTrust 失败。
	if _, err := os.Stat(path); err != nil {
		info.Status = SigStatusVerificationError
		return info, classifyFileErr(err)
	}
	fileInfo := WinTrustFileInfo{}
	fileInfo.CbStruct = uint32(unsafe.Sizeof(fileInfo))
	fileInfo.PcwszFilePath = syscall.StringToUTF16Ptr(path)

	data := WinTrustData{}
	data.CbStruct = uint32(unsafe.Sizeof(data))
	data.DwUIChoice = 2    // WTD_UI_NONE
	data.DwUnionChoice = 1 // WTD_CHOICE_FILE
	data.PFile = &fileInfo
	data.DwStateAction = 1 // WTD_STATEACTION_VERIFY
	// 离线边界：关掉吊销检查，并且只允许从本地缓存取证书/CRL（WTD_CACHE_ONLY_URL_RETRY）。
	// WinVerifyTrust 默认会为构建证书链访问 AIA/CRL URL；取证主机不允许联网，缺中间证书
	// 时应如实得到 verification_error，而不是悄悄发起外连。
	data.DwProvFlags = winTrustProvFlags

	ret, _, _ := procWinVerifyTrust.Call(0,
		uintptr(unsafe.Pointer(&actionGenericVerifyV2)), uintptr(unsafe.Pointer(&data)))
	info.RetCode = ret
	status, reason := ClassifyVerifyRet(ret)
	info.Status = status
	info.Valid = info.Status == SigStatusSigned

	// 签名者名称仅对 signed 提取
	if info.Status == SigStatusSigned && data.HWVTStateData != 0 {
		info.Publisher = ExtractPublisher(data.HWVTStateData)
	}

	// 释放状态
	data.DwStateAction = 2 // WTD_STATEACTION_CLOSE
	procWinVerifyTrust.Call(0,
		uintptr(unsafe.Pointer(&actionGenericVerifyV2)), uintptr(unsafe.Pointer(&data)))

	return info, reason
}

// ExtractPublisher 从 WVT 状态数据提取签名者名称（尽力而为，失败返回空）。
func ExtractPublisher(stateData uintptr) string {
	provData, _, _ := procWTHelperProvDataFromStateData.Call(stateData)
	if provData == 0 {
		return ""
	}
	// 四个参数一个都不能少：x64 下少传参数会让寄存器带垃圾值而访问违例。
	signer, _, _ := procWTHelperGetProvSignerFromChain.Call(provData, 0, 0, 0)
	if signer == 0 {
		return ""
	}
	// 第一个参数是**签名者**，不是 provider data。
	provCert, _, _ := procWTHelperGetProvCertFromChain.Call(signer, 0)
	if provCert == 0 {
		return ""
	}
	pCert := *(*uintptr)(unsafe.Add(toPointer(provCert), cryptProviderCertOffset))
	if pCert == 0 {
		return ""
	}
	buf := make([]uint16, 256)
	n, _, _ := procCertGetNameStringW.Call(pCert, 4 /* CERT_NAME_SIMPLE_DISPLAY_TYPE */, 0, 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	goruntime.KeepAlive(buf)
	if n == 0 || int(n) > len(buf) {
		return ""
	}
	return syscall.UTF16ToString(buf[:n-1])
}

// toPointer 把 uintptr 还原为 unsafe.Pointer（vet unsafeptr 兼容写法）。
func toPointer(p uintptr) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&p))
}

// classifyFileErr 把文件级错误分类为 collector 的失败原因常量。
func classifyFileErr(err error) string {
	if os.IsNotExist(err) {
		return collector.ReasonFileNotFound
	}
	if os.IsPermission(err) {
		return collector.ReasonAccessDenied
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case 5:
			return collector.ReasonAccessDenied
		case 2, 3:
			return collector.ReasonFileNotFound
		}
	}
	return collector.ReasonFileNotFound
}
