package process

import "easytrace/internal/filemeta"

// 本文件是**薄封装**：签名相关的唯一实现已于 2026-10-14 迁到 internal/filemeta
// （PE 安全目录轻量检测 + WinVerifyTrust 验签 + 签名者提取）。
// 这里只保留 process 内部沿用的类型名与函数名，避免大范围改动调用方与测试。
//
//   - signatureState / sigXxx：PE 安全目录轻量检测 → filemeta.SignatureState
//   - SignatureStatus / SigStatusXxx：WinVerifyTrust 结果语义（别名）
//   - classifyVerifyRet / verifyFileSignature：直接委托 filemeta

// signatureState 轻量签名状态（PE 头级检测，不调用 WinVerifyTrust）。
type signatureState string

const (
	sigUnknown signatureState = "unknown" // PE 头无法读取 / 非 PE
	sigPresent signatureState = "present" // PE 安全目录存在（有数字签名目录）
	sigMissing signatureState = "missing" // PE 安全目录不存在（无数字签名）
)

// SignatureStatus 是 WinVerifyTrust 全量验证的结果语义（别名到唯一实现）。
// 语义边界见 internal/filemeta/signature.go：unsigned 是事实而非恶意证据；
// verification_error 不代表任何签名结论。
type SignatureStatus = filemeta.SignatureStatus

const (
	SigStatusSigned            = filemeta.SigStatusSigned
	SigStatusUnsigned          = filemeta.SigStatusUnsigned
	SigStatusInvalidSignature  = filemeta.SigStatusInvalidSignature
	SigStatusTrustFailed       = filemeta.SigStatusTrustFailed
	SigStatusVerificationError = filemeta.SigStatusVerificationError
)

// signatureInfo 真实签名验证结果（process 内部结构，保持原有字段名与语义）。
type signatureInfo struct {
	valid     bool            // 签名链是否有效（= status == SigStatusSigned）
	publisher string          // 签名者名称（尽力而为，仅 Signed 时提取）
	issuer    string          // 颁发者（V0.1 暂留空）
	status    SignatureStatus // 结果语义（总会被设置，绝不保留零值）
	retCode   uintptr         // WinVerifyTrust 原始返回码
}

// signatureStateOf 轻量判断 PE 文件是否包含数字签名目录（不调用 WinVerifyTrust）。
func signatureStateOf(path string) signatureState {
	switch filemeta.SignatureState(path) {
	case filemeta.SigPresent:
		return sigPresent
	case filemeta.SigMissing:
		return sigMissing
	}
	return sigUnknown
}

// classifyVerifyRet 委托 filemeta.ClassifyVerifyRet（唯一实现）。
func classifyVerifyRet(ret uintptr) (SignatureStatus, string) {
	return filemeta.ClassifyVerifyRet(ret)
}

// verifyFileSignature 委托 filemeta.VerifySignature（唯一实现），映射回内部结构。
func verifyFileSignature(path string) (signatureInfo, string) {
	fi, reason := filemeta.VerifySignature(path)
	return signatureInfo{
		valid:     fi.Valid,
		publisher: fi.Publisher,
		issuer:    fi.Issuer,
		status:    fi.Status,
		retCode:   fi.RetCode,
	}, reason
}
