// Package easytrace 在模块根声明**内嵌的默认规则包**。
//
// 为什么放在仓库根：Go 的 //go:embed 只能嵌入**本包目录内**的文件，而规则源文件
// 位于仓库根的 rules/ 下（单一事实来源，不做复制）。构建时把 rules/ 的内容快照
// 编进二进制，运行时不依赖 cwd、也不需要随包分发 rules/ 目录；
// 仍可用 `-r <dir>` 覆盖为磁盘上的外部规则目录（现场临时加规则/替换规则包）。
package easytrace

import "embed"

// EmbeddedRules 是编译进二进制的默认规则包（构建时快照 rules/ 目录）。
// 只加载其中的 *.yaml / *.yml（与磁盘路径同一套 provider 逻辑）。
//
//go:embed rules
var EmbeddedRules embed.FS
