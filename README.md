# Easy_Trace

Windows 离线取证与排查工具（源码仓库，仅包含构建所需代码）。

## 构建

要求：Windows + Go 1.26.5 或更高版本。

```powershell
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

脚本会依次执行 gofmt、构建、清单自校验、go vet 和测试，最终生成 `Easy_Trace.exe`。
也可以只构建：

```powershell
go build -o Easy_Trace.exe ./cmd/easytrace-agent
```

## 运行

除 `help` / `version` / `verify` 外，命令需要以管理员身份运行；未提权时退出码为 3，且不会执行任何采集、数据库或文件操作。

## 目录

- `cmd/easytrace-agent/`：CLI 入口
- `internal/`：采集器、分析器、规则与存储等实现
- `rules/`：内置规则源文件。`rules_embed.go` 通过 `//go:embed rules` 将其编入二进制，**构建时不可删除**

构建产物、数据库、JSONL 与日志均已被 `.gitignore` 排除，不会进入仓库。
