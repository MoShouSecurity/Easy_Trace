# Easy_Trace 构建与自检脚本（一条命令完成 gofmt / build / vet / test）
#
# 用法：
#   powershell -ExecutionPolicy Bypass -File .\build.ps1
#
# 处理了几个常见环境问题：
#   1) 受限沙箱/CI 下 %LOCALAPPDATA%\go-build 可能不可写 → 缓存放到 %TEMP%
#   2) git 目录属主不一致会让 VCS stamping 失败 → -buildvcs=false
#   3) 用"能不能真的读到 System32\Tasks"判断权限，而不是 IsInRole(Administrator)：
#      UAC 过滤令牌 / 受限沙箱下 IsInRole 仍返回 $true，但目录读取照样 Access denied
#   4) native 命令失败必须中止（PowerShell 默认不会因 go build 非零退出而报错）
#   5) 第 3 步的 verify 除比对清单外，还会扫描**成品 exe 字节**是否含"高危连续字串"
#      （杀软启发式会拦下带这类特征的 exe，实测表现为执行报 Access is denied；
#       见 internal/rulelint 与 docs/rules.md「规则作者须知」）
$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $MyInvocation.MyCommand.Path)

$env:GOCACHE = Join-Path $env:TEMP "easytrace-gocache"
$env:GOTMPDIR = Join-Path $env:TEMP "easytrace-gotmp"
New-Item -ItemType Directory -Force -Path $env:GOCACHE, $env:GOTMPDIR | Out-Null
$env:GOFLAGS = "-buildvcs=false"
# 自检不属于操作者的调查动作，且构建目录不该被写日志：关掉操作留痕
$env:EASYTRACE_AUDIT_LOG = "off"

function Assert-Exit([string]$step) {
    if ($LASTEXITCODE -ne 0) {
        Write-Host "$step 失败（exit $LASTEXITCODE），中止。" -ForegroundColor Red
        exit $LASTEXITCODE
    }
}

Write-Host "[1/5] gofmt -l ." -ForegroundColor Cyan
$unformatted = gofmt -l .
if ($unformatted) {
    Write-Host "以下文件未格式化：" -ForegroundColor Red
    $unformatted | ForEach-Object { Write-Host "  $_" }
    exit 1
}

Write-Host "[2/5] go build" -ForegroundColor Cyan
go build -o Easy_Trace.exe ./cmd/easytrace-agent
Assert-Exit "[2/5] go build"

Write-Host "[3/5] 自校验清单（verify --write-manifest / verify）" -ForegroundColor Cyan
# 生成 Easy_Trace.manifest.sha256（exe + rules/ 的 SHA256），再立刻验一遍：
# 构建脚本自己就是第一个"自校验清单可用"的证据。
.\Easy_Trace.exe verify --write-manifest
Assert-Exit "[3/5] verify --write-manifest"
.\Easy_Trace.exe verify
Assert-Exit "[3/5] verify"
Write-Host "[4/5] go vet" -ForegroundColor Cyan
go vet ./...
Assert-Exit "[4/5] go vet"

Write-Host "[5/5] go test" -ForegroundColor Cyan
# 真实计划任务用例（internal/collector/task 与 pipeline 各 2 个）自带可读性探测，
# 不可读即 t.Skip；这里的 -short 只是第二道闸，不再整包排除 internal/collector/task
# （整包排除会丢掉该包其余 20+ 个纯离线用例的覆盖）。
$systemRoot = if ($env:SystemRoot) { $env:SystemRoot } else { 'C:\Windows' }
$tasksDir = Join-Path $systemRoot 'System32\Tasks'
$canReadTasks = $false
try {
    $null = Get-ChildItem -LiteralPath $tasksDir -Force -ErrorAction Stop | Select-Object -First 1
    $canReadTasks = $true
} catch {
    $canReadTasks = $false
}
if ($canReadTasks) {
    go test ./...
} else {
    Write-Host "本机 $tasksDir 不可读：需要真实计划任务目录的用例会自动跳过。-short 同样排除。" -ForegroundColor Yellow
    go test -short ./...
}
Assert-Exit "[5/5] go test"

Write-Host "OK: Easy_Trace.exe 已生成" -ForegroundColor Green
