# 本地 IOC 规则目录

本目录用于保存**本地、离线、只读**的 IOC 规则包。Easy_Trace 不会从网络下载、更新、缓存或修改这些文件；操作者自行按内部流程维护其内容。

## 启用与停用

- `ioc/**/*.yaml` 和 `ioc/**/*.yml` 会随规则包递归加载。
- 将文件改名为非 YAML 扩展名（例如 `source.yaml.disabled`）即可停用；加载器会忽略它，且不会修改原文件。
- 本仓库不附带会对默认主机产生 Finding 的启用 IOC 样例。

## 必须满足的约定

每条 IOC 规则继续使用现有严格 YAML DSL，不能新增键：

1. 规则文件必须位于 `ioc/` 下，且 `rule_id` 必须以 `ioc.` 开头；同一规则包内的 ID 仍必须全局唯一，不能覆盖内置规则。
2. `description` 或 `advice` 必须含有非空的 `Source:` 标记，记录可审计的本地来源。例如：`Source: incident-2026-10-06`。
3. 使用 `remote_ip` 或 `remote_port` 时，必须排除监听实体的远端占位值：

   ```yaml
   - field: state
     operator: not_equals
     value: LISTENING
   ```

4. 使用进程深采字段 `hash_sha256`、`parent_command_line`、`signature_valid`、`publisher`、`last_write_time` 或 `command_line` 时，必须明确要求深采证据（`command_line` 仅对 `process` 实体的深采采集成立；`event` 的 4688 `command_line` 是 Basic 字段）：

   ```yaml
   - field: collection_level
     operator: equals
     value: deep
   ```

缺少深采字段的 Basic 快照不会满足这类规则；这表示证据未采集，而不是该指标已被否定。匹配结果仅是后续核查线索，不构成定性结论。

## 最小模板

```yaml
rule_id: ioc.process.example
# Description/advice 必须包含可审计来源。
title: 本地进程指标
# description: 本地指标匹配。Source: <internal-reference>
severity: medium
target: process
conditions:
  - field: path
    operator: contains
    value: <indicator>
# advice: 根据 Source: <internal-reference> 复核路径、进程上下文和采集范围。
```

运行 `easytrace rules validate -r rules` 可在不访问 SQLite 的情况下校验规则包；`easytrace rules list -r rules` 可查看已启用规则及其相对来源路径。
