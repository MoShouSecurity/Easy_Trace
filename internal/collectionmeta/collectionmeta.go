// Package collectionmeta 记录一份快照的采集时间与采集时权限，并把它作为
// SQLite schema 之外的 sidecar 保存。
//
// 为什么需要 sidecar：
//   - snapshots 表的 schema 已冻结，没有"采集开始/结束/采集权限"列；
//   - report 生成时读取当前进程 Token 只能说明"报告进程"的权限，不能说明
//     "采集进程"的权限，二者可能不同（例如采集后换用户/降权再出报告）；
//   - 协议 v0.2 的 JSONL 信封也不能增加非协议字段。
//
// 因此采集时把元数据写到 JSONL 旁的 sidecar（<jsonl>.collection.json），
// 导入后按 snapshot_id 保存到数据库旁的 <db>.collection-meta/ 目录。报告只读
// 这份采集时元数据；没有 sidecar 的旧快照明确显示"未记录"，绝不拿报告进程
// 的权限冒充采集权限。
//
// sidecar 是**来源记录**，不是签名证据：攻击者若能改写数据库旁的文件，也能
// 改写它。报告只把它作为"采集环境说明"，不参与风险判定；需要强证据时以采集
// 时的原始 JSONL、证据 manifest 和事件包哈希链为准。
package collectionmeta

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// SchemaVersion 是 sidecar 自身的格式版本，与协议 schema_version 无关。
	SchemaVersion = 1

	// FileSuffix 是原始 JSONL 旁 sidecar 的后缀。
	FileSuffix = ".collection.json"

	// snapshotMetaDirSuffix 是数据库旁元数据目录的后缀。
	snapshotMetaDirSuffix = ".collection-meta"

	// maxSidecarBytes 是 sidecar 的大小上限：它只含少量元数据，超过即视为异常。
	maxSidecarBytes = 64 << 10
)

// 时间戳来源。collection 表示时间来自采集器记录的 collection_started_at；
// host_current_time 表示旧产物没有采集元数据，但 host 实体带有采集时的时间；
// import_time 表示两者都没有，snapshots.timestamp 只是导入时间。
const (
	TimestampSourceCollection      = "collection"
	TimestampSourceHostCurrentTime = "host_current_time"
	TimestampSourceImportTime      = "import_time"
	TimestampSourceUnavailable     = "unavailable"
)

// 权限来源。
const (
	PrivilegeSourceProcessToken = "collect_process_token"
	PrivilegeSourceUnavailable  = "unavailable"
)

// Privilege 是采集进程 Token 的只读权限状态。
//
// 使用指针而不是 bool，是为了区分"明确不是管理员"（false）与"没有记录"
// （nil）。报告绝不能把未记录当成 false。
type Privilege struct {
	Recorded                 bool   `json:"recorded"`
	AdministratorElevated    *bool  `json:"administrator_elevated,omitempty"`
	AdministratorGroupMember *bool  `json:"administrator_group_member,omitempty"`
	Source                   string `json:"source"`
}

// Meta 是采集环境 sidecar 的内容。
//
// 原始 JSONL 旁的 sidecar 没有 SnapshotID / SnapshotTimestamp / TimestampSource
// 的最终值（快照 ID 在导入时才生成）；导入后写到数据库旁的 sidecar 会补齐这三项。
type Meta struct {
	SchemaVersion int    `json:"schema_version"`
	ToolVersion   string `json:"tool_version,omitempty"`
	Hostname      string `json:"hostname,omitempty"`

	CollectionMode       string `json:"collection_mode,omitempty"`
	CollectionStartedAt  string `json:"collection_started_at,omitempty"`
	CollectionFinishedAt string `json:"collection_finished_at,omitempty"`

	SnapshotID        string `json:"snapshot_id,omitempty"`
	SnapshotTimestamp string `json:"snapshot_timestamp,omitempty"`
	TimestampSource   string `json:"timestamp_source,omitempty"`

	RunPrivilege Privilege `json:"run_privilege"`
}

// NewPrivilege 记录采集进程的权限状态。两个 bool 都是实测值；调用方不得用
// 零值伪造"未提权"。
func NewPrivilege(administratorElevated, administratorGroupMember bool) Privilege {
	elevated := administratorElevated
	member := administratorGroupMember
	return Privilege{
		Recorded:                 true,
		AdministratorElevated:    &elevated,
		AdministratorGroupMember: &member,
		Source:                   PrivilegeSourceProcessToken,
	}
}

// UnavailablePrivilege 表示该快照没有采集时权限记录（旧版本/外部 JSONL）。
func UnavailablePrivilege() Privilege {
	return Privilege{Recorded: false, Source: PrivilegeSourceUnavailable}
}

// NormalizeTimestamp 把 RFC3339 时间归一为 UTC 秒精度。
func NormalizeTimestamp(s string) (string, error) {
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(s))
	if err != nil {
		return "", err
	}
	return t.UTC().Format(time.RFC3339), nil
}

// ArtifactPath 返回 JSONL 旁 sidecar 的路径。
func ArtifactPath(jsonlPath string) string { return jsonlPath + FileSuffix }

// ReadArtifact 读取 JSONL 旁的采集元数据。
//
// 文件不存在时返回 (nil, nil)：调用方应退化为 host.current_time / 导入时间，
// 而不是把"没有元数据"当成错误。文件存在但内容非法时返回错误，不静默忽略。
func ReadArtifact(jsonlPath string) (*Meta, error) {
	path := ArtifactPath(jsonlPath)
	m, err := readOne(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if err := ValidateCollected(m); err != nil {
		return nil, fmt.Errorf("采集元数据 %s 非法: %w", path, err)
	}
	return m, nil
}

// WriteArtifact 在 JSONL 旁写采集元数据。文件必须不存在（不覆盖既有记录）。
func WriteArtifact(jsonlPath string, m *Meta) error {
	if m == nil {
		return fmt.Errorf("采集元数据为空")
	}
	if err := ValidateCollected(m); err != nil {
		return err
	}
	return writeExclusive(ArtifactPath(jsonlPath), m)
}

// ReadSnapshot 读取数据库旁按 snapshot_id 保存的采集元数据。
//
// 文件不存在时返回 (nil, nil)：旧快照可能没有 sidecar，报告应明确显示"未记录"。
// 文件存在时，snapshot_id 与快照时间戳都必须与数据库中的记录一致，避免把
// 同一目录下另一份快照/陈旧 sidecar 当成当前快照的来源。
func ReadSnapshot(dbPath, snapshotID, snapshotTimestamp string) (*Meta, error) {
	path := snapshotPath(dbPath, snapshotID)
	m, err := readOne(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if err := ValidateSnapshot(m, snapshotID, snapshotTimestamp); err != nil {
		return nil, fmt.Errorf("采集元数据 %s 非法: %w", path, err)
	}
	return m, nil
}

// WriteSnapshot 在数据库旁写采集元数据。文件必须不存在（不覆盖既有记录）。
func WriteSnapshot(dbPath string, m *Meta) error {
	if m == nil {
		return fmt.Errorf("采集元数据为空")
	}
	if err := ValidateSnapshot(m, m.SnapshotID, m.SnapshotTimestamp); err != nil {
		return err
	}
	dir := filepath.Join(dbPath + snapshotMetaDirSuffix)
	if err := ensureMetaDir(dir); err != nil {
		return err
	}
	return writeExclusive(snapshotPath(dbPath, m.SnapshotID), m)
}

// RemoveArtifact 删除 JSONL 旁 sidecar；不存在不算错误。
func RemoveArtifact(jsonlPath string) error {
	err := os.Remove(ArtifactPath(jsonlPath))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// snapshotPath 用 snapshot_id 的 SHA256 作为文件名：snapshot_id 来自数据库，
// 不能直接拼进路径（否则恶意 ID 可目录穿越）。sidecar 内部仍保存原 ID 并校验。
func snapshotPath(dbPath, snapshotID string) string {
	sum := sha256.Sum256([]byte(snapshotID))
	name := hex.EncodeToString(sum[:]) + ".json"
	return filepath.Join(dbPath+snapshotMetaDirSuffix, name)
}

func ensureMetaDir(dir string) error {
	info, err := os.Lstat(dir)
	if os.IsNotExist(err) {
		if err := os.Mkdir(dir, 0o700); err != nil {
			return fmt.Errorf("创建采集元数据目录失败: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("读取采集元数据目录失败: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("采集元数据路径不是目录: %s", dir)
	}
	return nil
}

func readOne(path string) (*Meta, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("采集元数据不是普通文件: %s", path)
	}
	if info.Size() > maxSidecarBytes {
		return nil, fmt.Errorf("采集元数据超过上限 %d 字节: %s", maxSidecarBytes, path)
	}
	// 不依赖 size 预分配：读取时仍设置硬上限，避免文件在 Stat 之后增长。
	data, err := io.ReadAll(io.LimitReader(f, maxSidecarBytes+1))
	if err != nil {
		return nil, fmt.Errorf("读取采集元数据失败: %w", err)
	}
	if len(data) > maxSidecarBytes {
		return nil, fmt.Errorf("采集元数据超过上限 %d 字节: %s", maxSidecarBytes, path)
	}
	var m Meta
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("解析采集元数据失败: %w", err)
	}
	return &m, nil
}

func writeExclusive(path string, m *Meta) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("编码采集元数据失败: %w", err)
	}
	data = append(data, '\n')
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("创建采集元数据 %s 失败: %w", path, err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("写入采集元数据 %s 失败: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("同步采集元数据 %s 失败: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("关闭采集元数据 %s 失败: %w", path, err)
	}
	ok = true
	return nil
}

// ValidateCollected 校验采集时（尚无 snapshot_id）的元数据。
func ValidateCollected(m *Meta) error {
	if m == nil {
		return fmt.Errorf("采集元数据为空")
	}
	if m.SchemaVersion != SchemaVersion {
		return fmt.Errorf("不支持的采集元数据版本 %d（支持 %d）", m.SchemaVersion, SchemaVersion)
	}
	if strings.TrimSpace(m.CollectionStartedAt) == "" {
		return fmt.Errorf("采集元数据缺少 collection_started_at")
	}
	if err := validateTimes(m); err != nil {
		return err
	}
	if err := validatePrivilege(m.RunPrivilege); err != nil {
		return err
	}
	if m.SnapshotID != "" || m.SnapshotTimestamp != "" || m.TimestampSource != "" {
		return fmt.Errorf("采集时元数据不应包含 snapshot_id/snapshot_timestamp/timestamp_source")
	}
	return nil
}

// ValidateSnapshot 校验导入后（已绑定 snapshot_id/时间戳）的元数据。
func ValidateSnapshot(m *Meta, snapshotID, snapshotTimestamp string) error {
	if m == nil {
		return fmt.Errorf("采集元数据为空")
	}
	if m.SchemaVersion != SchemaVersion {
		return fmt.Errorf("不支持的采集元数据版本 %d（支持 %d）", m.SchemaVersion, SchemaVersion)
	}
	if snapshotID == "" || m.SnapshotID != snapshotID {
		return fmt.Errorf("snapshot_id 不一致（期望 %q，实际 %q）", snapshotID, m.SnapshotID)
	}
	if err := validateTimes(m); err != nil {
		return err
	}
	wantTS, err := NormalizeTimestamp(snapshotTimestamp)
	if err != nil {
		return fmt.Errorf("快照时间戳非法: %w", err)
	}
	gotTS, err := NormalizeTimestamp(m.SnapshotTimestamp)
	if err != nil {
		return fmt.Errorf("sidecar 快照时间戳非法: %w", err)
	}
	if gotTS != wantTS {
		return fmt.Errorf("快照时间戳不一致（期望 %q，实际 %q）", wantTS, gotTS)
	}
	switch m.TimestampSource {
	case TimestampSourceCollection:
		start, err := NormalizeTimestamp(m.CollectionStartedAt)
		if err != nil {
			return fmt.Errorf("时间戳来源为 collection 时必须记录合法的 collection_started_at: %w", err)
		}
		if start != gotTS {
			return fmt.Errorf("时间戳来源为 collection，但快照时间戳 %q 与采集开始时间 %q 不一致", gotTS, start)
		}
	case TimestampSourceHostCurrentTime, TimestampSourceImportTime:
		// 快照时间可能来自 host.current_time 或导入时间；不要求 collection_started_at。
	default:
		return fmt.Errorf("未知的时间戳来源 %q", m.TimestampSource)
	}
	if err := validatePrivilege(m.RunPrivilege); err != nil {
		return err
	}
	return nil
}

func validateTimes(m *Meta) error {
	if m.CollectionStartedAt != "" {
		if _, err := NormalizeTimestamp(m.CollectionStartedAt); err != nil {
			return fmt.Errorf("collection_started_at 非法: %w", err)
		}
	}
	if m.CollectionFinishedAt != "" {
		if _, err := NormalizeTimestamp(m.CollectionFinishedAt); err != nil {
			return fmt.Errorf("collection_finished_at 非法: %w", err)
		}
	}
	return nil
}

func validatePrivilege(p Privilege) error {
	if p.Source == "" {
		return fmt.Errorf("run_privilege.source 为空")
	}
	if !p.Recorded {
		if p.AdministratorElevated != nil || p.AdministratorGroupMember != nil {
			return fmt.Errorf("未记录的运行权限不应包含权限值")
		}
		return nil
	}
	if p.AdministratorElevated == nil || p.AdministratorGroupMember == nil {
		return fmt.Errorf("已记录的运行权限缺少管理员状态字段")
	}
	if p.Source == PrivilegeSourceUnavailable {
		return fmt.Errorf("已记录的运行权限不能使用 unavailable 来源")
	}
	return nil
}
