package storage

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// SnapshotMeta 是一次采集快照的元信息（snapshots 表行）。
type SnapshotMeta struct {
	SnapshotID     string
	Timestamp      string // 采集时间（ISO8601 UTC）
	Hostname       string
	OSVersion      string
	Architecture   string
	CollectionMode string // basic / deep / forensic
	AgentVersion   string
	CreatedAt      string
}

// NewSnapshotID 生成唯一 snapshot_id：snapshot_YYYYMMDD_HHMMSS_xxxx（4 位随机 hex）。
func NewSnapshotID() string {
	now := time.Now().UTC()
	return fmt.Sprintf("snapshot_%s_%s", now.Format("20060102_150405"), randomHex(4))
}

// randomHex 返回 n 字节的随机 hex 字符串。
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%04d", time.Now().UnixNano()%10000)
	}
	return hex.EncodeToString(b)
}

// InsertSnapshot 写入 snapshots 表，返回新行 id。
func InsertSnapshot(db *DB, m *SnapshotMeta) (int64, error) {
	if m == nil {
		m = &SnapshotMeta{}
	}
	s, err := db.Prepare(`INSERT INTO snapshots
		(snapshot_id, timestamp, hostname, os_version, architecture, collection_mode, agent_version, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return 0, err
	}
	defer s.Close()
	now := time.Now().UTC().Format(time.RFC3339)
	if m.CreatedAt == "" {
		m.CreatedAt = now
	}
	if err := s.BindText(1, m.SnapshotID); err != nil {
		return 0, err
	}
	if err := s.BindText(2, m.Timestamp); err != nil {
		return 0, err
	}
	if err := s.BindText(3, m.Hostname); err != nil {
		return 0, err
	}
	if err := s.BindText(4, m.OSVersion); err != nil {
		return 0, err
	}
	if err := s.BindText(5, m.Architecture); err != nil {
		return 0, err
	}
	if err := s.BindText(6, m.CollectionMode); err != nil {
		return 0, err
	}
	if err := s.BindText(7, m.AgentVersion); err != nil {
		return 0, err
	}
	if err := s.BindText(8, m.CreatedAt); err != nil {
		return 0, err
	}
	if _, err := s.Step(); err != nil {
		return 0, err
	}
	return db.LastInsertRowID(), nil
}

// ListSnapshots 返回全部快照（按 created_at 倒序，同一秒内按 snapshot_id 倒序）。
//
// created_at 只有秒精度：连续导入两份快照时它可能相同。若只按 created_at 排序，
// “最新快照”取决于 SQLite 未定义的并列顺序，catch/analyze/report 可能静默选到另一份。
// snapshot_id 内含随机后缀且全局唯一，作为确定的二级排序键。
func ListSnapshots(db *DB) ([]SnapshotMeta, error) {
	s, err := db.Prepare(`SELECT snapshot_id, timestamp, hostname, os_version,
		architecture, collection_mode, agent_version, created_at
		FROM snapshots ORDER BY created_at DESC, snapshot_id DESC`)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	var out []SnapshotMeta
	for {
		hasRow, err := s.Step()
		if err != nil {
			return nil, err
		}
		if !hasRow {
			break
		}
		out = append(out, SnapshotMeta{
			SnapshotID:     s.ColumnText(0),
			Timestamp:      s.ColumnText(1),
			Hostname:       s.ColumnText(2),
			OSVersion:      s.ColumnText(3),
			Architecture:   s.ColumnText(4),
			CollectionMode: s.ColumnText(5),
			AgentVersion:   s.ColumnText(6),
			CreatedAt:      s.ColumnText(7),
		})
	}
	return out, nil
}

// GetSnapshot 按 snapshot_id 查询单个快照；不存在返回 ErrNotFound。
var ErrNotFound = fmt.Errorf("storage: 记录不存在")

func GetSnapshot(db *DB, snapshotID string) (*SnapshotMeta, error) {
	s, err := db.Prepare(`SELECT snapshot_id, timestamp, hostname, os_version,
		architecture, collection_mode, agent_version, created_at
		FROM snapshots WHERE snapshot_id = ?`)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if err := s.BindText(1, snapshotID); err != nil {
		return nil, err
	}
	hasRow, err := s.Step()
	if err != nil {
		return nil, err
	}
	if !hasRow {
		return nil, fmt.Errorf("%w: snapshot %s", ErrNotFound, snapshotID)
	}
	return &SnapshotMeta{
		SnapshotID:     s.ColumnText(0),
		Timestamp:      s.ColumnText(1),
		Hostname:       s.ColumnText(2),
		OSVersion:      s.ColumnText(3),
		Architecture:   s.ColumnText(4),
		CollectionMode: s.ColumnText(5),
		AgentVersion:   s.ColumnText(6),
		CreatedAt:      s.ColumnText(7),
	}, nil
}
