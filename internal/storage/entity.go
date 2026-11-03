package storage

import "fmt"

// EntityRow 是 entities 表行。
type EntityRow struct {
	SnapshotID    string
	EntityID      string
	EntityType    string
	SchemaVersion string
	DataJSON      string
	CreatedAt     string
}

// InsertEntity 写入 entities 表（snapshot 内 entity_id 唯一，由 UNIQUE 约束保证）。
func InsertEntity(db *DB, r *EntityRow) error {
	s, err := db.Prepare(`INSERT INTO entities
		(snapshot_id, entity_id, entity_type, schema_version, data_json, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.BindText(1, r.SnapshotID); err != nil {
		return err
	}
	if err := s.BindText(2, r.EntityID); err != nil {
		return err
	}
	if err := s.BindText(3, r.EntityType); err != nil {
		return err
	}
	if err := s.BindText(4, r.SchemaVersion); err != nil {
		return err
	}
	if err := s.BindText(5, r.DataJSON); err != nil {
		return err
	}
	if err := s.BindText(6, r.CreatedAt); err != nil {
		return err
	}
	_, err = s.Step()
	return err
}

// EntityExists 检查 snapshot 内 entity_id 是否存在（entity_update 顺序校验用）。
func EntityExists(db *DB, snapshotID, entityID string) (bool, error) {
	s, err := db.Prepare(`SELECT 1 FROM entities WHERE snapshot_id = ? AND entity_id = ?`)
	if err != nil {
		return false, err
	}
	defer s.Close()
	if err := s.BindText(1, snapshotID); err != nil {
		return false, err
	}
	if err := s.BindText(2, entityID); err != nil {
		return false, err
	}
	hasRow, err := s.Step()
	if err != nil {
		return false, err
	}
	return hasRow, nil
}

// GetEntities 返回快照内全部实体。
func GetEntities(db *DB, snapshotID string) ([]EntityRow, error) {
	s, err := db.Prepare(`SELECT snapshot_id, entity_id, entity_type, schema_version, data_json, created_at
		FROM entities WHERE snapshot_id = ? ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if err := s.BindText(1, snapshotID); err != nil {
		return nil, err
	}
	var out []EntityRow
	for {
		hasRow, err := s.Step()
		if err != nil {
			return nil, err
		}
		if !hasRow {
			break
		}
		out = append(out, EntityRow{
			SnapshotID:    s.ColumnText(0),
			EntityID:      s.ColumnText(1),
			EntityType:    s.ColumnText(2),
			SchemaVersion: s.ColumnText(3),
			DataJSON:      s.ColumnText(4),
			CreatedAt:     s.ColumnText(5),
		})
	}
	return out, nil
}

// GetEntity 按 snapshot_id + entity_id 查询单个实体；不存在返回 ErrNotFound。
func GetEntity(db *DB, snapshotID, entityID string) (*EntityRow, error) {
	s, err := db.Prepare(`SELECT snapshot_id, entity_id, entity_type, schema_version, data_json, created_at
		FROM entities WHERE snapshot_id = ? AND entity_id = ?`)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if err := s.BindText(1, snapshotID); err != nil {
		return nil, err
	}
	if err := s.BindText(2, entityID); err != nil {
		return nil, err
	}
	hasRow, err := s.Step()
	if err != nil {
		return nil, err
	}
	if !hasRow {
		return nil, fmt.Errorf("%w: entity %s in %s", ErrNotFound, entityID, snapshotID)
	}
	return &EntityRow{
		SnapshotID:    s.ColumnText(0),
		EntityID:      s.ColumnText(1),
		EntityType:    s.ColumnText(2),
		SchemaVersion: s.ColumnText(3),
		DataJSON:      s.ColumnText(4),
		CreatedAt:     s.ColumnText(5),
	}, nil
}
