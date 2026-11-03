package storage

// EntityUpdateRow 是 entity_updates 表行。
type EntityUpdateRow struct {
	SnapshotID    string
	EntityID      string
	UpdateType    string
	SchemaVersion string
	DataJSON      string
	Timestamp     string
	CreatedAt     string
}

// InsertEntityUpdate 写入 entity_updates 表。
// 不合并覆盖原 entity——保留 Entity + Update 历史（每个 entity 可有多个 update）。
func InsertEntityUpdate(db *DB, r *EntityUpdateRow) error {
	s, err := db.Prepare(`INSERT INTO entity_updates
		(snapshot_id, entity_id, update_type, schema_version, data_json, timestamp, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`)
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
	if err := s.BindText(3, r.UpdateType); err != nil {
		return err
	}
	if err := s.BindText(4, r.SchemaVersion); err != nil {
		return err
	}
	if err := s.BindText(5, r.DataJSON); err != nil {
		return err
	}
	if err := s.BindText(6, r.Timestamp); err != nil {
		return err
	}
	if err := s.BindText(7, r.CreatedAt); err != nil {
		return err
	}
	_, err = s.Step()
	return err
}

// GetEntityUpdates 返回快照内某实体的全部 update（按 id 顺序）。
func GetEntityUpdates(db *DB, snapshotID, entityID string) ([]EntityUpdateRow, error) {
	s, err := db.Prepare(`SELECT snapshot_id, entity_id, update_type, schema_version, data_json, timestamp, created_at
		FROM entity_updates WHERE snapshot_id = ? AND entity_id = ? ORDER BY id`)
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
	var out []EntityUpdateRow
	for {
		hasRow, err := s.Step()
		if err != nil {
			return nil, err
		}
		if !hasRow {
			break
		}
		out = append(out, EntityUpdateRow{
			SnapshotID:    s.ColumnText(0),
			EntityID:      s.ColumnText(1),
			UpdateType:    s.ColumnText(2),
			SchemaVersion: s.ColumnText(3),
			DataJSON:      s.ColumnText(4),
			Timestamp:     s.ColumnText(5),
			CreatedAt:     s.ColumnText(6),
		})
	}
	return out, nil
}

// GetEntityUpdatesAll 返回快照内全部 update（按 id 顺序）。
func GetEntityUpdatesAll(db *DB, snapshotID string) ([]EntityUpdateRow, error) {
	s, err := db.Prepare(`SELECT snapshot_id, entity_id, update_type, schema_version, data_json, timestamp, created_at
		FROM entity_updates WHERE snapshot_id = ? ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if err := s.BindText(1, snapshotID); err != nil {
		return nil, err
	}
	var out []EntityUpdateRow
	for {
		hasRow, err := s.Step()
		if err != nil {
			return nil, err
		}
		if !hasRow {
			break
		}
		out = append(out, EntityUpdateRow{
			SnapshotID:    s.ColumnText(0),
			EntityID:      s.ColumnText(1),
			UpdateType:    s.ColumnText(2),
			SchemaVersion: s.ColumnText(3),
			DataJSON:      s.ColumnText(4),
			Timestamp:     s.ColumnText(5),
			CreatedAt:     s.ColumnText(6),
		})
	}
	return out, nil
}
