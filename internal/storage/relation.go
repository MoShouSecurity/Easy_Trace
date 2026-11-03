package storage

// RelationRow 是 relations 表行。
type RelationRow struct {
	SnapshotID    string
	RelationID    string
	SourceID      string
	TargetID      string
	RelationType  string
	SchemaVersion string
	AttrsJSON     string
	CreatedAt     string
}

// InsertRelation 写入 relations 表。
// source_id / target_id 保留原始 ID，不强求外键可解析（跨模块引用/单模块采集/不完整快照均可保存）。
func InsertRelation(db *DB, r *RelationRow) error {
	s, err := db.Prepare(`INSERT INTO relations
		(snapshot_id, relation_id, source_id, target_id, relation_type, schema_version, attrs_json, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.BindText(1, r.SnapshotID); err != nil {
		return err
	}
	if err := s.BindText(2, r.RelationID); err != nil {
		return err
	}
	if err := s.BindText(3, r.SourceID); err != nil {
		return err
	}
	if err := s.BindText(4, r.TargetID); err != nil {
		return err
	}
	if err := s.BindText(5, r.RelationType); err != nil {
		return err
	}
	if err := s.BindText(6, r.SchemaVersion); err != nil {
		return err
	}
	if err := s.BindText(7, r.AttrsJSON); err != nil {
		return err
	}
	if err := s.BindText(8, r.CreatedAt); err != nil {
		return err
	}
	_, err = s.Step()
	return err
}

// GetRelations 返回快照内全部关系。
func GetRelations(db *DB, snapshotID string) ([]RelationRow, error) {
	s, err := db.Prepare(`SELECT snapshot_id, relation_id, source_id, target_id,
		relation_type, schema_version, attrs_json, created_at
		FROM relations WHERE snapshot_id = ? ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if err := s.BindText(1, snapshotID); err != nil {
		return nil, err
	}
	var out []RelationRow
	for {
		hasRow, err := s.Step()
		if err != nil {
			return nil, err
		}
		if !hasRow {
			break
		}
		out = append(out, RelationRow{
			SnapshotID:    s.ColumnText(0),
			RelationID:    s.ColumnText(1),
			SourceID:      s.ColumnText(2),
			TargetID:      s.ColumnText(3),
			RelationType:  s.ColumnText(4),
			SchemaVersion: s.ColumnText(5),
			AttrsJSON:     s.ColumnText(6),
			CreatedAt:     s.ColumnText(7),
		})
	}
	return out, nil
}
