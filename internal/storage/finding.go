package storage

// FindingRow 是 findings 表行（V0.1 预留，当前无 Analyzer 时为空）。
type FindingRow struct {
	SnapshotID          string
	FindingID           string
	RuleID              string
	Severity            string
	Title               string
	Description         string
	EntityID            string
	RelatedEntitiesJSON string
	EvidenceJSON        string
	Advice              string
	CreatedAt           string
}

// InsertFinding 写入 findings 表。
func InsertFinding(db *DB, r *FindingRow) error {
	s, err := db.Prepare(`INSERT INTO findings
		(snapshot_id, finding_id, rule_id, severity, title, description, entity_id,
		 related_entities_json, evidence_json, advice, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.BindText(1, r.SnapshotID); err != nil {
		return err
	}
	if err := s.BindText(2, r.FindingID); err != nil {
		return err
	}
	if err := s.BindText(3, r.RuleID); err != nil {
		return err
	}
	if err := s.BindText(4, r.Severity); err != nil {
		return err
	}
	if err := s.BindText(5, r.Title); err != nil {
		return err
	}
	if err := s.BindText(6, r.Description); err != nil {
		return err
	}
	if err := s.BindText(7, r.EntityID); err != nil {
		return err
	}
	if err := s.BindText(8, r.RelatedEntitiesJSON); err != nil {
		return err
	}
	if err := s.BindText(9, r.EvidenceJSON); err != nil {
		return err
	}
	if err := s.BindText(10, r.Advice); err != nil {
		return err
	}
	if err := s.BindText(11, r.CreatedAt); err != nil {
		return err
	}
	_, err = s.Step()
	return err
}

// GetFindings 返回快照内全部 findings。
func GetFindings(db *DB, snapshotID string) ([]FindingRow, error) {
	s, err := db.Prepare(`SELECT snapshot_id, finding_id, rule_id, severity, title, description,
		entity_id, related_entities_json, evidence_json, advice, created_at
		FROM findings WHERE snapshot_id = ? ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if err := s.BindText(1, snapshotID); err != nil {
		return nil, err
	}
	var out []FindingRow
	for {
		hasRow, err := s.Step()
		if err != nil {
			return nil, err
		}
		if !hasRow {
			break
		}
		out = append(out, FindingRow{
			SnapshotID:          s.ColumnText(0),
			FindingID:           s.ColumnText(1),
			RuleID:              s.ColumnText(2),
			Severity:            s.ColumnText(3),
			Title:               s.ColumnText(4),
			Description:         s.ColumnText(5),
			EntityID:            s.ColumnText(6),
			RelatedEntitiesJSON: s.ColumnText(7),
			EvidenceJSON:        s.ColumnText(8),
			Advice:              s.ColumnText(9),
			CreatedAt:           s.ColumnText(10),
		})
	}
	return out, nil
}
