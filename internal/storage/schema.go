package storage

import "fmt"

// schemaSQL 是 Easy_Trace SQLite Snapshot 的建表 DDL（Step 6 冻结）。
//
// 设计原则：结构化元数据 + JSON payload——实体数据以 data_json 保存原始协议
// JSON，不把 Process/Network/Service 等字段硬编码为列（协议扩展零迁移）。
const schemaSQL = `
CREATE TABLE IF NOT EXISTS snapshots (
	id               INTEGER PRIMARY KEY AUTOINCREMENT,
	snapshot_id      TEXT NOT NULL UNIQUE,
	timestamp        TEXT NOT NULL,
	hostname         TEXT,
	os_version       TEXT,
	architecture     TEXT,
	collection_mode  TEXT NOT NULL,
	agent_version    TEXT,
	created_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS entities (
	id             INTEGER PRIMARY KEY AUTOINCREMENT,
	snapshot_id    TEXT NOT NULL,
	entity_id      TEXT NOT NULL,
	entity_type    TEXT NOT NULL,
	schema_version TEXT NOT NULL,
	data_json      TEXT NOT NULL,
	created_at     TEXT NOT NULL,
	UNIQUE(snapshot_id, entity_id)
);

CREATE TABLE IF NOT EXISTS entity_updates (
	id             INTEGER PRIMARY KEY AUTOINCREMENT,
	snapshot_id    TEXT NOT NULL,
	entity_id      TEXT NOT NULL,
	update_type    TEXT NOT NULL,
	schema_version TEXT NOT NULL,
	data_json      TEXT NOT NULL,
	timestamp      TEXT NOT NULL,
	created_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS relations (
	id             INTEGER PRIMARY KEY AUTOINCREMENT,
	snapshot_id    TEXT NOT NULL,
	relation_id    TEXT NOT NULL,
	source_id      TEXT NOT NULL,
	target_id      TEXT NOT NULL,
	relation_type  TEXT NOT NULL,
	schema_version TEXT NOT NULL,
	attrs_json     TEXT NOT NULL DEFAULT '{}',
	created_at     TEXT NOT NULL,
	UNIQUE(snapshot_id, relation_id)
);

CREATE TABLE IF NOT EXISTS findings (
	id                    INTEGER PRIMARY KEY AUTOINCREMENT,
	snapshot_id           TEXT NOT NULL,
	finding_id            TEXT NOT NULL,
	rule_id               TEXT,
	severity              TEXT,
	title                 TEXT,
	description           TEXT,
	entity_id             TEXT,
	related_entities_json TEXT,
	evidence_json         TEXT,
	advice                TEXT,
	created_at            TEXT NOT NULL,
	UNIQUE(snapshot_id, finding_id)
);

CREATE INDEX IF NOT EXISTS idx_entities_snapshot   ON entities(snapshot_id);
CREATE INDEX IF NOT EXISTS idx_updates_snapshot    ON entity_updates(snapshot_id);
CREATE INDEX IF NOT EXISTS idx_relations_snapshot  ON relations(snapshot_id);
CREATE INDEX IF NOT EXISTS idx_findings_snapshot   ON findings(snapshot_id);
`

// InitSchema 创建所有表与索引（幂等）。
func InitSchema(db *DB) error {
	return db.Exec(schemaSQL)
}

// coreTables 是 Easy_Trace 数据库必须齐全的表（与 schemaSQL 一致）。
var coreTables = []string{"snapshots", "entities", "entity_updates", "relations", "findings"}

// CheckSchema 校验数据库里确实有 Easy_Trace 的表结构，不创建任何东西。
//
// 读命令不再调用 InitSchema：那会在空文件、其它 SQLite 库或只读介质上试图
// 建表，既可能失败（只读）也会把“路径给错了”伪装成“没有快照”。这里只检查
// 5 张核心表是否齐全，缺任何一张都明确报错并给出下一步。
func CheckSchema(db *DB) error {
	const q = `SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN (` +
		`'snapshots','entities','entity_updates','relations','findings')`
	s, err := db.Prepare(q)
	if err != nil {
		return fmt.Errorf("storage: 读取数据库结构失败（不是 Easy_Trace 数据库？）: %w", err)
	}
	defer s.Close()
	has, err := s.Step()
	if err != nil {
		return fmt.Errorf("storage: 读取数据库结构失败: %w", err)
	}
	var n int64
	if has {
		n = s.ColumnInt64(0)
	}
	if n != int64(len(coreTables)) {
		return fmt.Errorf("storage: 数据库缺少 Easy_Trace 表结构（找到 %d/%d 张核心表）: %s。"+
			"请确认 --db 指向 collect / snapshot import 生成的数据库；读命令不会自动建表",
			n, len(coreTables), db.Path())
	}
	return nil
}
