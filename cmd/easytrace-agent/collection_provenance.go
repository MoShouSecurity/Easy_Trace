package main

import (
	"fmt"

	"easytrace/internal/collectionmeta"
	"easytrace/internal/storage"
)

// collectionProvenance 是报告可见的“采集来源”视图。
//
// 它只来自两个地方：
//   - snapshots 表里冻结的 timestamp / snapshot_id；
//   - 数据库旁的采集元数据 sidecar（导入时写入，记录采集开始/结束与采集进程权限）。
//
// 关键边界：**绝不读取报告进程当前权限**。采集与报告可能不是同一个用户/同一个
// 提权状态，拿报告时的权限冒充采集权限会把“非管理员采集、管理员出报告”写成
// “管理员采集”，正好相反。
type collectionProvenance struct {
	Meta            *storage.SnapshotMeta
	Recorded        *collectionmeta.Meta // nil 表示没有采集元数据（旧快照/外部 JSONL）
	TimestampSource string               // collection / host_current_time / import_time / unavailable
	Privilege       collectionmeta.Privilege
}

// loadCollectionProvenance 读取并校验快照的采集元数据。
//
// sidecar 不存在 → (Recorded=nil)，报告显示“未记录”；
// sidecar 存在但非法/与快照不匹配 → 返回错误（不静默使用不可信来源）。
func loadCollectionProvenance(dbPath string, meta *storage.SnapshotMeta) (*collectionProvenance, error) {
	cm, err := collectionmeta.ReadSnapshot(dbPath, meta.SnapshotID, meta.Timestamp)
	if err != nil {
		return nil, fmt.Errorf("读取采集元数据失败: %w", err)
	}
	p := newUnknownProvenance(meta)
	if cm != nil {
		p.Recorded = cm
		p.TimestampSource = cm.TimestampSource
		p.Privilege = cm.RunPrivilege
	}
	return p, nil
}

// newUnknownProvenance 表示“没有采集元数据”：时间来源与采集权限都未记录。
func newUnknownProvenance(meta *storage.SnapshotMeta) *collectionProvenance {
	return &collectionProvenance{
		Meta:            meta,
		TimestampSource: collectionmeta.TimestampSourceUnavailable,
		Privilege:       collectionmeta.UnavailablePrivilege(),
	}
}

// timeLabel 返回快照时间戳在报告中的准确名称。
func (p *collectionProvenance) timeLabel() string {
	switch p.TimestampSource {
	case collectionmeta.TimestampSourceCollection:
		return "采集开始时间"
	case collectionmeta.TimestampSourceHostCurrentTime:
		return "主机当前时间"
	case collectionmeta.TimestampSourceImportTime:
		return "导入时间"
	}
	return "快照记录时间"
}

// timeNote 说明这个时间戳到底代表什么，避免读者把每个时间都当成采集时刻。
func (p *collectionProvenance) timeNote() string {
	switch p.TimestampSource {
	case collectionmeta.TimestampSourceCollection:
		return "采集开始时刻，不是事件时刻"
	case collectionmeta.TimestampSourceHostCurrentTime:
		return "采集时刻的近似值，不是事件时刻"
	case collectionmeta.TimestampSourceImportTime:
		return "导入时刻，不是采集时间"
	}
	return "采集时间来源未记录"
}

// timeSourceEN 是时间来源的机器可读标识（与 findings.json 一致）。
func (p *collectionProvenance) timeSourceEN() string {
	if p.TimestampSource == "" {
		return collectionmeta.TimestampSourceUnavailable
	}
	return p.TimestampSource
}

// timestamp 返回快照时间戳原值；没有时明确写“未记录”。
func (p *collectionProvenance) timestamp() string {
	if p.Meta == nil || p.Meta.Timestamp == "" {
		return "未记录"
	}
	return p.Meta.Timestamp
}

// timeSentence 生成一句可直接放进报告的时间说明。
func (p *collectionProvenance) timeSentence() string {
	return fmt.Sprintf("%s %s（UTC；%s）", p.timeLabel(), p.timestamp(), p.timeNote())
}

// privilegeKnown 区分“明确不是管理员”与“没有记录”。
func (p *collectionProvenance) privilegeKnown() bool {
	return p.Privilege.Recorded && p.Privilege.AdministratorElevated != nil
}

// elevated 只在有明确记录时返回 true。
func (p *collectionProvenance) elevated() bool {
	return p.privilegeKnown() && *p.Privilege.AdministratorElevated
}

// groupMember 返回管理员组成员状态；未记录时 ok=false。
func (p *collectionProvenance) groupMember() (bool, bool) {
	if !p.Privilege.Recorded || p.Privilege.AdministratorGroupMember == nil {
		return false, false
	}
	return *p.Privilege.AdministratorGroupMember, true
}

func (p *collectionProvenance) privilegeZh() string {
	if !p.privilegeKnown() {
		return "未记录"
	}
	if p.elevated() {
		return "是"
	}
	return "否"
}

func (p *collectionProvenance) privilegeEN() string {
	if !p.privilegeKnown() {
		return "NOT RECORDED"
	}
	if p.elevated() {
		return "YES"
	}
	return "NO"
}

func (p *collectionProvenance) collectionStartedAt() string {
	if p.Recorded == nil {
		return ""
	}
	return p.Recorded.CollectionStartedAt
}

func (p *collectionProvenance) collectionFinishedAt() string {
	if p.Recorded == nil {
		return ""
	}
	return p.Recorded.CollectionFinishedAt
}

// anchorDetail 是时间线锚点行的 detail：必须按真实来源措辞。
func (p *collectionProvenance) anchorDetail() string {
	switch p.TimestampSource {
	case collectionmeta.TimestampSourceCollection:
		return "快照采集开始时刻（锚点，非事件时刻）"
	case collectionmeta.TimestampSourceHostCurrentTime:
		return "主机当前时间（采集时刻近似值；锚点，非事件时刻）"
	case collectionmeta.TimestampSourceImportTime:
		return "快照导入时刻（不是采集时刻；锚点）"
	}
	return "快照记录时间（采集时间来源未记录；锚点，非事件时刻）"
}

// anchorDescription 接在 StatsLine 的“锚点 snapshot.collected_at 为……”后面。
func (p *collectionProvenance) anchorDescription() string {
	switch p.TimestampSource {
	case collectionmeta.TimestampSourceCollection:
		return "采集开始时间"
	case collectionmeta.TimestampSourceHostCurrentTime:
		return "主机当前时间（采集时刻近似值）"
	case collectionmeta.TimestampSourceImportTime:
		return "导入时间（不是采集时刻）"
	}
	return "快照记录时间（采集时间来源未记录）"
}
