package main

import (
	"time"

	"easytrace/internal/collectionmeta"
	"easytrace/internal/platform/privilege"
	"easytrace/internal/storage"
)

// runCollectionMeta 生成采集时元数据。started/finished 必须取自同一次采集的
// 墙钟起点与终点；权限取自**采集进程**当前 Token，而不是报告进程。
func runCollectionMeta(mode string, started, finished time.Time, priv privilege.PrivilegeInfo) *collectionmeta.Meta {
	return &collectionmeta.Meta{
		SchemaVersion:        collectionmeta.SchemaVersion,
		ToolVersion:          cliVersion,
		CollectionMode:       mode,
		CollectionStartedAt:  started.UTC().Format(time.RFC3339),
		CollectionFinishedAt: finished.UTC().Format(time.RFC3339),
		RunPrivilege: collectionmeta.NewPrivilege(
			priv.IsElevated, priv.IsAdminGroupMember),
	}
}

// snapshotCollectionMeta 把采集时元数据绑定到导入后的快照，供数据库旁 sidecar
// 保存。base 可以为 nil（没有采集时记录），此时权限明确写成 unavailable。
func snapshotCollectionMeta(base *collectionmeta.Meta, meta *storage.SnapshotMeta,
	timestampSource, toolVersion string) *collectionmeta.Meta {

	out := &collectionmeta.Meta{
		SchemaVersion:     collectionmeta.SchemaVersion,
		ToolVersion:       toolVersion,
		Hostname:          meta.Hostname,
		CollectionMode:    meta.CollectionMode,
		SnapshotID:        meta.SnapshotID,
		SnapshotTimestamp: meta.Timestamp,
		TimestampSource:   timestampSource,
		RunPrivilege:      collectionmeta.UnavailablePrivilege(),
	}
	if base != nil {
		if base.ToolVersion != "" {
			out.ToolVersion = base.ToolVersion
		}
		if out.Hostname == "" {
			out.Hostname = base.Hostname
		}
		out.CollectionStartedAt = base.CollectionStartedAt
		out.CollectionFinishedAt = base.CollectionFinishedAt
		out.RunPrivilege = base.RunPrivilege
	}
	return out
}

// writeSnapshotCollectionMeta 在数据库旁保存采集来源记录。
//
// 文件不存在才写入（由 collectionmeta 保证）；失败必须显式返回：没有这份记录，
// 报告应显示"未记录"，不能假装知道采集时权限。
func writeSnapshotCollectionMeta(dbPath string, meta *storage.SnapshotMeta,
	base *collectionmeta.Meta, timestampSource, toolVersion string) error {

	return collectionmeta.WriteSnapshot(dbPath,
		snapshotCollectionMeta(base, meta, timestampSource, toolVersion))
}
