package main

import (
	"encoding/json"
	"flag"
	"fmt"

	"easytrace/internal/collectionmeta"
	"easytrace/internal/storage"
)

// runSnapshot 处理 snapshot 子命令（Step 6 SQLite Snapshot 存储）：
//
//	easytrace snapshot import --db <path> [--mode basic|deep|forensic] <file.jsonl>
//	easytrace snapshot list --db <path>
//	easytrace snapshot show --db <path> <snapshot_id>
//	easytrace snapshot diff --db <path> --from <snapshot_id> --to <snapshot_id>
func runSnapshot(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("snapshot 子命令: import --db <path> [--mode <mode>] <file> | list --db <path> | show --db <path> <snapshot_id> | diff --db <path> --from <id> --to <id>")
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "import":
		fs := flag.NewFlagSet("snapshot import", flag.ContinueOnError)
		dbPath := fs.String("db", "easytrace.db", "SQLite 数据库路径")
		mode := fs.String("mode", "", "采集模式（basic/deep/forensic）；留空自动探测")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return fmt.Errorf("用法: snapshot import --db <path> [--mode <mode>] <file.jsonl>")
		}
		input := fs.Arg(0)
		// JSONL 旁的采集 sidecar 是采集时写下的原始记录：存在但不合法必须显式失败，
		// 不能悄悄退回“导入时间 + 未记录权限”。不存在则允许（外部/旧产物）。
		collected, err := collectionmeta.ReadArtifact(input)
		if err != nil {
			return err
		}
		db, err := storage.Open(*dbPath)
		if err != nil {
			return err
		}
		defer db.Close()
		if err := storage.InitSchema(db); err != nil {
			return err
		}
		res, err := storage.ImportJSONLWithOptions(db, input, storage.ImportOptions{
			Mode:         *mode,
			AgentVersion: cliVersion,
			Collection:   collected,
		})
		if err != nil {
			return err
		}
		meta := res.Meta
		if err := writeSnapshotCollectionMeta(*dbPath, meta, collected,
			res.TimestampSource, cliVersion); err != nil {
			return fmt.Errorf("导入成功（snapshot_id=%s），但采集元数据写入失败: %w",
				meta.SnapshotID, err)
		}
		fmt.Printf("导入成功: snapshot_id=%s mode=%s hostname=%s timestamp=%s source=%s entities 已保存到 %s\n",
			meta.SnapshotID, meta.CollectionMode, meta.Hostname,
			meta.Timestamp, res.TimestampSource, *dbPath)
		return nil
	case "list":
		fs := flag.NewFlagSet("snapshot list", flag.ContinueOnError)
		dbPath := fs.String("db", "easytrace.db", "SQLite 数据库路径")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		// 只读子命令（list/show/diff）不建表、不写 journal。
		db, err := storage.OpenReadOnly(*dbPath)
		if err != nil {
			return err
		}
		defer db.Close()
		if err := storage.CheckSchema(db); err != nil {
			return err
		}
		snaps, err := storage.ListSnapshots(db)
		if err != nil {
			return err
		}
		if len(snaps) == 0 {
			fmt.Println("（无快照）")
			return nil
		}
		for _, s := range snaps {
			fmt.Printf("%-32s mode=%-8s hostname=%-12s ts=%s\n",
				s.SnapshotID, s.CollectionMode, s.Hostname, s.Timestamp)
		}
		return nil
	case "show":
		fs := flag.NewFlagSet("snapshot show", flag.ContinueOnError)
		dbPath := fs.String("db", "easytrace.db", "SQLite 数据库路径")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return fmt.Errorf("用法: snapshot show --db <path> <snapshot_id>")
		}
		// 只读子命令（list/show/diff）不建表、不写 journal。
		db, err := storage.OpenReadOnly(*dbPath)
		if err != nil {
			return err
		}
		defer db.Close()
		if err := storage.CheckSchema(db); err != nil {
			return err
		}
		sid := fs.Arg(0)
		meta, err := storage.GetSnapshot(db, sid)
		if err != nil {
			return err
		}
		if meta == nil {
			return fmt.Errorf("快照 %s 不存在", sid)
		}
		ents, err := storage.GetEntities(db, sid)
		if err != nil {
			return fmt.Errorf("读取快照实体失败: %w", err)
		}
		ups, err := storage.GetEntityUpdatesAll(db, sid)
		if err != nil {
			return fmt.Errorf("读取快照更新失败: %w", err)
		}
		rels, err := storage.GetRelations(db, sid)
		if err != nil {
			return fmt.Errorf("读取快照关系失败: %w", err)
		}
		finds, err := storage.GetFindings(db, sid)
		if err != nil {
			return fmt.Errorf("读取快照线索失败: %w", err)
		}
		fmt.Printf("快照: %s\n", meta.SnapshotID)
		fmt.Printf("  mode=%s hostname=%s os_version=%s arch=%s ts=%s\n",
			meta.CollectionMode, meta.Hostname, meta.OSVersion, meta.Architecture, meta.Timestamp)
		fmt.Printf("  entities=%d updates=%d relations=%d findings=%d\n",
			len(ents), len(ups), len(rels), len(finds))
		return nil
	case "diff":
		fs := flag.NewFlagSet("snapshot diff", flag.ContinueOnError)
		dbPath := fs.String("db", "easytrace.db", "SQLite 数据库路径")
		from := fs.String("from", "", "源快照 snapshot_id")
		to := fs.String("to", "", "目标快照 snapshot_id")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if *from == "" || *to == "" {
			return fmt.Errorf("用法: snapshot diff --db <path> --from <snapshot_id> --to <snapshot_id>")
		}
		// 只读子命令（list/show/diff）不建表、不写 journal。
		db, err := storage.OpenReadOnly(*dbPath)
		if err != nil {
			return err
		}
		defer db.Close()
		if err := storage.CheckSchema(db); err != nil {
			return err
		}
		diff, err := storage.DiffSnapshots(db, *from, *to)
		if err != nil {
			return err
		}
		out, err := json.MarshalIndent(diff, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(out))
		return nil
	default:
		return fmt.Errorf("未知 snapshot 子命令 %q（支持: import / list / show / diff）", sub)
	}
}
