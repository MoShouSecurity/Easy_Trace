package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"easytrace/internal/storage"
	"easytrace/internal/whitelist"
)

// runWhitelist 处理 whitelist 子命令（V1.0 设计项，设计见 docs/设计-白名单.md）：
//
//	easytrace whitelist add    --rule <id> --entity <id> --reason "..." [--db <db>] [--snapshot <id>] [-w <file>]
//	easytrace whitelist list   [--db <db>] [-w <file>]
//	easytrace whitelist remove --rule <id> --entity <id> [--db <db>] [-w <file>]
//
// 白名单是**配置**，不是证据：它只抑制"这条规则在这个实体上"的报告提示，
// 被抑制的线索**仍然留在快照与 findings.json 里**（见 internal/whitelist 的包说明）。
// catch 从不读取白名单：证据留存不能被展示层配置削减。
//
// add 会从 --db 的目标快照读取实体，把主机名、实体类型与稳定指纹写进条目，
// 避免下一次采集中 PID/序号被复用时抑制到另一个对象。
func runWhitelist(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法: whitelist add|list|remove [--rule <id> --entity <id> --reason <text>] [--db <db>] [--snapshot <id>] [-w <file>]")
	}
	sub := args[0]
	fs := flag.NewFlagSet("whitelist "+sub, flag.ContinueOnError)
	dbPath := fs.String("db", "easytrace.db", "数据库路径（默认白名单位置；add 需要从中读取实体身份）")
	filePath := fs.String("w", "", "白名单文件（默认与 --db 同目录的 "+whitelist.FileName+"）")
	fs.StringVar(filePath, "whitelist", "", "-w 同义")
	ruleID := fs.String("rule", "", "规则 ID（如 process.user_path.executable）")
	entityID := fs.String("entity", "", "实体 ID（如 process_12196）")
	reason := fs.String("reason", "", "抑制理由（**必填**，便于日后审计）")
	snapshotID := fs.String("snapshot", "", "add 计算稳定身份所用快照（默认最新快照）")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("用法: whitelist %s [--rule <id> --entity <id> --reason <text>] [--db <db>] [--snapshot <id>] [-w <file>]", sub)
	}

	path := resolveWhitelistPath(*filePath, *dbPath)
	f, err := whitelist.Load(path)
	if err != nil {
		return err
	}

	switch sub {
	case "add":
		scope, err := whitelistEntryScope(*dbPath, *snapshotID, *entityID)
		if err != nil {
			return err
		}
		e := whitelist.Entry{
			RuleID:       *ruleID,
			EntityID:     *entityID,
			Reason:       *reason,
			AddedAt:      time.Now().UTC().Format(time.RFC3339),
			AddedBy:      operatorLabel(),
			EntityType:   scope.EntityType,
			Hostname:     scope.Hostname,
			Identity:     scope.Identity,
			EvidenceHash: scope.EvidenceHash,
		}
		if err := f.Add(e); err != nil {
			return err
		}
		if err := f.Save(path); err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "已加入白名单：%s / %s\n", e.RuleID, e.EntityID)
		fmt.Fprintf(os.Stdout, "  理由：%s\n", e.Reason)
		fmt.Fprintf(os.Stdout, "  范围：主机 %s，实体类型 %s，快照 %s\n", e.Hostname, e.EntityType, scope.SnapshotID)
		fmt.Fprintf(os.Stdout, "  稳定身份：%s\n", e.Identity)
		if e.EvidenceHash != "" {
			fmt.Fprintf(os.Stdout, "  实体哈希：%s\n", e.EvidenceHash)
		}
		fmt.Fprintf(os.Stdout, "  文件：%s\n", path)
		fmt.Fprintln(os.Stdout, "  说明：被抑制的线索仍留在快照与 findings.json 里，报告只是不再提示；")
		fmt.Fprintln(os.Stdout, "        catch 从不读取白名单，证据留存范围不受影响。")
		return nil

	case "list":
		if len(f.Entries) == 0 {
			fmt.Fprintf(os.Stdout, "白名单为空：%s\n", path)
			return nil
		}
		fmt.Fprintf(os.Stdout, "白名单 %s（%d 条）\n\n", path, len(f.Entries))
		for _, e := range f.Entries {
			fmt.Fprintf(os.Stdout, "  %s\n", e.RuleID)
			fmt.Fprintf(os.Stdout, "    实体：%s\n", e.EntityID)
			if e.Hostname != "" || e.EntityType != "" || e.Identity != "" {
				fmt.Fprintf(os.Stdout, "    范围：主机 %s，类型 %s\n",
					displayOrUnscoped(e.Hostname), displayOrUnscoped(e.EntityType))
				fmt.Fprintf(os.Stdout, "    稳定身份：%s\n", displayOrUnscoped(e.Identity))
			} else {
				fmt.Fprintln(os.Stdout, "    范围：旧式条目（仅按 rule_id + entity_id 匹配，存在 ID 复用风险）")
			}
			fmt.Fprintf(os.Stdout, "    理由：%s\n", e.Reason)
			fmt.Fprintf(os.Stdout, "    加入：%s  %s\n", e.AddedAt, e.AddedBy)
		}
		return nil

	case "remove":
		if !f.Remove(*ruleID, *entityID) {
			return fmt.Errorf("白名单里没有这条：%s / %s（文件：%s）", *ruleID, *entityID, path)
		}
		if err := f.Save(path); err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "已移除：%s / %s\n", *ruleID, *entityID)
		return nil
	}
	return fmt.Errorf("未知子命令 %q（支持 add / list / remove）", sub)
}

// resolveWhitelistPath 推导白名单路径：显式 -w 优先；否则与 --db 同目录。
func resolveWhitelistPath(explicit, dbPath string) string {
	if strings.TrimSpace(explicit) != "" {
		return explicit
	}
	dir := filepath.Dir(dbPath)
	if dir == "" {
		dir = "."
	}
	return filepath.Join(dir, whitelist.FileName)
}

type whitelistScope struct {
	SnapshotID   string
	Hostname     string
	EntityType   string
	Identity     string
	EvidenceHash string
}

// whitelistEntryScope 从数据库目标快照读取实体，生成条目的主机/类型/稳定指纹。
//
// 为什么 add 必须读库：白名单若只记 (rule_id, entity_id)，下一次采集时
// process_<pid> 可能已属于另一个进程、network 序号也可能重排，抑制会落到
// 错误对象上。稳定指纹来自实体自身事实（见 internal/whitelist/identity.go），
// 因此 add 时必须拿到实体；拿不到就显式失败，而不是写入一条不可靠的条目。
func whitelistEntryScope(dbPath, snapshotID, entityID string) (whitelistScope, error) {
	if strings.TrimSpace(entityID) == "" {
		return whitelistScope{}, fmt.Errorf("必须给 --entity（白名单 add 需要从快照读取实体稳定身份）")
	}
	// 只读打开：whitelist 只改白名单文件，不改数据库。
	db, err := storage.OpenReadOnly(dbPath)
	if err != nil {
		return whitelistScope{}, fmt.Errorf("whitelist add 需要可读的 --db（用于绑定实体稳定身份）：%w", err)
	}
	defer db.Close()
	if err := storage.CheckSchema(db); err != nil {
		return whitelistScope{}, err
	}

	if strings.TrimSpace(snapshotID) == "" {
		snaps, err := storage.ListSnapshots(db)
		if err != nil {
			return whitelistScope{}, err
		}
		if len(snaps) == 0 {
			return whitelistScope{}, fmt.Errorf("数据库中没有快照，无法绑定实体稳定身份；请先 collect 或 snapshot import")
		}
		snapshotID = snaps[0].SnapshotID
	}
	meta, err := storage.GetSnapshot(db, snapshotID)
	if err != nil {
		return whitelistScope{}, fmt.Errorf("读取快照 %s 失败（无法绑定实体稳定身份）：%w", snapshotID, err)
	}
	hostname := strings.TrimSpace(meta.Hostname)
	if hostname == "" {
		return whitelistScope{}, fmt.Errorf("快照 %s 未记录主机名，无法绑定主机范围；请重新采集包含 host 实体的快照", snapshotID)
	}
	entity, err := storage.GetEntity(db, snapshotID, entityID)
	if err != nil {
		return whitelistScope{}, fmt.Errorf("实体 %s 不在快照 %s 中，无法绑定稳定身份（请检查 --entity/--snapshot）：%w",
			entityID, snapshotID, err)
	}
	identity, ok := whitelist.EntityIdentity(entity.EntityType, entity.DataJSON)
	if !ok {
		return whitelistScope{}, fmt.Errorf("无法计算实体 %s（类型 %s）的稳定身份；实体数据非法或类型不受支持",
			entityID, entity.EntityType)
	}
	return whitelistScope{
		SnapshotID:   snapshotID,
		Hostname:     hostname,
		EntityType:   entity.EntityType,
		Identity:     identity,
		EvidenceHash: whitelist.EvidenceHashOf(entity.DataJSON),
	}, nil
}

func displayOrUnscoped(s string) string {
	if strings.TrimSpace(s) == "" {
		return "未绑定"
	}
	return s
}
