package main

import (
	"encoding/json"
	"errors"
	"fmt"

	"easytrace/internal/collector"
	"easytrace/internal/collector/process"
	"easytrace/internal/model"
	"easytrace/internal/protocol"
	"easytrace/internal/storage"
)

// inspectHistory 在构造/执行采集器前检查历史目标，杜绝孤儿补证和低精度身份放行。
func inspectHistory(db *storage.DB, snapshotID, entityID string, pid uint32) (model.ProcessData, error) {
	var data model.ProcessData
	row, err := storage.GetEntity(db, snapshotID, entityID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return data, fmt.Errorf("快照中不存在目标实体 %s，请先 Basic collect；未执行深采", entityID)
		}
		return data, fmt.Errorf("读取历史进程失败: %w", err)
	}
	if row.EntityType != "process" || entityID != fmt.Sprintf("process_%d", pid) {
		return data, fmt.Errorf("历史目标类型或 entity_id/PID 不一致，未执行深采")
	}
	if err := json.Unmarshal([]byte(row.DataJSON), &data); err != nil {
		return data, fmt.Errorf("历史进程数据损坏，未执行深采: %w", err)
	}
	if data.PID != pid {
		return data, fmt.Errorf("历史进程 data.pid 不一致，未执行深采")
	}
	return data, process.ValidateInspectIdentity(data)
}

func processInResult(res *collector.Result, entityID string) (model.ProcessData, error) {
	var data model.ProcessData
	for _, e := range res.Entities {
		if e == nil || e.EntityID != entityID {
			continue
		}
		if err := protocol.ValidateEntity(e); err != nil {
			return data, err
		}
		if e.EntityType != "process" {
			return data, fmt.Errorf("采集结果目标不是 process，未保存补证")
		}
		b, err := json.Marshal(e.Data)
		if err != nil {
			return data, err
		}
		if err := json.Unmarshal(b, &data); err != nil {
			return data, err
		}
		return data, nil
	}
	return data, fmt.Errorf("未找到目标进程：进程可能已退出或 PID 已失效（采集结果中无该实体）。" +
		"可运行 \"easytrace analyze\" 查看快照中该 PID 的既有线索，确认 PID 后重试")
}

func saveInspectUpdates(db *storage.DB, rows []*storage.EntityUpdateRow) error {
	if len(rows) == 0 {
		return nil
	}
	if err := db.Exec("BEGIN IMMEDIATE"); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			db.Exec("ROLLBACK")
		}
	}()
	for _, row := range rows {
		if err := storage.InsertEntityUpdate(db, row); err != nil {
			return fmt.Errorf("保存补充证据失败（整批回滚）: %w", err)
		}
	}
	if err := db.Exec("COMMIT"); err != nil {
		return err
	}
	committed = true
	return nil
}

// field 为空时查询任意目标失败；错误分类不写入冻结的协议。
func inspectFieldFailed(failures []collector.DeepFailure, entityID, field string) bool {
	for _, f := range failures {
		if f.EntityID == entityID && (field == "" || f.Field == field) {
			return true
		}
	}
	return false
}
