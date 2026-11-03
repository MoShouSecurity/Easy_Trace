package analyzer

import (
	"reflect"
	"strings"

	"easytrace/internal/model"
)

// entityFieldWhitelist 是规则条件允许使用的实体字段（entity_type → JSON 字段名）。
//
// 为什么要校验：规则匹配器对未知字段只会返回 false，拼写错误（signature_stte）
// 会静默变成“永远不命中”，比直接报错危险得多。字段表从 model 的 JSON tag 生成，
// 再补上 entity_update 带来的深采字段，避免手写清单与模型漂移。
var entityFieldWhitelist = buildEntityFieldWhitelist()

func buildEntityFieldWhitelist() map[string]map[string]bool {
	samples := map[string]any{
		"host":        model.HostData{},
		"process":     model.ProcessData{},
		"network":     model.NetworkData{},
		"persistence": model.PersistenceData{},
		"service":     model.ServiceData{},
		"task":        model.TaskData{},
		"user":        model.UserData{},
		"file":        model.FileData{},
		"registry":    model.RegistryData{},
		"driver":      model.DriverData{},
		"event":       model.EventData{},
		"prefetch":    model.PrefetchData{},
		"execution":   model.ExecutionData{},
	}

	out := make(map[string]map[string]bool, len(samples))
	for entityType, sample := range samples {
		fields := jsonFields(sample)
		// entity_update 合并后的深采字段不在 base 实体结构体中。
		switch entityType {
		case "process":
			for _, f := range []string{"parent_command_line", "signature_valid", "publisher", "last_write_time"} {
				fields[f] = true
			}
		case "persistence":
			// command_exe / command_arguments 是分析视图从 command 派生的字段
			// （见 addPersistenceCommandFields），不在实体 JSON 里，但规则可以显式使用。
			for _, f := range []string{"hash_sha256", "signature_state", "last_write_time", "collection_level", "command_exe", "command_arguments"} {
				fields[f] = true
			}
		}
		out[entityType] = fields
	}
	return out
}

func jsonFields(sample any) map[string]bool {
	out := map[string]bool{}
	t := reflect.TypeOf(sample)
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name != "" {
			out[name] = true
		}
	}
	return out
}

// isKnownEntityField 判断规则 target 下是否允许该条件字段。
func isKnownEntityField(entityType, field string) bool {
	fields, ok := entityFieldWhitelist[entityType]
	if !ok {
		return false
	}
	return fields[field]
}
