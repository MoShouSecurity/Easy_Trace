package main

import (
	"fmt"
	"io"

	"easytrace/internal/collectionmeta"
	"easytrace/internal/platform/privilege"
)

// printPrivilegeBanner 输出采集权限状态提示（Step 10.1）。
//
// 管理员：Privilege: Elevated: YES + Collection mode: Full access available
// 非管理员：Privilege: Elevated: NO + Notice（哪些信息可能缺失 + 提权提示）
//
// exe 入口的阻断由 elevation.go 的 runMain 负责；此函数仍供直接调用采集器的
// 内部路径与测试使用，只提示、不阻断。无风险评分、不把非管理员视为风险。
func printPrivilegeBanner(out io.Writer, info privilege.PrivilegeInfo) {
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Privilege:")
	if info.IsElevated {
		fmt.Fprintln(out, "  Elevated: YES")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Collection mode:")
		fmt.Fprintln(out, "  Full access available")
		fmt.Fprintln(out)
		return
	}
	fmt.Fprintln(out, "  Elevated: NO")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Notice:")
	fmt.Fprintln(out, "Easy_Trace is not running with administrator privileges.")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Some information may be unavailable:")
	fmt.Fprintln(out, " - Scheduled Tasks")
	fmt.Fprintln(out, " - Service details")
	fmt.Fprintln(out, " - Protected process information")
	fmt.Fprintln(out, " - Extended process metadata")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "For more complete DFIR collection, run:")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Right click Easy_Trace.exe")
	fmt.Fprintln(out, "→ Run as administrator")
	fmt.Fprintln(out)
}

// collectionEnvironment 报告中的采集环境信息（report metadata，非协议实体）。
//
// 所有字段都来自**采集时**写入的 sidecar；没有 sidecar 时 metadata_recorded=false，
// 时间来源为 unavailable，权限为未记录。绝不填充报告进程的当前权限。
type collectionEnvironment struct {
	MetadataRecorded     bool                     `json:"metadata_recorded"`
	TimestampSource      string                   `json:"timestamp_source"`
	CollectionStartedAt  string                   `json:"collection_started_at,omitempty"`
	CollectionFinishedAt string                   `json:"collection_finished_at,omitempty"`
	RunPrivilege         collectionmeta.Privilege `json:"run_privilege"`
}

// environment 生成 findings.json 的采集环境块。
func (p *collectionProvenance) environment() collectionEnvironment {
	return collectionEnvironment{
		MetadataRecorded:     p.Recorded != nil,
		TimestampSource:      p.timeSourceEN(),
		CollectionStartedAt:  p.collectionStartedAt(),
		CollectionFinishedAt: p.collectionFinishedAt(),
		RunPrivilege:         p.Privilege,
	}
}

// writeEnvironmentText 输出采集环境区块（summary.txt 专用；
// report.html 使用结构化标记，见 report.go 的 buildReportHTML）。
// 标签中英双语：中文为主，英文保留以便与协议术语和测试断言对照。
func writeEnvironmentText(w io.Writer, prov *collectionProvenance) {
	fmt.Fprintln(w, "采集环境 Collection Environment:")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  采集元数据 Collection metadata: "+yesNoRecorded(prov.Recorded != nil))
	fmt.Fprintln(w, "  采集开始时间 Collection started at: "+orNotRecorded(prov.collectionStartedAt()))
	fmt.Fprintln(w, "  采集结束时间 Collection finished at: "+orNotRecorded(prov.collectionFinishedAt()))
	fmt.Fprintln(w, "  时间来源 Timestamp source: "+prov.timeSourceEN()+"（"+prov.timeNote()+"）")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  运行权限 Run privilege:")
	fmt.Fprintln(w, "    管理员提权 Administrator elevated: "+prov.privilegeZh()+" "+prov.privilegeEN())
	if member, ok := prov.groupMember(); ok {
		fmt.Fprintln(w, "    管理员组成员 Administrator group member: "+yesNo(member))
	} else {
		fmt.Fprintln(w, "    管理员组成员 Administrator group member: 未记录 NOT RECORDED")
	}
	fmt.Fprintln(w, "    来源 Source: "+prov.Privilege.Source)
	fmt.Fprintln(w)
	if !prov.privilegeKnown() {
		// 明确说明“不知道”，避免读者把空白当成“非管理员”。
		fmt.Fprintln(w, "  说明 Note:")
		fmt.Fprintln(w, "    本快照没有采集时权限记录（旧版本产物或外部导入）。")
		fmt.Fprintln(w, "    报告不使用生成报告时的进程权限代替采集时权限。")
		fmt.Fprintln(w)
		return
	}
	if !prov.elevated() {
		fmt.Fprintln(w, "  建议 Recommendation:")
		fmt.Fprintln(w, "    采集时未提权，计划任务、服务细节与受保护进程信息可能不完整。")
		fmt.Fprintln(w, "    应急响应场景下建议以管理员身份重新采集。")
		fmt.Fprintln(w)
	}
}

func yesNo(b bool) string {
	if b {
		return "是 YES"
	}
	return "否 NO"
}

func yesNoRecorded(b bool) string {
	if b {
		return "有 RECORDED"
	}
	return "未记录 NOT RECORDED"
}

func orNotRecorded(s string) string {
	if s == "" {
		return "未记录 NOT RECORDED"
	}
	return s
}
