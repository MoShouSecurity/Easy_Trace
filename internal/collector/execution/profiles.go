package execution

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// userProfile 是一个磁盘上的用户配置目录。
type userProfile struct {
	name string
	dir  string
}

// userProfiles 枚举当前用户与 C:\Users 下可访问的用户目录。
//
// 只用于 Deep/Forensic 的文件类来源（PowerShell 历史、Recent LNK）；
// 单个目录不可读是预期权限边界（debug 日志），不阻断其他用户。
func userProfiles() ([]userProfile, []string) {
	var out []userProfile
	var notes []string
	seen := make(map[string]bool)

	add := func(dir, name string) {
		dir = filepath.Clean(dir)
		if dir == "" || dir == "." {
			return
		}
		key := strings.ToLower(dir)
		if seen[key] {
			return
		}
		seen[key] = true
		if name == "" {
			name = filepath.Base(dir)
		}
		out = append(out, userProfile{name: name, dir: dir})
	}

	if home := strings.TrimSpace(os.Getenv("USERPROFILE")); home != "" {
		add(home, "")
	}
	drive := strings.TrimSpace(os.Getenv("SystemDrive"))
	if drive == "" {
		drive = "C:"
	}
	usersDir := filepath.Join(drive+`\`, "Users")
	des, err := os.ReadDir(usersDir)
	if err != nil {
		if os.IsPermission(err) {
			debugf("read_users_dir_denied dir=%s: %v", usersDir, err)
		} else if !os.IsNotExist(err) {
			notes = append(notes, fmt.Sprintf("枚举用户目录 %s 失败（只采集当前用户）：%v", usersDir, err))
		}
	} else {
		for _, de := range des {
			if !de.IsDir() || isSystemProfile(de.Name()) {
				continue
			}
			add(filepath.Join(usersDir, de.Name()), de.Name())
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].dir) < strings.ToLower(out[j].dir)
	})
	return out, notes
}

// isSystemProfile 排除不属于真实用户的系统配置目录。
func isSystemProfile(name string) bool {
	switch strings.ToLower(name) {
	case "public", "default", "default user", "all users":
		return true
	}
	return false
}

// psHistoryPaths 返回一个用户下可能的 PSReadLine 历史文件。
// Windows PowerShell 5 与 PowerShell 7 使用不同目录，两者都尝试。
func psHistoryPaths(p userProfile) []string {
	return []string{
		filepath.Join(p.dir, `AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`),
		filepath.Join(p.dir, `AppData\Roaming\Microsoft\PowerShell\PSReadLine\ConsoleHost_history.txt`),
	}
}

// recentDirs 返回一个用户的 Recent 快捷方式目录。
func recentDirs(p userProfile) []string {
	return []string{
		filepath.Join(p.dir, `AppData\Roaming\Microsoft\Windows\Recent`),
	}
}
