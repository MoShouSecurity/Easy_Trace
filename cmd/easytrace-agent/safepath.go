package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	"easytrace/internal/safepath"
)

// outputAbsolutePath returns a cleaned absolute output path after rejecting existing
// parent components that are links, reparse points, or non-directories. The final
// component is deliberately not inspected here: creation functions below use
// atomic exclusive creation to reject every pre-existing final entry.
func outputAbsolutePath(path string) (string, error) {
	abs, err := safepath.RequireLocalDrivePath(path, "输出路径")
	if err != nil {
		return "", err
	}
	if err := rejectUnsafeOutputParents(abs); err != nil {
		return "", err
	}
	return abs, nil
}

// localInputDir 校验一个只读输入目录：本地盘符绝对路径、父链无链接/重解析点，
// 且最终组件本身是普通目录（不跟随 junction/符号链接）。
// 必须在 os.ReadDir 之前调用——对 UNC 路径的目录操作本身就会发起 SMB。
func localInputDir(path, label string) (string, error) {
	return safepath.RequireLocalDir(path, label)
}

// rejectUnsafeOutputParents uses Lstat so it never follows a symbolic link or a
// Windows junction while validating the existing parent chain. Missing parents
// are left to Mkdir/OpenFile so their native errors remain accurate.
func rejectUnsafeOutputParents(path string) error {
	return safepath.RejectUnsafeParents(path, "输出路径")
}

// isUnsafeOutputParent recognizes both ordinary symlinks and Windows junctions.
// Go exposes modern junctions as ModeIrregular and legacy junctions as
// ModeSymlink; a regular file is unsafe anywhere in a directory-only chain.
func isUnsafeOutputParent(info fs.FileInfo) bool {
	return safepath.IsUnsafeParent(info)
}

// createNewOutputFile creates a previously absent output file without following
// a pre-existing final-component link. O_EXCL makes the no-overwrite guarantee
// atomic even if another process races to populate the destination.
func createNewOutputFile(path string, perm os.FileMode) (*os.File, error) {
	abs, err := outputAbsolutePath(path)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(abs, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("输出文件已存在，拒绝覆盖: %s（请换一个新文件名；工具不会覆盖已有证据）", path)
		}
		return nil, fmt.Errorf("创建输出文件失败: %w", err)
	}
	return file, nil
}

// ensureNewOutputDir creates a previously absent report directory. It does not
// create intermediate directories and rejects every existing final entry.
func ensureNewOutputDir(path string) (string, error) {
	abs, err := outputAbsolutePath(path)
	if err != nil {
		return "", err
	}
	if err := os.Mkdir(abs, 0o755); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return "", fmt.Errorf("输出目录已存在，拒绝覆盖: %s（请换一个新目录名，例如加日期后缀；工具不会复用或清空已有目录）", path)
		}
		return "", fmt.Errorf("创建输出目录失败: %w", err)
	}
	return abs, nil
}

// copyToNewOutputFile copies src into a new final output file with the same
// parent-chain + O_EXCL protections as writeNewOutputFile. Used for staged
// artifacts (EVTX export) whose producer can only write by path.
func copyToNewOutputFile(dest, src string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("打开临时文件失败: %w", err)
	}
	defer in.Close()
	out, err := createNewOutputFile(dest, perm)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil || closeErr != nil {
		// createNewOutputFile 已确认该文件由本次调用创建；失败时移除半成品，
		// 不误删任何既有文件。
		_ = os.Remove(dest)
		if copyErr != nil {
			return fmt.Errorf("复制到最终文件失败: %w", copyErr)
		}
		return fmt.Errorf("关闭最终文件失败: %w", closeErr)
	}
	return nil
}

// writeNewOutputFile writes a report artifact through exclusive creation. It
// intentionally leaves a partial new artifact in place on later write errors
// instead of deleting user-visible output automatically.
func writeNewOutputFile(path string, data []byte, perm os.FileMode) error {
	file, err := createNewOutputFile(path, perm)
	if err != nil {
		return err
	}
	n, err := file.Write(data)
	if err != nil {
		_ = file.Close()
		return err
	}
	if n != len(data) {
		_ = file.Close()
		return io.ErrShortWrite
	}
	return file.Close()
}
