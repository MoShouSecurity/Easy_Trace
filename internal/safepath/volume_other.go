//go:build !windows

package safepath

// checkLocalVolume 在非 Windows 平台上没有“映射网络驱动器”的统一概念；
// 路径形状校验由 LocalDrivePath 负责。保留无操作实现让调用方保持同一 API。
func checkLocalVolume(path, label string) error { return nil }
