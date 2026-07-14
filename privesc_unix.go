//go:build !windows

package main

// getWindowsPrivescExploits 在非 Windows 平台不提供 Windows 专用提权建议
func getWindowsPrivescExploits() []privescExploit {
	return nil
}
