//go:build windows

package main

// debuggerDetected 是 antiDebug 的 Windows 实现入口
func debuggerDetected() bool {
	return windowsDebuggerDetected()
}
