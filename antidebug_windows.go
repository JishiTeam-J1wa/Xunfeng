//go:build windows

package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	antiDebugKernel32              = windows.NewLazyDLL("kernel32.dll")
	procIsDebuggerPresent          = antiDebugKernel32.NewProc("IsDebuggerPresent")
	procCheckRemoteDebuggerPresent = antiDebugKernel32.NewProc("CheckRemoteDebuggerPresent")
)

// windowsDebuggerDetected 通过 Windows API 做真实反调试检测：
// 1. IsDebuggerPresent 检查 PEB.BeingDebugged 标志；
// 2. CheckRemoteDebuggerPresent 检查是否有调试器附加到当前进程。
// 所有 API 调用失败时降级返回 false，绝不 panic。
func windowsDebuggerDetected() bool {
	// IsDebuggerPresent 无参数，返回非 0 表示正在被调试
	ret, _, _ := procIsDebuggerPresent.Call()
	if ret != 0 {
		return true
	}

	// CheckRemoteDebuggerPresent(GetCurrentProcess(), &present)
	// CurrentProcess 返回伪句柄（-1），对当前进程调用合法
	var present int32 // BOOL
	ret, _, _ = procCheckRemoteDebuggerPresent.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&present)),
	)
	if ret == 0 {
		return false // API 失败，降级
	}
	return present != 0
}
