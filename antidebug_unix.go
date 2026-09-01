//go:build !windows

package main

import (
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/shirou/gopsutil/v3/process"
)

// 调试器进程名特征（沿用原 antiDebug 的思路）
var debuggerProcessNames = []string{"lldb", "gdb", "strace", "ltrace", "dtrace"}

// pTraced 对应 macOS 的 P_TRACED（0x00000800），x/sys/unix 未导出该常量
const pTraced = 0x00000800

// unixDebuggerDetected 在 Unix 平台做反调试检测：
// 1. 进程名检查：系统里是否存在 gdb/lldb/strace 等调试器进程；
// 2. macOS：通过进程标志位检查 KERN_PROC 的 P_TRACED（等效 sysctl）；
// 3. Linux：读取 /proc/self/status 的 TracerPid，非 0 表示被跟踪。
// 所有检查失败均降级为 false，绝不 panic。
func unixDebuggerDetected() bool {
	if debuggerProcessRunning() {
		return true
	}
	switch runtime.GOOS {
	case "linux":
		return linuxTracerPidAttached()
	case "darwin":
		return darwinProcTraced()
	}
	return false
}

// debuggerProcessRunning 检查是否存在调试器进程
func debuggerProcessRunning() bool {
	procs, err := process.Processes()
	if err != nil {
		return false
	}
	for _, p := range procs {
		name, err := p.Name()
		if err != nil || name == "" {
			continue
		}
		nameLower := strings.ToLower(name)
		for _, d := range debuggerProcessNames {
			if strings.Contains(nameLower, d) {
				return true
			}
		}
	}
	return false
}

// linuxTracerPidAttached 解析 /proc/self/status 中的 TracerPid
func linuxTracerPidAttached() bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "TracerPid:") {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "TracerPid:")))
		if err != nil {
			return false
		}
		return pid != 0
	}
	return false
}

// darwinProcTraced 检查当前进程是否被调试器附加。
// 通过 `ps -o flags=` 读取进程 p_flag（ps 内部即调用 sysctl KERN_PROC），
// 检查 P_TRACED 位。单个 !windows 文件无法使用仅 darwin 可用的
// unix.SysctlKinfoProc 类型，故用 ps 命令等价实现；失败降级返回 false。
func darwinProcTraced() bool {
	out, err := exec.Command("ps", "-o", "flags=", "-p", strconv.Itoa(os.Getpid())).Output()
	if err != nil {
		return false
	}
	flags, err := strconv.ParseUint(strings.TrimSpace(string(out)), 0, 64)
	if err != nil {
		return false
	}
	return flags&pTraced != 0
}
