//go:build !windows

package main

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
)

// getOSRelease 读取 /etc/os-release 中的 NAME 和 VERSION_ID
func getOSRelease() (string, string) {
	out, err := exec.Command("cat", "/etc/os-release").Output()
	if err != nil {
		return "", ""
	}
	var name, version string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "NAME=") {
			name = strings.Trim(strings.TrimPrefix(line, "NAME="), "\"")
		}
		if strings.HasPrefix(line, "VERSION_ID=") {
			version = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "\"")
		}
	}
	return name, version
}

// getKernelVersion 获取内核版本
func getKernelVersion() string {
	out, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

// getCPUInfo 获取 CPU 信息
func getCPUInfo() string {
	info, err := cpu.Info()
	if err != nil || len(info) == 0 {
		return "unknown"
	}
	name := strings.TrimSpace(info[0].ModelName)
	cores := info[0].Cores
	if name == "" {
		return fmt.Sprintf("%d cores", cores)
	}
	return fmt.Sprintf("%s (%d cores)", name, cores)
}

// getMemoryGB 获取内存总量（GB）
func getMemoryGB() float64 {
	v, err := mem.VirtualMemory()
	if err != nil {
		return 0
	}
	return float64(v.Total) / 1024 / 1024 / 1024
}

// getSystemDetails 返回 Linux/macOS 系统详情字符串
func getSystemDetails() []string {
	var lines []string

	if runtime.GOOS == "darwin" {
		if out, err := exec.Command("sw_vers", "-productName").Output(); err == nil {
			name := strings.TrimSpace(string(out))
			if out2, err := exec.Command("sw_vers", "-productVersion").Output(); err == nil {
				name += " " + strings.TrimSpace(string(out2))
			}
			if name != "" {
				lines = append(lines, fmt.Sprintf("系统版本:        %s", name))
			}
		}
	} else {
		name, version := getOSRelease()
		if name != "" {
			if version != "" {
				lines = append(lines, fmt.Sprintf("系统版本:        %s %s", name, version))
			} else {
				lines = append(lines, fmt.Sprintf("系统版本:        %s", name))
			}
		}
	}

	lines = append(lines, fmt.Sprintf("内核版本:        %s", getKernelVersion()))
	lines = append(lines, fmt.Sprintf("架构:            %s", runtime.GOARCH))
	lines = append(lines, fmt.Sprintf("CPU:             %s", getCPUInfo()))
	lines = append(lines, fmt.Sprintf("内存:            %.1f GB", getMemoryGB()))

	return lines
}
