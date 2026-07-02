//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
)

// windowsVersion 保存 Windows 版本信息
type windowsVersion struct {
	Major  uint32
	Minor  uint32
	Build  uint32
	UBR    uint32 // Update Build Revision
	Arch   string
	Edition string
}

// getWindowsVersion 读取 Windows 主版本、次版本、构建号
func getWindowsVersion() windowsVersion {
	v := windowsVersion{Major: 0, Minor: 0, Arch: runtime.GOARCH}

	// 从注册表读取系统名称（避免 wmic 中文乱码）
	if out, err := exec.Command("reg", "query", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "/v", "ProductName").Output(); err == nil {
		re := regexp.MustCompile(`ProductName\s+REG_SZ\s+(.+)`)
		if m := re.FindStringSubmatch(string(out)); len(m) == 2 {
			v.Edition = strings.TrimSpace(m[1])
		}
	}

	// 通过 wmic 获取准确的构建号、版本和架构
	// CSV 格式：Node,BuildNumber,Caption,OSArchitecture,Version
	if out, err := exec.Command("cmd", "/c", "wmic", "os", "get", "BuildNumber,Version,Caption,OSArchitecture", "/format:csv").Output(); err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			fields := strings.Split(line, ",")
			// 跳过标题行和空行，数据行至少 5 列
			if len(fields) < 5 || fields[0] == "Node" || fields[0] == "" {
				continue
			}
			if b, err := strconv.Atoi(strings.TrimSpace(fields[1])); err == nil {
				v.Build = uint32(b)
			}
			v.Arch = strings.TrimSpace(fields[3])
			// Version 字段格式如 10.0.26200
			parts := strings.Split(strings.TrimSpace(fields[4]), ".")
			if len(parts) >= 2 {
				if mj, err := strconv.Atoi(parts[0]); err == nil {
					v.Major = uint32(mj)
				}
				if mn, err := strconv.Atoi(parts[1]); err == nil {
					v.Minor = uint32(mn)
				}
			}
		}
	}

	// 读取 UBR (注册表)
	if out, err := exec.Command("reg", "query", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "/v", "UBR").Output(); err == nil {
		re := regexp.MustCompile(`UBR\s+REG_DWORD\s+0x([0-9a-fA-F]+)`)
		if m := re.FindStringSubmatch(string(out)); len(m) == 2 {
			if ubr, err := strconv.ParseUint(m[1], 16, 32); err == nil {
				v.UBR = uint32(ubr)
			}
		}
	}

	return v
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

// getInstalledHotfixes 获取已安装补丁列表（前 20 个）
func getInstalledHotfixes() []string {
	out, err := exec.Command("cmd", "/c", "wmic", "qfe", "get", "HotFixID", "/format:csv").Output()
	if err != nil {
		return nil
	}
	var hfs []string
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		fields := strings.Split(line, ",")
		if len(fields) >= 2 {
			hf := strings.TrimSpace(fields[1])
			if strings.HasPrefix(hf, "KB") {
				hfs = append(hfs, hf)
			}
		}
	}
	if len(hfs) > 20 {
		hfs = hfs[:20]
	}
	return hfs
}

// getKernelVersion Windows 下返回空字符串（privesc 使用 Windows 构建号）
func getKernelVersion() string {
	return ""
}

// getSystemDetails 返回 Windows 系统详情字符串
func getSystemDetails() []string {
	v := getWindowsVersion()
	var lines []string

	buildStr := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Build)
	if v.UBR > 0 {
		buildStr += fmt.Sprintf(".%d", v.UBR)
	}

	// 注册表 ProductName 在 Win11 上通常仍显示 Windows 10，结合构建号判断
	edition := v.Edition
	if v.Build >= 22000 && strings.Contains(strings.ToLower(edition), "windows 10") {
		edition = strings.Replace(edition, "Windows 10", "Windows 11", 1)
	}
	if edition != "" {
		lines = append(lines, fmt.Sprintf("系统版本:        %s", edition))
	}
	lines = append(lines, fmt.Sprintf("构建号:          %s", buildStr))
	lines = append(lines, fmt.Sprintf("架构:            %s", v.Arch))
	lines = append(lines, fmt.Sprintf("CPU:             %s", getCPUInfo()))
	lines = append(lines, fmt.Sprintf("内存:            %.1f GB", getMemoryGB()))

	if hfs := getInstalledHotfixes(); len(hfs) > 0 {
		lines = append(lines, fmt.Sprintf("最近补丁:        %s", strings.Join(hfs, ", ")))
	}
	return lines
}
