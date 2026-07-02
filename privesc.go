package main

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
)

// privescExploit 描述一个提权漏洞/技术
type privescExploit struct {
	Name        string
	CVE         string
	Affected    string // 受影响的版本描述
	Requirement string // 利用条件
	Reliability string // 稳定程度
	Reference   string // 参考链接或关键词
}

// windowsPrivescDB Windows 常见本地提权漏洞库（按构建号区间）
// 构建号映射关系：
//   Win10 1507: 10240, 1511: 10586, 1607: 14393, 1703: 15063, 1709: 16299,
//   1803: 17134, 1809: 17763, 1903/1909: 18362/18363, 2004: 19041, 20H2: 19042,
//   21H1: 19043, 21H2: 19044, 22H2: 19045, Win11 21H2: 22000, 22H2: 22621, 23H2: 22631
var windowsPrivescDB = []privescExploit{
	{
		Name:        "Windows Token Kidnapping / Service Isolation Bypass",
		CVE:         "CVE-2019-1132",
		Affected:    "Win7/8.1/Win10 1803 之前部分版本",
		Requirement: "需要在目标上运行代码",
		Reliability: "中",
		Reference:   "search CVE-2019-1132 exploit",
	},
	{
		Name:        "Windows SMBGhost 本地提权",
		CVE:         "CVE-2020-0796",
		Affected:    "Win10 1903/1909 (Build 18362/18363) 未打补丁",
		Requirement: "需要本地用户权限",
		Reliability: "高",
		Reference:   "https://github.com/danigargu/CVE-2020-0796",
	},
	{
		Name:        "Windows PrintNightmare 打印 spooler 提权",
		CVE:         "CVE-2021-34527",
		Affected:    "Win7/8.1/Win10/Win11/Server 多版本，未打补丁或配置不当",
		Requirement: "Authenticated user，Print Spooler 运行",
		Reliability: "高",
		Reference:   "https://github.com/cube0x0/CVE-2021-1675",
	},
	{
		Name:        "Windows Installer 特权提升 (LPE)",
		CVE:         "CVE-2021-41379",
		Affected:    "Win10/Win11/Server 2022 部分版本",
		Requirement: "需要本地用户权限",
		Reliability: "中",
		Reference:   "https://github.com/klinix5/InstallerFileTakeOver",
	},
	{
		Name:        "Windows RPC Runtime 提权",
		CVE:         "CVE-2022-26809",
		Affected:    "Win7/8.1/Win10/Win11/Server 未打补丁",
		Requirement: "网络可达 + RPC",
		Reliability: "中",
		Reference:   "search CVE-2022-26809",
	},
	{
		Name:        "Windows Common Log File System Driver 提权",
		CVE:         "CVE-2022-24521",
		Affected:    "Win10/Win11/Server 2022 部分版本",
		Requirement: "需要本地低权限用户",
		Reliability: "高",
		Reference:   "search CVE-2022-24521 LPE",
	},
	{
		Name:        "Windows Win32k 特权提升 (0day/N-day)",
		CVE:         "CVE-2023-29360",
		Affected:    "Win10/Win11/Server 2022 部分版本",
		Requirement: "需要本地用户权限",
		Reliability: "中",
		Reference:   "search CVE-2023-29360",
	},
	{
		Name:        "Windows Kernel Elevation (AppLocker/WDAC bypass variants)",
		CVE:         "CVE-2024-30085",
		Affected:    "Win10 22H2 / Win11 23H2 等未打补丁",
		Requirement: "需要本地低权限用户",
		Reliability: "中",
		Reference:   "search CVE-2024-30085 exploit",
	},
	{
		Name:        "Windows Hyper-V / Plan 9 驱动本地提权",
		CVE:         "CVE-2024-38063",
		Affected:    "Win10/Win11 未打补丁，需启用 IPv6",
		Requirement: "本地用户 + IPv6 启用",
		Reliability: "中",
		Reference:   "search CVE-2024-38063 LPE",
	},
}

// linuxPrivescDB Linux 常见本地提权漏洞/配置库
var linuxPrivescDB = []privescExploit{
	{
		Name:        "Dirty COW (CVE-2016-5195)",
		CVE:         "CVE-2016-5195",
		Affected:    "Linux Kernel 2.6.22 ~ 4.8.3 未打补丁",
		Requirement: "本地用户权限",
		Reliability: "高",
		Reference:   "https://github.com/dirtycow/dirtycow.github.io",
	},
	{
		Name:        "Polkit pkexec 本地提权 (PwnKit)",
		CVE:         "CVE-2021-4034",
		Affected:    "polkit 0.113 ~ 0.118，多数 2022 年前发行版",
		Requirement: "本地用户权限，pkexec 存在",
		Reliability: "高",
		Reference:   "https://github.com/berdav/CVE-2021-4034",
	},
	{
		Name:        "Sudo Baron Samedit",
		CVE:         "CVE-2021-3156",
		Affected:    "sudo 1.8.2 ~ 1.9.5p1",
		Requirement: "本地用户，sudo 存在",
		Reliability: "高",
		Reference:   "https://github.com/worawit/CVE-2021-3156",
	},
	{
		Name:        "Kernel 本地提权 (Dirty Pipe)",
		CVE:         "CVE-2022-0847",
		Affected:    "Linux Kernel 5.8 ~ 5.16.10",
		Requirement: "本地用户权限",
		Reliability: "高",
		Reference:   "https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits",
	},
	{
		Name:        "GameOverlay 本地提权",
		CVE:         "CVE-2023-2640 / CVE-2023-32629",
		Affected:    "Ubuntu 22.04 等启用 gameoverlay 的发行版",
		Requirement: "本地用户权限",
		Reliability: "中",
		Reference:   "search CVE-2023-2640 Ubuntu LPE",
	},
	{
		Name:        "常用弱配置/错误配置",
		CVE:         "",
		Affected:    "所有 Linux",
		Requirement: "SUID 二进制、可写 /etc/passwd、sudo 配置错误、计划任务可写等",
		Reliability: "高",
		Reference:   "linpeas.sh / unix-privesc-check",
	},
}

// macosPrivescDB macOS 常见本地提权
var macosPrivescDB = []privescExploit{
	{
		Name:        "CVE-2020-9839 / Intel 芯片本地提权",
		CVE:         "CVE-2020-9839",
		Affected:    "macOS 10.15.5 之前",
		Requirement: "本地用户权限",
		Reliability: "中",
		Reference:   "search CVE-2020-9839 macOS LPE",
	},
	{
		Name:        "CVE-2022-46689 本地提权",
		CVE:         "CVE-2022-46689",
		Affected:    "macOS Ventura 13.0.1 / Monterey 12.6.2 之前",
		Requirement: "本地用户权限",
		Reliability: "中",
		Reference:   "search CVE-2022-46689",
	},
	{
		Name:        "常见配置问题",
		CVE:         "",
		Affected:    "所有 macOS",
		Requirement: "SUID 二进制、可写系统路径、sudo 配置错误等",
		Reliability: "高",
		Reference:   "linpeas.sh / MacOS-privesc",
	},
}

// getPrivilegeEscalationExploits 根据当前系统版本返回可能的提权漏洞/技术列表
func getPrivilegeEscalationExploits() []privescExploit {
	if isPrivileged() {
		return nil
	}

	switch runtime.GOOS {
	case "windows":
		return getWindowsPrivescExploits()
	case "linux":
		return getLinuxPrivescExploits()
	case "darwin":
		return getMacOSPrivescExploits()
	default:
		return []privescExploit{{
			Name:        "未知操作系统",
			Requirement: "无法自动识别系统类型，建议手动运行 linPEAS / winPEAS 进行枚举",
			Reliability: "低",
		}}
	}
}

// getWindowsPrivescExploits 根据 Windows 构建号返回匹配漏洞
func getWindowsPrivescExploits() []privescExploit {
	v := getWindowsVersion()
	var out []privescExploit

	for _, exp := range windowsPrivescDB {
		if exp.CVE != "" && windowsBuildVulnerable(v, exp) {
			out = append(out, exp)
		}
	}

	// 通用配置问题建议
	for _, exp := range windowsPrivescDB {
		if exp.CVE == "" {
			out = append(out, exp)
		}
	}

	return out
}

// windowsBuildVulnerable 粗略判断该构建号是否在漏洞影响范围内
func windowsBuildVulnerable(v windowsVersion, exp privescExploit) bool {
	switch exp.CVE {
	case "CVE-2019-1132":
		// Win7/8.1/Win10 1803 及更早
		return v.Build > 0 && v.Build <= 17134
	case "CVE-2020-0796":
		// Win10 1903/1909
		return v.Build == 18362 || v.Build == 18363
	case "CVE-2021-34527":
		// PrintNightmare 影响范围极广
		return v.Build >= 7600
	case "CVE-2021-41379":
		return v.Build >= 17763
	case "CVE-2022-26809":
		return v.Build >= 7600
	case "CVE-2022-24521":
		return v.Build >= 17763
	case "CVE-2023-29360":
		return v.Build >= 17763
	case "CVE-2024-30085":
		return v.Build >= 19041
	case "CVE-2024-38063":
		return v.Build >= 19041
	}
	return false
}

// getLinuxPrivescExploits 给出 Linux 提权漏洞/建议
func getLinuxPrivescExploits() []privescExploit {
	var out []privescExploit
	kernel := getKernelVersion()

	// 解析内核版本号（例如 5.15.0）
	parts := strings.Split(kernel, ".")
	if len(parts) >= 2 {
		major, _ := strconv.Atoi(parts[0])
		minor, _ := strconv.Atoi(parts[1])

		if major == 2 || (major == 3 && minor < 10) || (major == 4 && minor < 9) {
			out = append(out, linuxPrivescDB[0]) // Dirty COW
		}
		if major == 5 && minor >= 8 && minor <= 16 {
			out = append(out, linuxPrivescDB[3]) // Dirty Pipe
		}
	}

	// 通用配置问题建议
	for _, exp := range linuxPrivescDB {
		if exp.CVE == "" {
			out = append(out, exp)
		}
	}

	return out
}

// getMacOSPrivescExploits 给出 macOS 提权漏洞/建议
func getMacOSPrivescExploits() []privescExploit {
	out := make([]privescExploit, len(macosPrivescDB))
	copy(out, macosPrivescDB)
	return out
}

// formatExploitShort 输出简洁的终端格式
func formatExploitShort(exp privescExploit) string {
	cve := exp.CVE
	if cve == "" {
		cve = "配置问题"
	}
	rel := exp.Reliability
	if rel == "高" {
		rel = red(rel)
	} else if rel == "中" {
		rel = yellow(rel)
	} else {
		rel = cyan(rel)
	}
	return fmt.Sprintf("[%s] %s | 条件: %s | 稳定: %s",
		cve, exp.Name, exp.Requirement, rel)
}

func formatExploit(exp privescExploit) string {
	cve := exp.CVE
	if cve == "" {
		cve = "N/A"
	}
	return fmt.Sprintf("[%s] %s | 影响: %s | 条件: %s | 稳定: %s | 参考: %s",
		cve, exp.Name, exp.Affected, exp.Requirement, exp.Reliability, exp.Reference)
}
