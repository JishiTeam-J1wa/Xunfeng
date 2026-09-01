package main

import (
	"fmt"
	"os/exec"
	"regexp"
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
//
//	Win10 1507: 10240, 1511: 10586, 1607: 14393, 1703: 15063, 1709: 16299,
//	1803: 17134, 1809: 17763, 1903/1909: 18362/18363, 2004: 19041, 20H2: 19042,
//	21H1: 19043, 21H2: 19044, 22H2: 19045, Win11 21H2: 22000, 22H2: 22621, 23H2: 22631
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

// getLinuxPrivescExploits 给出 Linux 提权漏洞/建议
func getLinuxPrivescExploits() []privescExploit {
	var out []privescExploit
	kernel := getKernelVersion()
	kv, kerr := parseDottedVersion(kernel)

	if kerr == nil {
		if dirtyCOWAffected(kv) {
			out = append(out, linuxPrivescDB[0]) // Dirty COW
		}
		if dirtyPipeAffected(kv) {
			out = append(out, linuxPrivescDB[3]) // Dirty Pipe
		}
	}

	// PwnKit (CVE-2021-4034)：按 polkit 版本判断，拿不到版本但 pkexec 为 SUID 时保守提示
	if pv, ok := parsePolkitVersion(getPolkitVersion()); ok {
		if pwnkitAffected(pv) {
			out = append(out, linuxPrivescDB[1])
		}
	} else if pkexecSUIDExists() {
		out = append(out, linuxPrivescDB[1])
	}

	// Baron Samedit (CVE-2021-3156)：按 sudo 版本判断
	if sv, ok := parseSudoVersion(getSudoVersion()); ok && baronSameditAffected(sv) {
		out = append(out, linuxPrivescDB[2])
	}

	// GameOverlay (CVE-2023-2640/32629)：Ubuntu + 内核 >= 5.15 可能受影响
	if kerr == nil {
		name, _ := getOSRelease()
		if strings.Contains(strings.ToLower(name), "ubuntu") && gameOverlayAffected(kv) {
			out = append(out, linuxPrivescDB[4])
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

// getMacOSPrivescExploits 给出 macOS 提权漏洞/建议（按 sw_vers 版本匹配）
func getMacOSPrivescExploits() []privescExploit {
	verStr := ""
	if out, err := exec.Command("sw_vers", "-productVersion").Output(); err == nil {
		verStr = strings.TrimSpace(string(out))
	}
	v, err := parseDottedVersion(verStr)

	var out []privescExploit
	for _, exp := range macosPrivescDB {
		if exp.CVE == "" {
			out = append(out, exp) // 通用配置建议总是给出
			continue
		}
		if err != nil {
			// 版本不可知时保守地全部列出
			out = append(out, exp)
			continue
		}
		if macosCVEAffected(exp.CVE, v) {
			out = append(out, exp)
		}
	}
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

// ==================== 本地真实提权检查 ====================

// PrivescFinding 一次本地提权检查的发现
type PrivescFinding struct {
	Severity string // 高 / 中 / 低 / 信息
	Category string // SUID / 文件权限 / Sudo / Cron / NFS / CVE / 配置 / 服务
	Title    string
	Detail   string
}

// RunLocalPrivescChecks 执行本地真实提权检查（非静态建议）。
// 已是 root/管理员时返回 nil。各平台实现见 privesc_unix.go / privesc_windows.go。
func RunLocalPrivescChecks() []PrivescFinding {
	if isPrivileged() {
		return nil
	}
	switch runtime.GOOS {
	case "windows":
		return runWindowsPrivescChecks()
	case "linux", "darwin":
		return runUnixPrivescChecks()
	default:
		return nil
	}
}

// exploitToFinding 将匹配的漏洞条目转换为检查发现
func exploitToFinding(exp privescExploit) PrivescFinding {
	sev := "中"
	cat := "CVE"
	if exp.CVE == "" {
		cat = "配置"
		sev = "信息"
	} else if exp.Reliability == "高" {
		sev = "高"
	}
	return PrivescFinding{
		Severity: sev,
		Category: cat,
		Title:    exp.Name,
		Detail: fmt.Sprintf("影响: %s | 条件: %s | 参考: %s",
			exp.Affected, exp.Requirement, exp.Reference),
	}
}

// ==================== 版本解析与比较（纯函数，可测试） ====================

// parseDottedVersion 解析 "5.15.0-91-generic"、"10.15.7" 这类点分版本号前缀
func parseDottedVersion(s string) ([]int, error) {
	s = strings.TrimSpace(s)
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return nil, fmt.Errorf("empty version")
	}
	parts := strings.Split(fields[0], ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("not a dotted version: %q", s)
	}
	out := make([]int, 0, 3)
	for _, p := range parts {
		if len(out) == 3 {
			break
		}
		num := leadingDigits(p)
		if num == "" {
			return nil, fmt.Errorf("bad version component: %q", p)
		}
		n, err := strconv.Atoi(num)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

func leadingDigits(s string) string {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return s[:i]
}

// compareVersions 按三段比较，缺失段按 0 处理：-1 / 0 / 1
func compareVersions(a, b []int) int {
	for i := 0; i < 3; i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x < y {
			return -1
		}
		if x > y {
			return 1
		}
	}
	return 0
}

// dirtyCOWAffected 内核 2.6.22 ~ 4.8.3 均受影响（含 3.10~3.19，此前遗漏）
// 注意：发行版可能回迁补丁，命中仅代表"可能未修复"
func dirtyCOWAffected(v []int) bool {
	return compareVersions(v, []int{2, 6, 22}) >= 0 &&
		compareVersions(v, []int{4, 8, 3}) <= 0
}

// dirtyPipeAffected 内核 5.8 ~ 5.16.10（发行版可能回迁补丁）
func dirtyPipeAffected(v []int) bool {
	return compareVersions(v, []int{5, 8}) >= 0 &&
		compareVersions(v, []int{5, 16, 10}) <= 0
}

// gameOverlayAffected Ubuntu gameoverlay 内核大致区间 5.15 ~ 6.2
func gameOverlayAffected(v []int) bool {
	return compareVersions(v, []int{5, 15}) >= 0 &&
		compareVersions(v, []int{6, 3}) < 0
}

// sudoVersion sudo 版本号（1.9.5p1 → nums=[1 9 5], patch=1）
type sudoVersion struct {
	nums  []int
	patch int
}

var sudoVersionRe = regexp.MustCompile(`(\d+)\.(\d+)(?:\.(\d+))?(?:p(\d+))?`)

// parseSudoVersion 从 "Sudo version 1.9.5p1" 或裸版本号解析
func parseSudoVersion(s string) (sudoVersion, bool) {
	m := sudoVersionRe.FindStringSubmatch(s)
	if m == nil {
		return sudoVersion{}, false
	}
	sv := sudoVersion{nums: []int{0, 0, 0}}
	for i := 1; i <= 3; i++ {
		if m[i] == "" {
			continue
		}
		n, err := strconv.Atoi(m[i])
		if err != nil {
			return sudoVersion{}, false
		}
		sv.nums[i-1] = n
	}
	if m[4] != "" {
		sv.patch, _ = strconv.Atoi(m[4])
	}
	return sv, true
}

// baronSameditAffected CVE-2021-3156：sudo 1.8.2 ~ 1.8.31p2 及 1.9.0 ~ 1.9.5p1
func baronSameditAffected(sv sudoVersion) bool {
	if sv.nums[0] != 1 {
		return false
	}
	switch sv.nums[1] {
	case 8:
		if compareVersions(sv.nums, []int{1, 8, 2}) < 0 {
			return false
		}
		c := compareVersions(sv.nums, []int{1, 8, 31})
		return c < 0 || (c == 0 && sv.patch <= 2)
	case 9:
		c := compareVersions(sv.nums, []int{1, 9, 5})
		return c < 0 || (c == 0 && sv.patch <= 1)
	}
	return false
}

var polkitVersionRe = regexp.MustCompile(`(\d+)\.(\d+)`)

// parsePolkitVersion 从 "pkexec version 0.117" 解析 polkit 主次版本
func parsePolkitVersion(s string) ([]int, bool) {
	m := polkitVersionRe.FindStringSubmatch(s)
	if m == nil {
		return nil, false
	}
	major, err1 := strconv.Atoi(m[1])
	minor, err2 := strconv.Atoi(m[2])
	if err1 != nil || err2 != nil {
		return nil, false
	}
	return []int{major, minor}, true
}

// pwnkitAffected CVE-2021-4034 影响 polkit 0.105 ~ 0.120（上游未发新版，靠发行版补丁，
// 命中仅代表"可能未修复"，需人工确认补丁状态）
func pwnkitAffected(v []int) bool {
	return len(v) >= 2 && v[0] == 0 && v[1] >= 105 && v[1] <= 120
}

// macosCVEAffected 按 macOS 版本判断 CVE 是否可能受影响
func macosCVEAffected(cve string, v []int) bool {
	switch cve {
	case "CVE-2020-9839":
		// macOS Catalina 10.15.5 之前
		return len(v) >= 2 && v[0] == 10 && compareVersions(v, []int{10, 15, 5}) < 0
	case "CVE-2022-46689":
		// 修复于 13.1 / 12.6.2 / 11.7.2
		if len(v) == 0 {
			return false
		}
		switch v[0] {
		case 13:
			return compareVersions(v, []int{13, 1}) < 0
		case 12:
			return compareVersions(v, []int{12, 6, 2}) < 0
		case 11:
			return compareVersions(v, []int{11, 7, 2}) < 0
		}
	}
	return false
}

// windowsFixUBR 各 CVE 修复时对应的 UBR（按构建号；数据为公开发布信息的近似值，
// ubr < 修复值 视为可能未打补丁）
var windowsFixUBR = map[string]map[uint32]uint32{
	"CVE-2020-0796": {18362: 720, 18363: 720},
	"CVE-2021-34527": {14393: 4530, 17763: 2029, 18362: 1646, 18363: 1646,
		19041: 1083, 19042: 1083, 19043: 1083},
	"CVE-2021-41379": {17763: 2300, 18362: 1916, 19041: 1348, 19042: 1348,
		19043: 1348, 22000: 348},
	"CVE-2022-24521": {19041: 1645, 19042: 1645, 19043: 1645, 19044: 1645, 22000: 613},
	"CVE-2023-29360": {19044: 3086, 19045: 3086, 22000: 2176, 22621: 1848},
	"CVE-2024-30085": {19045: 4529, 22621: 3737, 22631: 3737},
	"CVE-2024-38063": {19045: 4651, 22621: 3880, 22631: 3880},
}

// windowsPatchVulnerable 按 构建号+UBR 判断是否可能未修复。
// 返回 known=false 表示该 CVE 无补丁数据，调用方应回退到构建号粗匹配；
// known=true 时 vulnerable 即结论（ubr==0 表示未读取到 UBR，保守视为未修复）。
func windowsPatchVulnerable(build, ubr uint32, cve string) (vulnerable, known bool) {
	m, ok := windowsFixUBR[cve]
	if !ok {
		return false, false
	}
	fix, ok := m[build]
	if !ok {
		return false, true // 该构建不在影响范围
	}
	if ubr == 0 {
		return true, true
	}
	return ubr < fix, true
}

// ==================== 输出解析（纯函数，可测试） ====================

// parseExportsNoRootSquash 从 /etc/exports 内容中找出启用 no_root_squash 的行
func parseExportsNoRootSquash(content string) []string {
	var out []string
	for _, line := range strings.Split(content, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if i := strings.Index(t, "#"); i >= 0 {
			t = strings.TrimSpace(t[:i])
		}
		if strings.Contains(t, "no_root_squash") {
			out = append(out, t)
		}
	}
	return out
}

// parseSudoListOutput 解析 sudo -n -l 的输出，提取 sudo 权限发现
func parseSudoListOutput(out string) []PrivescFinding {
	var findings []PrivescFinding
	seen := make(map[string]bool)
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		nopass := strings.Contains(trimmed, "NOPASSWD")
		// 形如 "(ALL : ALL) ALL" 或 "(ALL) NOPASSWD: ALL"
		broad := strings.Contains(trimmed, "(ALL") &&
			strings.HasSuffix(strings.TrimSpace(strings.TrimPrefix(trimmed, "NOPASSWD:")), "ALL")
		if !broad && !nopass {
			continue
		}
		if seen[trimmed] {
			continue
		}
		seen[trimmed] = true
		switch {
		case broad && nopass:
			findings = append(findings, PrivescFinding{
				Severity: "高", Category: "Sudo",
				Title: "sudo 免密切授予全部权限", Detail: trimmed})
		case broad:
			findings = append(findings, PrivescFinding{
				Severity: "中", Category: "Sudo",
				Title: "sudo 授予了全部权限（需密码）", Detail: trimmed})
		default:
			findings = append(findings, PrivescFinding{
				Severity: "中", Category: "Sudo",
				Title: "sudo NOPASSWD 条目", Detail: trimmed})
		}
	}
	if len(findings) == 0 &&
		(strings.Contains(out, "may run the following") || strings.Contains(out, "may run")) {
		findings = append(findings, PrivescFinding{
			Severity: "低", Category: "Sudo",
			Title: "当前用户拥有部分 sudo 权限", Detail: "建议人工检查 sudo -l 输出中的命令是否可提权（GTFOBins）"})
	}
	return findings
}
