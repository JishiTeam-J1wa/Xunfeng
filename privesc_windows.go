//go:build windows

package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"unicode/utf16"

	"golang.org/x/sys/windows/registry"
)

// getWindowsPrivescExploits 根据 Windows 构建号 + UBR 返回匹配漏洞
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

// windowsBuildVulnerable 优先按 构建号+UBR 补丁级匹配；无补丁数据的 CVE 回退到构建号区间
func windowsBuildVulnerable(v windowsVersion, exp privescExploit) bool {
	if vulnerable, known := windowsPatchVulnerable(v.Build, v.UBR, exp.CVE); known {
		return vulnerable
	}
	switch exp.CVE {
	case "CVE-2019-1132":
		// Win7/8.1/Win10 1803 及更早
		return v.Build > 0 && v.Build <= 17134
	case "CVE-2022-26809":
		return v.Build >= 7600
	}
	return false
}

// ==================== Windows 本地真实提权检查 ====================

// runWindowsPrivescChecks Windows 本地真实提权检查
func runWindowsPrivescChecks() []PrivescFinding {
	var findings []PrivescFinding

	for _, exp := range getWindowsPrivescExploits() {
		if exp.CVE != "" {
			findings = append(findings, exploitToFinding(exp))
		}
	}

	findings = append(findings, checkAlwaysInstallElevated()...)
	findings = append(findings, checkWritableServiceBinaries()...)
	return findings
}

// checkAlwaysInstallElevated 检查 HKLM+HKCU 的 AlwaysInstallElevated（两者都为 1 时可 msi 提权）
func checkAlwaysInstallElevated() []PrivescFinding {
	get := func(root registry.Key, rootName string) uint64 {
		k, err := registry.OpenKey(root, `SOFTWARE\Policies\Microsoft\Windows\Installer`, registry.QUERY_VALUE)
		if err != nil {
			return 0
		}
		defer k.Close()
		val, _, err := k.GetIntegerValue("AlwaysInstallElevated")
		if err != nil {
			return 0
		}
		return val
	}
	hklm := get(registry.LOCAL_MACHINE, "HKLM")
	hkcu := get(registry.CURRENT_USER, "HKCU")
	if hklm == 1 && hkcu == 1 {
		return []PrivescFinding{{
			Severity: "高", Category: "配置",
			Title:  "AlwaysInstallElevated 已启用 (HKLM+HKCU)",
			Detail: "任意 .msi 安装包将以 SYSTEM 权限执行，可构造恶意 msi 直接提权",
		}}
	}
	return nil
}

var winEnvVarRe = regexp.MustCompile(`%([^%]+)%`)

// expandWindowsEnv 展开 %VAR% 风格环境变量（os.ExpandEnv 不处理该风格）
func expandWindowsEnv(s string) string {
	return winEnvVarRe.ReplaceAllStringFunc(s, func(m string) string {
		name := m[1 : len(m)-1]
		if v := os.Getenv(name); v != "" {
			return v
		}
		// 常见兜底
		switch strings.ToUpper(name) {
		case "SYSTEMROOT", "WINDIR":
			return `C:\Windows`
		case "PROGRAMFILES":
			return `C:\Program Files`
		case "PROGRAMFILES(X86)":
			return `C:\Program Files (x86)`
		case "PROGRAMDATA":
			return `C:\ProgramData`
		}
		return m
	})
}

// utf16BytesToString 将注册表返回的 UTF-16LE 字节解码为字符串
func utf16BytesToString(b []byte) string {
	if len(b)%2 != 0 {
		return ""
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	return strings.TrimRight(string(utf16.Decode(u)), "\x00")
}

// extractServiceExePath 从 ImagePath 中提取 exe 路径并展开环境变量
func extractServiceExePath(imagePath string) string {
	s := strings.TrimSpace(imagePath)
	s = strings.Trim(s, `"`)
	s = expandWindowsEnv(s)
	// 截取到 .exe 为止（去掉命令行参数）
	lower := strings.ToLower(s)
	if i := strings.Index(lower, ".exe"); i >= 0 {
		return strings.TrimSpace(s[:i+4])
	}
	return s
}

// checkWritableServiceBinaries 枚举注册表服务，检查服务二进制路径是否可写
func checkWritableServiceBinaries() []PrivescFinding {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services`,
		registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()

	names, err := k.ReadSubKeyNames(1000)
	if err != nil {
		return nil
	}

	var findings []PrivescFinding
	for _, name := range names {
		if len(findings) >= 10 {
			break
		}
		sk, err := registry.OpenKey(k, name, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		buf := make([]byte, 2048)
		n, valtype, err := sk.GetValue("ImagePath", buf)
		sk.Close()
		if err != nil || (valtype != registry.SZ && valtype != registry.EXPAND_SZ) {
			continue
		}
		exePath := extractServiceExePath(utf16BytesToString(buf[:n]))
		if exePath == "" || !strings.HasSuffix(strings.ToLower(exePath), ".exe") {
			continue
		}
		if _, err := os.Stat(exePath); err != nil {
			continue
		}
		// 追加写测试：能以写方式打开即视为可写
		f, err := os.OpenFile(exePath, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			continue
		}
		f.Close()
		findings = append(findings, PrivescFinding{
			Severity: "高", Category: "服务",
			Title:  fmt.Sprintf("服务 %s 的二进制路径可写", name),
			Detail: fmt.Sprintf("%s（替换该文件后等待服务重启即可以服务权限执行）", exePath),
		})
	}
	return findings
}

// ==================== Unix 辅助函数的 Windows 存根 ====================
// privesc.go 中的 Linux 命中逻辑会引用这些函数，Windows 下不会被运行期调用。

func getPolkitVersion() string { return "" }

func getSudoVersion() string { return "" }

func pkexecSUIDExists() bool { return false }

func getOSRelease() (string, string) { return "", "" }

// runUnixPrivescChecks Windows 平台存根（运行期不会被调用）
func runUnixPrivescChecks() []PrivescFinding { return nil }
