//go:build !windows

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// getWindowsPrivescExploits 在非 Windows 平台不提供 Windows 专用提权建议
func getWindowsPrivescExploits() []privescExploit {
	return nil
}

// runWindowsPrivescChecks 非 Windows 平台存根（运行期不会被调用）
func runWindowsPrivescChecks() []PrivescFinding {
	return nil
}

// ==================== Unix 本地真实提权检查 ====================

// gtfoBins 可被用于提权的常见 SUID 二进制名单（GTFOBins 子集）
var gtfoBins = map[string]bool{
	// shell / 解释器
	"bash": true, "sh": true, "dash": true, "zsh": true, "ksh": true, "csh": true,
	"fish": true, "busybox": true, "python": true, "python2": true, "python3": true,
	"perl": true, "ruby": true, "php": true, "lua": true, "node": true, "expect": true,
	// 编辑器 / 分页器
	"vim": true, "vi": true, "nvim": true, "view": true, "ex": true, "nano": true,
	"emacs": true, "ed": true, "less": true, "more": true, "man": true,
	// 文件 / 归档工具
	"find": true, "cp": true, "mv": true, "dd": true, "xxd": true, "base64": true,
	"tar": true, "cpio": true, "zip": true, "7z": true, "rsync": true, "tee": true,
	// 文本处理
	"awk": true, "gawk": true, "mawk": true, "nawk": true, "sed": true, "env": true,
	// 系统 / 权限
	"chmod": true, "chown": true, "mount": true, "umount": true, "su": true,
	"sudo": true, "doas": true, "pkexec": true, "crontab": true, "at": true,
	"systemctl": true, "journalctl": true, "loginctl": true,
	// 调试 / 容器
	"gdb": true, "strace": true, "ltrace": true, "docker": true, "podman": true,
	"kubectl": true,
	// 网络工具
	"nmap": true, "nc": true, "ncat": true, "netcat": true, "socat": true,
	"wget": true, "curl": true, "ftp": true, "tftp": true, "ssh": true, "scp": true,
	"tcpdump": true, "git": true, "openssl": true,
	// 终端复用 / 任务
	"screen": true, "tmux": true, "taskset": true, "nice": true, "timeout": true,
	"stdbuf": true, "flock": true, "watch": true,
}

// suidScanDirs 扫描 SUID/SGID 的常见目录
var suidScanDirs = []string{
	"/bin", "/sbin", "/usr/bin", "/usr/sbin",
	"/usr/local/bin", "/usr/local/sbin", "/snap/bin",
}

// runUnixPrivescChecks Linux/macOS 的本地真实提权检查
func runUnixPrivescChecks() []PrivescFinding {
	var findings []PrivescFinding

	// CVE 版本匹配结果一并纳入
	var exps []privescExploit
	if runtime.GOOS == "linux" {
		exps = getLinuxPrivescExploits()
	} else {
		exps = getMacOSPrivescExploits()
	}
	for _, exp := range exps {
		if exp.CVE != "" {
			findings = append(findings, exploitToFinding(exp))
		}
	}

	findings = append(findings, checkSUIDBinaries()...)
	findings = append(findings, checkWritableSystemFiles()...)
	findings = append(findings, checkCronWritable()...)
	findings = append(findings, checkSudoRights()...)
	if runtime.GOOS == "linux" {
		findings = append(findings, checkNFSExports()...)
	}
	return findings
}

// isWritable 检查当前用户是否可写该路径（文件或目录）
func isWritable(path string) bool {
	// syscall.Access 第二个参数 2 = W_OK
	return syscall.Access(path, 0x2) == nil
}

// checkSUIDBinaries 扫描常见路径下的 SUID/SGID 二进制并对照 GTFOBins 名单
func checkSUIDBinaries() []PrivescFinding {
	var findings []PrivescFinding
	var others []string

	for _, dir := range suidScanDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			mode := info.Mode()
			if mode&(os.ModeSetuid|os.ModeSetgid) == 0 {
				continue
			}
			path := filepath.Join(dir, e.Name())
			kind := "SUID"
			if mode&os.ModeSetuid == 0 {
				kind = "SGID"
			}
			if gtfoBins[strings.ToLower(e.Name())] {
				findings = append(findings, PrivescFinding{
					Severity: "高", Category: "SUID",
					Title:  fmt.Sprintf("GTFOBins 可利用的 %s 二进制: %s", kind, e.Name()),
					Detail: fmt.Sprintf("%s（参考 https://gtfobins.github.io/gtfobins/%s/#suid）", path, strings.ToLower(e.Name())),
				})
			} else {
				others = append(others, fmt.Sprintf("%s(%s)", path, kind))
			}
		}
	}

	if len(others) > 0 {
		shown := others
		if len(shown) > 15 {
			shown = shown[:15]
		}
		findings = append(findings, PrivescFinding{
			Severity: "信息", Category: "SUID",
			Title:  fmt.Sprintf("发现 %d 个其他 SUID/SGID 二进制", len(others)),
			Detail: strings.Join(shown, ", "),
		})
	}
	return findings
}

// checkWritableSystemFiles 检查关键系统文件可写性
func checkWritableSystemFiles() []PrivescFinding {
	type target struct {
		path  string
		title string
	}
	targets := []target{
		{"/etc/passwd", "/etc/passwd 可写，可直接添加 root 用户"},
		{"/etc/shadow", "/etc/shadow 可写，可直接替换 root 密码哈希"},
		{"/etc/sudoers", "/etc/sudoers 可写，可直接授予 sudo 权限"},
		{"/etc/sudoers.d", "/etc/sudoers.d 目录可写，可写入任意 sudo 规则"},
	}
	var findings []PrivescFinding
	for _, t := range targets {
		if fi, err := os.Stat(t.path); err == nil && fi.IsDir() {
			if isWritable(t.path) {
				findings = append(findings, PrivescFinding{
					Severity: "高", Category: "文件权限", Title: t.title, Detail: t.path})
			}
			continue
		}
		if _, err := os.Stat(t.path); err != nil {
			continue
		}
		if isWritable(t.path) {
			findings = append(findings, PrivescFinding{
				Severity: "高", Category: "文件权限", Title: t.title, Detail: t.path})
		}
	}
	return findings
}

// checkCronWritable 检查 cron 相关文件/目录可写性
func checkCronWritable() []PrivescFinding {
	paths := []string{
		"/etc/crontab", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
		"/etc/cron.weekly", "/etc/cron.monthly",
		"/var/spool/cron", "/var/spool/cron/crontabs",
	}
	var findings []PrivescFinding
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		if isWritable(p) {
			findings = append(findings, PrivescFinding{
				Severity: "高", Category: "Cron",
				Title:  "cron 路径可写，可植入 root 计划任务",
				Detail: p,
			})
		}
	}
	return findings
}

// checkSudoRights 非交互解析 sudo -n -l 输出（需要密码或失败时跳过）
func checkSudoRights() []PrivescFinding {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "sudo", "-n", "-l").CombinedOutput()
	if err != nil {
		return nil // 非交互失败（需要密码等），跳过
	}
	return parseSudoListOutput(string(out))
}

// checkNFSExports 检查 /etc/exports 中的 no_root_squash 配置
func checkNFSExports() []PrivescFinding {
	data, err := os.ReadFile("/etc/exports")
	if err != nil {
		return nil
	}
	var findings []PrivescFinding
	for _, line := range parseExportsNoRootSquash(string(data)) {
		findings = append(findings, PrivescFinding{
			Severity: "高", Category: "NFS",
			Title:  "NFS 导出启用了 no_root_squash",
			Detail: fmt.Sprintf("%s（远端 root 可写 SUID 二进制后本地执行提权）", line),
		})
	}
	return findings
}

// ==================== 供 privesc.go 命中的版本探测辅助 ====================

// getPolkitVersion 通过 pkexec --version 获取 polkit 版本字符串
func getPolkitVersion() string {
	out, err := exec.Command("pkexec", "--version").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// getSudoVersion 通过 sudo -V 获取 sudo 版本字符串
func getSudoVersion() string {
	out, err := exec.Command("sudo", "-V").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// pkexecSUIDExists 判断 pkexec 是否存在且带 SUID 位
func pkexecSUIDExists() bool {
	candidates := []string{"/usr/bin/pkexec", "/bin/pkexec", "/usr/local/bin/pkexec"}
	if p, err := exec.LookPath("pkexec"); err == nil {
		candidates = append(candidates, p)
	}
	for _, p := range candidates {
		if fi, err := os.Stat(p); err == nil && fi.Mode()&os.ModeSetuid != 0 {
			return true
		}
	}
	return false
}
