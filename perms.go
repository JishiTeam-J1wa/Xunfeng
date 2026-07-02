package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
)

// WritableDir 风险等级：哪些可写目录更容易被用于驻留/横向
type writableDirRisk int

const (
	riskLow writableDirRisk = iota
	riskMedium
	riskHigh
	riskCritical
)

func (r writableDirRisk) String() string {
	switch r {
	case riskCritical:
		return "CRITICAL"
	case riskHigh:
		return "HIGH"
	case riskMedium:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// scanWritableDirs 检查当前用户拥有写+执行权限的高价值目录
func scanWritableDirs() {
	candidates := collectWritableDirCandidates()

	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	seen := make(map[string]struct{})
	var mu sync.Mutex

	for _, dir := range candidates {
		dir = filepath.Clean(dir)
		mu.Lock()
		if _, ok := seen[dir]; ok {
			mu.Unlock()
			continue
		}
		seen[dir] = struct{}{}
		mu.Unlock()

		wg.Add(1)
		sem <- struct{}{}
		go func(d string) {
			defer wg.Done()
			defer func() { <-sem }()
			checkAndReportWritableDir(d)
		}(dir)
	}
	wg.Wait()
}

// collectWritableDirCandidates 收集需要重点检查的目录
func collectWritableDirCandidates() []string {
	var dirs []string

	// PATH 环境变量中的目录（可直接执行命令）
	for _, p := range filepath.SplitList(os.Getenv("PATH")) {
		if p != "" {
			dirs = append(dirs, p)
		}
	}

	home, _ := os.UserHomeDir()
	if home != "" {
		dirs = append(dirs, home)
		dirs = append(dirs, filepath.Join(home, "Desktop"))
		dirs = append(dirs, filepath.Join(home, "Downloads"))
		dirs = append(dirs, filepath.Join(home, "Documents"))
		dirs = append(dirs, filepath.Join(home, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"))
	}

	// Windows 公共启动目录
	dirs = append(dirs,
		`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`,
		`C:\Windows\Temp`,
		`C:\Temp`,
		`C:\Users\Public`,
		`C:\Users\Public\Downloads`,
		`C:\Users\Public\Desktop`,
	)

	// 通用临时目录
	dirs = append(dirs, os.TempDir())

	// 当前工作目录
	if cwd, err := os.Getwd(); err == nil {
		dirs = append(dirs, cwd)
	}

	return dirs
}

// checkAndReportWritableDir 检查目录是否可写+可执行，并上报
func checkAndReportWritableDir(dir string) {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return
	}

	// 可执行（遍历）权限：尝试列出目录内容
	if _, err := os.ReadDir(dir); err != nil {
		return
	}

	// 可写权限：尝试创建并删除临时文件
	tmpPath := filepath.Join(dir, ".xunfeng_write_test_"+randomSuffix())
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		return
	}
	_, _ = f.WriteString("xunfeng")
	f.Close()
	os.Remove(tmpPath)

	// 目录确实可写+可执行，判断风险等级
	risk := classifyWritableDirRisk(dir)
	category := "WritableDir"
	switch risk {
	case riskCritical:
		category = "WritableDirCritical"
	case riskHigh:
		category = "WritableDirHigh"
	case riskMedium:
		category = "WritableDirMedium"
	default:
		category = "WritableDirLow"
	}

	atomic.AddUint64(&totalFindings, 1)
	globalReporter.AddFinding(category, risk.String(), dir, 0, "writable+executable")

	if !silent {
		printFinding(getSeverity(category), category, dir, 0, risk.String()+" 可写可执行目录")
	}
}

// classifyWritableDirRisk 根据目录位置判断风险等级
func classifyWritableDirRisk(dir string) writableDirRisk {
	dirLower := strings.ToLower(dir)

	// 启动目录：可直接持久化
	if strings.Contains(dirLower, "startup") || strings.Contains(dirLower, "start menu\\programs") {
		return riskCritical
	}

	// PATH 中的目录：可以替换/劫持可执行文件
	for _, p := range filepath.SplitList(os.Getenv("PATH")) {
		if p == "" {
			continue
		}
		if strings.EqualFold(filepath.Clean(p), dirLower) {
			return riskHigh
		}
	}

	// 系统/公共目录可写：影响所有用户
	if strings.HasPrefix(dirLower, `c:\windows`) || strings.Contains(dirLower, `c:\programdata`) || strings.Contains(dirLower, `c:\users\public`) {
		return riskHigh
	}

	// 用户高价值目录
	if strings.Contains(dirLower, "downloads") || strings.Contains(dirLower, "desktop") || strings.Contains(dirLower, "documents") {
		return riskMedium
	}

	return riskLow
}

func randomSuffix() string {
	b := make([]byte, 8)
	for i := range b {
		b[i] = byte('a' + (i*7+13)%26)
	}
	return string(b)
}
