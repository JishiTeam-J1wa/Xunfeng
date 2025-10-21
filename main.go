package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/karrick/godirwalk"
)

// --- Global Dictionaries & Rules ---

var (
	// targetExtensions defines file types to scan for content.
	targetExtensions = map[string]bool{
		".xml": true, ".json": true, ".yml": true, ".yaml": true, ".conf": true,
		".cfg": true, ".ini": true, ".log": true, ".txt": true, ".md": true,
		".pem": true, ".key": true, ".cer": true, ".crt": true, ".p12": true,
		".pfx": true, ".properties": true, ".env": true, ".sh": true, ".bat": true,
		".sql": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true,
	}

	// nonScanExtensions defines file types that are sensitive by nature but shouldn't be content-scanned (e.g., binary).
	nonScanExtensions = map[string]bool{
		".db": true, ".sqlite": true, ".mdb": true, ".keystore": true, ".jks": true,
		".pcap": true, ".dmp": true,
	}

	// sensitiveFilenames defines specific filenames that are considered sensitive.
	sensitiveFilenames = map[string]bool{
		"web.config": true, "app.config": true, "credentials": true, "credential": true,
		"config.php": true, "settings.py": true, "local_settings.py": true,
		"id_rsa": true, "id_dsa": true, "id_ecdsa": true,
	}

	// sensitivePatterns defines the regex rules for finding sensitive content.
	sensitivePatterns = map[string]*regexp.Regexp{
		"邮箱":        regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`),
		"手机号":       regexp.MustCompile(`\b1[3-9]\d{9}\b`),
		"身份证号":      regexp.MustCompile(`\b[1-6]\d{5}(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dX]\b`),
		"通用密码/密钥":   regexp.MustCompile(`(?i)\b(password|passwd|secret|key|token|auth|credential|api_key|access_key)\b\s*[:=]\s*['"]?[\w-]{8,}`),
		"成对的账号密码":   regexp.MustCompile(`(?i)\b(user|username|account|login)\b\s*[:=]\s*['"]?[\w.-]+['"]?.*\b(password|passwd)\b\s*[:=]\s*['"]?[\w-]{8,}`),
		"数据库连接字符串":  regexp.MustCompile(`(?i)\b(jdbc|odbc|dsn|connectionstring|database_url)\b\s*[:=]\s*['"]?.*(user|uid|password|pwd|secret).*[>"]?`),
		"AWS密钥":     regexp.MustCompile(`\b(AKIA[0-9A-Z]{16})\b`),
		"阿里云密钥":     regexp.MustCompile(`\b(LTAI[0-9A-Za-z]{20})\b`),
		"JWT令牌":     regexp.MustCompile(`\b(ey[A-Za-z0-9-_=]+\.ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+)\b`),
		"SSH私钥头部":   regexp.MustCompile(`-----BEGIN (RSA|OPENSSH|DSA|EC) PRIVATE KEY-----`),
		"Shiro密钥":   regexp.MustCompile(`rememberMe\s*=\s*deleteMe`),
		"命令执行函数":    regexp.MustCompile(`\b(eval|system|exec|popen|passthru|shell_exec|assert)\s*\(`),
		"中文-数据库":    regexp.MustCompile(`数据库`),
		"中文-账号":     regexp.MustCompile(`账号`),
		"中文-密码":     regexp.MustCompile(`密码`),
		"中文-VPN":    regexp.MustCompile(`vpn`),
		"中文-堡垒机":    regexp.MustCompile(`堡垒机`),
		"关键字-root":  regexp.MustCompile(`\broot\b`),
		"关键字-admin": regexp.MustCompile(`\badmin\b`),
		"关键字-cmd":   regexp.MustCompile(`\bcmd\b`),
	}

	// interestingProcesses defines regex rules for finding high-value processes.
	// The regex is matched against the full command line of the process for accuracy.
	interestingProcesses = map[string]*regexp.Regexp{
		// OA & ERP (High-Value Targets)
		"泛微OA (Weaver)":   regexp.MustCompile(`(?i)weaver.hrms`),
		"致远OA (Seeyon)":   regexp.MustCompile(`(?i)seeyon`),
		"通达OA (Tongda)":   regexp.MustCompile(`(?i)tongda`),
		"用友NC (Yonyou)":   regexp.MustCompile(`(?i)yonyou`),
		"金蝶EAS (Kingdee)": regexp.MustCompile(`(?i)kingdee`),

		// Web & App Servers
		"Tomcat":        regexp.MustCompile(`(?i)tomcat`),
		"Nginx":         regexp.MustCompile(`^nginx\b`),
		"Apache httpd":  regexp.MustCompile(`^httpd\b|^apache2\b`),
		"WebLogic":      regexp.MustCompile(`(?i)weblogic.server`),
		"WebSphere":     regexp.MustCompile(`(?i)websphere`),
		"JBoss/WildFly": regexp.MustCompile(`(?i)jboss|wildfly`),

		// Databases
		"MySQL/MariaDB": regexp.MustCompile(`^mysqld\b`),
		"PostgreSQL":    regexp.MustCompile(`^postgres\b`),
		"MS SQL Server": regexp.MustCompile(`^sqlservr\b`),
		"Oracle":        regexp.MustCompile(`ora_pmon_`), // Oracle Process Monitor
		"MongoDB":       regexp.MustCompile(`^mongod\b`),
		"Redis":         regexp.MustCompile(`^redis-server\b`),
		"DB2":           regexp.MustCompile(`^db2sysc\b`),

		// Big Data & DevOps
		"Elasticsearch": regexp.MustCompile(`(?i)elasticsearch`),
		"Jenkins":       regexp.MustCompile(`(?i)jenkins.war`),
		"GitLab":        regexp.MustCompile(`(?i)gitlab`),
		"Docker":        regexp.MustCompile(`^dockerd\b`),
		"Kubernetes":    regexp.MustCompile(`^kubelet\b`),

		// Runtimes (as a fallback)
		"Java Application":   regexp.MustCompile(`\.jar\b`),
		"Python Application": regexp.MustCompile(`\.py\b`),
		"Node.js":            regexp.MustCompile(`\.js\b`),
		".NET Application":   regexp.MustCompile(`\.dll\b`),
	}

	// excludedDirKeywords defines parts of directory names to skip.
	excludedDirKeywords = map[string]bool{
		"node_modules": true, "vendor": true, "cache": true, "tmp": true, "temp": true,
		"__pycache__": true, ".git": true, ".svn": true, ".hg": true,
		"site-packages": true, "dist-packages": true, "test": true, "tests": true,
		"example": true, "examples": true, "doc": true, "docs": true, "sample": true,
		"samples": true, "fuzz": true, "dict": true, "dic": true,
	}

	// excludedPathPrefixes will be populated at runtime.
	excludedPathPrefixes []string
)

// --- Result Structs & Temp Files ---

var (
	contentFile     *os.File
	filesFile       *os.File
	permissionsFile *os.File
	contentWriter   *bufio.Writer
	filesWriter     *bufio.Writer
	permWriter      *bufio.Writer
	writerMutex     sync.Mutex
)

// --- Global State ---

var (
	scannedFilesCount  uint64
	sensitiveHitsCount uint64
	contentHitsCount   uint64
	fileHitsCount      uint64
	fileQueue          chan string
	wg                 sync.WaitGroup
	statusTicker       *time.Ticker
	doneChan           chan bool
	red                = color.New(color.FgRed).SprintFunc()
	cyan               = color.New(color.FgCyan).SprintFunc()
	yellow             = color.New(color.FgYellow).SprintFunc()
)

// --- Core Functions ---

func printBanner() {
	banner := `
=========================================
  J4Team - 寻风 (Sensitive Info Finder)
=========================================
`
	color.Cyan(banner)
}

func initializeExclusions() {
	usr, err := user.Current()
	if err != nil {
		fmt.Printf("无法获取当前用户目录（常见于权限不足）: %v\n", err)
		return
	}
	homeDir := usr.HomeDir

	// --- Build the exclusion list ---
	// This list is crucial for performance and accuracy. It avoids scanning
	// system directories, caches, and developer toolchains, which are full of
	// "false positives" and irrelevant data.
	// Importantly, it DOES NOT exclude common user directories like 'Desktop',
	// 'Documents', or '/root', as these are high-value scan targets.

	// 1. General development and cache directories (cross-platform)
	// These are often located in the user's home directory.
	generalDevExclusions := []string{
		"go", ".go", "node_modules", ".npm", ".nvm", "vendor",
		".bundle", ".rvm", ".rbenv", ".pyenv", ".local/share",
	}
	for _, p := range generalDevExclusions {
		excludedPathPrefixes = append(excludedPathPrefixes, filepath.Join(homeDir, p))
	}

	// 2. OS-specific system, application, and tool directories
	var osSpecificExclusions []string
	switch runtime.GOOS {
	case "darwin":
		osSpecificExclusions = []string{
			filepath.Join(homeDir, "Library"), // User-specific app data and caches
			"/Library",                        // System-wide app data and caches
			"/System",                         // Core OS files
			"/usr/local/Cellar",               // Homebrew package location
			"/opt/homebrew",                   // Apple Silicon Homebrew location
			"/usr/local/go",                   // Default Go installation path
		}
	case "linux":
		osSpecificExclusions = []string{
			"/proc", "/sys", "/dev", "/run", // Virtual filesystems
			"/var/lib", "/var/cache", // System data and caches
		}
	case "windows":
		osSpecificExclusions = []string{
			"C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)",
			filepath.Join(homeDir, "AppData"), // User-specific app data
		}
	}
	excludedPathPrefixes = append(excludedPathPrefixes, osSpecificExclusions...)
}

func setupTempFiles() error {
	var err error
	contentFile, err = os.Create("content.tmp")
	if err != nil {
		return fmt.Errorf("无法创建 content.tmp: %w", err)
	}
	filesFile, err = os.Create("files.tmp")
	if err != nil {
		return fmt.Errorf("无法创建 files.tmp: %w", err)
	}
	permissionsFile, err = os.Create("permissions.tmp")
	if err != nil {
		return fmt.Errorf("无法创建 permissions.tmp: %w", err)
	}
	contentWriter = bufio.NewWriter(contentFile)
	filesWriter = bufio.NewWriter(filesFile)
	permWriter = bufio.NewWriter(permissionsFile)
	return nil
}

func isExcluded(path string) bool {
	for _, prefix := range excludedPathPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	for keyword := range excludedDirKeywords {
		if strings.Contains(filepath.ToSlash(path), "/"+keyword+"/") || strings.HasSuffix(path, "/"+keyword) {
			return true
		}
	}
	return false
}

func getFilePermissions(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return "Unknown"
	}
	mode := info.Mode()
	var perms []string
	if mode&os.ModeDir != 0 {
		perms = append(perms, "d")
	} else {
		perms = append(perms, "-")
	}
	for i := 0; i < 3; i++ {
		if mode&(1<<(8-3*i)) != 0 {
			perms = append(perms, "r")
		} else {
			perms = append(perms, "-")
		}
		if mode&(1<<(7-3*i)) != 0 {
			perms = append(perms, "w")
		} else {
			perms = append(perms, "-")
		}
		if mode&(1<<(6-3*i)) != 0 {
			perms = append(perms, "x")
		} else {
			perms = append(perms, "-")
		}
	}
	return strings.Join(perms, "")
}

func discoverAndAnalyze(roots []string, stealthDelay int) {
	defer wg.Done()
	for _, root := range roots {
		err := godirwalk.Walk(root, &godirwalk.Options{
			Callback: func(path string, de *godirwalk.Dirent) error {
				if stealthDelay > 0 {
					time.Sleep(time.Duration(stealthDelay) * time.Millisecond)
				}
				if isExcluded(path) {
					if de.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}

				if de.IsDir() {
					perms := getFilePermissions(path)
					// Noise reduction: only report world-writable directories
					if len(perms) == 10 && perms[8] == 'w' {
						writerMutex.Lock()
						permWriter.WriteString(fmt.Sprintf("[%s] %s\n", perms, path))
						writerMutex.Unlock()
					}
					return nil
				}

				ext := strings.ToLower(filepath.Ext(path))
				filename := strings.ToLower(filepath.Base(path))

				if nonScanExtensions[ext] {
					atomic.AddUint64(&fileHitsCount, 1)
					writerMutex.Lock()
					filesWriter.WriteString(fmt.Sprintf("[文件] %s\n  [原因] %s\n\n", path, "敏感文件后缀"))
					writerMutex.Unlock()
					return nil
				}

				if sensitiveFilenames[filename] {
					atomic.AddUint64(&fileHitsCount, 1)
					writerMutex.Lock()
					filesWriter.WriteString(fmt.Sprintf("[文件] %s\n  [原因] %s\n\n", path, "敏感文件名"))
					writerMutex.Unlock()
				}

				if targetExtensions[ext] {
					fileQueue <- path
				}

				return nil
			},
			ErrorCallback: func(path string, err error) godirwalk.ErrorAction {
				writerMutex.Lock()
				permWriter.WriteString(fmt.Sprintf("[无权限访问] %s\n", path))
				writerMutex.Unlock()
				return godirwalk.SkipNode
			},
			Unsorted: true,
		})
		if err != nil {
			fmt.Printf("遍历目录 %s 时出错: %v\n", root, err)
		}
	}
	close(fileQueue)
}

func scanFileForContent(filePath string) {
	file, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer file.Close()

	atomic.AddUint64(&scannedFilesCount, 1)

	reader := io.LimitReader(file, 10*1024*1024) // 10MB limit
	scanner := bufio.NewScanner(reader)
	lineNum := 0
	foundRules := make(map[string]bool)

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		for name, pattern := range sensitivePatterns {
			if _, found := foundRules[name]; found {
				continue
			}
			if pattern.MatchString(line) {
				atomic.AddUint64(&contentHitsCount, 1)
				result := fmt.Sprintf("[文件] %s:%d\n  [规则] %s\n  [内容] %s\n\n", filePath, lineNum, name, strings.TrimSpace(line))
				writerMutex.Lock()
				contentWriter.WriteString(result)
				writerMutex.Unlock()
				foundRules[name] = true
			}
		}
	}
}

func worker() {
	defer wg.Done()
	for filePath := range fileQueue {
		scanFileForContent(filePath)
	}
}

func scanProcesses() string {
	var sb strings.Builder
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		// Get PID and full command line. WMIC is more reliable for full command lines.
		cmd = exec.Command("wmic", "process", "get", "ProcessId,CommandLine", "/FORMAT:CSV")
	case "linux", "darwin":
		// Get PID and full command line (command). 'comm' is just the executable name.
		cmd = exec.Command("ps", "-eo", "pid,command")
	default:
		return ""
	}

	output, err := cmd.Output()
	if err != nil {
		return "" // Silently fail if command is not available or fails
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	isFirstLine := true
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if isFirstLine || line == "" {
			isFirstLine = false
			continue
		}

		var pid, commandLine string
		if runtime.GOOS == "windows" {
			// WMIC CSV output is Node,CommandLine,ProcessId
			parts := strings.SplitN(line, ",", 3)
			if len(parts) < 3 {
				continue
			}
			commandLine = parts[1]
			pid = parts[2]
		} else {
			// ps output is PID followed by the command
			parts := strings.Fields(line)
			if len(parts) < 2 {
				continue
			}
			pid = parts[0]
			commandLine = strings.Join(parts[1:], " ")
		}

		if commandLine == "" {
			continue
		}

		for desc, pattern := range interestingProcesses {
			if pattern.MatchString(commandLine) {
				// Truncate long command lines for readability in the report
				shortCmd := commandLine
				if len(shortCmd) > 150 {
					shortCmd = shortCmd[:150] + "..."
				}
				sb.WriteString(fmt.Sprintf("[描述] %s (PID: %s)\n  [命令] %s\n\n", desc, pid, shortCmd))
				break // Report first match only
			}
		}
	}
	return sb.String()
}

func printStatus() {
	for {
		select {
		case <-doneChan:
			atomic.StoreUint64(&sensitiveHitsCount, atomic.LoadUint64(&contentHitsCount)+atomic.LoadUint64(&fileHitsCount))
			fmt.Printf("\r%s\n", strings.Repeat(" ", 80)) // Clear line
			fmt.Printf("扫描完成. 已扫描文件: %s | 命中敏感项: %s\n",
				cyan(strconv.FormatUint(atomic.LoadUint64(&scannedFilesCount), 10)),
				red(strconv.FormatUint(atomic.LoadUint64(&sensitiveHitsCount), 10)),
			)
			return
		case <-statusTicker.C:
			atomic.StoreUint64(&sensitiveHitsCount, atomic.LoadUint64(&contentHitsCount)+atomic.LoadUint64(&fileHitsCount))
			scanned := atomic.LoadUint64(&scannedFilesCount)
			hits := atomic.LoadUint64(&sensitiveHitsCount)
			fmt.Printf("\r正在扫描... 已扫描文件: %s | 命中敏感项: %s",
				cyan(strconv.FormatUint(scanned, 10)),
				red(strconv.FormatUint(hits, 10)),
			)
		}
	}
}

func finalizeReport(startTime time.Time, outputFilename string) {
	fmt.Println("\n正在生成最终报告...")

	// Flush and close temp files
	contentWriter.Flush()
	filesWriter.Flush()
	permWriter.Flush()
	contentFile.Close()
	filesFile.Close()
	permissionsFile.Close()

	// Create final report file
	finalReport, err := os.Create(outputFilename)
	if err != nil {
		fmt.Printf("无法创建最终报告文件: %v\n", err)
		return
	}
	defer finalReport.Close()

	writer := bufio.NewWriter(finalReport)

	writer.WriteString("J4team 寻风 - 敏感信息扫描报告\n")
	writer.WriteString("====================================\n\n")

	// Helper to append a temp file to the report
	appendSection := func(title, tempFileName string) {
		writer.WriteString(title)
		tempFile, err := os.Open(tempFileName)
		if err != nil {
			writer.WriteString(fmt.Sprintf("无法读取 %s\n\n", tempFileName))
			return
		}
		defer tempFile.Close()
		stat, _ := tempFile.Stat()
		if stat.Size() == 0 {
			writer.WriteString("未发现相关信息。\n\n")
		} else {
			io.Copy(writer, tempFile)
			writer.WriteString("\n")
		}
	}

	appendSection("--- 敏感信息 (Content Hits) ---\n", "content.tmp")
	appendSection("--- 敏感文件 (Sensitive Files) ---\n", "files.tmp")
	appendSection("--- 目录权限 (Directory Permissions) ---\n", "permissions.tmp")

	// Processes
	writer.WriteString("\n--- 运行中进程 (Running Processes) ---\n")
	processInfo := scanProcesses()
	if processInfo == "" {
		writer.WriteString("未发现值得关注的进程。\n\n")
	} else {
		writer.WriteString(processInfo)
	}

	// Summary
	writer.WriteString("\n--- 扫描摘要 (Summary) ---\n")
	writer.WriteString(fmt.Sprintf("扫描用时: %s\n", time.Since(startTime).Round(time.Second)))
	writer.WriteString(fmt.Sprintf("扫描文件总数: %d\n", atomic.LoadUint64(&scannedFilesCount)))
	writer.WriteString(fmt.Sprintf("内容命中数: %d\n", atomic.LoadUint64(&contentHitsCount)))
	writer.WriteString(fmt.Sprintf("文件命中数: %d\n", atomic.LoadUint64(&fileHitsCount)))

	writer.Flush()

	// Cleanup temp files
	os.Remove("content.tmp")
	os.Remove("files.tmp")
	os.Remove("permissions.tmp")

	fmt.Printf("报告已生成: %s\n", yellow(outputFilename))
}

func setupSignalHandler(startTime time.Time, outputFilename string) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\n捕获到中断信号...")
		// Stop the status ticker and discovery
		statusTicker.Stop()
		close(doneChan)
		// Finalize the report
		finalizeReport(startTime, outputFilename)
		os.Exit(1)
	}()
}

func main() {
	threads := flag.Int("t", runtime.NumCPU(), "设置扫描线程数")
	outputFile := flag.String("o", "result.txt", "指定输出报告文件名")
	stealth := flag.Int("s", 0, "设置扫描延迟（毫秒），降低EDR检测风险")
	flag.Parse()
	runtime.GOMAXPROCS(*threads)

	printBanner()
	initializeExclusions()

	if err := setupTempFiles(); err != nil {
		fmt.Printf("初始化临时文件失败: %v\n", err)
		os.Exit(1)
	}

	startTime := time.Now()
	setupSignalHandler(startTime, *outputFile)

	fileQueue = make(chan string, *threads*2)
	statusTicker = time.NewTicker(2 * time.Second)
	doneChan = make(chan bool)

	fmt.Printf("使用 %d 个线程进行扫描...\n", *threads)

	wg.Add(*threads)
	for i := 0; i < *threads; i++ {
		go worker()
	}

	wg.Add(1)
	var roots []string
	if runtime.GOOS == "windows" {
		for c := 'A'; c <= 'Z'; c++ {
			path := string(c) + ":\\"
			if _, err := os.Stat(path); err == nil {
				roots = append(roots, path)
			}
		}
	} else {
		roots = append(roots, "/")
	}
	fmt.Printf("扫描根目录: %v\n", roots)
	go discoverAndAnalyze(roots, *stealth)
	go printStatus()

	wg.Wait() // Wait for discovery and workers to finish

	statusTicker.Stop()
	close(doneChan)

	finalizeReport(startTime, *outputFile)
}
