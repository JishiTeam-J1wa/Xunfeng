package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"database/sql"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"math"
	"math/rand"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/fatih/color"
	"github.com/karrick/godirwalk"
	_ "github.com/mattn/go-sqlite3"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	psnet "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

// ==================== 全局配置 ====================

const (
	// 分片数量 (2的幂次方，用于位运算)
	shardCount     = 64
	shardMask      = shardCount - 1
	maxLineLen     = 4096        // 最大行长度
	readBufferSize = 256 * 1024  // 256KB 读取缓冲
	maxFileSize    = 10 << 20    // 10MB 最大文件
	queueMultiple  = 200         // 队列倍数
)

var (
	outputFile   *os.File
	outputWriter *bufio.Writer
	silent       bool

	// 统计计数器
	scannedFiles   uint64
	totalFindings  uint64
	contentHits    uint64
	fileHits       uint64
	processHits    uint64
	networkHits    uint64
	credentialHits uint64

	// 并发
	fileQueue chan string
	wg        sync.WaitGroup

	// 颜色
	cyan    = color.New(color.FgCyan).SprintFunc()
	green   = color.New(color.FgGreen).SprintFunc()
	red     = color.New(color.FgRed).SprintFunc()
	yellow  = color.New(color.FgYellow).SprintFunc()
	magenta = color.New(color.FgMagenta).SprintFunc()
	white   = color.New(color.FgWhite, color.Bold).SprintFunc()

	// 分片去重 (减少锁竞争)
	seenShards [shardCount]struct {
		sync.RWMutex
		m map[uint64]struct{}
	}

	// 排除目录 (使用数组加速小集合查找)
	excludedDirsList = []string{
		"node_modules", "vendor", ".git", ".svn",
		"__pycache__", ".idea", ".vscode", "cache",
		".cache", "Cache", "tmp", "temp", "logs",
		".npm", ".yarn", "dist", "build", ".next",
		"coverage", ".pytest_cache", "venv", ".venv",
		"target", "Pods", "DerivedData",
	}
	excludedDirs  = make(map[string]struct{}, 30)
	excludedPaths []string

	// Aho-Corasick 多模式匹配器
	keywordMatcher *AhoCorasick
)

func init() {
	// 初始化分片 map
	for i := 0; i < shardCount; i++ {
		seenShards[i].m = make(map[uint64]struct{}, 256)
	}
	// 初始化排除目录 map
	for _, d := range excludedDirsList {
		excludedDirs[d] = struct{}{}
	}
}

// ==================== 快速字符串工具 ====================

// 快速检查字节是否包含关键字符 (用于极速预筛选)
var sensitiveCharMask [256]bool

func initCharMask() {
	chars := "pPsStTkKaAcCjJmMrRbBeEgG密口账数"
	for _, c := range chars {
		if c < 256 {
			sensitiveCharMask[byte(c)] = true
		}
	}
}

// 快速预筛选：检查是否可能包含敏感内容
func quickPreFilter(line []byte) bool {
	// 长度检查
	if len(line) < 8 || len(line) > maxLineLen {
		return false
	}
	// 字符检查
	for _, b := range line {
		if sensitiveCharMask[b] {
			return true
		}
	}
	return false
}

// ==================== 熵值计算 (优化版) ====================

// 预计算 log2 查找表
var log2Table [256]float64

func init() {
	for i := 1; i < 256; i++ {
		log2Table[i] = math.Log2(float64(i))
	}
}

func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	// 使用数组替代 map (ASCII 优化)
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}

	length := float64(len(s))
	logLen := math.Log2(length)
	var entropy float64

	for _, count := range freq {
		if count > 0 {
			// 使用查找表加速
			if count < 256 {
				entropy += float64(count) * (logLen - log2Table[count])
			} else {
				entropy += float64(count) * (logLen - math.Log2(float64(count)))
			}
		}
	}

	return entropy / length
}

// 快速熵值估算 (用于短字符串)
func quickEntropyCheck(s string, threshold float64) bool {
	if len(s) < 8 {
		return false
	}

	// 快速检查：统计不同字符数
	var seen [256]bool
	unique := 0
	for i := 0; i < len(s); i++ {
		if !seen[s[i]] {
			seen[s[i]] = true
			unique++
		}
	}

	// 如果字符种类太少，肯定低熵
	minUnique := int(threshold * float64(len(s)) / 4)
	if unique < minUnique {
		return false
	}

	return calculateEntropy(s) >= threshold
}

// ==================== 哈希 ====================

func fnv1a(s string) uint64 {
	var h uint64 = 14695981039346656037
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

// 分片去重 (大幅减少锁竞争)
func isDuplicate(category, content string) bool {
	hash := fnv1a(category + ":" + content)
	shard := &seenShards[hash&shardMask]

	shard.RLock()
	_, exists := shard.m[hash]
	shard.RUnlock()
	if exists {
		return true
	}

	shard.Lock()
	// 双重检查
	if _, exists = shard.m[hash]; exists {
		shard.Unlock()
		return true
	}
	shard.m[hash] = struct{}{}
	shard.Unlock()
	return false
}

// 快速去重 (仅检查哈希)
func isDuplicateHash(hash uint64) bool {
	shard := &seenShards[hash&shardMask]

	shard.RLock()
	_, exists := shard.m[hash]
	shard.RUnlock()
	if exists {
		return true
	}

	shard.Lock()
	if _, exists = shard.m[hash]; exists {
		shard.Unlock()
		return true
	}
	shard.m[hash] = struct{}{}
	shard.Unlock()
	return false
}

// ==================== 输出 ====================

func printBanner() {
	if silent {
		return
	}
	banner := `
   ██╗  ██╗██╗   ██╗███╗   ██╗███████╗███████╗███╗   ██╗ ██████╗
   ╚██╗██╔╝██║   ██║████╗  ██║██╔════╝██╔════╝████╗  ██║██╔════╝
    ╚███╔╝ ██║   ██║██╔██╗ ██║█████╗  █████╗  ██╔██╗ ██║██║  ███╗
    ██╔██╗ ██║   ██║██║╚██╗██║██╔══╝  ██╔══╝  ██║╚██╗██║██║   ██║
   ██╔╝ ██╗╚██████╔╝██║ ╚████║██║     ███████╗██║ ╚████║╚██████╔╝
   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝     ╚══════╝╚═╝  ╚═══╝ ╚═════╝
                                            %s
`
	fmt.Printf(cyan(banner), yellow("v3.0 by J4Team"))
	fmt.Println()
}

func printInfo(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if !silent {
		fmt.Printf("[%s] %s\n", cyan("*"), msg)
	}
	writeOutput("[*] " + msg)
}

func printSuccess(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	atomic.AddUint64(&totalFindings, 1)
	if !silent {
		fmt.Printf("[%s] %s\n", green("+"), msg)
	}
	writeOutput("[+] " + msg)
}

func printWarning(format string, args ...interface{}) {
	if !silent {
		fmt.Printf("[%s] %s\n", yellow("!"), fmt.Sprintf(format, args...))
	}
}

func printSection(title string) {
	if !silent {
		fmt.Printf("\n%s %s %s\n", yellow("━━━━━━━━━━"), white(title), yellow("━━━━━━━━━━"))
	}
	writeOutput("\n========== " + title + " ==========")
}

// 输出缓冲 (批量写入减少锁竞争)
var outputBuffer struct {
	sync.Mutex
	buf []string
}

func writeOutput(msg string) {
	// 已弃用 - 使用 globalReporter 替代
}

func flushOutputLocked() {
	if outputWriter == nil || len(outputBuffer.buf) == 0 {
		return
	}
	for _, msg := range outputBuffer.buf {
		outputWriter.WriteString(msg)
		outputWriter.WriteByte('\n')
	}
	outputBuffer.buf = outputBuffer.buf[:0]
}

func flushOutput() {
	outputBuffer.Lock()
	flushOutputLocked()
	outputBuffer.Unlock()
}

// ==================== 隐匿性 ====================

func checkSandbox() bool {
	if runtime.NumCPU() < 2 {
		return true
	}
	if v, _ := mem.VirtualMemory(); v != nil && v.Total < 2*1024*1024*1024 {
		return true
	}
	if uptime, _ := host.Uptime(); uptime > 0 && uptime < 600 {
		return true
	}
	if procs, _ := process.Processes(); len(procs) < 30 {
		return true
	}
	return false
}

func antiDebug() bool {
	if runtime.GOOS == "windows" {
		return false
	}
	debuggers := []string{"lldb", "gdb", "strace", "ltrace", "dtrace"}
	procs, _ := process.Processes()
	for _, p := range procs {
		if name, _ := p.Name(); name != "" {
			nameLower := strings.ToLower(name)
			for _, d := range debuggers {
				if strings.Contains(nameLower, d) {
					return true
				}
			}
		}
	}
	return false
}

// ==================== 工具函数 ====================

func initExclusions() {
	usr, _ := user.Current()
	if usr == nil {
		return
	}
	home := usr.HomeDir

	common := []string{
		filepath.Join(home, "go"), filepath.Join(home, ".go"),
		filepath.Join(home, "node_modules"), filepath.Join(home, ".npm"),
		filepath.Join(home, ".nvm"), filepath.Join(home, ".cargo"),
		filepath.Join(home, ".rustup"), filepath.Join(home, ".local/share"),
	}
	excludedPaths = append(excludedPaths, common...)

	switch runtime.GOOS {
	case "darwin":
		excludedPaths = append(excludedPaths,
			filepath.Join(home, "Library"), "/Library", "/System",
			"/usr/local/Cellar", "/opt/homebrew", "/usr/local/go",
			"/Applications", "/private/var",
		)
	case "linux":
		excludedPaths = append(excludedPaths,
			"/proc", "/sys", "/dev", "/run", "/var/lib", "/var/cache",
			"/snap", "/usr/lib", "/usr/share",
		)
	case "windows":
		excludedPaths = append(excludedPaths,
			"C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)",
			filepath.Join(home, "AppData\\Local\\Microsoft"),
		)
	}
}

func truncate(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	b.Grow(maxLen + 4)
	lastSpace := false
	count := 0
	for _, r := range s {
		if count >= maxLen {
			b.WriteString("...")
			break
		}
		if r == '\n' || r == '\r' || r == '\t' {
			r = ' '
		}
		if r == ' ' {
			if lastSpace {
				continue
			}
			lastSpace = true
		} else {
			lastSpace = false
		}
		b.WriteRune(r)
		count++
	}
	return b.String()
}

// ==================== Office 文档解析 ====================

// extractDocText 从旧版 .doc 文件提取文本
func extractDocText(path string) (string, error) {
	// 方法1: macOS textutil (最佳选择)
	if cmdPath, err := exec.LookPath("textutil"); err == nil {
		out, err := exec.Command(cmdPath, "-stdout", "-convert", "txt", path).Output()
		if err == nil && len(out) > 0 {
			return string(out), nil
		}
	}

	// 方法2: 尝试使用 antiword 或 catdoc (Linux)
	for _, cmd := range []string{"antiword", "catdoc"} {
		if cmdPath, err := exec.LookPath(cmd); err == nil {
			out, err := exec.Command(cmdPath, path).Output()
			if err == nil && len(out) > 0 {
				return string(out), nil
			}
		}
	}

	// 方法3: 直接从二进制中提取文本字符串
	return extractStringsFromBinary(path)
}

// extractXlsText 从旧版 .xls 文件提取文本
func extractXlsText(path string) (string, error) {
	// 方法1: macOS textutil (可以处理部分 xls)
	if cmdPath, err := exec.LookPath("textutil"); err == nil {
		out, err := exec.Command(cmdPath, "-stdout", "-convert", "txt", path).Output()
		if err == nil && len(out) > 0 {
			return string(out), nil
		}
	}

	// 方法2: 尝试使用 ssconvert (gnumeric) 或 xls2csv (Linux)
	for _, cmd := range []string{"ssconvert", "xls2csv"} {
		if cmdPath, err := exec.LookPath(cmd); err == nil {
			var out []byte
			var err error
			if cmd == "ssconvert" {
				out, err = exec.Command(cmdPath, path, "fd://1", "--export-type=Gnumeric_stf:stf_csv").Output()
			} else {
				out, err = exec.Command(cmdPath, path).Output()
			}
			if err == nil && len(out) > 0 {
				return string(out), nil
			}
		}
	}

	// 方法3: 直接从二进制中提取文本字符串
	return extractStringsFromBinary(path)
}

// extractStringsFromBinary 从二进制文件中提取可打印字符串
func extractStringsFromBinary(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// 限制读取大小
	data := make([]byte, 2*1024*1024) // 最多 2MB
	n, err := file.Read(data)
	if err != nil && err != io.EOF {
		return "", err
	}
	if n == 0 {
		return "", nil
	}
	data = data[:n]

	var result strings.Builder
	var current strings.Builder
	minLen := 6 // 最小字符串长度

	for _, b := range data {
		// 可打印 ASCII 或中文字符
		if (b >= 32 && b <= 126) || b >= 0x80 {
			current.WriteByte(b)
		} else {
			if current.Len() >= minLen {
				result.WriteString(current.String())
				result.WriteByte('\n')
			}
			current.Reset()
		}
	}

	// 最后一个字符串
	if current.Len() >= minLen {
		result.WriteString(current.String())
	}

	return result.String(), nil
}

func extractDocxText(path string) (string, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return "", err
	}
	defer r.Close()

	var content strings.Builder
	for _, f := range r.File {
		if f.Name == "word/document.xml" {
			rc, err := f.Open()
			if err != nil {
				continue
			}
			data, err := io.ReadAll(io.LimitReader(rc, 5*1024*1024))
			rc.Close()
			if err != nil {
				continue
			}
			content.WriteString(extractXMLText(data))
			break
		}
	}
	return content.String(), nil
}

func extractXlsxText(path string) (string, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return "", err
	}
	defer r.Close()

	// 先读取共享字符串
	var sharedStrings []string
	for _, f := range r.File {
		if f.Name == "xl/sharedStrings.xml" {
			rc, err := f.Open()
			if err != nil {
				continue
			}
			data, err := io.ReadAll(io.LimitReader(rc, 5*1024*1024))
			rc.Close()
			if err != nil {
				continue
			}
			sharedStrings = parseSharedStrings(data)
			break
		}
	}

	var content strings.Builder
	for _, f := range r.File {
		if strings.HasPrefix(f.Name, "xl/worksheets/sheet") && strings.HasSuffix(f.Name, ".xml") {
			rc, err := f.Open()
			if err != nil {
				continue
			}
			data, err := io.ReadAll(io.LimitReader(rc, 5*1024*1024))
			rc.Close()
			if err != nil {
				continue
			}
			content.WriteString(extractSheetText(data, sharedStrings))
		}
	}
	return content.String(), nil
}

func parseSharedStrings(data []byte) []string {
	var result []string
	decoder := xml.NewDecoder(bytes.NewReader(data))
	var inT bool
	for {
		t, err := decoder.Token()
		if err != nil {
			break
		}
		switch se := t.(type) {
		case xml.StartElement:
			if se.Name.Local == "t" {
				inT = true
			}
		case xml.CharData:
			if inT {
				result = append(result, string(se))
			}
		case xml.EndElement:
			if se.Name.Local == "t" {
				inT = false
			}
		}
	}
	return result
}

func extractSheetText(data []byte, sharedStrings []string) string {
	var result strings.Builder
	decoder := xml.NewDecoder(bytes.NewReader(data))
	var inV bool
	for {
		t, err := decoder.Token()
		if err != nil {
			break
		}
		switch se := t.(type) {
		case xml.StartElement:
			if se.Name.Local == "v" {
				inV = true
			}
		case xml.CharData:
			if inV {
				result.WriteString(string(se))
				result.WriteString(" ")
			}
		case xml.EndElement:
			if se.Name.Local == "v" {
				inV = false
			}
		}
	}
	return result.String()
}

func extractXMLText(data []byte) string {
	var result strings.Builder
	decoder := xml.NewDecoder(bytes.NewReader(data))
	for {
		t, err := decoder.Token()
		if err != nil {
			break
		}
		if cd, ok := t.(xml.CharData); ok {
			text := strings.TrimSpace(string(cd))
			if text != "" {
				result.WriteString(text)
				result.WriteString(" ")
			}
		}
	}
	return result.String()
}

// ==================== 文件扫描 ====================

func discoverFiles(roots []string, stealthMs int) {
	rand.Shuffle(len(roots), func(i, j int) { roots[i], roots[j] = roots[j], roots[i] })

	// 预计算扩展名集合 (减少 map 查找)
	scanExts := make(map[string]struct{}, 100)
	for ext := range targetExtensions {
		scanExts[ext] = struct{}{}
	}
	for ext := range officeExtensions {
		scanExts[ext] = struct{}{}
	}
	for ext := range highValueExtensions {
		scanExts[ext] = struct{}{}
	}
	for ext := range scanOnlyExtensions {
		scanExts[ext] = struct{}{}
	}

	for _, root := range roots {
		godirwalk.Walk(root, &godirwalk.Options{
			Unsorted:            true,
			FollowSymbolicLinks: false,
			Callback: func(path string, de *godirwalk.Dirent) error {
				if stealthMs > 0 {
					time.Sleep(time.Duration(stealthMs+rand.Intn(stealthMs/2+1)) * time.Millisecond)
				}

				name := de.Name()

				if de.IsDir() {
					// 快速目录过滤
					if _, skip := excludedDirs[name]; skip {
						return godirwalk.SkipThis
					}
					for _, prefix := range excludedPaths {
						if strings.HasPrefix(path, prefix) {
							return godirwalk.SkipThis
						}
					}
					return nil
				}

				// 路径排除
				for _, prefix := range excludedPaths {
					if strings.HasPrefix(path, prefix) {
						return nil
					}
				}

				atomic.AddUint64(&scannedFiles, 1)

				// 快速获取扩展名
				nameLower := toLowerASCII(name)
				ext := ""
				for i := len(name) - 1; i >= 0; i-- {
					if name[i] == '.' {
						ext = toLowerASCII(name[i:])
						break
					}
				}

				// 敏感文件名 (使用哈希去重)
				if sensitiveFilenames[nameLower] {
					hash := fnv1a("file:" + path)
					if !isDuplicateHash(hash) {
						atomic.AddUint64(&fileHits, 1)
						printSuccess("SensitiveFile  %-15s  %s", magenta(nameLower), path)
					}
				}

				// 敏感扩展名 (不扫描内容，直接报告)
				if nonScanExtensions[ext] {
					hash := fnv1a("file:" + path)
					if !isDuplicateHash(hash) {
						atomic.AddUint64(&fileHits, 1)
						printSuccess("SensitiveExt   %-15s  %s", magenta(ext), path)
					}
					return nil
				}

				// 高价值文件 (凭证/私钥等必报)
				if desc, ok := highValueExtensions[ext]; ok {
					hash := fnv1a("highvalue:" + path)
					if !isDuplicateHash(hash) {
						atomic.AddUint64(&fileHits, 1)
						printSuccess("HighValue      %-15s  %s", magenta(desc), path)
					}
				}

				// 需要扫描内容的文件 - 使用预计算集合
				if _, shouldScan := scanExts[ext]; shouldScan {
					info, err := os.Lstat(path)
					if err != nil || info.Size() > maxFileSize || info.Size() == 0 {
						return nil
					}
					fileQueue <- path
				}

				return nil
			},
			ErrorCallback: func(path string, err error) godirwalk.ErrorAction {
				return godirwalk.SkipNode
			},
		})
	}
}

// 规则匹配逻辑
func scanLineWithRules(path, line string, lineNum int, matchedRules map[string]struct{}) {
	for ruleName, rule := range sensitiveRules {
		if _, matched := matchedRules[ruleName]; matched {
			continue
		}

		if !rule.preCheck(line) {
			continue
		}

		// 先用 Match 快速检查
		if !rule.pattern.MatchString(line) {
			continue
		}

		// 只在确认匹配后才提取
		match := rule.pattern.FindString(line)
		if match == "" {
			continue
		}

		// 验证匹配质量
		if !validateMatch(ruleName, match, line) {
			continue
		}

		content := truncate(match, 80)
		key := path + ":" + ruleName
		if !isDuplicate("content", key) {
			atomic.AddUint64(&contentHits, 1)
			globalReporter.PrintFinding(ruleName, ruleName, path, lineNum, content)
			matchedRules[ruleName] = struct{}{}
		}
	}
}

// Office 文档扫描
func scanOfficeFile(path, ext string) {
	var content string
	var err error

	switch ext {
	case ".docx":
		content, err = extractDocxText(path)
	case ".xlsx":
		content, err = extractXlsxText(path)
	case ".doc":
		content, err = extractDocText(path)
	case ".xls":
		content, err = extractXlsText(path)
	case ".pptx":
		content, err = extractPptxText(path)
	case ".ppt":
		content, err = extractStringsFromBinary(path)
	}
	if err != nil || content == "" {
		return
	}

	lines := strings.Split(content, "\n")
	if len(lines) == 1 && len(content) > 500 {
		lines = splitByLength(content, 500)
	}

	matchedRules := make(map[string]struct{}, 8)
	for lineNum, line := range lines {
		if len(line) < 8 || len(line) > maxLineLen {
			continue
		}
		if !keywordMatcher.ContainsAny(line) {
			continue
		}
		scanLineWithRules(path, line, lineNum+1, matchedRules)
	}
}

// extractPptxText 从 .pptx 文件提取文本
func extractPptxText(path string) (string, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return "", err
	}
	defer r.Close()

	var content strings.Builder
	for _, f := range r.File {
		// PPT 幻灯片在 ppt/slides/slide*.xml
		if strings.HasPrefix(f.Name, "ppt/slides/slide") && strings.HasSuffix(f.Name, ".xml") {
			rc, err := f.Open()
			if err != nil {
				continue
			}
			data, err := io.ReadAll(io.LimitReader(rc, 2*1024*1024))
			rc.Close()
			if err != nil {
				continue
			}
			content.WriteString(extractXMLText(data))
			content.WriteByte('\n')
		}
	}
	return content.String(), nil
}

func splitByLength(s string, maxLen int) []string {
	var result []string
	for len(s) > maxLen {
		result = append(result, s[:maxLen])
		s = s[maxLen:]
	}
	if len(s) > 0 {
		result = append(result, s)
	}
	return result
}

// 二进制文件魔数检测表
var binaryMagics = [][]byte{
	{0x7F, 'E', 'L', 'F'},       // ELF
	{0xCA, 0xFE, 0xBA, 0xBE},    // Mach-O Fat
	{0xCF, 0xFA, 0xED, 0xFE},    // Mach-O 64
	{0xCE, 0xFA, 0xED, 0xFE},    // Mach-O 32
	{0x4D, 0x5A},                // PE/EXE
	{0x50, 0x4B, 0x03, 0x04},    // ZIP
	{0x1F, 0x8B},                // GZIP
	{0x52, 0x61, 0x72, 0x21},    // RAR
	{0x89, 'P', 'N', 'G'},       // PNG
	{0xFF, 0xD8, 0xFF},          // JPEG
	{0x47, 0x49, 'F', '8'},      // GIF
	{0x25, 0x50, 0x44, 0x46},    // PDF
	{0x00, 0x00, 0x00},          // MP4/MOV
	{0x49, 0x44, 0x33},          // MP3
	{0x66, 0x4C, 0x61, 0x43},    // FLAC
	{0x52, 0x49, 0x46, 0x46},    // WAV/AVI
}

func isBinaryFile(header []byte) bool {
	if len(header) < 4 {
		return false
	}

	// 快速魔数检测
	for _, magic := range binaryMagics {
		if len(header) >= len(magic) {
			match := true
			for i, b := range magic {
				if header[i] != b {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
	}

	// 检查非打印字符比例 (优化版)
	checkLen := len(header)
	if checkLen > 256 {
		checkLen = 256
	}

	nonPrintable := 0
	threshold := checkLen / 8 // 12.5% 阈值

	for i := 0; i < checkLen; i++ {
		b := header[i]
		if b == 0 || (b < 32 && b != '\n' && b != '\r' && b != '\t') {
			nonPrintable++
			if nonPrintable > threshold {
				return true
			}
		}
	}
	return false
}

// 误报关键词 AC 匹配器
var falsePositivesMatcher *AhoCorasick

func init() {
	falsePositivesMatcher = NewAhoCorasick([]string{
		"example", "sample", "test", "demo", "placeholder",
		"your_", "xxx", "yyy", "fake", "dummy", "@example.com",
		"<password>", "${password}", "{{password}}", "%password%",
		"password_field", "password_hash", "password_input",
		"getpassword", "setpassword", "checkpassword", "validatepassword",
		"passwordencoder", "passwordvalidator", "passwordpolicy",
		"todo", "fixme", "null", "none", "undefined", "n/a",
	})
}

// 验证匹配质量 (优化版)
func validateMatch(rule, match, line string) bool {
	// 快速误报检测
	if falsePositivesMatcher.ContainsAny(match) {
		return false
	}

	// 提取值部分
	value := extractValue(match)
	if value == "" {
		if rule == "PrivateKey" || rule == "PGPKey" {
			return true
		}
	}

	// 规则特定验证
	switch rule {
	case "Password", "Secret", "Token", "APIKey":
		if len(value) < 6 {
			return false
		}
		if isVariableReference(value) {
			return false
		}
		if rule == "Password" && len(value) >= 8 {
			if !quickEntropyCheck(value, 2.5) {
				return false
			}
		}
		if len(value) < 10 && (isAllDigits(value) || isAllSameCase(value)) {
			return false
		}

	case "AWSKey", "AliKey", "TencentKey", "GithubToken", "GitlabToken", "SlackToken", "StripeKey", "NPMToken":
		if !quickEntropyCheck(match, 3.0) {
			return false
		}

	case "JWT":
		dotCount := 0
		for i := 0; i < len(match); i++ {
			if match[i] == '.' {
				dotCount++
			}
		}
		if dotCount != 2 {
			return false
		}

	case "DBConnStr":
		hasAt := false
		hasHost := false
		for i := 0; i < len(match); i++ {
			if match[i] == '@' {
				hasAt = true
				break
			}
		}
		if !hasAt {
			hasHost = containsIgnoreCase(match, "host")
		}
		if !hasAt && !hasHost {
			return false
		}
	}

	// 代码上下文过滤
	if isCodeContext(line) && !isLikelyRealValue(value) {
		return false
	}

	return true
}

func extractValue(match string) string {
	// 尝试提取 = 或 : 后的值
	for _, sep := range []string{"=", ":", "：", " "} {
		if idx := strings.Index(match, sep); idx > 0 {
			val := strings.TrimSpace(match[idx+1:])
			val = strings.Trim(val, `'"`)
			return val
		}
	}
	return match
}

func isVariableReference(s string) bool {
	s = strings.TrimSpace(s)
	prefixes := []string{"$", "%", "{", "(", "ENV[", "os.getenv", "process.env"}
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func isAllDigits(s string) bool {
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func isAllSameCase(s string) bool {
	hasUpper, hasLower := false, false
	for _, r := range s {
		if unicode.IsUpper(r) {
			hasUpper = true
		}
		if unicode.IsLower(r) {
			hasLower = true
		}
	}
	return !(hasUpper && hasLower)
}

// 代码上下文 AC 匹配器
var codeContextMatcher *AhoCorasick

func init() {
	codeContextMatcher = NewAhoCorasick([]string{
		"func ", "def ", "function ", "class ", "import ", "package ",
		"return ", "if ", "for ", "while ", "switch ", "case ",
		"var ", "const ", "let ", "type ", "interface ", "struct ",
		"public ", "private ", "protected ", "static ",
		"fmt.", "log.", "print(", "console.", "system.",
		"append(", "make(", "new ", "delete ", "throw ",
		":= ", " = base64", " = md5", " = sha", " = hash",
		"encoding.", "crypto.", "[]byte(", "string(",
		"runlocalcmd", "runcmd", "exec(", "execute(",
	})
}

func isCodeContext(line string) bool {
	return codeContextMatcher.ContainsAny(line)
}

// 代码变量 AC 匹配器
var codeVarsMatcher *AhoCorasick

func init() {
	codeVarsMatcher = NewAhoCorasick([]string{
		"password", "passwd", "secret", "token", "rawpass",
		"userpass", "pass_", "_pass", "passphrase",
		"encoding", "decode", "encode", "hash", "base64",
		"stdencoding", "md5", "sha256", "sha1", "crypto",
		"encrypt", "decrypt", "cipher", "getpass", "setpass",
	})
}

func isLikelyRealValue(value string) bool {
	if len(value) < 4 {
		return false
	}

	// 快速检查是否是代码变量名
	if codeVarsMatcher.ContainsAny(value) {
		return false
	}

	// 真实值通常包含数字和字母混合
	hasDigit, hasLetter := false, false
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c >= '0' && c <= '9' {
			hasDigit = true
		} else if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			hasLetter = true
		}
		if hasDigit && hasLetter {
			return len(value) >= 6
		}
	}
	return hasDigit && hasLetter && len(value) >= 6
}

func contentWorker() {
	defer wg.Done()

	// 每个 worker 持有自己的规则 map 和缓冲区
	localMatchedRules := make(map[string]struct{}, 16)
	localBuf := make([]byte, readBufferSize)

	for path := range fileQueue {
		ext := strings.ToLower(filepath.Ext(path))

		// Office 文档使用特殊处理
		if officeExtensions[ext] {
			scanOfficeFile(path, ext)
		} else {
			// 普通文件扫描
			scanFileContentOptimized(path, localBuf, localMatchedRules)
		}

		// 清空 map 以复用
		for k := range localMatchedRules {
			delete(localMatchedRules, k)
		}
	}
}

// 快速文件扫描 - 一次性读取，避免多次系统调用
func scanFileContentOptimized(path string, buf []byte, matchedRules map[string]struct{}) {
	ext := strings.ToLower(filepath.Ext(path))

	// Office 文档特殊处理
	if officeExtensions[ext] {
		scanOfficeFile(path, ext)
		return
	}

	// 一次性读取整个文件（或前 512KB）
	file, err := os.Open(path)
	if err != nil {
		return
	}

	// 获取文件大小
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return
	}
	size := info.Size()
	if size == 0 {
		file.Close()
		return
	}

	// 限制读取大小（最多 512KB，敏感信息通常在前面）
	readSize := size
	const maxReadSize = 512 * 1024
	if readSize > maxReadSize {
		readSize = maxReadSize
	}

	// 一次性读取到缓冲区
	var data []byte
	if int(readSize) <= len(buf) {
		// 使用复用缓冲区
		n, err := io.ReadFull(file, buf[:readSize])
		file.Close()
		if err != nil && err != io.ErrUnexpectedEOF {
			return
		}
		data = buf[:n]
	} else {
		// 大文件分配新缓冲区
		data = make([]byte, readSize)
		n, err := io.ReadFull(file, data)
		file.Close()
		if err != nil && err != io.ErrUnexpectedEOF {
			return
		}
		data = data[:n]
	}

	// 检查是否二进制
	checkLen := len(data)
	if checkLen > 4096 {
		checkLen = 4096
	}
	if isBinaryFile(data[:checkLen]) {
		return
	}

	// 快速全文预筛选 - 如果整个文件没有关键字特征，直接跳过
	if !quickPreFilter(data) {
		return
	}
	if !keywordMatcher.ContainsAnyBytes(data) {
		return
	}

	// 扫描每一行
	lineNum := 0
	lineStart := 0
	maxLines := 5000 // 只扫描前 5000 行

	for i := 0; i < len(data) && lineNum < maxLines; i++ {
		if data[i] == '\n' {
			lineNum++
			lineEnd := i
			if lineEnd > lineStart && data[lineEnd-1] == '\r' {
				lineEnd--
			}

			line := data[lineStart:lineEnd]
			lineLen := len(line)

			if lineLen >= 8 && lineLen <= maxLineLen {
				// 极速预筛选
				if quickPreFilter(line) && keywordMatcher.ContainsAnyBytes(line) {
					lineStr := string(line)
					scanLineWithRules(path, lineStr, lineNum, matchedRules)
				}
			}

			lineStart = i + 1
		}
	}

	// 处理最后一行（如果没有换行符）
	if lineStart < len(data) && lineNum < maxLines {
		line := data[lineStart:]
		lineLen := len(line)
		if lineLen >= 8 && lineLen <= maxLineLen {
			if quickPreFilter(line) && keywordMatcher.ContainsAnyBytes(line) {
				lineStr := string(line)
				scanLineWithRules(path, lineStr, lineNum+1, matchedRules)
			}
		}
	}
}

// ==================== 进程扫描 ====================

func scanProcesses() {
	procs, _ := process.Processes()
	seen := make(map[string]struct{}, 32)

	for _, p := range procs {
		name, _ := p.Name()
		if name == "" {
			continue
		}
		cmdline, _ := p.Cmdline()
		target := name + " " + cmdline

		for desc, pattern := range interestingProcesses {
			key := desc + ":" + name
			if _, ok := seen[key]; ok {
				continue
			}
			if pattern.MatchString(target) {
				seen[key] = struct{}{}
				atomic.AddUint64(&processHits, 1)
				cmd := truncate(cmdline, 60)
				if cmd == "" {
					cmd = name
				}
				printSuccess("Process        %-20s  PID:%-6d  %s", magenta(desc), p.Pid, cmd)
				break
			}
		}
	}
}

// ==================== 网络扫描 ====================

func scanNetworkConnections() {
	conns, _ := psnet.Connections("all")

	suspiciousPorts := map[uint32]string{
		4444: "Metasploit", 5555: "ADB/RAT", 6666: "IRC/RAT",
		1080: "SOCKS", 3389: "RDP", 5900: "VNC",
		4443: "Meterpreter", 8080: "Proxy", 31337: "BackOrifice",
	}

	seen := make(map[string]struct{}, 16)

	for _, conn := range conns {
		if conn.Status == "LISTEN" {
			if desc, ok := suspiciousPorts[conn.Laddr.Port]; ok {
				key := fmt.Sprintf("listen:%d", conn.Laddr.Port)
				if _, exists := seen[key]; !exists {
					seen[key] = struct{}{}
					atomic.AddUint64(&networkHits, 1)
					printSuccess("NetListen      %-20s  0.0.0.0:%d", magenta(desc), conn.Laddr.Port)
				}
			}
		} else if conn.Status == "ESTABLISHED" && conn.Raddr.IP != "" {
			ip := conn.Raddr.IP
			if ip == "127.0.0.1" || ip == "::1" || strings.HasPrefix(ip, "192.168.") ||
				strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "172.") {
				continue
			}
			if desc, ok := suspiciousPorts[conn.Raddr.Port]; ok {
				key := fmt.Sprintf("conn:%s:%d", ip, conn.Raddr.Port)
				if _, exists := seen[key]; !exists {
					seen[key] = struct{}{}
					atomic.AddUint64(&networkHits, 1)
					printSuccess("NetConn        %-20s  -> %s:%d", magenta(desc), ip, conn.Raddr.Port)
				}
			}
		}
	}
}

// ==================== 凭证扫描 ====================

func scanCredentials() {
	usr, _ := user.Current()
	if usr == nil {
		return
	}
	home := usr.HomeDir

	// SSH
	sshKeys := []string{"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
	for _, key := range sshKeys {
		keyPath := filepath.Join(home, ".ssh", key)
		if _, err := os.Stat(keyPath); err == nil {
			atomic.AddUint64(&credentialHits, 1)
			printSuccess("SSHKey         %-20s  %s", magenta("PrivateKey"), keyPath)
		}
	}

	// Cloud
	cloudCreds := map[string]string{
		"AWS": filepath.Join(home, ".aws", "credentials"),
		"GCP": filepath.Join(home, ".config", "gcloud", "credentials.db"),
		"K8s": filepath.Join(home, ".kube", "config"),
	}
	for name, path := range cloudCreds {
		if _, err := os.Stat(path); err == nil {
			atomic.AddUint64(&credentialHits, 1)
			printSuccess("CloudCred      %-20s  %s", magenta(name), path)
		}
	}

	// Docker
	dockerConfig := filepath.Join(home, ".docker", "config.json")
	if content, err := os.ReadFile(dockerConfig); err == nil {
		if bytes.Contains(content, []byte("auth")) {
			atomic.AddUint64(&credentialHits, 1)
			printSuccess("CloudCred      %-20s  %s", magenta("Docker"), dockerConfig)
		}
	}

	// Git
	gitCreds := filepath.Join(home, ".git-credentials")
	if _, err := os.Stat(gitCreds); err == nil {
		atomic.AddUint64(&credentialHits, 1)
		printSuccess("GitCred        %-20s  %s", magenta("Credentials"), gitCreds)
	}
}

// ==================== Shell历史 ====================

func scanShellHistory() {
	usr, _ := user.Current()
	if usr == nil {
		return
	}
	home := usr.HomeDir

	historyFiles := []string{
		filepath.Join(home, ".bash_history"),
		filepath.Join(home, ".zsh_history"),
	}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(mysql|psql|mongo).*-p\s*['"]?[^\s'"]+`),
		regexp.MustCompile(`(?i)curl.*(-u|--user)\s+[^\s:]+:[^\s]+`),
		regexp.MustCompile(`(?i)sshpass\s+-p\s*['"]?[^\s'"]+`),
		regexp.MustCompile(`(?i)(export|set)\s+(PASSWORD|SECRET|TOKEN|API_KEY)=`),
	}

	for _, histFile := range historyFiles {
		func() {
			file, err := os.Open(histFile)
			if err != nil {
				return
			}
			defer file.Close()

			scanner := bufio.NewScanner(file)
			seen := make(map[uint64]struct{}, 64)

			for scanner.Scan() {
				line := scanner.Text()
				for _, pattern := range patterns {
					if pattern.MatchString(line) {
						hash := fnv1a(line)
						if _, exists := seen[hash]; exists {
							continue
						}
						seen[hash] = struct{}{}
						atomic.AddUint64(&credentialHits, 1)
						printSuccess("ShellHistory   %-20s  %s", magenta("SensitiveCmd"), truncate(line, 70))
						break
					}
				}
			}
		}()
	}
}

// ==================== 浏览器 ====================

func scanBrowserData() {
	usr, _ := user.Current()
	if usr == nil {
		return
	}
	home := usr.HomeDir

	browsers := map[string][]string{
		"Chrome": {
			filepath.Join(home, "Library/Application Support/Google/Chrome/Default/History"),
			filepath.Join(home, ".config/google-chrome/Default/History"),
			filepath.Join(home, "AppData/Local/Google/Chrome/User Data/Default/History"),
		},
		"Edge": {
			filepath.Join(home, "Library/Application Support/Microsoft Edge/Default/History"),
			filepath.Join(home, ".config/microsoft-edge/Default/History"),
			filepath.Join(home, "AppData/Local/Microsoft/Edge/User Data/Default/History"),
		},
	}

	for browser, paths := range browsers {
		for _, path := range paths {
			if _, err := os.Stat(path); os.IsNotExist(err) {
				continue
			}
			tmpPath := filepath.Join(os.TempDir(), fmt.Sprintf("xf_%d.db", time.Now().UnixNano()))
			if input, _ := os.ReadFile(path); len(input) > 0 {
				if os.WriteFile(tmpPath, input, 0644) == nil {
					scanBrowserHistory(browser, tmpPath)
					os.Remove(tmpPath)
				}
			}
			break
		}
	}
}

func scanBrowserHistory(browser, dbPath string) {
	db, err := sql.Open("sqlite3", dbPath+"?mode=ro")
	if err != nil {
		return
	}
	defer db.Close()

	query := `SELECT url FROM urls WHERE
		url LIKE '%admin%' OR url LIKE '%login%' OR url LIKE '%password%' OR
		url LIKE '%token%' OR url LIKE '%jenkins%' OR url LIKE '%gitlab%' OR
		url LIKE '%internal%' OR url LIKE '%vpn%' OR url LIKE '%console%'
		ORDER BY last_visit_time DESC LIMIT 20`

	rows, err := db.Query(query)
	if err != nil {
		return
	}
	defer rows.Close()

	seen := make(map[uint64]struct{}, 32)
	count := 0
	for rows.Next() {
		var url string
		if rows.Scan(&url) == nil {
			hash := fnv1a(url)
			if _, exists := seen[hash]; exists {
				continue
			}
			seen[hash] = struct{}{}
			count++
			atomic.AddUint64(&credentialHits, 1)
			// 使用 Reporter（会自动限制数量）
			globalReporter.PrintFinding("BrowserHist", browser, url, 0, truncate(url, 70))
		}
	}
}

// ==================== 环境变量 ====================

func scanEnvironment() {
	sensitiveKeys := []string{
		"PASSWORD", "SECRET", "TOKEN", "API_KEY", "APIKEY",
		"AWS_", "AZURE", "DATABASE_URL", "DB_PASS", "PRIVATE_KEY",
	}

	for _, env := range os.Environ() {
		idx := strings.Index(env, "=")
		if idx < 1 {
			continue
		}
		key, value := env[:idx], env[idx+1:]
		if len(value) < 8 {
			continue
		}

		keyUpper := strings.ToUpper(key)
		for _, sensitive := range sensitiveKeys {
			if strings.Contains(keyUpper, sensitive) {
				masked := value
				if len(value) > 12 {
					masked = value[:4] + "****" + value[len(value)-4:]
				}
				atomic.AddUint64(&credentialHits, 1)
				printSuccess("EnvVar         %-20s  %s=%s", magenta("Sensitive"), key, masked)
				break
			}
		}
	}
}

// ==================== Config ====================

// Config 扫描配置
type Config struct {
	TargetPath   string
	Workers      int
	StealthMs    int
	OutputPath   string
	OutputFormat string
	SkipSandbox  bool
	SkipDebug    bool
}

// parseConfig 解析命令行参数
func parseConfig() *Config {
	cfg := &Config{}

	flag.StringVar(&cfg.TargetPath, "p", "", "Target path (default: full disk)")
	flag.IntVar(&cfg.Workers, "w", runtime.NumCPU()*2, "Worker threads")
	flag.IntVar(&cfg.StealthMs, "s", 0, "Stealth delay (ms)")
	flag.StringVar(&cfg.OutputPath, "o", "xunfeng_report.txt", "Output file")
	flag.StringVar(&cfg.OutputFormat, "f", "txt", "Output format: txt, json, md")
	flag.BoolVar(&silent, "silent", false, "Silent mode")
	flag.BoolVar(&cfg.SkipSandbox, "skip-sandbox", false, "Skip sandbox check")
	flag.BoolVar(&cfg.SkipDebug, "skip-debug", false, "Skip debug check")
	flag.Parse()

	// 根据格式调整输出文件扩展名
	cfg.fixOutputExtension()

	return cfg
}

func (c *Config) fixOutputExtension() {
	if c.OutputFormat == "json" && !strings.HasSuffix(c.OutputPath, ".json") {
		c.OutputPath = strings.TrimSuffix(c.OutputPath, filepath.Ext(c.OutputPath)) + ".json"
	} else if c.OutputFormat == "md" && !strings.HasSuffix(c.OutputPath, ".md") {
		c.OutputPath = strings.TrimSuffix(c.OutputPath, filepath.Ext(c.OutputPath)) + ".md"
	}
}

// initScanner 初始化扫描器
func initScanner() {
	initCharMask()

	keywordMatcher = NewAhoCorasick([]string{
		"password", "passwd", "pwd", "secret", "token", "key", "api",
		"credential", "auth", "private", "jdbc", "mongodb", "redis",
		"mysql", "postgres", "密码", "口令", "账号", "BEGIN",
		"AKIA", "LTAI", "AKID", "ghp_", "gho_", "glpat-", "xox",
		"sk_live", "npm_", "eyJ", "bearer", "basic",
		"access", "connect", "database", "db_", "spring", "django",
		"laravel", "rails", "heroku", "sendgrid", "twilio", "stripe",
	})

	InitAllRules()
}

// checkEnvironment 检查运行环境
func checkEnvironment(cfg *Config) bool {
	if !cfg.SkipSandbox && checkSandbox() {
		printWarning("Sandbox detected, exiting...")
		return false
	}
	if !cfg.SkipDebug && antiDebug() {
		printWarning("Debugger detected, exiting...")
		return false
	}
	return true
}

// setupOutput 设置输出
func setupOutput(outputPath string) error {
	var err error
	outputFile, err = os.Create(outputPath)
	if err != nil {
		return err
	}
	outputWriter = bufio.NewWriterSize(outputFile, 256*1024)
	return nil
}

// resolveTargets 解析扫描目标
func resolveTargets(targetPath string) (roots []string, singleFile string) {
	if targetPath != "" {
		info, err := os.Stat(targetPath)
		if err != nil {
			printWarning("Cannot access target: %v", err)
			return nil, ""
		}
		if info.IsDir() {
			roots = []string{targetPath}
		} else {
			singleFile = targetPath
		}
		printInfo("Target: %s", targetPath)
	} else {
		switch runtime.GOOS {
		case "windows":
			for i := 'A'; i <= 'Z'; i++ {
				drive := string(i) + ":\\"
				if _, err := os.Stat(drive); err == nil {
					roots = append(roots, drive)
				}
			}
		default:
			roots = []string{"/"}
		}
		printInfo("Target: Full disk")
	}
	return roots, singleFile
}

// runQuickScans 运行快速扫描
func runQuickScans() {
	printSection("PROCESS SCAN")
	scanProcesses()

	printSection("NETWORK SCAN")
	scanNetworkConnections()

	printSection("CREDENTIAL SCAN")
	scanCredentials()

	printSection("ENVIRONMENT SCAN")
	scanEnvironment()

	printSection("SHELL HISTORY")
	scanShellHistory()

	printSection("BROWSER SCAN")
	scanBrowserData()
}

// runFileSystemScan 运行文件系统扫描
func runFileSystemScan(cfg *Config, roots []string, singleFile string) {
	printSection("FILESYSTEM SCAN")

	// 计算 worker 数量
	actualWorkers := cfg.Workers
	if actualWorkers < runtime.NumCPU() {
		actualWorkers = runtime.NumCPU()
	}
	contentWorkers := actualWorkers * 4
	if contentWorkers > 128 {
		contentWorkers = 128
	}

	fileQueue = make(chan string, contentWorkers*queueMultiple)

	wg.Add(contentWorkers)
	for i := 0; i < contentWorkers; i++ {
		go contentWorker()
	}

	wg.Add(1)
	go func() {
		if singleFile != "" {
			atomic.AddUint64(&scannedFiles, 1)
			fileQueue <- singleFile
		} else {
			discoverFiles(roots, cfg.StealthMs)
		}
		close(fileQueue)
		wg.Done()
	}()

	wg.Wait()
}

// printResults 打印结果
func printResults(cfg *Config, elapsed time.Duration) {
	printSection("SCAN COMPLETE")

	if !silent {
		fmt.Println()
		fmt.Printf("  %s Scanned:  %d files in %s\n", cyan("│"), atomic.LoadUint64(&scannedFiles), elapsed.Round(time.Millisecond))
	}

	globalReporter.PrintSummary()

	if err := globalReporter.GenerateReport(cfg.OutputPath, cfg.OutputFormat, elapsed); err != nil {
		printWarning("Failed to save report: %v", err)
	} else if !silent {
		fmt.Println()
		fmt.Printf("  %s Report saved: %s\n", green("►"), cfg.OutputPath)
	}
}

// ==================== Main ====================

func main() {
	cfg := parseConfig()

	initScanner()
	printBanner()

	if !checkEnvironment(cfg) {
		return
	}

	if err := setupOutput(cfg.OutputPath); err != nil {
		fmt.Printf("[!] Failed to create output: %v\n", err)
		return
	}
	defer outputFile.Close()
	defer func() {
		flushOutput()
		outputWriter.Flush()
	}()

	initExclusions()

	roots, singleFile := resolveTargets(cfg.TargetPath)
	if roots == nil && singleFile == "" && cfg.TargetPath != "" {
		return
	}

	printInfo("Workers: %d | Stealth: %dms | Output: %s", cfg.Workers, cfg.StealthMs, cfg.OutputPath)

	startTime := time.Now()

	runQuickScans()
	runFileSystemScan(cfg, roots, singleFile)

	printResults(cfg, time.Since(startTime))
}
