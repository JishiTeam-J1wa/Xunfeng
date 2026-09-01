package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
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
	"unicode/utf8"

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
	// Version 由编译时 ldflags 注入，例如 -X main.Version=3.0.0
	Version = "dev"

	outputFile   *os.File
	outputWriter *bufio.Writer

	// 统计计数器
	scannedFiles   uint64
	totalFindings  uint64
	contentHits    uint64
	fileHits       uint64
	processHits    uint64
	networkHits    uint64
	credentialHits uint64

	// 并发
	fileQueue chan fileJob
	wg        sync.WaitGroup
)

// 文件任务（携带已计算好的扩展名，避免 worker 重复计算）
type fileJob struct {
	path string
	ext  string
}

var (
	// 分片去重 (减少锁竞争)
	seenShards [shardCount]struct {
		sync.RWMutex
		m map[uint64]struct{}
	}

	// 排除目录 (使用数组加速小集合查找)
	// 默认不按目录名排除任何位置：node_modules/.git/tmp/logs 等都可能含有
	// 高价值数据或攻击者驻留痕迹。如需排除请自行用 -p 限定扫描范围。
	excludedDirsList = []string{}
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
	chars := "pPsStTkKaAcCjJmMrRbBeEgGhHfFvVnNxXyYuUlLiIoO密口账数"
	for _, c := range chars {
		if c < 256 {
			sensitiveCharMask[byte(c)] = true
			continue
		}
		// 中文字符需要把 UTF-8 每个字节都加入掩码，否则纯中文敏感行会被预筛选直接丢弃
		var buf [utf8.UTFMax]byte
		n := utf8.EncodeRune(buf[:], c)
		for i := 0; i < n; i++ {
			sensitiveCharMask[buf[i]] = true
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

// printSystemInfo 在启动时展示当前环境和权限信息
func printSystemInfo() {
	if silent {
		return
	}

	usr, _ := user.Current()
	username := "unknown"
	if usr != nil {
		username = usr.Username
	}

	privilege := "普通用户"
	if isPrivileged() {
		privilege = green("管理员/ROOT")
	} else {
		privilege = yellow("普通用户")
	}

	hostname, _ := os.Hostname()

	consolePrint("")
	consolePrintf("%s %s %s", yellow("┌"), white("SYSTEM INFO"), yellow("───────────────────────────────┐"))
	consolePrintf("%s %-14s %s", yellow("│"), cyan("当前用户:"), username)
	consolePrintf("%s %-14s %s", yellow("│"), cyan("权限级别:"), privilege)
	consolePrintf("%s %-14s %s", yellow("│"), cyan("主机名:"), hostname)
	consolePrintf("%s %-14s %s", yellow("│"), cyan("操作系统:"), runtime.GOOS)

	// 网卡/IP
	ifaces, err := net.Interfaces()
	if err == nil {
		first := true
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok {
					ip := ipnet.IP
					if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
						continue
					}
					label := cyan("网卡/IP:")
					if first {
						first = false
					} else {
						label = cyan("            ")
					}
					consolePrintf("%s %-14s %s: %s", yellow("│"), label, iface.Name, ip.String())
				}
			}
		}
	}

	// 系统详细信息
	for _, line := range getSystemDetails() {
		consolePrintf("%s %-14s %s", yellow("│"), cyan(""), line)
	}

	consolePrintf("%s", yellow("└────────────────────────────────────────────┘"))
	consolePrint("")

	// 提权建议
	if !isPrivileged() {
		consolePrintf("%s %s %s", yellow("┌"), white("PRIVILEGE ESCALATION"), yellow("────────────────────────┐"))
		exploits := getPrivilegeEscalationExploits()
		if len(exploits) == 0 {
			consolePrintf("%s %s", yellow("│"), cyan("ℹ 未匹配到已知提权漏洞，建议运行 PEAS 工具进行自动化枚举"))
		} else {
			for _, exp := range exploits {
				consolePrintf("%s %s%s", yellow("│"), red("⚠ "), formatExploitShort(exp))
				writeLiveLog(fmt.Sprintf("[PRIVESC] %s", formatExploit(exp)))
			}
		}
		consolePrintf("%s %s", yellow("│"), cyan("ℹ 建议运行 winPEAS / Seatbelt / PrivescCheck / linPEAS 进行自动化枚举"))
		consolePrintf("%s", yellow("└────────────────────────────────────────────┘"))
		consolePrint("")
	}
}

// ==================== 隐匿性 ====================

func checkSandbox() bool {
	if runtime.NumCPU() < 2 {
		printWarning("Sandbox check triggered: CPU count < 2")
		return true
	}
	if v, _ := mem.VirtualMemory(); v != nil && v.Total < 2*1024*1024*1024 {
		printWarning("Sandbox check triggered: total RAM < 2GB")
		return true
	}
	// Windows 真实主机重启后也常出现较短 uptime，阈值从 600s 放宽到 120s，降低误报
	const minUptime = 120
	if uptime, _ := host.Uptime(); uptime > 0 && uptime < minUptime {
		printWarning("Sandbox check triggered: system uptime < %ds", minUptime)
		return true
	}
	if procs, _ := process.Processes(); len(procs) < 30 {
		printWarning("Sandbox check triggered: process count < 30")
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

// initExclusions 初始化目录排除规则。noDir 为 true 时不排除任何目录
// （完整扫描模式，包含 /proc /sys /dev 等伪文件系统）。
//
// 默认模式也只排除纯系统目录；用户数据目录（含其他用户家目录、
// node_modules/.git/tmp/logs 等）全部纳入扫描——其中常有高价值数据，
// 无权限的条目会在遍历时自然跳过，不会产生报错噪音。
func initExclusions(noDir bool) {
	if noDir {
		excludedDirs = make(map[string]struct{}, 0)
		excludedPaths = nil
		return
	}

	switch runtime.GOOS {
	case "darwin":
		excludedPaths = append(excludedPaths,
			"/System", "/Library",
			"/usr", "/bin", "/sbin", "/opt",
		)
	case "linux":
		excludedPaths = append(excludedPaths,
			"/proc", "/sys", "/dev", "/run", "/var/cache",
			"/usr", "/lib", "/lib64", "/bin", "/sbin", "/opt",
		)
	case "windows":
		sysRoot := os.Getenv("SystemRoot")
		if sysRoot == "" {
			sysRoot = `C:\Windows`
		}
		excludedPaths = append(excludedPaths,
			sysRoot,
			`C:\$Recycle.Bin`,
			`C:\Recovery`,
			`C:\Users\All Users`, // 联接点，指向 C:\ProgramData
			`C:\Users\Default`,   // 模板配置文件，无真实用户数据
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

	// 方法3: 从 OLE WordDocument 流提取文本
	if r, err := newOLEReader(path); err == nil {
		if stream, err := r.findStream("WordDocument"); err == nil && len(stream) > 0 {
			var result strings.Builder
			result.WriteString(extractASCIIStrings(stream, 5))
			result.WriteByte('\n')
			result.WriteString(extractUTF16LEStrings(stream, 3))
			return result.String(), nil
		}
	}
	// 方法4: 退回到原始字节提取
	return extractOfficeBinaryText(path)
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

	// 方法3: 从 OLE Workbook 流解析 BIFF 提取单元格文本
	if r, err := newOLEReader(path); err == nil {
		if stream, err := r.findStream("Workbook"); err == nil && len(stream) > 0 {
			var result strings.Builder
			result.WriteString(extractBiffText(stream))
			result.WriteByte('\n')
			result.WriteString(extractASCIIStrings(stream, 6))
			result.WriteByte('\n')
			result.WriteString(extractUTF16LEStrings(stream, 4))
			return result.String(), nil
		}
	}
	// 方法4: 退回到原始字节提取
	return extractOfficeBinaryText(path)
}

// extractPptText 从旧版 .ppt 文件提取文本
func extractPptText(path string) (string, error) {
	// 从 OLE PowerPoint Document 流解析文本记录
	if r, err := newOLEReader(path); err == nil {
		if stream, err := r.findStream("PowerPoint Document"); err == nil && len(stream) > 0 {
			var result strings.Builder
			result.WriteString(extractASCIIStrings(stream, 5))
			result.WriteByte('\n')
			result.WriteString(extractUTF16LEStrings(stream, 3))
			result.WriteByte('\n')
			result.WriteString(extractPPTTextRecords(stream))
			return result.String(), nil
		}
	}
	// 退回到原始字节提取
	return extractOfficeBinaryText(path)
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

	return extractASCIIStrings(data, 6), nil
}

// extractASCIIStrings 从字节流中提取可打印 ASCII / UTF-8 字符串
func extractASCIIStrings(data []byte, minLen int) string {
	var result strings.Builder
	var current strings.Builder

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

	if current.Len() >= minLen {
		result.WriteString(current.String())
	}

	return result.String()
}

// isPrintableBMP 判断 UTF-16 码点是否为可打印 BMP 字符
func isPrintableBMP(r rune) bool {
	// 控制字符跳过
	if r < 0x20 {
		return false
	}
	// BMP 私有区、代理区、特殊控制区跳过
	if r >= 0xD800 && r <= 0xDFFF {
		return false
	}
	if r >= 0xE000 && r <= 0xF8FF {
		return false
	}
	if r == 0xFFFE || r == 0xFFFF {
		return false
	}
	return r <= 0xFFFD
}

// extractUTF16LEStrings 从字节流中提取 UTF-16LE 可打印字符串
// Office 旧版 .doc/.xls/.ppt 中大量文本以 UTF-16LE 存储
func extractUTF16LEStrings(data []byte, minLen int) string {
	var result strings.Builder
	var current strings.Builder

	for i := 0; i+1 < len(data); i += 2 {
		low := data[i]
		high := data[i+1]
		code := uint16(low) | uint16(high)<<8

		if isPrintableBMP(rune(code)) {
			current.WriteRune(rune(code))
		} else {
			if current.Len() >= minLen {
				result.WriteString(current.String())
				result.WriteByte('\n')
			}
			current.Reset()
		}
	}

	if current.Len() >= minLen {
		result.WriteString(current.String())
	}

	return result.String()
}

// extractPPTTextRecords 解析 PPT 二进制文件中的 TextCharsAtom(0x0FA0)/TextBytesAtom(0x0FA1)
func extractPPTTextRecords(data []byte) string {
	const (
		textCharsAtom  = 0x0FA0
		textBytesAtom  = 0x0FA1
	)
	var result strings.Builder

	// 遍历可能的记录头：RecordHeader = 2 bytes ver/instance + 2 bytes type + 4 bytes length
	for i := 0; i+8 <= len(data); i++ {
		recType := uint16(data[i+2]) | uint16(data[i+3])<<8
		recLen := uint32(data[i+4]) | uint32(data[i+5])<<8 | uint32(data[i+6])<<16 | uint32(data[i+7])<<24
		if recLen > 64*1024 || recLen == 0 {
			continue
		}
		end := i + 8 + int(recLen)
		if end > len(data) {
			continue
		}

		payload := data[i+8 : end]
		switch recType {
		case textCharsAtom:
			// UTF-16LE 文本
			result.WriteString(extractUTF16LEStrings(payload, 2))
		case textBytesAtom:
			// ASCII 文本
			result.WriteString(extractASCIIStrings(payload, 3))
		}
	}

	return result.String()
}

// extractOfficeBinaryText 综合提取 Office 二进制文件中的文本
// .doc/.xls/.ppt 等旧格式含有大量 UTF-16LE 字符串
func extractOfficeBinaryText(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	data := make([]byte, 8*1024*1024) // 最多 8MB
	n, err := file.Read(data)
	if err != nil && err != io.EOF {
		return "", err
	}
	if n == 0 {
		return "", nil
	}
	data = data[:n]

	var result strings.Builder
	result.Grow(n / 8)
	result.WriteString(extractASCIIStrings(data, 5))
	result.WriteByte('\n')
	result.WriteString(extractUTF16LEStrings(data, 3))

	// PPT 专门解析文本记录
	if len(data) > 8 && data[0] == 0xD0 && data[1] == 0xCF && data[2] == 0x11 && data[3] == 0xE0 {
		result.WriteByte('\n')
		result.WriteString(extractPPTTextRecords(data))
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

// countTargetFiles 预统计目标目录下会被文件系统扫描阶段处理的文件总数（用于稽核模式真实进度条）
func countTargetFiles(roots []string) uint64 {
	var total atomic.Uint64
	var wg sync.WaitGroup
	for _, root := range roots {
		wg.Add(1)
		go func(r string) {
			defer wg.Done()
			filepath.WalkDir(r, func(path string, d os.DirEntry, err error) error {
				if err != nil {
					return nil
				}
				name := d.Name()
				if d.IsDir() {
					if _, skip := excludedDirs[name]; skip {
						return filepath.SkipDir
					}
					if isExcludedPath(path) {
						return filepath.SkipDir
					}
					return nil
				}
				if isExcludedPath(path) {
					return nil
				}
				total.Add(1)
				return nil
			})
		}(root)
	}
	wg.Wait()
	return total.Load()
}

func discoverFiles(roots []string, stealthMs int) {
	rand.Shuffle(len(roots), func(i, j int) { roots[i], roots[j] = roots[j], roots[i] })

	scanExts := buildScanExts()

	// 按根目录并发遍历：filepath.WalkDir 单线程效率很高，多个根/驱动器并行可提升整体吞吐
	var wg sync.WaitGroup
	for _, root := range roots {
		wg.Add(1)
		go func(r string) {
			defer wg.Done()
			filepath.WalkDir(r, func(path string, d os.DirEntry, err error) error {
				// 无权限/特殊文件节点直接跳过，避免 Windows 下偶发错误导致扫描中断
				if err != nil {
					return nil
				}

				if stealthMs > 0 {
					time.Sleep(time.Duration(stealthMs+rand.Intn(stealthMs/2+1)) * time.Millisecond)
				}

				name := d.Name()

				if d.IsDir() {
					if _, skip := excludedDirs[name]; skip {
						return filepath.SkipDir
					}
					if isExcludedPath(path) {
						return filepath.SkipDir
					}
					return nil
				}

				if isExcludedPath(path) {
					return nil
				}

				atomic.AddUint64(&scannedFiles, 1)
				processFileEntry(path, name, scanExts)
				return nil
			})
		}(root)
	}
	wg.Wait()
}

func buildScanExts() map[string]struct{} {
	scanExts := make(map[string]struct{}, 120)
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
	return scanExts
}

func isExcludedPath(path string) bool {
	for _, prefix := range excludedPaths {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func processFileEntry(path, name string, scanExts map[string]struct{}) {
	nameLower := toLowerASCII(name)

	// 快速获取扩展名
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

	// 文件名模糊匹配（vpn/代理/内网/入职/手册等敏感词）
	for _, pattern := range sensitiveFilenamePatterns {
		if strings.Contains(nameLower, pattern) {
			hash := fnv1a("filepattern:" + path)
			if !isDuplicateHash(hash) {
				atomic.AddUint64(&fileHits, 1)
				printSuccess("SensitiveFile  %-15s  %s", magenta(pattern), path)
			}
			break
		}
	}

	// 敏感扩展名 (不扫描内容，直接报告)
	if nonScanExtensions[ext] {
		hash := fnv1a("file:" + path)
		if !isDuplicateHash(hash) {
			atomic.AddUint64(&fileHits, 1)
			printSuccess("SensitiveExt   %-15s  %s", magenta(ext), path)
		}
		return
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
			return
		}
		fileQueue <- fileJob{path: path, ext: ext}
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
		content, err = extractPptText(path)
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

	// 补充模式扫描：IP、URL、凭据对、弱口令、邮箱
	scanContentPatterns(path, content)
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

	for job := range fileQueue {
		// Office 文档使用特殊处理
		if officeExtensions[job.ext] {
			scanOfficeFile(job.path, job.ext)
		} else {
			// 普通文件扫描
			scanFileContentOptimized(job.path, job.ext, localBuf, localMatchedRules)
		}

		// 可选的 YARA 特征扫描（仅启用 yara build tag 时生效）
		scanFileWithYara(job.path)

		// 清空 map 以复用
		for k := range localMatchedRules {
			delete(localMatchedRules, k)
		}
	}
}

// 快速文件扫描 - 一次性读取，避免多次系统调用
func scanFileContentOptimized(path, ext string, buf []byte, matchedRules map[string]struct{}) {
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

	// 补充模式扫描：IP、URL、凭据对、弱口令、邮箱（不依赖 keyword 预筛选）
	contentStr := string(data)
	scanContentPatterns(path, contentStr)

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

// cleanCmdlinePaths 把命令行中的完整路径替换成 basename，避免目录名里的工具名造成误报
var pathStripper = regexp.MustCompile(`(?i)(?:[A-Za-z]:\\[^ ]*\\|/[^ ]*/)([^ /\\]+)`)

func cleanCmdlinePaths(cmdline string) string {
	return pathStripper.ReplaceAllString(cmdline, "$1")
}

func scanProcesses() {
	procs, _ := process.Processes()
	seen := make(map[string]struct{}, 32)

	for _, p := range procs {
		name, _ := p.Name()
		if name == "" {
			continue
		}
		cmdline, _ := p.Cmdline()

		nameLower := strings.ToLower(name)
		cmdClean := cleanCmdlinePaths(cmdline)

		matched := false
		for desc, pattern := range interestingProcesses {
			key := desc + ":" + name
			if _, ok := seen[key]; ok {
				continue
			}

			// 默认只匹配进程名，避免命令行路径里的目录名造成误报
			// SSHTunnel 需要同时看命令行参数（ssh -R/-L/-D）
			target := nameLower
			if desc == "SSHTunnel" && cmdClean != "" {
				target = nameLower + " " + cmdClean
			}

			if pattern.MatchString(target) {
				seen[key] = struct{}{}
				atomic.AddUint64(&processHits, 1)
				cmd := truncate(cmdline, 60)
				if cmd == "" {
					cmd = name
				}
				printSuccess("Process        %-20s  PID:%-6d  %s", magenta(desc), p.Pid, cmd)
				cat := processSeverityMap[desc]
				if cat == "" {
					cat = "Process"
				}
				globalReporter.AddFinding(cat, desc, fmt.Sprintf("%s (PID:%d)", name, p.Pid), 0, cmd)
				matched = true
				break
			}
		}

		// 外部 JSON 规则（EDR/AV/安全产品等），避免与内置规则重复报告
		if matched {
			continue
		}
		for _, rule := range externalProcessRules {
			if rule.re == nil {
				continue
			}
			key := rule.Name + ":" + name
			if _, ok := seen[key]; ok {
				continue
			}
			if rule.re.MatchString(nameLower) {
				seen[key] = struct{}{}
				atomic.AddUint64(&processHits, 1)
				cmd := truncate(cmdline, 60)
				if cmd == "" {
					cmd = name
				}
				printSuccess("Process        %-20s  PID:%-6d  %s", magenta(rule.Name), p.Pid, cmd)
				cat := rule.Category
				if cat == "" {
					cat = "Process"
				}
				globalReporter.AddFinding(cat, rule.Name, fmt.Sprintf("%s (PID:%d)", name, p.Pid), 0, cmd)
				break
			}
		}

		// 可选的 YARA 进程内存扫描（仅启用 yara build tag 时生效）
		scanProcessWithYara(p.Pid, name)
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
	db, err := openSQLiteDB(dbPath + "?mode=ro")
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
	TargetPath    string
	Workers       int
	StealthMs     int
	OutputPath    string
	OutputFormat  string
	SkipSandbox   bool
	SkipDebug     bool
	YaraRulesPath string
	Jiwa          bool // 稽核模式：显示详细进度条和阶段信息
	NoDir         bool // 完整扫描模式：不排除任何目录
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
	flag.StringVar(&cfg.YaraRulesPath, "yara-rules", "", "YARA rule file/directory (requires yara build tag)")
	flag.BoolVar(&cfg.Jiwa, "jiwa", false, "稽核模式：显示详细进度条和阶段信息")
	flag.BoolVar(&cfg.NoDir, "nodir", false, "完整扫描：不排除任何目录")
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
func initScanner(cfg *Config) {
	initCharMask()

	keywordMatcher = NewAhoCorasick([]string{
		"password", "passwd", "pwd", "secret", "token", "key", "api",
		"credential", "auth", "private", "jdbc", "mongodb", "redis",
		"mysql", "postgres", "密码", "口令", "账号", "BEGIN",
		"AKIA", "LTAI", "AKID", "ghp_", "gho_", "glpat-", "xox",
		"sk_live", "npm_", "eyJ", "bearer", "basic",
		"access", "connect", "database", "db_", "spring", "django",
		"laravel", "rails", "heroku", "sendgrid", "twilio", "stripe",
		"admin", "root", "user", "guest", "manager", "operator",
		"http", "https", "ftp://", "://",
		"vpn", "proxy", "内网", "入职", "手册", "内部", "intranet", "tunnel",
		"绝密", "机密", "秘密", "保密", "涉密", "密级", "解密",
		"政务", "红头", "公文", "机关", "党委",
		"决策", "决议", "纪要", "批示", "常委",
	})

	InitAllRules()

	// 初始化可选的 YARA 引擎（仅在启用 yara build tag 且提供规则时工作）
	if err := initYaraScanner(cfg.YaraRulesPath); err != nil {
		printWarning("YARA init failed: %v", err)
	}
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
	// 同时初始化实时日志，崩溃时可恢复结果
	return setupLiveLog(outputPath)
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

	printSection("WRITABLE DIRECTORIES")
	scanWritableDirs()
}

// runFileSystemScan 运行文件系统扫描
func runFileSystemScan(cfg *Config, roots []string, singleFile string) {
	printSection("FILESYSTEM SCAN")

	// 计算 worker 数量
	actualWorkers := cfg.Workers
	if actualWorkers < runtime.NumCPU() {
		actualWorkers = runtime.NumCPU()
	}
	// 内容扫描以 CPU 为主，worker 数与逻辑核心数持平即可，避免过量上下文切换
	contentWorkers := actualWorkers
	if contentWorkers > 64 {
		contentWorkers = 64
	}

	fileQueue = make(chan fileJob, contentWorkers*queueMultiple)
	fileScanning.Store(true)
	defer fileScanning.Store(false)

	// 稽核模式：预统计文件总数，启用真实进度条
	if cfg.Jiwa && singleFile == "" {
		printInfo("Stage 1/2: Enumerating files...")
		totalFiles := countTargetFiles(roots)
		setTotalFilesForProgress(totalFiles)
		printInfo("Stage 2/2: Scanning %d files...", totalFiles)
	}

	// 进度条/实时状态 goroutine
	progressCtx, cancelProgress := context.WithCancel(context.Background())
	progressing.Store(true)
	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-progressCtx.Done():
				progressing.Store(false)
				return
			case <-ticker.C:
				if silent {
					continue
				}
				if jiwaMode.Load() {
					// 稽核模式下，只有完成预统计后才显示真实进度条
					if totalFilesForProgress.Load() > 0 {
						printProgressBar(atomic.LoadUint64(&scannedFiles), atomic.LoadUint64(&totalFindings))
					}
				} else {
					printProgress(atomic.LoadUint64(&scannedFiles), atomic.LoadUint64(&totalFindings))
				}
			}
		}
	}()

	wg.Add(contentWorkers)
	for i := 0; i < contentWorkers; i++ {
		go contentWorker()
	}

	wg.Add(1)
	go func() {
		if singleFile != "" {
			atomic.AddUint64(&scannedFiles, 1)
			fileQueue <- fileJob{path: singleFile, ext: strings.ToLower(filepath.Ext(singleFile))}
		} else {
			discoverFiles(roots, cfg.StealthMs)
		}
		close(fileQueue)
		wg.Done()
	}()

	wg.Wait()
	cancelProgress()
}

// printResults 打印结果
func printResults(cfg *Config, elapsed time.Duration) {
	progressing.Store(false)
	fileScanning.Store(false)
	// 清除最后一行进度条，避免与总结输出交错
	clearProgressBar()
	if !silent {
		stdoutMu.Lock()
		fmt.Fprint(stdoutWriter, "\r\033[K")
		stdoutWriter.Flush()
		stdoutMu.Unlock()
	}
	printSection("SCAN COMPLETE")

	if !silent {
		consolePrint("")
		consolePrintf("  %s Scanned:  %d files in %s", cyan("│"), atomic.LoadUint64(&scannedFiles), elapsed.Round(time.Millisecond))
	}

	globalReporter.PrintSummary()

	if err := globalReporter.GenerateReport(cfg.OutputPath, cfg.OutputFormat, elapsed); err != nil {
		printWarning("Failed to save report: %v", err)
	} else if !silent {
		consolePrint("")
		consolePrintf("  %s Report saved: %s", green("►"), cfg.OutputPath)
	}
	consoleFlush()
}

// runWithConfig 根据配置执行一次完整扫描
func runWithConfig(cfg *Config) error {
	// 启动后台终端刷新，避免每条消息都 flush 导致卡顿
	startConsoleWriter()

	initScanner(cfg)
	setJiwaMode(cfg.Jiwa)
	printBanner()
	printSystemInfo()

	if !checkEnvironment(cfg) {
		return fmt.Errorf("environment check failed")
	}

	if err := setupOutput(cfg.OutputPath); err != nil {
		return fmt.Errorf("failed to create output: %w", err)
	}
	defer outputFile.Close()
	defer func() {
		outputWriter.Flush()
		flushLiveLog()
	}()
	defer closeYaraScanner()

	initExclusions(cfg.NoDir)

	roots, singleFile := resolveTargets(cfg.TargetPath)
	if roots == nil && singleFile == "" && cfg.TargetPath != "" {
		return fmt.Errorf("cannot resolve target: %s", cfg.TargetPath)
	}

	if cfg.Jiwa {
		printInfo("Mode: 稽核检查 | Workers: %d | Output: %s", cfg.Workers, cfg.OutputPath)
	} else {
		printInfo("Workers: %d | Stealth: %dms | Output: %s", cfg.Workers, cfg.StealthMs, cfg.OutputPath)
	}

	startTime := time.Now()

	runQuickScans()
	runFileSystemScan(cfg, roots, singleFile)

	printResults(cfg, time.Since(startTime))
	return nil
}

// ==================== Main ====================

func main() {
	cfg := parseConfig()
	if err := runWithConfig(cfg); err != nil {
		fmt.Printf("[!] %v\n", err)
		os.Exit(1)
	}
}
