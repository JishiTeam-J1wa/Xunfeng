package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// 风险等级
type Severity int

const (
	SeverityCritical Severity = iota
	SeverityHigh
	SeverityMedium
	SeverityLow
	SeverityInfo
)

func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "CRITICAL"
	case SeverityHigh:
		return "HIGH"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityLow:
		return "LOW"
	default:
		return "INFO"
	}
}

func (s Severity) Color() func(a ...interface{}) string {
	switch s {
	case SeverityCritical:
		return red
	case SeverityHigh:
		return magenta
	case SeverityMedium:
		return yellow
	case SeverityLow:
		return cyan
	default:
		return white
	}
}

// Finding 发现结果
type Finding struct {
	Category    string    `json:"category"`
	Severity    Severity  `json:"severity"`
	Title       string    `json:"title"`
	Path        string    `json:"path,omitempty"`
	Line        int       `json:"line,omitempty"`
	Match       string    `json:"match,omitempty"`
	Description string    `json:"description,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

// Reporter 报告生成器
type Reporter struct {
	mu       sync.Mutex
	findings []Finding
	counts   map[string]int
	maxPerCategory map[string]int
}

// NewReporter 创建新的报告生成器
func NewReporter() *Reporter {
	return &Reporter{
		findings: make([]Finding, 0, 1000),
		counts:   make(map[string]int),
		maxPerCategory: map[string]int{
			"BrowserHist":    10,
			"ShellHistory":   20,
			"EnvVar":         10,
			"IPAddr":         50,
			"URL":            50,
			"Email":          20,
			"WeakPassword":        30,
			"CredentialPair":      50,
			"WritableDirCritical": 10,
			"WritableDirHigh":     30,
			"WritableDirMedium":   30,
			"WritableDirLow":      20,
		},
	}
}

var globalReporter = NewReporter()

// 类别到严重程度的映射
var categorySeverity = map[string]Severity{
	// Critical - 直接可利用 / 恶意进程
	"PrivateKey":     SeverityCritical,
	"AWSKey":         SeverityCritical,
	"AWSSecret":      SeverityCritical,
	"GithubToken":    SeverityCritical,
	"GitlabToken":    SeverityCritical,
	"SSHKey":         SeverityCritical,
	"DBConnStr":      SeverityCritical,
	"MalwareProc":    SeverityCritical,
	"StealerProc":    SeverityCritical,
	"C2Proc":         SeverityCritical,
	"CredentialTool": SeverityCritical,

	// High - 敏感凭证 / 渗透工具
	"Password":        SeverityHigh,
	"Secret":          SeverityHigh,
	"Token":           SeverityHigh,
	"APIKey":          SeverityHigh,
	"AliKey":          SeverityHigh,
	"TencentKey":      SeverityHigh,
	"CloudCred":       SeverityHigh,
	"DBPassword":      SeverityHigh,
	"JWT":             SeverityHigh,
	"PentestTool":     SeverityHigh,
	"CredentialPair":  SeverityHigh,
	"WeakPassword":    SeverityMedium,
	"Email":           SeverityInfo,

	// Medium - 配置/凭证文件
	"SensitiveFile": SeverityMedium,
	"HighValue":     SeverityMedium,
	"CNPassword":    SeverityMedium,
	"CNDatabase":    SeverityMedium,
	"GitCred":       SeverityMedium,
	"DjangoSecret":  SeverityMedium,
	"LaravelKey":    SeverityMedium,
	"VPNConfig":     SeverityMedium,
	"ProxyConfig":   SeverityMedium,

	// Low - 可能有用的信息
	"SensitiveExt":        SeverityLow,
	"Process":             SeverityLow,
	"NetListen":           SeverityLow,
	"NetConn":             SeverityLow,
	"ShellHistory":        SeverityLow,
	"ProxyTool":           SeverityLow,
	"RemoteTool":          SeverityLow,
	"Security":            SeverityLow,
	"AV":                  SeverityLow,
	"EDR":                 SeverityLow,
	"EPP":                 SeverityLow,
	"Firewall/CloudSec":   SeverityLow,
	"Telemetry":           SeverityLow,
	"Agent/Monitor":       SeverityLow,
	"ZTNA":                SeverityLow,
	"SIEM-EDR":            SeverityLow,
	"Vuln Scanner":        SeverityLow,
	"DFIR":                SeverityLow,
	"IntranetInfo":        SeverityLow,
	"OnboardingDoc":       SeverityLow,
	"ManualDoc":           SeverityLow,
	"IPAddr":              SeverityInfo,
	"URL":                 SeverityInfo,
	"YaraRule":            SeverityMedium,

	// Info - 信息收集
	"BrowserHist":   SeverityInfo,
	"EnvVar":        SeverityInfo,
	"YaraProc":      SeverityHigh,

	// Writable directories - 可写可执行目录风险
	"WritableDirCritical": SeverityCritical,
	"WritableDirHigh":     SeverityHigh,
	"WritableDirMedium":   SeverityMedium,
	"WritableDirLow":      SeverityLow,
}

func getSeverity(category string) Severity {
	if s, ok := categorySeverity[category]; ok {
		return s
	}
	return SeverityInfo
}

// AddFinding 添加发现（同时写入实时日志）
func (r *Reporter) AddFinding(category, title, path string, line int, match string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// 检查是否超过限制
	if max, ok := r.maxPerCategory[category]; ok {
		if r.counts[category] >= max {
			return
		}
	}

	r.counts[category]++

	finding := Finding{
		Category:  category,
		Severity:  getSeverity(category),
		Title:     title,
		Path:      path,
		Line:      line,
		Match:     match,
		Timestamp: time.Now(),
	}

	r.findings = append(r.findings, finding)
}

// PrintFinding 打印发现（带颜色）
func (r *Reporter) PrintFinding(category, title, path string, line int, match string) {
	severity := getSeverity(category)
	colorFn := severity.Color()

	// 检查限制
	r.mu.Lock()
	if max, ok := r.maxPerCategory[category]; ok {
		count := r.counts[category]
		if count >= max {
			if count == max {
				r.counts[category]++
				r.mu.Unlock()
				if !silent {
					consolePrintf("[%s] %s ... (more results hidden)", yellow("!"), category)
				}
				return
			}
			r.mu.Unlock()
			return
		}
	}
	r.mu.Unlock()

	r.AddFinding(category, title, path, line, match)

	if silent {
		return
	}

	// 格式化路径
	displayPath := formatPath(path, 50)

	// 格式化匹配内容
	displayMatch := ""
	if match != "" {
		displayMatch = truncate(match, 60)
	}

	// 输出格式：[严重程度] 类别  路径:行号  匹配内容
	sevStr := fmt.Sprintf("%-8s", severity.String())

	if line > 0 {
		consolePrintf("[%s] %-14s  %s:%d  %s",
			colorFn(sevStr[:4]),
			category,
			displayPath,
			line,
			cyan(displayMatch))
	} else if match != "" {
		consolePrintf("[%s] %-14s  %-50s  %s",
			colorFn(sevStr[:4]),
			category,
			displayPath,
			cyan(displayMatch))
	} else {
		consolePrintf("[%s] %-14s  %s",
			colorFn(sevStr[:4]),
			category,
			displayPath)
	}
	// 确保内容扫描等通过 PrintFinding 上报的发现也落入实时日志
	writeLiveLog(fmt.Sprintf("[%s] %s %s %d %s", severity.String(), category, path, line, match))
}

// formatPath 格式化路径显示 (UTF-8 安全)
func formatPath(path string, maxLen int) string {
	if maxLen < 20 {
		maxLen = 20
	}
	runes := []rune(path)
	if len(runes) <= maxLen {
		return path
	}

	// 按字符（rune）截断，保留开头和结尾
	half := (maxLen - 3) / 2
	if half < 5 {
		half = 5
	}
	return string(runes[:half]) + "..." + string(runes[len(runes)-half:])
}

// GenerateReport 生成报告
func (r *Reporter) GenerateReport(outputPath string, format string, scanTime time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	switch format {
	case "json":
		return r.generateJSON(outputPath, scanTime)
	case "md", "markdown":
		return r.generateMarkdown(outputPath, scanTime)
	default:
		return r.generateText(outputPath, scanTime)
	}
}

func (r *Reporter) generateText(outputPath string, scanTime time.Duration) error {
	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	// 标题
	fmt.Fprintf(f, "╔══════════════════════════════════════════════════════════════════╗\n")
	fmt.Fprintf(f, "║                    XUNFENG SCAN REPORT                           ║\n")
	fmt.Fprintf(f, "║                    J4Team Security Scanner                       ║\n")
	fmt.Fprintf(f, "╚══════════════════════════════════════════════════════════════════╝\n\n")

	fmt.Fprintf(f, "Scan Time: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(f, "Duration:  %s\n", scanTime.Round(time.Millisecond))
	fmt.Fprintf(f, "Findings:  %d\n\n", len(r.findings))

	// 按严重程度统计
	fmt.Fprintf(f, "┌─────────────────────────────────────────────────────────────────┐\n")
	fmt.Fprintf(f, "│                        SUMMARY                                  │\n")
	fmt.Fprintf(f, "├─────────────────────────────────────────────────────────────────┤\n")

	severityCounts := make(map[Severity]int)
	for _, finding := range r.findings {
		severityCounts[finding.Severity]++
	}

	fmt.Fprintf(f, "│  %-12s  %d\n", "CRITICAL:", severityCounts[SeverityCritical])
	fmt.Fprintf(f, "│  %-12s  %d\n", "HIGH:", severityCounts[SeverityHigh])
	fmt.Fprintf(f, "│  %-12s  %d\n", "MEDIUM:", severityCounts[SeverityMedium])
	fmt.Fprintf(f, "│  %-12s  %d\n", "LOW:", severityCounts[SeverityLow])
	fmt.Fprintf(f, "│  %-12s  %d\n", "INFO:", severityCounts[SeverityInfo])
	fmt.Fprintf(f, "└─────────────────────────────────────────────────────────────────┘\n\n")

	// 按严重程度排序
	sort.Slice(r.findings, func(i, j int) bool {
		if r.findings[i].Severity != r.findings[j].Severity {
			return r.findings[i].Severity < r.findings[j].Severity
		}
		return r.findings[i].Category < r.findings[j].Category
	})

	// 输出详细结果
	currentSeverity := Severity(-1)
	for _, finding := range r.findings {
		if finding.Severity != currentSeverity {
			currentSeverity = finding.Severity
			fmt.Fprintf(f, "\n══════════════════════════════════════════════════════════════════\n")
			fmt.Fprintf(f, "  %s FINDINGS\n", finding.Severity.String())
			fmt.Fprintf(f, "══════════════════════════════════════════════════════════════════\n\n")
		}

		fmt.Fprintf(f, "[%s] %s\n", finding.Category, finding.Title)
		if finding.Path != "" {
			if finding.Line > 0 {
				fmt.Fprintf(f, "    Path: %s:%d\n", finding.Path, finding.Line)
			} else {
				fmt.Fprintf(f, "    Path: %s\n", finding.Path)
			}
		}
		if finding.Match != "" {
			fmt.Fprintf(f, "    Match: %s\n", finding.Match)
		}
		fmt.Fprintf(f, "\n")
	}

	return nil
}

func (r *Reporter) generateJSON(outputPath string, scanTime time.Duration) error {
	report := struct {
		ScanTime  string    `json:"scan_time"`
		Duration  string    `json:"duration"`
		Summary   map[string]int `json:"summary"`
		Findings  []Finding `json:"findings"`
	}{
		ScanTime: time.Now().Format(time.RFC3339),
		Duration: scanTime.String(),
		Summary:  make(map[string]int),
		Findings: r.findings,
	}

	for _, f := range r.findings {
		report.Summary[f.Severity.String()]++
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(outputPath, data, 0644)
}

func (r *Reporter) generateMarkdown(outputPath string, scanTime time.Duration) error {
	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	// 统计各级别数量
	severityCounts := make(map[Severity]int)
	for _, finding := range r.findings {
		severityCounts[finding.Severity]++
	}

	// 计算重要发现数量（不包括 INFO）
	importantCount := severityCounts[SeverityCritical] + severityCounts[SeverityHigh] +
		severityCounts[SeverityMedium] + severityCounts[SeverityLow]

	// 标题和元信息
	fmt.Fprintf(f, "# 🔍 XunFeng 敏感信息扫描报告\n\n")
	fmt.Fprintf(f, "```\n")
	fmt.Fprintf(f, "扫描时间: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(f, "扫描耗时: %s\n", scanTime.Round(time.Millisecond))
	fmt.Fprintf(f, "发现总数: %d 个敏感信息\n", importantCount)
	fmt.Fprintf(f, "```\n\n")

	// 风险摘要 - 紧凑版
	fmt.Fprintf(f, "## 📊 风险概览\n\n")
	fmt.Fprintf(f, "| 等级 | 数量 | 类型 |\n")
	fmt.Fprintf(f, "|:----:|:----:|:-----|\n")

	if c := severityCounts[SeverityCritical]; c > 0 {
		fmt.Fprintf(f, "| 🔴 严重 | **%d** | 私钥 / DB连接串 / 云密钥 |\n", c)
	}
	if c := severityCounts[SeverityHigh]; c > 0 {
		fmt.Fprintf(f, "| 🟠 高危 | **%d** | 密码 / Token / API Key |\n", c)
	}
	if c := severityCounts[SeverityMedium]; c > 0 {
		fmt.Fprintf(f, "| 🟡 中危 | **%d** | 配置文件 / 中文凭证 |\n", c)
	}
	if c := severityCounts[SeverityLow]; c > 0 {
		fmt.Fprintf(f, "| 🔵 低危 | **%d** | 敏感文件 / 进程信息 |\n", c)
	}

	fmt.Fprintf(f, "\n---\n\n")

	// 敏感发现详情 - 使用表格，更紧凑
	for _, sev := range []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow} {
		findings := make([]Finding, 0)
		for _, finding := range r.findings {
			if finding.Severity == sev {
				findings = append(findings, finding)
			}
		}

		if len(findings) == 0 {
			continue
		}

		sevEmoji := map[Severity]string{
			SeverityCritical: "🔴",
			SeverityHigh:     "🟠",
			SeverityMedium:   "🟡",
			SeverityLow:      "🔵",
		}
		sevName := map[Severity]string{
			SeverityCritical: "严重",
			SeverityHigh:     "高危",
			SeverityMedium:   "中危",
			SeverityLow:      "低危",
		}

		fmt.Fprintf(f, "## %s %s风险 (%d)\n\n", sevEmoji[sev], sevName[sev], len(findings))
		fmt.Fprintf(f, "| # | 类型 | 文件位置 | 敏感内容 |\n")
		fmt.Fprintf(f, "|:-:|:----:|:---------|:---------|\n")

		for i, finding := range findings {
			// 格式化路径 (UTF-8 安全)
			path := finding.Path
			if finding.Line > 0 {
				path = fmt.Sprintf("%s:%d", path, finding.Line)
			}
			pathRunes := []rune(path)
			if len(pathRunes) > 50 {
				path = "..." + string(pathRunes[len(pathRunes)-47:])
			}

			// 格式化匹配内容 (UTF-8 安全)
			match := strings.ReplaceAll(finding.Match, "|", "\\|")
			match = strings.ReplaceAll(match, "`", "'")
			matchRunes := []rune(match)
			if len(matchRunes) > 45 {
				match = string(matchRunes[:42]) + "..."
			}

			fmt.Fprintf(f, "| %d | %s | `%s` | `%s` |\n",
				i+1, finding.Category, path, match)
		}
		fmt.Fprintf(f, "\n")
	}

	// INFO 级别 - 折叠
	if infoCount := severityCounts[SeverityInfo]; infoCount > 0 {
		fmt.Fprintf(f, "---\n\n")
		fmt.Fprintf(f, "<details>\n<summary>📋 <b>信息收集</b> (%d 条) - 点击展开</summary>\n\n", infoCount)
		fmt.Fprintf(f, "| 类型 | 内容 |\n")
		fmt.Fprintf(f, "|:----:|:-----|\n")

		for _, finding := range r.findings {
			if finding.Severity == SeverityInfo {
				match := truncate(finding.Match, 70)
				match = strings.ReplaceAll(match, "|", "\\|")
				fmt.Fprintf(f, "| %s | `%s` |\n", finding.Category, match)
			}
		}
		fmt.Fprintf(f, "\n</details>\n")
	}

	// 页脚
	fmt.Fprintf(f, "\n---\n\n")
	fmt.Fprintf(f, "<p align=\"center\">\n")
	fmt.Fprintf(f, "  <i>Generated by XunFeng v3.0 | J4Team Security Scanner</i>\n")
	fmt.Fprintf(f, "</p>\n")

	return nil
}

// PrintSummary 打印总结
func (r *Reporter) PrintSummary() {
	if silent {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	severityCounts := make(map[Severity]int)
	for _, finding := range r.findings {
		severityCounts[finding.Severity]++
	}

	// 计算重要发现（不包括 INFO）
	importantCount := severityCounts[SeverityCritical] + severityCounts[SeverityHigh] +
		severityCounts[SeverityMedium] + severityCounts[SeverityLow]

	consolePrint("")
	consolePrintf("  %s 敏感发现:", white("┌"))

	if c := severityCounts[SeverityCritical]; c > 0 {
		consolePrintf("  %s %s  %d (私钥/连接串/云密钥)", white("│"), red("严重:"), c)
	}
	if c := severityCounts[SeverityHigh]; c > 0 {
		consolePrintf("  %s %s  %d (密码/Token/APIKey)", white("│"), magenta("高危:"), c)
	}
	if c := severityCounts[SeverityMedium]; c > 0 {
		consolePrintf("  %s %s  %d (配置文件/中文密码)", white("│"), yellow("中危:"), c)
	}
	if c := severityCounts[SeverityLow]; c > 0 {
		consolePrintf("  %s %s  %d (敏感文件/进程)", white("│"), cyan("低危:"), c)
	}

	consolePrintf("  %s", white("├──────────────────────────"))
	consolePrintf("  %s 合计:  %s 个敏感发现", white("╰"), yellow(fmt.Sprintf("%d", importantCount)))

	// INFO 单独显示（如果有）
	if c := severityCounts[SeverityInfo]; c > 0 {
		consolePrintf("       %s (%d 条信息收集)", white("+ INFO"), c)
	}
}
