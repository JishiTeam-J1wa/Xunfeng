package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// ==================== Aho-Corasick 测试 ====================

func TestAhoCorasickBasic(t *testing.T) {
	ac := NewAhoCorasick([]string{"password", "secret", "token"})

	tests := []struct {
		input    string
		expected bool
	}{
		{"this has password in it", true},
		{"SECRET should match", true},
		{"no match here", false},
		{"TOKEN=abc123", true},
		{"pass word separated", false},
		{"", false},
	}

	for _, tt := range tests {
		got := ac.ContainsAny(tt.input)
		if got != tt.expected {
			t.Errorf("ContainsAny(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestAhoCorasickCaseInsensitive(t *testing.T) {
	ac := NewAhoCorasick([]string{"api_key", "mongodb"})

	tests := []struct {
		input    string
		expected bool
	}{
		{"API_KEY=xxx", true},
		{"Api_Key=xxx", true},
		{"api_key=xxx", true},
		{"MongoDB://localhost", true},
		{"MONGODB://localhost", true},
	}

	for _, tt := range tests {
		got := ac.ContainsAny(tt.input)
		if got != tt.expected {
			t.Errorf("ContainsAny(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestAhoCorasickChinese(t *testing.T) {
	ac := NewAhoCorasick([]string{"密码", "口令"})

	tests := []struct {
		input    string
		expected bool
	}{
		{"密码：Admin123", true},
		{"登录口令为xxx", true},
		{"普通文本", false},
	}

	for _, tt := range tests {
		got := ac.ContainsAny(tt.input)
		if got != tt.expected {
			t.Errorf("ContainsAny(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestAhoCorasickBytes(t *testing.T) {
	ac := NewAhoCorasick([]string{"jdbc:", "redis://"})

	tests := []struct {
		input    []byte
		expected bool
	}{
		{[]byte("jdbc:mysql://localhost"), true},
		{[]byte("redis://localhost:6379"), true},
		{[]byte("http://example.com"), false},
	}

	for _, tt := range tests {
		got := ac.ContainsAnyBytes(tt.input)
		if got != tt.expected {
			t.Errorf("ContainsAnyBytes(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

// ==================== 熵值计算测试 ====================

func TestCalculateEntropy(t *testing.T) {
	tests := []struct {
		input       string
		minEntropy  float64
		maxEntropy  float64
	}{
		{"aaaaaaaaaa", 0, 0.1},           // 低熵 (重复)
		{"abcdefghij", 3.0, 3.5},         // 高熵 (均匀分布)
		{"password123", 2.5, 3.5},        // 中等熵
		{"AKIAIOSFODNN7EXAMPLE", 3.0, 4.5}, // AWS Key 高熵
		{"", 0, 0},                        // 空字符串
	}

	for _, tt := range tests {
		got := calculateEntropy(tt.input)
		if got < tt.minEntropy || got > tt.maxEntropy {
			t.Errorf("calculateEntropy(%q) = %v, want in [%v, %v]",
				tt.input, got, tt.minEntropy, tt.maxEntropy)
		}
	}
}

func TestQuickEntropyCheck(t *testing.T) {
	tests := []struct {
		input     string
		threshold float64
		expected  bool
	}{
		{"aaaaaaaa", 3.0, false},           // 低熵
		{"abcdefghijklmnop", 3.0, true},    // 高熵
		{"short", 3.0, false},              // 太短
		{"ghp_abcdefghijklmnopqrstuvwxyz123456", 3.5, true}, // GitHub Token
	}

	for _, tt := range tests {
		got := quickEntropyCheck(tt.input, tt.threshold)
		if got != tt.expected {
			t.Errorf("quickEntropyCheck(%q, %v) = %v, want %v",
				tt.input, tt.threshold, got, tt.expected)
		}
	}
}

// ==================== 哈希和去重测试 ====================

func TestFnv1a(t *testing.T) {
	// 相同输入应该产生相同哈希
	h1 := fnv1a("test_string")
	h2 := fnv1a("test_string")
	if h1 != h2 {
		t.Errorf("fnv1a should be deterministic: %v != %v", h1, h2)
	}

	// 不同输入应该产生不同哈希
	h3 := fnv1a("different_string")
	if h1 == h3 {
		t.Errorf("fnv1a collision: %q and %q produced same hash", "test_string", "different_string")
	}
}

func TestIsDuplicate(t *testing.T) {
	// 重置分片
	for i := 0; i < shardCount; i++ {
		seenShards[i].m = make(map[uint64]struct{}, 256)
	}

	// 第一次应该返回 false
	if isDuplicate("test", "content1") {
		t.Error("First call should return false")
	}

	// 第二次应该返回 true
	if !isDuplicate("test", "content1") {
		t.Error("Second call should return true")
	}

	// 不同内容应该返回 false
	if isDuplicate("test", "content2") {
		t.Error("Different content should return false")
	}
}

// ==================== 字符串工具测试 ====================

func TestTruncate(t *testing.T) {
	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{"short", 10, "short"},
		{"this is a very long string", 10, "this is a ..."},
		{"  spaces  ", 5, "space..."},
		{"", 10, ""},
		{"中文测试字符串", 5, "中文测试字..."},
	}

	for _, tt := range tests {
		got := truncate(tt.input, tt.maxLen)
		if !strings.HasPrefix(got, tt.expected[:min(len(tt.expected), len(got))]) {
			t.Errorf("truncate(%q, %d) = %q, want prefix %q",
				tt.input, tt.maxLen, got, tt.expected)
		}
	}
}

func TestToLowerASCII(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"ABC", "abc"},
		{"abc", "abc"},
		{"AbCdEf", "abcdef"},
		{"TEST123", "test123"},
		{"MixedCASE.txt", "mixedcase.txt"},
		{"", ""},
	}

	for _, tt := range tests {
		got := toLowerASCII(tt.input)
		if got != tt.expected {
			t.Errorf("toLowerASCII(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestToLowerByte(t *testing.T) {
	tests := []struct {
		input    byte
		expected byte
	}{
		{'A', 'a'},
		{'Z', 'z'},
		{'a', 'a'},
		{'0', '0'},
		{'.', '.'},
	}

	for _, tt := range tests {
		got := toLowerByte(tt.input)
		if got != tt.expected {
			t.Errorf("toLowerByte(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

// ==================== 预筛选测试 ====================

func TestQuickPreFilter(t *testing.T) {
	initCharMask()

	tests := []struct {
		input    []byte
		expected bool
	}{
		{[]byte("password=xxx"), true},
		{[]byte("SECRET_KEY=xxx"), true},
		{[]byte("token: abc"), true},
		{[]byte("密码：12345678"), true},     // 纯中文敏感词应通过预筛选
		{[]byte("口令=87654321"), true},       // 纯中文敏感词应通过预筛选
		{[]byte("12345678901234567890"), false}, // 纯数字，无敏感字符
		{[]byte("short"), false},                 // 太短
		{[]byte(strings.Repeat("x", 5000)), false}, // 太长
	}

	for _, tt := range tests {
		got := quickPreFilter(tt.input)
		if got != tt.expected {
			t.Errorf("quickPreFilter(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

// ==================== 规则匹配测试 ====================

func TestRulePatterns(t *testing.T) {
	InitAllRules()

	tests := []struct {
		ruleName string
		input    string
		shouldMatch bool
	}{
		// Password - 需要 6+ 字符的值
		{"Password", "password = 'Secret123!'", true},
		{"Password", "PASSWORD=AdminPassword", true},
		{"Password", "no password here", false},

		// APIKey - 需要 16+ 字符
		{"APIKey", "api_key: sk-1234567890abcdef", true},
		{"APIKey", "API_KEY=ABCDEFGHIJKLMNOPQR", true},
		{"APIKey", "random text", false},

		// DBConnStr
		{"DBConnStr", "mongodb://user:pass@localhost:27017", true},
		{"DBConnStr", "postgres://admin:secret@db.example.com:5432/mydb", true},
		{"DBConnStr", "http://example.com", false},

		// AWSKey - AKIA + 16 大写字母/数字
		{"AWSKey", "AKIAIOSFODNN7EXAMPLE", true},
		{"AWSKey", "AKIA1234567890ABCDEF", true},
		{"AWSKey", "not an aws key", false},

		// GithubToken - ghp_ + 36+ 字符
		{"GithubToken", "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890ABC", true},
		{"GithubToken", "not a github token", false},

		// CNPassword
		{"CNPassword", "密码：Admin@123", true},
		{"CNPassword", "口令: Test456", true},
		{"CNPassword", "普通文本", false},
	}

	for _, tt := range tests {
		rule, ok := sensitiveRules[tt.ruleName]
		if !ok {
			t.Errorf("Rule %q not found", tt.ruleName)
			continue
		}

		matches := rule.pattern.MatchString(tt.input)
		if matches != tt.shouldMatch {
			t.Errorf("Rule %q on %q: got %v, want %v",
				tt.ruleName, tt.input, matches, tt.shouldMatch)
		}
	}
}

// ==================== Reporter 测试 ====================

func TestSeverityClassification(t *testing.T) {
	tests := []struct {
		category string
		expected Severity
	}{
		{"PrivateKey", SeverityCritical},
		{"DBConnStr", SeverityCritical},
		{"AWSKey", SeverityCritical},
		{"Password", SeverityHigh},
		{"APIKey", SeverityHigh},
		{"Token", SeverityHigh},
		{"CNPassword", SeverityMedium},
		{"BrowserHist", SeverityInfo},
		{"UnknownCategory", SeverityInfo}, // 默认
	}

	for _, tt := range tests {
		got := getSeverity(tt.category)
		if got != tt.expected {
			t.Errorf("getSeverity(%q) = %v, want %v", tt.category, got, tt.expected)
		}
	}
}

// ==================== Office 文档测试 ====================

func TestExtractXMLText(t *testing.T) {
	tests := []struct {
		input       string
		shouldMatch string
	}{
		{"<w:t>Hello</w:t>", "Hello"},
		{"<w:t>Hello</w:t><w:t>World</w:t>", "Hello"},
		{"", ""},
	}

	for _, tt := range tests {
		got := extractXMLText([]byte(tt.input))
		if !strings.Contains(got, tt.shouldMatch) && tt.shouldMatch != "" {
			t.Errorf("extractXMLText(%q) = %q, should contain %q", tt.input, got, tt.shouldMatch)
		}
	}
}

func TestIsBinaryFile(t *testing.T) {
	tests := []struct {
		input    []byte
		expected bool
	}{
		{[]byte("Hello, World!"), false},
		{[]byte("Line1\nLine2\n"), false},
		{[]byte(""), false},
	}

	for _, tt := range tests {
		got := isBinaryFile(tt.input)
		if got != tt.expected {
			t.Errorf("isBinaryFile(%v) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

// ==================== 验证函数测试 ====================

func TestValidateMatch(t *testing.T) {
	tests := []struct {
		rule        string
		match       string
		line        string
		shouldValid bool
	}{
		// Password 验证
		{"Password", "SuperSecret123!", "password = 'SuperSecret123!'", true},
		{"Password", "xxx", "password = 'xxx'", false}, // 太短

		// Token 验证
		{"Token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", true},
	}

	for _, tt := range tests {
		got := validateMatch(tt.rule, tt.match, tt.line)
		if got != tt.shouldValid {
			t.Errorf("validateMatch(%q, %q, %q) = %v, want %v",
				tt.rule, tt.match, tt.line, got, tt.shouldValid)
		}
	}
}

// ==================== Reporter 测试 ====================

func TestReporterAddFinding(t *testing.T) {
	r := NewReporter()

	// 添加一些发现 (category, title, path, line, match)
	r.AddFinding("Password", "test", "/path/to/file", 10, "password=secret")
	r.AddFinding("AWSKey", "test", "/path/to/aws", 20, "AKIAIOSFODNN7EXAMPLE")

	if len(r.findings) != 2 {
		t.Errorf("Expected 2 findings, got %d", len(r.findings))
	}
}

func TestReporterCategoryLimit(t *testing.T) {
	r := NewReporter()

	// BrowserHist 限制为 10
	for i := 0; i < 20; i++ {
		r.AddFinding("BrowserHist", "Chrome", "http://example.com", 0, "url")
	}

	count := 0
	for _, f := range r.findings {
		if f.Category == "BrowserHist" {
			count++
		}
	}

	if count > 10 {
		t.Errorf("BrowserHist should be limited to 10, got %d", count)
	}
}

// ==================== 并发安全测试 ====================

func TestConcurrentDedup(t *testing.T) {
	// 重置分片
	for i := 0; i < shardCount; i++ {
		seenShards[i].m = make(map[uint64]struct{}, 256)
	}

	var wg sync.WaitGroup
	results := make([]bool, 1000)

	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			// 使用相同的 key 测试并发
			key := fmt.Sprintf("key-%d", id%10)
			results[id] = isDuplicate("test", key)
		}(i)
	}
	wg.Wait()

	// 每个唯一 key 应该只有一个 false（第一次）
	falseCount := make(map[int]int)
	for i, r := range results {
		if !r {
			falseCount[i%10]++
		}
	}

	for key, count := range falseCount {
		if count != 1 {
			t.Errorf("Key %d: expected 1 false, got %d", key, count)
		}
	}
}

// ==================== 边界条件测试 ====================

func TestEdgeCases(t *testing.T) {
	initCharMask()
	InitAllRules()

	// 空输入
	if quickPreFilter([]byte("")) {
		t.Error("Empty input should return false")
	}

	// 超长输入
	longInput := make([]byte, 10000)
	for i := range longInput {
		longInput[i] = 'a'
	}
	if quickPreFilter(longInput) {
		t.Error("Very long input without keywords should return false")
	}

	// 创建测试用的 AC matcher
	testMatcher := NewAhoCorasick([]string{"password", "密码", "token"})
	if !testMatcher.ContainsAny("密码test") {
		t.Error("Chinese keywords should match")
	}
}

func TestFormatPath(t *testing.T) {
	tests := []struct {
		input       string
		maxLen      int
		hasEllipsis bool
	}{
		{"/short/path", 50, false},
		{"/very/long/path/that/exceeds/maximum/length/limit/for/display", 30, true},
		{"/very/long/path/with/many/segments/to/exceed/limit", 25, true},
	}

	for _, tt := range tests {
		got := formatPath(tt.input, tt.maxLen)
		hasEllipsis := strings.Contains(got, "...")
		if hasEllipsis != tt.hasEllipsis {
			t.Errorf("formatPath(%q, %d) = %q, ellipsis = %v, want %v",
				tt.input, tt.maxLen, got, hasEllipsis, tt.hasEllipsis)
		}
	}
}

// ==================== Config 测试 ====================

func TestConfigFixOutputExtension(t *testing.T) {
	tests := []struct {
		format   string
		input    string
		expected string
	}{
		{"json", "report.txt", "report.json"},
		{"md", "report.txt", "report.md"},
		{"txt", "report.txt", "report.txt"},
		{"json", "report.json", "report.json"},
		{"md", "report.md", "report.md"},
	}

	for _, tt := range tests {
		cfg := &Config{
			OutputFormat: tt.format,
			OutputPath:   tt.input,
		}
		cfg.fixOutputExtension()
		if cfg.OutputPath != tt.expected {
			t.Errorf("fixOutputExtension(%q, %q) = %q, want %q",
				tt.format, tt.input, cfg.OutputPath, tt.expected)
		}
	}
}

// ==================== 扫描函数测试 ====================

func TestResolveTargets(t *testing.T) {
	// 测试空路径
	roots, single := resolveTargets("")
	if single != "" {
		t.Error("Empty path should not return single file")
	}
	if len(roots) == 0 {
		t.Error("Empty path should return default roots")
	}
}

func TestSplitByLength(t *testing.T) {
	tests := []struct {
		input    string
		maxLen   int
		expected int // 期望的分割数量
	}{
		{"short", 10, 1},
		{"this is a longer string", 5, 5},
		{"", 10, 0},
	}

	for _, tt := range tests {
		got := splitByLength(tt.input, tt.maxLen)
		if len(got) != tt.expected {
			t.Errorf("splitByLength(%q, %d) = %d parts, want %d",
				tt.input, tt.maxLen, len(got), tt.expected)
		}
	}
}

func TestParseSharedStrings(t *testing.T) {
	input := `<sst><si><t>Hello</t></si><si><t>World</t></si></sst>`
	result := parseSharedStrings([]byte(input))

	if len(result) != 2 {
		t.Errorf("parseSharedStrings: expected 2 strings, got %d", len(result))
	}
	if len(result) > 0 && result[0] != "Hello" {
		t.Errorf("parseSharedStrings: expected 'Hello', got %q", result[0])
	}
}

// ==================== 文件类型测试 ====================

func TestTargetExtensions(t *testing.T) {
	// 测试目标扩展名
	if len(targetExtensions) == 0 {
		t.Error("targetExtensions should not be empty")
	}

	// 检查常见扩展名
	expected := []string{".json", ".yaml", ".yml", ".env", ".py", ".go"}
	for _, ext := range expected {
		if !targetExtensions[ext] {
			t.Errorf("targetExtensions should contain %s", ext)
		}
	}
}

func TestOfficeExtensions(t *testing.T) {
	// 测试 Office 扩展名
	expected := []string{".docx", ".xlsx", ".doc", ".xls", ".pptx"}
	for _, ext := range expected {
		if !officeExtensions[ext] {
			t.Errorf("officeExtensions should contain %s", ext)
		}
	}
}

func TestHighValueExtensions(t *testing.T) {
	// 测试高价值扩展名
	expected := []string{".pem", ".key", ".tfstate"}
	for _, ext := range expected {
		if _, ok := highValueExtensions[ext]; !ok {
			t.Errorf("highValueExtensions should contain %s", ext)
		}
	}
}

// ==================== 排除规则测试 ====================

func TestExcludedDirs(t *testing.T) {
	expected := []string{"node_modules", ".git", "vendor", "__pycache__"}
	for _, dir := range expected {
		if _, ok := excludedDirs[dir]; !ok {
			t.Errorf("excludedDirs should contain %s", dir)
		}
	}
}

// ==================== 集成测试 ====================

func TestInitScanner(t *testing.T) {
	// 确保初始化不会 panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("initScanner panicked: %v", r)
		}
	}()

	initScanner(&Config{})

	if keywordMatcher == nil {
		t.Error("keywordMatcher should not be nil after init")
	}
}

func TestCheckEnvironment(t *testing.T) {
	cfg := &Config{
		SkipSandbox: true,
		SkipDebug:   true,
	}

	// 跳过所有检查应该返回 true
	if !checkEnvironment(cfg) {
		t.Error("checkEnvironment with skips should return true")
	}
}

func TestExtractOfficeBinaryText(t *testing.T) {
	// 构造一个包含 ASCII、UTF-16LE 字符串以及中文 UTF-16LE 的假二进制文件
	data := []byte{
		// UTF-16LE "Hello World"
		0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00,
		0x20, 0x00, 0x57, 0x00, 0x6F, 0x00, 0x72, 0x00, 0x6C, 0x00, 0x64, 0x00,
		0x00, 0x00,
		// ASCII password=Secret123
		'p', 'a', 's', 's', 'w', 'o', 'r', 'd', '=', 'S', 'e', 'c', 'r', 'e', 't', '1', '2', '3',
		0x00, 0x00,
		// UTF-16LE 中文 "中文字"
		0x2D, 0x4E, 0x87, 0x65, 0x57, 0x5B,
		0x00, 0x00,
	}
	path := filepath.Join(os.TempDir(), "xunfeng_office_extract_test.bin")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)

	text, err := extractOfficeBinaryText(path)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(text, "Hello World") {
		t.Errorf("expected UTF-16LE 'Hello World', got: %s", text)
	}
	if !strings.Contains(text, "password=Secret123") {
		t.Errorf("expected ASCII 'password=Secret123', got: %s", text)
	}
	if !strings.Contains(text, "中文字") {
		t.Errorf("expected UTF-16LE CJK '中文字', got: %s", text)
	}
}

func TestExtractPPTTextRecords(t *testing.T) {
	// 构造一个假的 PPT 记录：
	// RecordHeader: ver/instance(2) + type(2) + length(4) = 8 bytes
	// TextCharsAtom type = 0x0FA0, payload 为 UTF-16LE "ppt_password=Secret"
	utf16Payload := []byte{
		0x70, 0x00, 0x70, 0x00, 0x74, 0x00, 0x5F, 0x00, 0x70, 0x00, 0x61, 0x00,
		0x73, 0x00, 0x73, 0x00, 0x77, 0x00, 0x6F, 0x00, 0x72, 0x00, 0x64, 0x00,
		0x3D, 0x00, 0x53, 0x00, 0x65, 0x00, 0x63, 0x00, 0x72, 0x00, 0x65, 0x00,
		0x74, 0x00,
	}
	recLen := uint32(len(utf16Payload))
	data := []byte{
		0x00, 0x00, // ver/instance
		0xA0, 0x0F, // type = 0x0FA0 (TextCharsAtom)
		byte(recLen), byte(recLen >> 8), byte(recLen >> 16), byte(recLen >> 24),
	}
	data = append(data, utf16Payload...)

	text := extractPPTTextRecords(data)
	if !strings.Contains(text, "ppt_password=Secret") {
		t.Errorf("expected PPT TextCharsAtom text 'ppt_password=Secret', got: %s", text)
	}
}

func TestExtractBiffText(t *testing.T) {
	// 构造一个 BIFF8 LABEL 记录：
	// rt=0x0204, rl, row(2), col(2), xf(2), cch(2), grbit(1), ASCII text
	text := "password=Secret123"
	cch := len(text)
	rl := 6 + 1 + cch // row+col+xf + cch + grbit + chars
	payload := make([]byte, 0, rl)
	payload = binary.LittleEndian.AppendUint16(payload, 0) // row
	payload = binary.LittleEndian.AppendUint16(payload, 0) // col
	payload = binary.LittleEndian.AppendUint16(payload, 0) // xf
	payload = binary.LittleEndian.AppendUint16(payload, uint16(cch))
	payload = append(payload, 0x00) // grbit: compressed
	payload = append(payload, text...)

	data := make([]byte, 0, 4+len(payload))
	data = binary.LittleEndian.AppendUint16(data, 0x0204) // LABEL
	data = binary.LittleEndian.AppendUint16(data, uint16(len(payload)))
	data = append(data, payload...)

	got := extractBiffText(data)
	if !strings.Contains(got, text) {
		t.Errorf("expected BIFF LABEL text %q, got: %s", text, got)
	}
}

func TestScanContentPatterns(t *testing.T) {
	before := len(globalReporter.findings)
	content := `
server=192.168.1.100
admin admin123
root:Password1
https://internal.example.com/login
http://192.168.0.1:8080/admin
contact@example.com
admin123
`
	scanContentPatterns("test.txt", content)
	after := len(globalReporter.findings)
	if after <= before {
		t.Error("expected content pattern findings")
	}
}

// ==================== 辅助函数 ====================

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
