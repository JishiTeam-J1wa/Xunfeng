package main

import (
	"regexp"
	"strings"
	"sync/atomic"
)

// 网络与凭据模式（不依赖 keywordMatcher 预筛选，直接全文扫描）
var (
	ipv4Regex = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)

	urlRegex = regexp.MustCompile(`(?i)\b(?:https?|ftp|sftp|file|tftp|ftps)://[^\s"'<>\]\)]+`)

	// user=pass / user:pass / user pass（常见默认账号紧接密码）
	// 密码部分要求至少 6 位，且不能是纯小写代码标识符
	credentialPairRegex = regexp.MustCompile(`(?i)(?:^|[\s:;,|])(admin|root|user|test|guest|manager|operator|service|app|web|deploy|api|db|mysql|postgres|oracle|sa)\s*[:=\s]\s*['"]?([A-Za-z0-9!@#$%^&*._\-]{6,40})['"]?`)

	// 常见弱口令/默认口令：admin123、root123、password123、12345678 等
	// 要求 admin/root 等前缀至少带 2 位后缀；password/pass 等至少带 1 位后缀
	weakPasswordRegex = regexp.MustCompile(`(?i)\b(?:admin|root|user|test|guest|manager|operator|mysql|postgres|oracle|sa)[0-9!@#$]{2,10}\b|\b(?:password|pass|pwd|123456|qwerty|abc123|letmein|welcome|monkey|dragon)[0-9!@#$]{1,10}\b`)

	// 邮箱账号（可能用于登录）
	emailRegex = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)
)

// scanContentPatterns 对文件内容执行补充模式扫描：IP、URL、凭据对、弱口令、邮箱。
// 这些模式不依赖 keywordMatcher，避免漏掉纯数字 IP 等情况。
func scanContentPatterns(path string, content string) {
	// 快速预筛选：目标模式至少包含 /、@、: 或数字之一，避免对纯文本跑 5 个正则
	if !hasPatternChars(content) {
		return
	}
	// 限制扫描窗口，避免对大文件全文跑正则；200KB 已足够覆盖绝大多数配置文件
	const maxPatternScan = 200 * 1024
	if len(content) > maxPatternScan {
		content = content[:maxPatternScan]
	}
	scanIPs(path, content)
	scanURLs(path, content)
	scanCredentialPairs(path, content)
	scanWeakPasswords(path, content)
	scanEmails(path, content)
}

// hasPatternChars 快速判断文本是否可能包含 IP/URL/凭据/邮箱等模式
func hasPatternChars(s string) bool {
	// 仅检查前 4KB，平衡速度与召回率
	limit := len(s)
	if limit > 4096 {
		limit = 4096
	}
	for i := 0; i < limit; i++ {
		c := s[i]
		if c == '/' || c == '@' || c == ':' || (c >= '0' && c <= '9') {
			return true
		}
	}
	return false
}

func scanIPs(path, content string) {
	seen := make(map[string]struct{})
	for _, m := range ipv4Regex.FindAllString(content, -1) {
		// 排除常见误报：版本号、时间戳
		if isBogusIP(m) {
			continue
		}
		if _, ok := seen[m]; ok {
			continue
		}
		seen[m] = struct{}{}
		atomic.AddUint64(&contentHits, 1)
		globalReporter.PrintFinding("IPAddr", "IPv4", path, 0, m)
	}
}

func isBogusIP(ip string) bool {
	switch ip {
	case "0.0.0.0", "127.0.0.1", "255.255.255.255", "192.168.0.0", "10.0.0.0", "172.16.0.0":
		return true
	}
	// 排除纯版本号，如 1.2.3.4 太像版本号，但保留（很多内网也长这样）
	return false
}

func scanURLs(path, content string) {
	seen := make(map[string]struct{})
	for _, m := range urlRegex.FindAllString(content, -1) {
		m = strings.TrimRight(m, ".,;:!?]") // 去掉末尾标点
		if len(m) < 10 || len(m) > 300 {
			continue
		}
		if _, ok := seen[m]; ok {
			continue
		}
		seen[m] = struct{}{}
		atomic.AddUint64(&contentHits, 1)
		globalReporter.PrintFinding("URL", "URL", path, 0, m)
	}
}

func scanCredentialPairs(path, content string) {
	seen := make(map[string]struct{})
	for _, m := range credentialPairRegex.FindAllStringSubmatch(content, -1) {
		if len(m) < 3 {
			continue
		}
		user := strings.ToLower(m[1])
		pass := m[2]
		if isCommonNonPassword(pass) {
			continue
		}
		// 排除纯小写代码标识符，如 api:invoke、web:browser
		if !looksLikePassword(pass) {
			continue
		}
		key := user + ":" + pass
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		atomic.AddUint64(&contentHits, 1)
		globalReporter.PrintFinding("CredentialPair", "CredentialPair", path, 0, key)
	}
}

// looksLikePassword 要求密码不是纯小写单词（避免匹配代码标识符）
func looksLikePassword(s string) bool {
	if len(s) < 6 {
		return false
	}
	hasDigit := false
	hasUpper := false
	hasSpecial := false
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			hasDigit = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r == '!' || r == '@' || r == '#' || r == '$' || r == '%' || r == '^' || r == '&' || r == '*' || r == '.' || r == '_' || r == '-':
			hasSpecial = true
		}
	}
	return hasDigit || hasUpper || hasSpecial
}

func scanWeakPasswords(path, content string) {
	seen := make(map[string]struct{})
	for _, m := range weakPasswordRegex.FindAllString(content, -1) {
		m = strings.ToLower(m)
		if _, ok := seen[m]; ok {
			continue
		}
		seen[m] = struct{}{}
		atomic.AddUint64(&contentHits, 1)
		globalReporter.PrintFinding("WeakPassword", "WeakPassword", path, 0, m)
	}
}

func scanEmails(path, content string) {
	seen := make(map[string]struct{})
	for _, m := range emailRegex.FindAllString(content, -1) {
		if strings.HasSuffix(m, ".png") || strings.HasSuffix(m, ".jpg") || strings.HasSuffix(m, ".gif") {
			continue
		}
		if _, ok := seen[m]; ok {
			continue
		}
		seen[m] = struct{}{}
		atomic.AddUint64(&contentHits, 1)
		globalReporter.PrintFinding("Email", "Email", path, 0, m)
	}
}

func isCommonNonPassword(s string) bool {
	lower := strings.ToLower(s)
	switch lower {
	case "true", "false", "null", "none", "undefined", "default", "enabled", "disabled",
		"yes", "no", "on", "off", "required", "optional", "auto", "manual",
		"panel", "page", "user", "admin", "root", "test", "guest", "manager",
		"entry", "directory", "invoke", "registered", "browser", "header",
		"object", "exports", "module", "event", "code", "api", "web",
		"o.default.object", "r.eventcode.api", "oa.exports",
		"_mocha", "mocha", "chai", "jest":
		return true
	}
	// 排除类似 o.default.object 的 JS 路径
	if strings.Contains(lower, ".default.") || strings.Contains(lower, ".eventcode.") || strings.Contains(lower, ".exports") {
		return true
	}
	return false
}
