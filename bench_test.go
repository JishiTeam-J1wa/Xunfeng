package main

import (
	"strings"
	"testing"
)

var testLines = []string{
	"password = 'SuperSecretPass123!'",
	"api_key: AKIA1234567890123456",
	"connection_string: mongodb://user:pass@localhost:27017",
	"this is a normal line without any sensitive data",
	"DEBUG=true LOG_LEVEL=info",
	"const config = { database: 'production' }",
	"export AWS_SECRET_ACCESS_KEY=abcdefghijklmnopqrstuvwxyz123456",
	"token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	"密码：Admin@123456",
	"数据库地址：mysql://root:password@192.168.1.1:3306/db",
}

func BenchmarkAhoCorasick(b *testing.B) {
	ac := NewAhoCorasick([]string{
		"password", "passwd", "pwd", "secret", "token", "key", "api",
		"credential", "auth", "private", "jdbc", "mongodb", "redis",
		"mysql", "postgres", "密码", "口令", "账号", "BEGIN",
		"AKIA", "LTAI", "AKID", "ghp_", "gho_", "glpat-", "xox",
		"sk_live", "npm_", "eyJ", "bearer", "basic",
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, line := range testLines {
			ac.ContainsAny(line)
		}
	}
}

func BenchmarkNaiveContains(b *testing.B) {
	keywords := []string{
		"password", "passwd", "pwd", "secret", "token", "key", "api",
		"credential", "auth", "private", "jdbc", "mongodb", "redis",
		"mysql", "postgres", "密码", "口令", "账号", "BEGIN",
		"AKIA", "LTAI", "AKID", "ghp_", "gho_", "glpat-", "xox",
		"sk_live", "npm_", "eyJ", "bearer", "basic",
	}
	lower := make([]string, len(keywords))
	for i, kw := range keywords {
		lower[i] = strings.ToLower(kw)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, line := range testLines {
			lineLower := strings.ToLower(line)
			for _, kw := range lower {
				if strings.Contains(lineLower, kw) {
					break
				}
			}
		}
	}
}

func BenchmarkQuickPreFilter(b *testing.B) {
	initCharMask()
	lines := make([][]byte, len(testLines))
	for i, l := range testLines {
		lines[i] = []byte(l)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, line := range lines {
			quickPreFilter(line)
		}
	}
}

func BenchmarkFNV1a(b *testing.B) {
	s := "content:/Users/test/path/to/file.go:Password"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fnv1a(s)
	}
}

func BenchmarkToLowerASCII(b *testing.B) {
	s := "ThisIsATestString.GoFile"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		toLowerASCII(s)
	}
}

func BenchmarkStringsToLower(b *testing.B) {
	s := "ThisIsATestString.GoFile"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		strings.ToLower(s)
	}
}
