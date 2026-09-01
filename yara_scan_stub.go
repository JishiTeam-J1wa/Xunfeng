//go:build !yara

package main

import "fmt"

// initYaraScanner 是 YARA 扫描器的存根实现。
// 当未使用 "yara" build tag 时，不提供 YARA 能力，但保持 API 一致，
// 使默认构建不依赖 libyara/CGO。
func initYaraScanner(rulesPath string) error {
	if rulesPath != "" {
		return fmt.Errorf("YARA support not compiled in: rebuild with `go build -tags yara` (requires libyara)")
	}
	return nil
}

func scanFileWithYara(path string) {}

func scanProcessWithYara(pid int32, name string) {}

func closeYaraScanner() {}
