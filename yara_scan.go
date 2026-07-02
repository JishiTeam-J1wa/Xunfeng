//go:build yara

package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	yara "github.com/hillu/go-yara/v4"
)

// yaraEngine 持有编译后的 YARA 规则与扫描器。
// 该文件仅在构建时带有 "yara" tag 才会被编译（go build -tags yara）。
type yaraEngine struct {
	rules   *yara.Rules
	scanner *yara.Scanner
}

var (
	yaraEngineInstance *yaraEngine
	yaraRuleCount      int
)

// initYaraScanner 从文件或目录加载 YARA 规则并编译。
// 当 rulesPath 为空时直接返回 nil，表示不启用 YARA 扫描。
func initYaraScanner(rulesPath string) error {
	if rulesPath == "" {
		return nil
	}

	info, err := os.Stat(rulesPath)
	if err != nil {
		return err
	}

	compiler, err := yara.NewCompiler()
	if err != nil {
		return err
	}

	if info.IsDir() {
		entries, err := os.ReadDir(rulesPath)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			lower := strings.ToLower(name)
			if !(strings.HasSuffix(lower, ".yar") || strings.HasSuffix(lower, ".yara")) {
				continue
			}
			path := filepath.Join(rulesPath, name)
			if err := addYaraRuleFile(compiler, path); err != nil {
				return err
			}
		}
	} else {
		if err := addYaraRuleFile(compiler, rulesPath); err != nil {
			return err
		}
	}

	rules, err := compiler.GetRules()
	if err != nil {
		return err
	}

	scanner, err := yara.NewScanner(rules)
	if err != nil {
		return err
	}

	yaraEngineInstance = &yaraEngine{rules: rules, scanner: scanner}
	printInfo("YARA engine loaded: %d rules from %s", yaraRuleCount, rulesPath)
	return nil
}

func addYaraRuleFile(compiler *yara.Compiler, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := compiler.AddFile(f, filepath.Base(path)); err != nil {
		return err
	}
	yaraRuleCount++
	return nil
}

// scanFileWithYara 对文件路径执行 YARA 规则匹配。
func scanFileWithYara(path string) {
	if yaraEngineInstance == nil {
		return
	}

	var matches yara.MatchRules
	if err := yaraEngineInstance.scanner.SetCallback(&matches).ScanFile(path); err != nil {
		return
	}

	for _, m := range matches {
		atomic.AddUint64(&fileHits, 1)
		desc := m.Rule
		if len(m.Tags) > 0 {
			desc += " [" + strings.Join(m.Tags, ", ") + "]"
		}
		globalReporter.PrintFinding("YaraRule", m.Rule, path, 0, desc)
	}
}

// scanProcessWithYara 对进程内存执行 YARA 规则匹配。
func scanProcessWithYara(pid int32, name string) {
	if yaraEngineInstance == nil {
		return
	}

	var matches yara.MatchRules
	if err := yaraEngineInstance.scanner.SetCallback(&matches).ScanProc(int(pid)); err != nil {
		return
	}

	for _, m := range matches {
		atomic.AddUint64(&processHits, 1)
		desc := m.Rule
		if len(m.Tags) > 0 {
			desc += " [" + strings.Join(m.Tags, ", ") + "]"
		}
		globalReporter.PrintFinding("YaraProc", m.Rule, name+" (PID:"+itoa(int(pid))+")", 0, desc)
	}
}

// closeYaraScanner 释放 YARA 引擎资源。
func closeYaraScanner() {
	if yaraEngineInstance == nil {
		return
	}
	if yaraEngineInstance.rules != nil {
		yaraEngineInstance.rules.Destroy()
	}
	yaraEngineInstance = nil
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	negative := i < 0
	if negative {
		i = -i
	}
	n := 0
	for i > 0 {
		buf[n] = byte('0' + i%10)
		i /= 10
		n++
	}
	if negative {
		buf[n] = '-'
		n++
	}
	for i, j := 0, n-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf[:n])
}
