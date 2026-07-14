//go:build plugin

package main

import (
	"fmt"
	"runtime"
)

// RunScanPlugin 是 plugin 模式下的导出入口
// 参数：target 扫描目标路径，output 报告输出路径
// 返回错误信息，空字符串表示成功
func RunScanPlugin(target, output string) string {
	cfg := &Config{
		TargetPath:   target,
		OutputPath:   output,
		OutputFormat: "txt",
		Workers:      runtime.NumCPU() * 2,
		SkipSandbox:  true,
		SkipDebug:    true,
	}
	cfg.fixOutputExtension()
	if cfg.OutputPath == "" {
		cfg.OutputPath = "xunfeng_report.txt"
	}
	if err := runWithConfig(cfg); err != nil {
		return err.Error()
	}
	return ""
}

// RunScanPluginJSON 是 plugin 模式下的 JSON 输出导出入口
func RunScanPluginJSON(target, output string) string {
	cfg := &Config{
		TargetPath:   target,
		OutputPath:   output,
		OutputFormat: "json",
		Workers:      runtime.NumCPU() * 2,
		SkipSandbox:  true,
		SkipDebug:    true,
	}
	cfg.fixOutputExtension()
	if cfg.OutputPath == "" {
		cfg.OutputPath = "xunfeng_report.json"
	}
	if err := runWithConfig(cfg); err != nil {
		return err.Error()
	}
	return ""
}

// VersionPlugin 返回版本信息（plugin 模式）
func VersionPlugin() string {
	return fmt.Sprintf("XunFeng %s (%s/%s)", Version, runtime.GOOS, runtime.GOARCH)
}
