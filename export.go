//go:build cgo && !plugin

package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"runtime"
)

//export GetVersion
// GetVersion 返回当前版本信息
func GetVersion() *C.char {
	return C.CString(fmt.Sprintf("XunFeng %s (%s/%s)", Version, runtime.GOOS, runtime.GOARCH))
}

//export RunScan
// RunScan 执行一次完整扫描
// target: 扫描目标路径，为空则扫描全盘
// output: 报告输出路径
// 返回 0 表示成功，非 0 表示失败
func RunScan(target, output *C.char) int {
	cfg := &Config{
		TargetPath:    C.GoString(target),
		OutputPath:    C.GoString(output),
		OutputFormat:  "txt",
		Workers:       runtime.NumCPU() * 2,
		SkipSandbox:   true,
		SkipDebug:     true,
	}
	cfg.fixOutputExtension()
	if cfg.OutputPath == "" {
		cfg.OutputPath = "xunfeng_report.txt"
	}
	if err := runWithConfig(cfg); err != nil {
		return 1
	}
	return 0
}

//export RunScanJSON
// RunScanJSON 执行一次完整扫描并输出 JSON 格式报告
func RunScanJSON(target, output *C.char) int {
	cfg := &Config{
		TargetPath:    C.GoString(target),
		OutputPath:    C.GoString(output),
		OutputFormat:  "json",
		Workers:       runtime.NumCPU() * 2,
		SkipSandbox:   true,
		SkipDebug:     true,
	}
	cfg.fixOutputExtension()
	if cfg.OutputPath == "" {
		cfg.OutputPath = "xunfeng_report.json"
	}
	if err := runWithConfig(cfg); err != nil {
		return 1
	}
	return 0
}
