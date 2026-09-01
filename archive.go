package main

import (
	"archive/zip"
	"io"
	"path/filepath"
	"strings"
)

// ArchiveEntry 是压缩包中提取出的一个文本类成员
type ArchiveEntry struct {
	Name string // 压缩包内路径
	Text []byte // 成员解压后的文本内容
}

// archiveMemberMaxSize 单个成员解压后的上限（var 便于测试调小）
var archiveMemberMaxSize int64 = 5 << 20 // 5MB

// archiveDefaultMaxTotal maxTotal 传 0 或负数时的默认解压总量上限
const archiveDefaultMaxTotal int64 = 32 << 20 // 32MB

// archiveTextSampleSize 判断成员是否文本时采样的字节数
const archiveTextSampleSize = 4096

// archiveBinaryThreshold 采样中非打印字符超过该比例即视为二进制
const archiveBinaryThreshold = 0.30

// ExtractArchiveText 解包压缩包并返回其中文本类成员的内容，供主扫描管道匹配。
// 仅支持 .zip（标准库 archive/zip）；.rar/.7z 显式返回 nil——
// rar 是专有格式、7z 依赖 LZMA/加密支持，标准库均不支持，只能按路径报告。
// 防护：单成员解压 ≤5MB、解压总量 ≤maxTotal，防 zip bomb。
// 所有错误均降级跳过对应成员或返回 nil，绝不 panic。
func ExtractArchiveText(path string, maxTotal int64) []ArchiveEntry {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".zip":
		return extractZipText(path, maxTotal)
	default:
		// .rar/.7z 及其他格式：标准库不支持，返回空
		return nil
	}
}

// extractZipText 在内存中逐个读取 zip 成员，只收集文本类成员
func extractZipText(path string, maxTotal int64) []ArchiveEntry {
	if maxTotal <= 0 {
		maxTotal = archiveDefaultMaxTotal
	}
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil
	}
	defer r.Close()

	var entries []ArchiveEntry
	var total int64
	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if total >= maxTotal {
			break
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		// 多读 1 字节判断是否超过单成员上限
		buf, err := io.ReadAll(io.LimitReader(rc, archiveMemberMaxSize+1))
		rc.Close()
		if err != nil {
			continue
		}
		if int64(len(buf)) > archiveMemberMaxSize {
			continue // 单成员超限，丢弃（不计入总量，继续看后续成员）
		}
		if total+int64(len(buf)) > maxTotal {
			break // 严格保证解压总量 ≤maxTotal
		}
		total += int64(len(buf))
		if len(buf) == 0 || !isArchiveTextData(buf) {
			continue
		}
		entries = append(entries, ArchiveEntry{Name: f.Name, Text: buf})
	}
	return entries
}

// isArchiveTextData 用非打印字符比例判断数据是否为文本：
// 含 NUL 直接判二进制；采样前 4096 字节，非打印字符占比超 30% 判二进制。
func isArchiveTextData(data []byte) bool {
	sample := data
	if len(sample) > archiveTextSampleSize {
		sample = sample[:archiveTextSampleSize]
	}
	if len(sample) == 0 {
		return false
	}
	nonPrint := 0
	for _, b := range sample {
		if b == 0 {
			return false
		}
		// 允许常见空白字符；其余控制字符和 0x7F 视为非打印
		if (b < 0x20 && b != '\t' && b != '\n' && b != '\r') || b == 0x7F {
			nonPrint++
		}
	}
	return float64(nonPrint)/float64(len(sample)) <= archiveBinaryThreshold
}
