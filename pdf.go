package main

import (
	"bytes"
	"compress/zlib"
	"io"
	"strings"
	"unicode/utf16"
)

// maxPDFInputSize 限制 PDF 输入大小，超过直接放弃解析（var 便于测试调小）
var maxPDFInputSize = 10 << 20 // 10MB

// pdfStreamDictLookback 定位 stream 关键字时向前回看字典的最大字节数
const pdfStreamDictLookback = 2048

// ExtractPDFText 从未加密 PDF 的原始字节中提取文本。
// 思路：定位 stream/endstream 块，对声明了 /FlateDecode 的流用 zlib 解压，
// 从内容流中提取 Tj / ' / " / TJ 文本显示操作符的字符串参数并拼接。
// 支持字面量字符串的 \ 转义（含八进制 \ddd）和 UTF-16BE（BOM 0xFEFF）文本。
// 加密 PDF（字典含 /Encrypt）或任何解析失败均降级返回空串，绝不 panic。
func ExtractPDFText(data []byte) string {
	if len(data) == 0 || len(data) > maxPDFInputSize {
		return ""
	}
	if !bytes.HasPrefix(bytes.TrimSpace(data[:min(len(data), 64)]), []byte("%PDF")) {
		return ""
	}
	// 加密 PDF 的内容流无法直接解码，显式放弃
	if bytes.Contains(data, []byte("/Encrypt")) {
		return ""
	}

	var out strings.Builder
	for _, stream := range findPDFStreams(data) {
		extractPDFContentText(stream, &out)
	}
	return out.String()
}

// findPDFStreams 返回所有 stream/endstream 块的内容（flate 流已解压）
func findPDFStreams(data []byte) [][]byte {
	var streams [][]byte
	pos := 0
	for {
		idx := bytes.Index(data[pos:], []byte("stream"))
		if idx < 0 {
			break
		}
		idx += pos
		pos = idx + len("stream")

		// 跳过 "endstream" 中的 "stream" 字样
		if idx >= 3 && string(data[idx-3:idx]) == "end" {
			continue
		}

		// stream 关键字后必须跟一个 EOL（CRLF / LF / CR）
		body := idx + len("stream")
		switch {
		case body+1 < len(data) && data[body] == '\r' && data[body+1] == '\n':
			body += 2
		case body < len(data) && (data[body] == '\n' || data[body] == '\r'):
			body++
		default:
			continue // 不符合 PDF 规范，不是真正的流
		}

		end := bytes.Index(data[body:], []byte("endstream"))
		if end < 0 {
			break
		}
		end += body
		pos = end + len("endstream")

		content := data[body:end]
		if streamDictHasFlateDecode(data, idx) {
			if decoded, err := inflatePDFStream(content); err == nil {
				content = decoded
			} else {
				continue // 解压失败，跳过该流
			}
		}
		streams = append(streams, content)
	}
	return streams
}

// streamDictHasFlateDecode 回看 stream 关键字之前的对象字典，判断是否声明 /FlateDecode
func streamDictHasFlateDecode(data []byte, streamKwIdx int) bool {
	start := streamKwIdx - pdfStreamDictLookback
	if start < 0 {
		start = 0
	}
	window := data[start:streamKwIdx]
	// 只看最近一个字典 << ... >> 范围，避免误读上一个对象的 Filter
	if dictStart := bytes.LastIndex(window, []byte("<<")); dictStart >= 0 {
		window = window[dictStart:]
	}
	return bytes.Contains(window, []byte("/FlateDecode"))
}

// inflatePDFStream 对 flate 压缩的流做 zlib 解压，限制解压输出 64MB 防解压炸弹
func inflatePDFStream(content []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(content))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(io.LimitReader(r, 64<<20))
}

// extractPDFContentText 从（可能已解压的）内容流中提取文本显示操作符的字符串
func extractPDFContentText(data []byte, out *strings.Builder) {
	i, n := 0, len(data)
	for i < n {
		switch data[i] {
		case '(':
			str, next := parsePDFLiteralString(data, i)
			if next <= i {
				i++
				continue
			}
			// 字符串后紧跟 Tj / ' / " 才是文本显示
			j := skipPDFWhitespace(data, next)
			if j < n && (matchPDFOperator(data, j, "Tj") || data[j] == '\'' || data[j] == '"') {
				writePDFText(out, decodePDFTextString(str))
			}
			i = next
		case '[':
			// TJ 数组：收集数组内全部字面量字符串
			texts, next := parsePDFArrayStrings(data, i)
			if next <= i {
				i++
				continue
			}
			j := skipPDFWhitespace(data, next)
			if matchPDFOperator(data, j, "TJ") {
				for _, s := range texts {
					writePDFText(out, decodePDFTextString(s))
				}
			}
			i = next
		default:
			i++
		}
	}
}

// writePDFText 拼接一段文本，段间用换行分隔
func writePDFText(out *strings.Builder, s string) {
	if s == "" {
		return
	}
	out.WriteString(s)
	out.WriteByte('\n')
}

// parsePDFLiteralString 解析 data[start:] 处的字面量字符串（start 处为 '('），
// 返回转义解码后的原始字节和字符串结束的下一个位置。解析失败返回 (nil, start)。
func parsePDFLiteralString(data []byte, start int) ([]byte, int) {
	if start >= len(data) || data[start] != '(' {
		return nil, start
	}
	var buf []byte
	depth := 1
	i := start + 1
	for i < len(data) {
		c := data[i]
		switch c {
		case '\\':
			if i+1 >= len(data) {
				return nil, start
			}
			next := data[i+1]
			switch next {
			case 'n':
				buf = append(buf, '\n')
				i += 2
			case 'r':
				buf = append(buf, '\r')
				i += 2
			case 't':
				buf = append(buf, '\t')
				i += 2
			case 'b':
				buf = append(buf, '\b')
				i += 2
			case 'f':
				buf = append(buf, '\f')
				i += 2
			case '(', ')', '\\':
				buf = append(buf, next)
				i += 2
			case '\r', '\n':
				// 行延续：反斜杠 + EOL 不产生字符
				i += 2
				if next == '\r' && i < len(data) && data[i] == '\n' {
					i++
				}
			default:
				// 八进制转义 \ddd（最多 3 位）
				if next >= '0' && next <= '7' {
					val := 0
					digits := 0
					for digits < 3 && i+1+digits < len(data) {
						d := data[i+1+digits]
						if d < '0' || d > '7' {
							break
						}
						val = val*8 + int(d-'0')
						digits++
					}
					buf = append(buf, byte(val))
					i += 1 + digits
				} else {
					// 未知转义按字面字符处理
					buf = append(buf, next)
					i += 2
				}
			}
		case '(':
			depth++
			buf = append(buf, c)
			i++
		case ')':
			depth--
			if depth == 0 {
				return buf, i + 1
			}
			buf = append(buf, c)
			i++
		default:
			buf = append(buf, c)
			i++
		}
	}
	return nil, start // 括号不配对，视为失败
}

// parsePDFArrayStrings 解析 data[start:] 处的数组（start 处为 '['），
// 收集其中全部字面量字符串，返回字符串列表和 ']' 的下一个位置。
func parsePDFArrayStrings(data []byte, start int) ([][]byte, int) {
	if start >= len(data) || data[start] != '[' {
		return nil, start
	}
	var texts [][]byte
	i := start + 1
	for i < len(data) {
		switch data[i] {
		case ']':
			return texts, i + 1
		case '(':
			str, next := parsePDFLiteralString(data, i)
			if next <= i {
				return nil, start
			}
			texts = append(texts, str)
			i = next
		default:
			i++
		}
	}
	return nil, start
}

// decodePDFTextString 将字符串原始字节解码为文本：带 0xFEFF BOM 的按 UTF-16BE 处理
func decodePDFTextString(b []byte) string {
	if len(b) >= 2 && b[0] == 0xFE && b[1] == 0xFF {
		u16 := make([]uint16, 0, (len(b)-2)/2)
		for i := 2; i+1 < len(b); i += 2 {
			u16 = append(u16, uint16(b[i])<<8|uint16(b[i+1]))
		}
		return string(utf16.Decode(u16))
	}
	return string(b)
}

// skipPDFWhitespace 跳过 PDF 空白字符
func skipPDFWhitespace(data []byte, i int) int {
	for i < len(data) {
		switch data[i] {
		case ' ', '\t', '\r', '\n', '\f', 0:
			i++
		default:
			return i
		}
	}
	return i
}

// matchPDFOperator 判断 data[i:] 是否以操作符 op 开头且后跟分隔符
func matchPDFOperator(data []byte, i int, op string) bool {
	if i+len(op) > len(data) || string(data[i:i+len(op)]) != op {
		return false
	}
	if i+len(op) == len(data) {
		return true
	}
	c := data[i+len(op)]
	switch c {
	case ' ', '\t', '\r', '\n', '\f', 0, '(', '[', '<', '/', '%':
		return true
	}
	return false
}
