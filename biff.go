package main

import (
	"encoding/binary"
	"strings"
)

// extractBiffText 从 Excel 97-2003 (.xls) 的 Workbook 流中提取文本。
// 解析 BIFF8 记录：SST（共享字符串表）、LABEL、LABELSST、STRING 等。
func extractBiffText(data []byte) string {
	var result strings.Builder
	var sst []string

	for i := 0; i+4 <= len(data); {
		rt := binary.LittleEndian.Uint16(data[i : i+2])
		rl := binary.LittleEndian.Uint16(data[i+2 : i+4])
		if i+4+int(rl) > len(data) {
			break
		}
		payload := data[i+4 : i+4+int(rl)]
		i += 4 + int(rl)

		switch rt {
		case 0x00FC: // SST
			sst = parseBIFFSST(payload)
		case 0x00FD: // LABELSST
			if len(payload) >= 10 && len(sst) > 0 {
				idx := binary.LittleEndian.Uint32(payload[6:10])
				if int(idx) < len(sst) {
					result.WriteString(sst[idx])
					result.WriteByte('\n')
				}
			}
		case 0x0204: // LABEL
			if len(payload) >= 8 {
				text := readBIFFString(payload[6:])
				if text != "" {
					result.WriteString(text)
					result.WriteByte('\n')
				}
			}
		case 0x0207: // STRING (公式结果字符串)
			text := readBIFFString(payload)
			if text != "" {
				result.WriteString(text)
				result.WriteByte('\n')
			}
		}
	}

	return result.String()
}

// parseBIFFSST 解析共享字符串表。
// 注意：此简化实现不处理跨 CONTINUE 记录的大型 SST，适用于常见小文件。
func parseBIFFSST(payload []byte) []string {
	if len(payload) < 8 {
		return nil
	}
	// cstTotal (4) + cstUnique (4)
	cstUnique := binary.LittleEndian.Uint32(payload[4:8])
	var result []string
	pos := 8
	for j := 0; j < int(cstUnique) && pos < len(payload); j++ {
		s, n := readBIFFStringWithPos(payload[pos:])
		if n <= 0 {
			break
		}
		result = append(result, s)
		pos += n
	}
	return result
}

// readBIFFString 读取一个 BIFF8 字符串。
func readBIFFString(data []byte) string {
	s, _ := readBIFFStringWithPos(data)
	return s
}

// readBIFFStringWithPos 读取 BIFF8 字符串并返回读取的字节数。
func readBIFFStringWithPos(data []byte) (string, int) {
	if len(data) < 3 {
		return "", 0
	}
	cch := binary.LittleEndian.Uint16(data[0:2])
	grbit := data[2]
	pos := 3

	// fRichStr: 跳过 cRun(2) + cbExtRst(4)
	if grbit&0x08 != 0 {
		if pos+6 > len(data) {
			return "", 0
		}
		pos += 6
	} else if grbit&0x04 != 0 {
		// fExtSt: 跳过 cbExtRst(4)
		if pos+4 > len(data) {
			return "", 0
		}
		pos += 4
	}

	unicode := grbit&0x01 != 0
	var result strings.Builder
	result.Grow(int(cch) * 2)
	for j := 0; j < int(cch) && pos < len(data); j++ {
		if unicode {
			if pos+1 >= len(data) {
				break
			}
			c := binary.LittleEndian.Uint16(data[pos : pos+2])
			result.WriteRune(rune(c))
			pos += 2
		} else {
			result.WriteByte(data[pos])
			pos++
		}
	}
	return result.String(), pos
}
