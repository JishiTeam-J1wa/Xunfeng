package main

import (
	"encoding/binary"
	"strings"
)

// .doc (Word 97-2003) 文本提取。
// 解析 FIB 头定位 table 流（0Table/1Table）中的 CLX，
// 按 piece table（plcpcd）逐个提取文本片段，处理 ANSI(8 位)/Unicode(16 位) 混合编码。
// 失败时返回空字符串，由调用方退回 strings 兜底。

const (
	docFibMagic     = 0xA5EC
	docFlagWhichTbl = 0x0200 // fWhichTblStm：1 表示使用 1Table
	docFlagExtChar  = 0x1000 // fExtChar：旧版全 Unicode 文档
	// FIB 中 fcClx / lcbClx 的偏移（fibRgFcLcb97）
	docOffFcClx  = 0x01A2
	docOffLcbClx = 0x01A6
	// FIB 中 fcMin / fcMac 的偏移（旧版兜底）
	docOffFcMin = 0x0018
	docOffFcMac = 0x001C
)

// ExtractDocText 从完整的 .doc OLE 复合文档数据中提取正文文本。
func ExtractDocText(data []byte) string {
	r, err := newOLEReaderFromBytes(data)
	if err != nil {
		return ""
	}
	word, err := r.findStream("WordDocument")
	if err != nil || len(word) < 0x200 {
		return ""
	}
	if binary.LittleEndian.Uint16(word[0:2]) != docFibMagic {
		return ""
	}
	flags := binary.LittleEndian.Uint16(word[10:12])
	tableName := "0Table"
	if flags&docFlagWhichTbl != 0 {
		tableName = "1Table"
	}
	table, err := r.findStream(tableName)
	if err != nil {
		return ""
	}

	fcClx := binary.LittleEndian.Uint32(word[docOffFcClx : docOffFcClx+4])
	lcbClx := binary.LittleEndian.Uint32(word[docOffLcbClx : docOffLcbClx+4])
	if lcbClx > 0 && uint64(fcClx)+uint64(lcbClx) <= uint64(len(table)) {
		if text := extractDocPieces(word, table[fcClx:fcClx+lcbClx]); text != "" {
			return text
		}
	}

	// 兜底：无有效 piece table 时按 fcMin..fcMac 整体读取
	fcMin := binary.LittleEndian.Uint32(word[docOffFcMin : docOffFcMin+4])
	fcMac := binary.LittleEndian.Uint32(word[docOffFcMac : docOffFcMac+4])
	if fcMac <= fcMin || int(fcMac) > len(word) {
		return ""
	}
	body := word[fcMin:fcMac]
	if flags&docFlagExtChar != 0 {
		return decodeDocUTF16(body)
	}
	return cp1252ToUTF8(body)
}

// extractDocPieces 解析 CLX，找到 plcpcd 后提取文本。
func extractDocPieces(word, clx []byte) string {
	pos := 0
	for pos < len(clx) {
		switch clx[pos] {
		case 0x01: // Prc：跳过
			if pos+3 > len(clx) {
				return ""
			}
			cb := int(binary.LittleEndian.Uint16(clx[pos+1 : pos+3]))
			pos += 3 + cb
		case 0x02: // Pcdt：plcpcd
			if pos+5 > len(clx) {
				return ""
			}
			lcb := int(binary.LittleEndian.Uint32(clx[pos+1 : pos+5]))
			pos += 5
			if pos+lcb > len(clx) {
				return ""
			}
			return extractFromPlcPcd(word, clx[pos:pos+lcb])
		default:
			return ""
		}
	}
	return ""
}

// extractFromPlcPcd 按 piece table 提取文本。
// plcpcd 布局：CP 数组 (n+1 个 uint32) + PCD 数组 (n 个 8 字节)。
func extractFromPlcPcd(word, plc []byte) string {
	n := (len(plc) - 4) / 12
	if n <= 0 || 4*(n+1)+8*n > len(plc) {
		return ""
	}
	pcdBase := 4 * (n + 1)
	var result strings.Builder
	for i := 0; i < n; i++ {
		cpStart := binary.LittleEndian.Uint32(plc[i*4 : i*4+4])
		cpEnd := binary.LittleEndian.Uint32(plc[(i+1)*4 : (i+1)*4+4])
		if cpEnd <= cpStart {
			continue
		}
		pcd := plc[pcdBase+i*8 : pcdBase+i*8+8]
		fc := binary.LittleEndian.Uint32(pcd[2:6])
		length := int(cpEnd - cpStart)
		if fc&0x40000000 != 0 {
			// ANSI（8 位代码页）：fc 低 30 位是字节偏移*2
			off := int64(fc&0x3FFFFFFF) / 2
			if off+int64(length) > int64(len(word)) {
				length = len(word) - int(off)
			}
			if length > 0 {
				result.WriteString(cp1252ToUTF8(word[off : off+int64(length)]))
			}
		} else {
			// Unicode（UTF-16LE）
			off := int64(fc)
			if off+int64(length)*2 > int64(len(word)) {
				length = int((int64(len(word)) - off) / 2)
			}
			if length > 0 {
				result.WriteString(decodeDocUTF16(word[off : off+int64(length)*2]))
			}
		}
	}
	return result.String()
}

// decodeDocUTF16 解码 UTF-16LE，并将 Word 的段落标记规整为换行。
func decodeDocUTF16(data []byte) string {
	var result strings.Builder
	result.Grow(len(data) / 2)
	for i := 0; i+2 <= len(data); i += 2 {
		c := rune(binary.LittleEndian.Uint16(data[i : i+2]))
		result.WriteRune(normalizeDocRune(c))
	}
	return result.String()
}

// normalizeDocRune 将 Word 内部控制字符规整为换行/空格。
func normalizeDocRune(c rune) rune {
	switch c {
	case 0x000D, 0x000B, 0x000C: // 段落标记 / 软换行 / 分页
		return '\n'
	case 0x0007: // 单元格/行结束标记
		return '\t'
	}
	return c
}

// cp1252 0x80-0x9F 区间的特殊映射（其余与 Latin-1 一致）。
var cp1252High = [32]rune{
	0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021,
	0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x008D, 0x017D, 0x008F,
	0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
	0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x009D, 0x017E, 0x0178,
}

// cp1252ToUTF8 将 Word ANSI 片段（近似按 cp1252）转为 UTF-8。
func cp1252ToUTF8(data []byte) string {
	var result strings.Builder
	result.Grow(len(data))
	for _, b := range data {
		var c rune
		if b >= 0x80 && b <= 0x9F {
			c = cp1252High[b-0x80]
		} else {
			c = rune(b)
		}
		result.WriteRune(normalizeDocRune(c))
	}
	return result.String()
}
