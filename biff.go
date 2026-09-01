package main

import (
	"encoding/binary"
	"strings"
)

// extractBiffText 从 Excel 97-2003 (.xls) 的 Workbook 流中提取文本。
// 解析 BIFF8 记录：SST（共享字符串表）、LABEL、LABELSST、STRING 等。
// 支持 SST 跨 0x003C CONTINUE 记录的场景（续段首字节为新的 option flags）。
// BIFF5/7 的 "Book" 流同样是 BIFF 记录流，传入 Book 流数据时
// 按 BOF 版本号自动降级到 BIFF5 的 LABEL/STRING 字节串格式。
func extractBiffText(data []byte) string {
	var result strings.Builder
	var sst []string
	biff5 := false

	for i := 0; i+4 <= len(data); {
		rt := binary.LittleEndian.Uint16(data[i : i+2])
		rl := binary.LittleEndian.Uint16(data[i+2 : i+4])
		if i+4+int(rl) > len(data) {
			break
		}
		payload := data[i+4 : i+4+int(rl)]
		next := i + 4 + int(rl)

		switch rt {
		case 0x0809: // BOF：根据版本号判断 BIFF8 还是 BIFF5/7（Book 流）
			if len(payload) >= 2 {
				vers := binary.LittleEndian.Uint16(payload[0:2])
				biff5 = vers < 0x0600
			}
		case 0x00FC: // SST
			// 收集紧随其后的 CONTINUE 记录，拼接成一个逻辑流
			segs := [][]byte{payload}
			j := next
			for j+4 <= len(data) {
				rt2 := binary.LittleEndian.Uint16(data[j : j+2])
				rl2 := binary.LittleEndian.Uint16(data[j+2 : j+4])
				if rt2 != 0x003C || j+4+int(rl2) > len(data) {
					break
				}
				segs = append(segs, data[j+4:j+4+int(rl2)])
				j += 4 + int(rl2)
			}
			sst = parseBIFFSSTSegments(segs)
			// 跳过已消费的 CONTINUE 记录
			next = j
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
				var text string
				if biff5 {
					// BIFF5：rw(2) col(2) ixfe(2) cch(2) + 字节串，无 grbit
					text = readBIFF5String(payload[6:])
				} else {
					text = readBIFFString(payload[6:])
				}
				if text != "" {
					result.WriteString(text)
					result.WriteByte('\n')
				}
			}
		case 0x0207: // STRING (公式结果字符串)
			var text string
			if biff5 {
				text = readBIFF5String(payload)
			} else {
				text = readBIFFString(payload)
			}
			if text != "" {
				result.WriteString(text)
				result.WriteByte('\n')
			}
		}
		i = next
	}

	return result.String()
}

// parseBIFFSST 解析共享字符串表（单记录，无 CONTINUE 的兼容入口）。
func parseBIFFSST(payload []byte) []string {
	return parseBIFFSSTSegments([][]byte{payload})
}

// parseBIFFSSTSegments 解析跨 CONTINUE 记录的共享字符串表。
// segs[0] 为 SST 记录体，其余为按序排列的 CONTINUE 记录体。
func parseBIFFSSTSegments(segs [][]byte) []string {
	if len(segs) == 0 || len(segs[0]) < 8 {
		return nil
	}
	// cstTotal (4) + cstUnique (4)
	cstUnique := binary.LittleEndian.Uint32(segs[0][4:8])
	sr := &biffSegReader{segs: segs, pos: 8}
	var result []string
	for j := 0; j < int(cstUnique); j++ {
		s, ok := sr.readString()
		if !ok {
			break
		}
		result = append(result, s)
	}
	return result
}

// biffSegReader 在多个记录体段（SST + CONTINUE）上提供连续读取视图。
type biffSegReader struct {
	segs [][]byte
	seg  int
	pos  int
}

func (r *biffSegReader) avail() int {
	if r.seg >= len(r.segs) {
		return 0
	}
	return len(r.segs[r.seg]) - r.pos
}

// nextSegment 前进到下一个 CONTINUE 段。
func (r *biffSegReader) nextSegment() bool {
	r.seg++
	r.pos = 0
	return r.seg < len(r.segs)
}

// skip 跨段跳过 n 字节（富文本 runs / 扩展数据，续段无 grbit 重读）。
func (r *biffSegReader) skip(n int) bool {
	for n > 0 {
		a := r.avail()
		if a == 0 {
			if !r.nextSegment() {
				return false
			}
			continue
		}
		if a > n {
			a = n
		}
		r.pos += a
		n -= a
	}
	return true
}

// readString 读取一个可跨 CONTINUE 段的 XLUnicodeRichExtendedString。
// 字符串字符数据跨段时，续段首字节是新的 grbit（option flags），
// 需重新判断后续字符是 8 位还是 16 位编码。
func (r *biffSegReader) readString() (string, bool) {
	if r.avail() < 3 {
		return "", false
	}
	seg := r.segs[r.seg]
	cch := binary.LittleEndian.Uint16(seg[r.pos : r.pos+2])
	grbit := seg[r.pos+2]
	r.pos += 3

	var cRun, cbExtRst int
	if grbit&0x08 != 0 { // fRichSt
		if r.avail() < 2 {
			return "", false
		}
		cRun = int(binary.LittleEndian.Uint16(r.segs[r.seg][r.pos : r.pos+2]))
		r.pos += 2
	}
	if grbit&0x04 != 0 { // fExtSt
		if r.avail() < 4 {
			return "", false
		}
		cbExtRst = int(binary.LittleEndian.Uint32(r.segs[r.seg][r.pos : r.pos+4]))
		r.pos += 4
	}

	unicode := grbit&0x01 != 0
	var result strings.Builder
	result.Grow(int(cch))
	remaining := int(cch)
	for remaining > 0 {
		if r.avail() == 0 {
			if !r.nextSegment() {
				return result.String(), false
			}
			// 续段首字节为新的 option flags
			if r.avail() < 1 {
				return result.String(), false
			}
			grbit = r.segs[r.seg][r.pos]
			r.pos++
			unicode = grbit&0x01 != 0
			continue
		}
		charSize := 1
		if unicode {
			charSize = 2
		}
		n := r.avail() / charSize
		if n > remaining {
			n = remaining
		}
		if n == 0 {
			// 罕见边界：Unicode 字符的 2 字节被拆到两个段。
			// 低字节已在本段末尾，高字节在下一段 grbit 之后。
			lo := r.segs[r.seg][r.pos]
			if !r.nextSegment() || r.avail() < 2 {
				return result.String(), false
			}
			grbit = r.segs[r.seg][r.pos]
			r.pos++ // 续段 grbit
			hi := r.segs[r.seg][r.pos]
			r.pos++
			result.WriteRune(rune(uint16(lo) | uint16(hi)<<8))
			unicode = grbit&0x01 != 0
			remaining--
			continue
		}
		seg = r.segs[r.seg]
		if unicode {
			for k := 0; k < n; k++ {
				result.WriteRune(rune(binary.LittleEndian.Uint16(seg[r.pos : r.pos+2])))
				r.pos += 2
			}
		} else {
			for k := 0; k < n; k++ {
				result.WriteByte(seg[r.pos])
				r.pos++
			}
		}
		remaining -= n
	}

	// 跳过富文本格式 runs 与扩展数据（这部分跨段时无 grbit）
	if cRun > 0 && !r.skip(cRun*4) {
		return result.String(), false
	}
	if cbExtRst > 0 && !r.skip(cbExtRst) {
		return result.String(), false
	}
	return result.String(), true
}

// readBIFFString 读取一个 BIFF8 字符串。
func readBIFFString(data []byte) string {
	s, _ := readBIFFStringWithPos(data)
	return s
}

// readBIFF5String 读取 BIFF5/7 的字节串（cch(2) + 代码页字节，无 grbit）。
func readBIFF5String(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	cch := int(binary.LittleEndian.Uint16(data[0:2]))
	if 2+cch > len(data) {
		cch = len(data) - 2
	}
	var result strings.Builder
	result.Grow(cch)
	for _, b := range data[2 : 2+cch] {
		result.WriteRune(rune(b))
	}
	return result.String()
}

// readBIFFStringWithPos 读取 BIFF8 字符串并返回读取的字节数。
func readBIFFStringWithPos(data []byte) (string, int) {
	if len(data) < 3 {
		return "", 0
	}
	cch := binary.LittleEndian.Uint16(data[0:2])
	grbit := data[2]
	pos := 3

	// fRichSt: cRun(2)；fExtSt: cbExtRst(4)
	if grbit&0x08 != 0 {
		if pos+2 > len(data) {
			return "", 0
		}
		pos += 2
	}
	if grbit&0x04 != 0 {
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
