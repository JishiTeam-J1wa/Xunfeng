package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// 最小化 OLE Compound File 解析器，用于提取指定命名流的内容。
// 仅支持常见 512 字节扇区、 Little Endian 的 Office 旧格式文件。

type oleReader struct {
	data       []byte
	sectorSize int
	fat        []uint32
}

func newOLEReader(path string) (*oleReader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	// 最多读取 32MB，避免超大文件拖慢
	size := info.Size()
	const maxOLE = 32 << 20
	if size > maxOLE {
		size = maxOLE
	}
	data := make([]byte, size)
	_, err = io.ReadFull(f, data)
	if err != nil && err != io.ErrUnexpectedEOF {
		return nil, err
	}

	// 签名检查：D0 CF 11 E0 A1 B1 1A E1
	if len(data) < 512 || data[0] != 0xD0 || data[1] != 0xCF || data[2] != 0x11 || data[3] != 0xE0 {
		return nil, fmt.Errorf("not an OLE compound file")
	}

	sectorShift := binary.LittleEndian.Uint16(data[30:32])
	sectorSize := 1 << sectorShift
	if sectorSize != 512 && sectorSize != 4096 {
		return nil, fmt.Errorf("unsupported sector size %d", sectorSize)
	}

	r := &oleReader{data: data, sectorSize: sectorSize}
	r.fat = r.readFAT()
	return r, nil
}

func (r *oleReader) readSector(sector uint32) []byte {
	off := int64(sector+1) * int64(r.sectorSize)
	if off+int64(r.sectorSize) > int64(len(r.data)) {
		return nil
	}
	return r.data[off : off+int64(r.sectorSize)]
}

func (r *oleReader) readStream(startSector uint32, size uint64) []byte {
	if startSector == 0xFFFFFFFE {
		return nil
	}
	var out []byte
	seen := make(map[uint32]struct{})
	sec := startSector
	for {
		if _, ok := seen[sec]; ok {
			break
		}
		seen[sec] = struct{}{}
		buf := r.readSector(sec)
		if buf == nil {
			break
		}
		out = append(out, buf...)
		if int(sec) >= len(r.fat) {
			break
		}
		next := r.fat[sec]
		if next == 0xFFFFFFFF || next == 0xFFFFFFFE {
			break
		}
		sec = next
	}
	if uint64(len(out)) > size {
		out = out[:size]
	}
	return out
}

func (r *oleReader) readFAT() []uint32 {
	// FAT 扇区号列表在头中最多 109 个
	const maxFatSectors = 109
	fatSectors := make([]uint32, 0, maxFatSectors)
	for i := 0; i < maxFatSectors; i++ {
		off := 76 + i*4
		if off+4 > len(r.data) {
			break
		}
		s := binary.LittleEndian.Uint32(r.data[off : off+4])
		if s == 0xFFFFFFFF {
			break
		}
		fatSectors = append(fatSectors, s)
	}

	var fat []uint32
	for _, sec := range fatSectors {
		buf := r.readSector(sec)
		if buf == nil {
			break
		}
		for i := 0; i < r.sectorSize; i += 4 {
			if i+4 > len(buf) {
				break
			}
			fat = append(fat, binary.LittleEndian.Uint32(buf[i:i+4]))
		}
	}
	return fat
}

func (r *oleReader) findStream(name string) ([]byte, error) {
	// 目录流默认从根目录入口读取
	// 根目录是目录流的第一个条目，其 starting sector 指向目录流本身
	if len(r.data) < 512 {
		return nil, fmt.Errorf("data too short")
	}
	dirStart := binary.LittleEndian.Uint32(r.data[48:52])
	dirStream := r.readStream(dirStart, 1<<60)
	if dirStream == nil {
		return nil, fmt.Errorf("failed to read directory stream")
	}

	entrySize := 128
	for i := 0; i+entrySize <= len(dirStream); i += entrySize {
		entry := dirStream[i : i+entrySize]
		// 名称长度（UTF-16LE 字节数）
		nameLen := binary.LittleEndian.Uint16(entry[64:66])
		if nameLen == 0 || nameLen > 64 {
			continue
		}
		// 转换名称为 UTF-8
		var entryName stringsBuilder
		for j := 0; j < int(nameLen)-2 && j+1 < 64; j += 2 {
			c := binary.LittleEndian.Uint16(entry[j : j+2])
			if c == 0 {
				break
			}
			entryName.WriteRune(rune(c))
		}
		if entryName.String() == name {
			streamSize := binary.LittleEndian.Uint64(entry[120:128])
			startSec := binary.LittleEndian.Uint32(entry[116:120])
			return r.readStream(startSec, streamSize), nil
		}
	}
	return nil, fmt.Errorf("stream %q not found", name)
}

// stringsBuilder 避免额外 import strings
type stringsBuilder struct {
	buf []byte
}

func (b *stringsBuilder) WriteRune(r rune) {
	if r < 0x80 {
		b.buf = append(b.buf, byte(r))
	} else if r < 0x800 {
		b.buf = append(b.buf, byte(0xC0|r>>6), byte(0x80|r&0x3F))
	} else {
		b.buf = append(b.buf, byte(0xE0|r>>12), byte(0x80|(r>>6)&0x3F), byte(0x80|r&0x3F))
	}
}

func (b *stringsBuilder) String() string { return string(b.buf) }
