package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// 最小化 OLE Compound File 解析器，用于提取指定命名流的内容。
// 支持 512/4096 字节扇区、Little Endian 的 Office 旧格式文件。
// 支持 DIFAT 链（超过头部 109 个 FAT 扇区指针的大文件）以及
// mini-stream（小于 4096 字节的流存放在 Root Entry 的 mini 流容器中，
// 通过 miniFAT 扇区链索引）。

const (
	oleEndOfChain  = 0xFFFFFFFE
	oleFreeSector  = 0xFFFFFFFF
	oleFATSector   = 0xFFFFFFFD
	oleDIFATSector = 0xFFFFFFFC
	// 小于该值的流走 mini-stream（头部 Mini Stream Cutoff Size，通常 4096）
	oleDefaultMiniCutoff = 4096
)

type oleReader struct {
	data          []byte
	sectorSize    int
	miniSecSize   int
	miniCutoff    uint64
	fat           []uint32
	miniFAT       []uint32
	miniStream    []byte
	rootStartSec  uint32
	rootStreamLen uint64
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
	return newOLEReaderFromBytes(data)
}

// newOLEReaderFromBytes 从内存数据构造解析器，便于测试。
func newOLEReaderFromBytes(data []byte) (*oleReader, error) {
	// 签名检查：D0 CF 11 E0 A1 B1 1A E1
	if len(data) < 512 || data[0] != 0xD0 || data[1] != 0xCF || data[2] != 0x11 || data[3] != 0xE0 {
		return nil, fmt.Errorf("not an OLE compound file")
	}

	sectorShift := binary.LittleEndian.Uint16(data[30:32])
	sectorSize := 1 << sectorShift
	if sectorSize != 512 && sectorSize != 4096 {
		return nil, fmt.Errorf("unsupported sector size %d", sectorSize)
	}
	miniShift := binary.LittleEndian.Uint16(data[32:34])
	miniSecSize := 1 << miniShift
	if miniSecSize <= 0 || miniSecSize > sectorSize {
		miniSecSize = 64
	}
	miniCutoff := uint64(binary.LittleEndian.Uint32(data[56:60]))
	if miniCutoff == 0 {
		miniCutoff = oleDefaultMiniCutoff
	}

	r := &oleReader{
		data:        data,
		sectorSize:  sectorSize,
		miniSecSize: miniSecSize,
		miniCutoff:  miniCutoff,
	}
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

// readStream 读取常规 FAT 扇区链。
func (r *oleReader) readStream(startSector uint32, size uint64) []byte {
	return r.readChain(startSector, size, r.fat, r.sectorSize, r.readSector)
}

// readChain 是扇区链读取的通用实现。
func (r *oleReader) readChain(startSector uint32, size uint64, chainTable []uint32, blockSize int, readBlock func(uint32) []byte) []byte {
	if startSector == oleEndOfChain || startSector == oleFreeSector {
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
		buf := readBlock(sec)
		if buf == nil {
			break
		}
		out = append(out, buf...)
		if uint64(len(out)) >= size {
			break
		}
		if int(sec) >= len(chainTable) {
			break
		}
		next := chainTable[sec]
		if next == oleFreeSector || next == oleEndOfChain || next == oleFATSector || next == oleDIFATSector {
			break
		}
		sec = next
	}
	if uint64(len(out)) > size {
		out = out[:size]
	}
	return out
}

// readMiniStream 通过 miniFAT 读取 mini 流容器中的小流。
func (r *oleReader) readMiniStream(startSector uint32, size uint64) []byte {
	if size == 0 {
		return nil
	}
	if r.miniStream == nil {
		r.loadMiniStream()
	}
	if r.miniStream == nil || r.miniFAT == nil {
		return nil
	}
	return r.readChain(startSector, size, r.miniFAT, r.miniSecSize, func(sec uint32) []byte {
		off := int64(sec) * int64(r.miniSecSize)
		if off+int64(r.miniSecSize) > int64(len(r.miniStream)) {
			return nil
		}
		return r.miniStream[off : off+int64(r.miniSecSize)]
	})
}

// loadMiniStream 加载 miniFAT 与 mini 流容器（Root Entry 的流）。
func (r *oleReader) loadMiniStream() {
	if len(r.data) < 512 {
		return
	}
	miniFATStart := binary.LittleEndian.Uint32(r.data[60:64])
	miniFATSectors := binary.LittleEndian.Uint32(r.data[64:68])
	if miniFATStart != oleEndOfChain && miniFATStart != oleFreeSector && miniFATSectors > 0 {
		buf := r.readStream(miniFATStart, uint64(miniFATSectors)*uint64(r.sectorSize))
		for i := 0; i+4 <= len(buf); i += 4 {
			r.miniFAT = append(r.miniFAT, binary.LittleEndian.Uint32(buf[i:i+4]))
		}
	}
	r.miniStream = r.readStream(r.rootStartSec, r.rootStreamLen)
}

// readFAT 读取 FAT。先取头部 109 个 DIFAT 指针，
// 若头部声明了 DIFAT 链（offset 68），继续沿 DIFAT 扇区遍历。
func (r *oleReader) readFAT() []uint32 {
	const headerDIFAT = 109
	fatSectors := make([]uint32, 0, headerDIFAT)
	for i := 0; i < headerDIFAT; i++ {
		off := 76 + i*4
		if off+4 > len(r.data) {
			break
		}
		s := binary.LittleEndian.Uint32(r.data[off : off+4])
		if s == oleFreeSector {
			break
		}
		if s == oleEndOfChain {
			continue
		}
		fatSectors = append(fatSectors, s)
	}

	// DIFAT 链：每个 DIFAT 扇区包含 (sectorSize/4 - 1) 个 FAT 扇区指针，
	// 最后一个 uint32 指向下一个 DIFAT 扇区。
	if len(r.data) >= 76 {
		difatSec := binary.LittleEndian.Uint32(r.data[68:72])
		difatCount := binary.LittleEndian.Uint32(r.data[72:76])
		seen := make(map[uint32]struct{})
		entriesPerSector := r.sectorSize/4 - 1
		for difatSec != oleEndOfChain && difatSec != oleFreeSector && difatCount > 0 {
			if _, ok := seen[difatSec]; ok {
				break
			}
			seen[difatSec] = struct{}{}
			buf := r.readSector(difatSec)
			if buf == nil {
				break
			}
			for i := 0; i < entriesPerSector; i++ {
				s := binary.LittleEndian.Uint32(buf[i*4 : i*4+4])
				if s == oleFreeSector {
					continue
				}
				fatSectors = append(fatSectors, s)
			}
			difatSec = binary.LittleEndian.Uint32(buf[entriesPerSector*4:])
			difatCount--
		}
	}

	var fat []uint32
	for _, sec := range fatSectors {
		buf := r.readSector(sec)
		if buf == nil {
			break
		}
		for i := 0; i+4 <= len(buf); i += 4 {
			fat = append(fat, binary.LittleEndian.Uint32(buf[i:i+4]))
		}
	}
	return fat
}

// oleDirEntry 是目录条目中与流定位相关的字段。
type oleDirEntry struct {
	name     string
	startSec uint32
	size     uint64
	isRoot   bool
}

// readDirEntries 读取目录流中的所有条目，同时记录 Root Entry 的流信息
//（Root Entry 的流即 mini 流容器）。
func (r *oleReader) readDirEntries() ([]oleDirEntry, error) {
	if len(r.data) < 512 {
		return nil, fmt.Errorf("data too short")
	}
	dirStart := binary.LittleEndian.Uint32(r.data[48:52])
	dirStream := r.readStream(dirStart, 1<<60)
	if dirStream == nil {
		return nil, fmt.Errorf("failed to read directory stream")
	}

	const entrySize = 128
	var entries []oleDirEntry
	for i := 0; i+entrySize <= len(dirStream); i += entrySize {
		entry := dirStream[i : i+entrySize]
		// 名称长度（UTF-16LE 字节数，含结尾 NUL）
		nameLen := binary.LittleEndian.Uint16(entry[64:66])
		objType := entry[66]
		if nameLen == 0 || nameLen > 64 {
			continue
		}
		var entryName stringsBuilder
		for j := 0; j < int(nameLen)-2 && j+1 < 64; j += 2 {
			c := binary.LittleEndian.Uint16(entry[j : j+2])
			if c == 0 {
				break
			}
			entryName.WriteRune(rune(c))
		}
		e := oleDirEntry{
			name:     entryName.String(),
			startSec: binary.LittleEndian.Uint32(entry[116:120]),
			size:     binary.LittleEndian.Uint64(entry[120:128]),
			isRoot:   objType == 5,
		}
		// v3（512 字节扇区）文件的高 32 位大小必须为 0
		if r.sectorSize == 512 {
			e.size &= 0xFFFFFFFF
		}
		entries = append(entries, e)
		if e.isRoot {
			r.rootStartSec = e.startSec
			r.rootStreamLen = e.size
		}
	}
	return entries, nil
}

func (r *oleReader) findStream(name string) ([]byte, error) {
	entries, err := r.readDirEntries()
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.name != name {
			continue
		}
		// 小于 cutoff 的流存放在 mini-stream 中
		if e.size < r.miniCutoff && !e.isRoot {
			return r.readMiniStream(e.startSec, e.size), nil
		}
		return r.readStream(e.startSec, e.size), nil
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
