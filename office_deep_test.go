package main

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// ---------- 测试辅助：构造 OLE / BIFF 二进制样本 ----------

func putU16(b []byte, off int, v uint16) { binary.LittleEndian.PutUint16(b[off:], v) }
func putU32(b []byte, off int, v uint32) { binary.LittleEndian.PutUint32(b[off:], v) }
func putU64(b []byte, off int, v uint64) { binary.LittleEndian.PutUint64(b[off:], v) }

type testOLEStream struct {
	name string
	data []byte
	mini bool // 是否走 mini-stream
}

// buildTestOLE 构造一个 512 字节扇区的 OLE 复合文档样本。
// mini 流通过 miniFAT + Root Entry 容器存放，其余走常规 FAT 链。
func buildTestOLE(t *testing.T, streams []testOLEStream) []byte {
	t.Helper()
	const (
		ss       = 512
		miniSize = 64
		endOf    = 0xFFFFFFFE
		free     = 0xFFFFFFFF
		fatSect  = 0xFFFFFFFD
	)

	nEntries := 1 + len(streams)
	dirSectors := (nEntries*128 + ss - 1) / ss

	// mini 流布局
	type miniInfo struct{ start int }
	miniInfos := map[int]miniInfo{}
	var miniContainer []byte
	var miniFATEntries []uint32
	for idx, s := range streams {
		if !s.mini {
			continue
		}
		n := (len(s.data) + miniSize - 1) / miniSize
		if n == 0 {
			n = 1
		}
		start := len(miniFATEntries)
		for k := 0; k < n; k++ {
			next := uint32(start + k + 1)
			if k == n-1 {
				next = endOf
			}
			miniFATEntries = append(miniFATEntries, next)
		}
		miniContainer = append(miniContainer, s.data...)
		miniContainer = append(miniContainer, make([]byte, n*miniSize-len(s.data))...)
		miniInfos[idx] = miniInfo{start}
	}
	miniContainerSectors := (len(miniContainer) + ss - 1) / ss
	miniFATSectors := 0
	if len(miniFATEntries) > 0 {
		miniFATSectors = (len(miniFATEntries)*4 + ss - 1) / ss
	}

	// big 流扇区数
	bigSectors := map[int]int{}
	totalBig := 0
	for idx, s := range streams {
		if s.mini {
			continue
		}
		n := (len(s.data) + ss - 1) / ss
		bigSectors[idx] = n
		totalBig += n
	}

	// FAT 扇区数（含 FAT 扇区自身，迭代收敛）
	fatSectors := 1
	for {
		need := dirSectors + miniFATSectors + miniContainerSectors + totalBig + fatSectors
		fs := (need + 127) / 128
		if fs == fatSectors {
			break
		}
		fatSectors = fs
	}
	if fatSectors > 109 {
		t.Fatalf("test OLE too large: %d FAT sectors", fatSectors)
	}

	totalSectors := dirSectors + miniFATSectors + miniContainerSectors + totalBig + fatSectors

	chain := func(fat []uint32, start, n int) {
		for k := 0; k < n; k++ {
			next := uint32(start + k + 1)
			if k == n-1 {
				next = endOf
			}
			fat[start+k] = next
		}
	}

	fat := make([]uint32, fatSectors*128)
	for i := range fat {
		fat[i] = free
	}
	chain(fat, 0, dirSectors)
	sec := dirSectors
	miniFATStart := sec
	chain(fat, sec, miniFATSectors)
	sec += miniFATSectors
	miniContainerStart := sec
	chain(fat, sec, miniContainerSectors)
	sec += miniContainerSectors
	bigStart := map[int]int{}
	for idx, s := range streams {
		if s.mini {
			continue
		}
		bigStart[idx] = sec
		chain(fat, sec, bigSectors[idx])
		sec += bigSectors[idx]
	}
	fatStart := sec
	for k := 0; k < fatSectors; k++ {
		fat[fatStart+k] = fatSect
	}

	// 组装文件
	out := make([]byte, ss*(1+totalSectors))
	sectorBuf := func(n int) []byte { return out[ss*(1+n) : ss*(2+n)] }

	// 头
	copy(out[0:8], []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1})
	putU16(out, 24, 0x003E) // minor version
	putU16(out, 26, 0x0003) // major version (v3, 512 扇区)
	putU16(out, 28, 0xFFFE) // byte order
	putU16(out, 30, 9)      // sector shift
	putU16(out, 32, 6)      // mini sector shift
	putU32(out, 40, 0)      // num dir sectors (v3 必须为 0)
	putU32(out, 44, uint32(fatSectors))
	putU32(out, 48, 0) // first dir sector
	putU32(out, 56, 4096)
	if miniFATSectors > 0 {
		putU32(out, 60, uint32(miniFATStart))
	} else {
		putU32(out, 60, endOf)
	}
	putU32(out, 64, uint32(miniFATSectors))
	putU32(out, 68, endOf) // first DIFAT sector
	putU32(out, 72, 0)     // num DIFAT sectors
	for i := 0; i < 109; i++ {
		if i < fatSectors {
			putU32(out, 76+i*4, uint32(fatStart+i))
		} else {
			putU32(out, 76+i*4, free)
		}
	}

	// 目录流
	dir := make([]byte, dirSectors*ss)
	writeEntry := func(idx int, name string, objType byte, start uint32, size uint64) {
		e := dir[idx*128 : (idx+1)*128]
		for j, c := range name {
			putU16(e, j*2, uint16(c))
		}
		putU16(e, 64, uint16(len(name)*2+2))
		e[66] = objType
		e[67] = 1 // color
		putU32(e, 68, free)
		putU32(e, 72, free)
		putU32(e, 76, free)
		putU32(e, 116, start)
		putU64(e, 120, size)
	}
	rootStart := uint32(endOf)
	if miniContainerSectors > 0 {
		rootStart = uint32(miniContainerStart)
	}
	writeEntry(0, "Root Entry", 5, rootStart, uint64(len(miniContainer)))
	for idx, s := range streams {
		start := uint32(endOf)
		if s.mini {
			start = uint32(miniInfos[idx].start)
		} else if bigSectors[idx] > 0 {
			start = uint32(bigStart[idx])
		}
		writeEntry(idx+1, s.name, 2, start, uint64(len(s.data)))
	}
	for k := 0; k < dirSectors; k++ {
		copy(sectorBuf(k), dir[k*ss:(k+1)*ss])
	}

	// miniFAT
	for k := 0; k < miniFATSectors; k++ {
		buf := sectorBuf(miniFATStart + k)
		for i := 0; i < 128; i++ {
			idx := k*128 + i
			v := uint32(free)
			if idx < len(miniFATEntries) {
				v = miniFATEntries[idx]
			}
			putU32(buf, i*4, v)
		}
	}
	// mini 容器
	for k := 0; k < miniContainerSectors; k++ {
		copy(sectorBuf(miniContainerStart+k), miniContainer[k*ss:])
	}
	// big 流
	for idx, s := range streams {
		if s.mini {
			continue
		}
		for k := 0; k < bigSectors[idx]; k++ {
			buf := sectorBuf(bigStart[idx] + k)
			lo := k * ss
			hi := lo + ss
			if hi > len(s.data) {
				hi = len(s.data)
			}
			copy(buf, s.data[lo:hi])
		}
	}
	// FAT
	for k := 0; k < fatSectors; k++ {
		buf := sectorBuf(fatStart + k)
		for i := 0; i < 128; i++ {
			putU32(buf, i*4, fat[k*128+i])
		}
	}
	return out
}

func biffRecord(rt uint16, payload []byte) []byte {
	rec := make([]byte, 4+len(payload))
	putU16(rec, 0, rt)
	putU16(rec, 2, uint16(len(payload)))
	copy(rec[4:], payload)
	return rec
}

// ---------- OLE：mini-stream 读取 ----------

func TestOLEMiniStreamRead(t *testing.T) {
	// 小流内容跨多个 64 字节 mini 扇区（200 字节 -> 4 个 mini 扇区）
	small := []byte("API_KEY=mini-stream-secret-" + strings.Repeat("x", 173))
	// 大流走常规 FAT（>4096 字节）
	big := []byte("BIGSTREAM:" + strings.Repeat("y", 5000))

	data := buildTestOLE(t, []testOLEStream{
		{name: "Small1", data: small, mini: true},
		{name: "Big1", data: big, mini: false},
	})

	r, err := newOLEReaderFromBytes(data)
	if err != nil {
		t.Fatalf("newOLEReaderFromBytes: %v", err)
	}
	got, err := r.findStream("Small1")
	if err != nil {
		t.Fatalf("findStream(Small1): %v", err)
	}
	if !bytes.Equal(got, small) {
		t.Fatalf("mini-stream 内容不匹配：got %d bytes, want %d bytes", len(got), len(small))
	}
	gotBig, err := r.findStream("Big1")
	if err != nil {
		t.Fatalf("findStream(Big1): %v", err)
	}
	if !bytes.Equal(gotBig, big) {
		t.Fatalf("big stream 内容不匹配：got %d bytes, want %d bytes", len(gotBig), len(big))
	}
}

// ---------- OLE：DIFAT 链遍历 ----------

func TestOLEDIFATChain(t *testing.T) {
	const ss = 512
	// 布局：
	//   sector 0   目录
	//   sector 1   FAT-A（头部 DIFAT 指向，覆盖 sector 0..127）
	//   sector 2   FAT-B（仅能通过 DIFAT 链到达，覆盖 sector 128..255）
	//   sector 3   DIFAT 扇区
	//   sector 128..135  大流数据（8 扇区 = 4096 字节，不小于 mini cutoff）
	totalSectors := 136
	out := make([]byte, ss*(1+totalSectors))
	sectorBuf := func(n int) []byte { return out[ss*(1+n) : ss*(2+n)] }

	copy(out[0:8], []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1})
	putU16(out, 24, 0x003E)
	putU16(out, 26, 0x0003)
	putU16(out, 28, 0xFFFE)
	putU16(out, 30, 9)
	putU16(out, 32, 6)
	putU32(out, 44, 2) // 2 个 FAT 扇区
	putU32(out, 48, 0) // 目录从 sector 0 开始
	putU32(out, 56, 4096)
	putU32(out, 60, 0xFFFFFFFE) // 无 miniFAT
	putU32(out, 64, 0)
	putU32(out, 68, 3) // 第一个 DIFAT 扇区
	putU32(out, 72, 1) // 1 个 DIFAT 扇区
	putU32(out, 76, 1) // 头部 DIFAT[0] = FAT-A
	for i := 1; i < 109; i++ {
		putU32(out, 76+i*4, 0xFFFFFFFF)
	}

	// 目录：Root Entry + Big 流
	dir := sectorBuf(0)
	writeEntry := func(idx int, name string, objType byte, start uint32, size uint64) {
		e := dir[idx*128 : (idx+1)*128]
		for j, c := range name {
			putU16(e, j*2, uint16(c))
		}
		putU16(e, 64, uint16(len(name)*2+2))
		e[66] = objType
		putU32(e, 68, 0xFFFFFFFF)
		putU32(e, 72, 0xFFFFFFFF)
		putU32(e, 76, 0xFFFFFFFF)
		putU32(e, 116, start)
		putU64(e, 120, size)
	}
	writeEntry(0, "Root Entry", 5, 0xFFFFFFFE, 0)
	writeEntry(1, "Big", 2, 128, 4096)

	// FAT-A：sector 0..127
	fatA := sectorBuf(1)
	for i := 0; i < 128; i++ {
		putU32(fatA, i*4, 0xFFFFFFFF)
	}
	putU32(fatA, 0, 0xFFFFFFFE) // 目录 ENDOFCHAIN
	putU32(fatA, 1*4, 0xFFFFFFFD)
	putU32(fatA, 2*4, 0xFFFFFFFD)
	putU32(fatA, 3*4, 0xFFFFFFFC) // DIFAT 扇区标记
	// FAT-B：sector 128..255，流数据链 128->129->...->135->END
	fatB := sectorBuf(2)
	for i := 0; i < 128; i++ {
		putU32(fatB, i*4, 0xFFFFFFFF)
	}
	for s := 128; s < 135; s++ {
		putU32(fatB, (s-128)*4, uint32(s+1))
	}
	putU32(fatB, (135-128)*4, 0xFFFFFFFE)
	// DIFAT 扇区：第一个指针指向 FAT-B，末尾指向 ENDOFCHAIN
	difat := sectorBuf(3)
	for i := 0; i < 127; i++ {
		putU32(difat, i*4, 0xFFFFFFFF)
	}
	putU32(difat, 0, 2)
	putU32(difat, 127*4, 0xFFFFFFFE)

	// 流数据
	want := make([]byte, 4096)
	for i := range want {
		want[i] = byte(i % 251)
	}
	copy(want, "DIFAT-CHAIN-SECRET")
	for s := 128; s < 136; s++ {
		copy(sectorBuf(s), want[(s-128)*ss:(s-127)*ss])
	}

	r, err := newOLEReaderFromBytes(out)
	if err != nil {
		t.Fatalf("newOLEReaderFromBytes: %v", err)
	}
	got, err := r.findStream("Big")
	if err != nil {
		t.Fatalf("findStream(Big): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("DIFAT 链读取内容不匹配：got %d bytes, want %d bytes", len(got), len(want))
	}
}

// ---------- BIFF：SST 跨 CONTINUE 拼接（含 option flags 重读） ----------

func TestBIFFContinueSST(t *testing.T) {
	var wb []byte
	// BOF：BIFF8
	bof := make([]byte, 16)
	putU16(bof, 0, 0x0600)
	wb = append(wb, biffRecord(0x0809, bof)...)

	// SST：cstTotal=2, cstUnique=2
	// 字符串 1 "secret"：前 4 个字符 "secr" 在 SST 记录内（8 位编码），
	// 剩余 "et" 在 CONTINUE 中，续段 grbit=0x01 切换为 16 位 Unicode。
	sst := make([]byte, 8)
	putU32(sst, 0, 2)
	putU32(sst, 4, 2)
	sst = append(sst, 0x06, 0x00, 0x00) // cch=6, grbit=0（8 位）
	sst = append(sst, 's', 'e', 'c', 'r')
	wb = append(wb, biffRecord(0x00FC, sst)...)

	// CONTINUE：grbit=0x01（16 位）+ "et" UTF-16LE + 字符串 2 "key" 完整头部
	cont := []byte{0x01, 'e', 0x00, 't', 0x00}
	cont = append(cont, 0x03, 0x00, 0x00) // cch=3, grbit=0（8 位）
	cont = append(cont, 'k', 'e', 'y')
	wb = append(wb, biffRecord(0x003C, cont)...)

	// 两个 LABELSST 引用
	for _, idx := range []uint32{0, 1} {
		payload := make([]byte, 10)
		putU32(payload, 6, idx)
		wb = append(wb, biffRecord(0x00FD, payload)...)
	}
	wb = append(wb, biffRecord(0x000A, nil)...) // EOF

	got := extractBiffText(wb)
	want := "secret\nkey\n"
	if got != want {
		t.Fatalf("extractBiffText = %q, want %q", got, want)
	}
}

// ---------- BIFF5/7 "Book" 流兼容 ----------

func TestBIFF5BookStream(t *testing.T) {
	var wb []byte
	// BOF：BIFF5
	bof := make([]byte, 16)
	putU16(bof, 0, 0x0500)
	wb = append(wb, biffRecord(0x0809, bof)...)

	// BIFF5 LABEL：rw(2) col(2) ixfe(2) cch(2) + 字节串（无 grbit）
	payload := make([]byte, 8)
	putU16(payload, 6, 5)
	payload = append(payload, 't', 'o', 'k', 'e', 'n')
	wb = append(wb, biffRecord(0x0204, payload)...)
	wb = append(wb, biffRecord(0x000A, nil)...)

	got := extractBiffText(wb)
	if got != "token\n" {
		t.Fatalf("extractBiffText(BIFF5) = %q, want %q", got, "token\n")
	}
}

// ---------- .doc：FIB + piece table 提取（ANSI/Unicode 混合） ----------

func TestExtractDocTextPieceTable(t *testing.T) {
	// WordDocument 流（1024 字节，走 mini-stream）
	word := make([]byte, 0x400)
	putU16(word, 0, 0xA5EC)  // FIB magic
	putU16(word, 10, 0x0200) // fWhichTblStm -> 1Table

	ansi := "password="
	uni := "密钥123"
	copy(word[0x200:], ansi)
	i := 0
	for _, c := range uni {
		putU16(word, 0x300+i*2, uint16(c))
		i++
	}

	// piece table：2 个片段
	//   CP [0, 9, 14]
	//   piece0：ANSI，fc = (0x200*2) | 0x40000000
	//   piece1：Unicode，fc = 0x300
	plc := make([]byte, 4*3+8*2)
	putU32(plc, 0, 0)
	putU32(plc, 4, 9)
	putU32(plc, 8, 14)
	putU32(plc, 12+2, 0x40000000|0x200*2)
	putU32(plc, 20+2, 0x300)

	clx := []byte{0x02, 0, 0, 0, 0}
	putU32(clx, 1, uint32(len(plc)))
	clx = append(clx, plc...)

	putU32(word, 0x01A2, 0)              // fcClx
	putU32(word, 0x01A6, uint32(len(clx))) // lcbClx

	data := buildTestOLE(t, []testOLEStream{
		{name: "WordDocument", data: word, mini: true},
		{name: "1Table", data: clx, mini: true},
	})

	got := ExtractDocText(data)
	want := "password=密钥123"
	if got != want {
		t.Fatalf("ExtractDocText = %q, want %q", got, want)
	}
}

func TestExtractDocTextInvalid(t *testing.T) {
	if got := ExtractDocText([]byte("not an ole file at all")); got != "" {
		t.Fatalf("ExtractDocText(garbage) = %q, want empty", got)
	}
}
