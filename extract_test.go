package main

import (
	"archive/zip"
	"bytes"
	"compress/zlib"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildTestPDF 构造一个包含 FlateDecode 内容流的最小 PDF
func buildTestPDF(t *testing.T, contentStream []byte) []byte {
	t.Helper()
	var compressed bytes.Buffer
	zw := zlib.NewWriter(&compressed)
	if _, err := zw.Write(contentStream); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}
	var pdf bytes.Buffer
	pdf.WriteString("%PDF-1.4\n")
	fmt.Fprintf(&pdf, "1 0 obj\n<< /Length %d /Filter /FlateDecode >>\nstream\n", compressed.Len())
	pdf.Write(compressed.Bytes())
	pdf.WriteString("\nendstream\nendobj\n%%EOF\n")
	return pdf.Bytes()
}

func TestExtractPDFTextLiteralTj(t *testing.T) {
	pdf := buildTestPDF(t, []byte(`BT /F1 12 Tf 72 720 Td (Hello \(World\)) Tj ET`))
	text := ExtractPDFText(pdf)
	if !strings.Contains(text, "Hello (World)") {
		t.Errorf("expected 'Hello (World)', got %q", text)
	}
}

func TestExtractPDFTextOctalEscape(t *testing.T) {
	// \110\145\154\154\157 = "Hello"
	pdf := buildTestPDF(t, []byte(`BT (\110\145\154\154\157) Tj ET`))
	text := ExtractPDFText(pdf)
	if !strings.Contains(text, "Hello") {
		t.Errorf("expected 'Hello', got %q", text)
	}
}

func TestExtractPDFTextTJArray(t *testing.T) {
	pdf := buildTestPDF(t, []byte(`BT [(pass) 120 (word) -50 (=) 0 (secret123)] TJ ET`))
	text := ExtractPDFText(pdf)
	for _, want := range []string{"pass", "word", "=", "secret123"} {
		if !strings.Contains(text, want) {
			t.Errorf("expected %q in %q", want, text)
		}
	}
}

func TestExtractPDFTextUTF16BE(t *testing.T) {
	// BOM 0xFEFF + "密钥" 的 UTF-16BE 编码（0x5BC6 0x94A5）
	var cs bytes.Buffer
	cs.WriteString("BT (")
	cs.Write([]byte{0xFE, 0xFF, 0x5B, 0xC6, 0x94, 0xA5})
	cs.WriteString(") Tj ET")
	pdf := buildTestPDF(t, cs.Bytes())
	text := ExtractPDFText(pdf)
	if !strings.Contains(text, "密钥") {
		t.Errorf("expected UTF-16BE text '密钥', got %q", text)
	}
}

func TestExtractPDFTextRawStream(t *testing.T) {
	// 未压缩（无 /FlateDecode）的内容流也应提取
	pdf := []byte("%PDF-1.4\n1 0 obj\n<< /Length 20 >>\nstream\nBT (RawText) Tj ET\nendstream\nendobj\n%%EOF\n")
	text := ExtractPDFText(pdf)
	if !strings.Contains(text, "RawText") {
		t.Errorf("expected 'RawText', got %q", text)
	}
}

func TestExtractPDFTextEncrypted(t *testing.T) {
	pdf := buildTestPDF(t, []byte(`BT (hidden) Tj ET`))
	pdf = append(pdf, []byte("trailer\n<< /Encrypt 2 0 R >>\n")...)
	if text := ExtractPDFText(pdf); text != "" {
		t.Errorf("encrypted PDF should return empty, got %q", text)
	}
}

func TestExtractPDFTextOversize(t *testing.T) {
	orig := maxPDFInputSize
	defer func() { maxPDFInputSize = orig }()
	maxPDFInputSize = 16
	pdf := buildTestPDF(t, []byte(`BT (x) Tj ET`))
	if text := ExtractPDFText(pdf); text != "" {
		t.Errorf("oversize input should return empty, got %q", text)
	}
}

func TestExtractPDFTextGarbage(t *testing.T) {
	for _, data := range [][]byte{
		nil,
		{},
		[]byte("not a pdf at all"),
		[]byte("%PDF-1.4\nbroken streams ((((("),
	} {
		if text := ExtractPDFText(data); text != "" {
			t.Errorf("garbage input %q should return empty, got %q", data, text)
		}
	}
}

// createTestZip 在临时目录生成 zip 文件
func createTestZip(t *testing.T, members map[string][]byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for name, data := range members {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create member: %v", err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatalf("zip write member: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return path
}

func TestExtractArchiveTextZip(t *testing.T) {
	binary := append([]byte("MZ"), bytes.Repeat([]byte{0x00, 0x01, 0x02}, 100)...)
	path := createTestZip(t, map[string][]byte{
		"config.txt":  []byte("password=secret123\napi_key=AKIAIOSFODNN7EXAMPLE\n"),
		"payload.bin": binary,
		"empty.txt":   {},
	})
	entries := ExtractArchiveText(path, 1<<20)
	if len(entries) != 1 {
		t.Fatalf("expected 1 text entry, got %d: %+v", len(entries), entries)
	}
	if entries[0].Name != "config.txt" {
		t.Errorf("unexpected entry name %q", entries[0].Name)
	}
	if !strings.Contains(string(entries[0].Text), "password=secret123") {
		t.Errorf("entry text missing expected content: %q", entries[0].Text)
	}
}

func TestExtractArchiveTextMemberSizeLimit(t *testing.T) {
	orig := archiveMemberMaxSize
	defer func() { archiveMemberMaxSize = orig }()
	archiveMemberMaxSize = 8

	path := createTestZip(t, map[string][]byte{
		"big.txt": []byte(strings.Repeat("password=x\n", 20)),
	})
	if entries := ExtractArchiveText(path, 1<<20); len(entries) != 0 {
		t.Errorf("oversize member should be skipped, got %d entries", len(entries))
	}
}

func TestExtractArchiveTextMaxTotal(t *testing.T) {
	path := createTestZip(t, map[string][]byte{
		"a.txt": []byte("0123456789"),
		"b.txt": []byte("0123456789"),
		"c.txt": []byte("0123456789"),
	})
	entries := ExtractArchiveText(path, 25)
	var total int64
	for _, e := range entries {
		total += int64(len(e.Text))
	}
	if total > 25 {
		t.Errorf("total %d exceeds maxTotal 25", total)
	}
	if len(entries) > 2 {
		t.Errorf("expected at most 2 entries within maxTotal, got %d", len(entries))
	}
}

func TestExtractArchiveTextUnsupported(t *testing.T) {
	if entries := ExtractArchiveText("some.rar", 1<<20); entries != nil {
		t.Errorf("rar should return nil, got %v", entries)
	}
	if entries := ExtractArchiveText("some.7z", 1<<20); entries != nil {
		t.Errorf("7z should return nil, got %v", entries)
	}
	if entries := ExtractArchiveText("nonexistent.zip", 1<<20); entries != nil {
		t.Errorf("missing file should return nil, got %v", entries)
	}
}
