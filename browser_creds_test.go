package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// gcmEncryptV10 用测试密钥构造 v10 格式的加密数据
func gcmEncryptV10(t *testing.T, key, plaintext []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	out := []byte("v10")
	out = append(out, nonce...)
	out = append(out, gcm.Seal(nil, nonce, plaintext, nil)...)
	return out
}

// TestPBKDF2SHA1 用 RFC 6070 向量验证 PBKDF2 实现
func TestPBKDF2SHA1(t *testing.T) {
	got := pbkdf2SHA1([]byte("password"), []byte("salt"), 1, 20)
	want, _ := hex.DecodeString("0c60c80f961f0e71f3a9b524af6012062fe037a6")
	if string(got) != string(want) {
		t.Fatalf("pbkdf2 mismatch: got %x want %x", got, want)
	}
	// 迭代 2 次的向量
	got = pbkdf2SHA1([]byte("password"), []byte("salt"), 2, 20)
	want, _ = hex.DecodeString("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957")
	if string(got) != string(want) {
		t.Fatalf("pbkdf2 iter=2 mismatch: got %x want %x", got, want)
	}
}

// TestDecryptBrowserValueGCM 验证 v10 AES-256-GCM 解密
func TestDecryptBrowserValueGCM(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	want := "Sup3rSecret!Passw0rd"
	enc := gcmEncryptV10(t, key, []byte(want))

	got, err := decryptBrowserValue(key, enc)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}

	// 错误密钥应报错而不是 panic
	wrongKey := make([]byte, 32)
	if _, err := decryptBrowserValue(wrongKey, enc); err == nil {
		t.Fatal("expected error with wrong key")
	}
}

// TestDecryptBrowserValueCBC 验证 macOS/Linux 老格式 AES-128-CBC 解密
func TestDecryptBrowserValueCBC(t *testing.T) {
	key := pbkdf2SHA1([]byte("peanuts"), []byte("saltysalt"), 1, 16)
	want := "legacy-cbc-password"

	// PKCS7 填充后用空格 IV 加密
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	pt := []byte(want)
	pad := aes.BlockSize - len(pt)%aes.BlockSize
	for i := 0; i < pad; i++ {
		pt = append(pt, byte(pad))
	}
	ct := make([]byte, len(pt))
	cipher.NewCBCEncrypter(block, []byte("                ")).CryptBlocks(ct, pt)

	enc := append([]byte("v10"), ct...)
	got, err := decryptBrowserValue(key, enc)
	if err != nil {
		t.Fatalf("cbc decrypt failed: %v", err)
	}
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

// TestDecryptBrowserValueV20 验证 v20 App-Bound 加密被跳过而非 panic
func TestDecryptBrowserValueV20(t *testing.T) {
	key := make([]byte, 32)
	_, err := decryptBrowserValue(key, []byte("v20\xfake-app-bound-data"))
	if err != errAppBound {
		t.Fatalf("expected errAppBound, got %v", err)
	}
}

// TestDecryptBrowserValuePlaintext 验证 Linux 无 keyring 时的明文回退
func TestDecryptBrowserValuePlaintext(t *testing.T) {
	got, err := decryptBrowserValue(make([]byte, 32), []byte("plaintext-password"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "plaintext-password" {
		t.Fatalf("got %q", got)
	}
}

// TestReadEncryptedKey 验证 Local State 主密钥解析（去 DPAPI 前缀）
func TestReadEncryptedKey(t *testing.T) {
	dir := t.TempDir()
	raw := append([]byte("DPAPI"), []byte("fake-dpapi-blob")...)
	state := `{"os_crypt":{"encrypted_key":"` + base64.StdEncoding.EncodeToString(raw) + `"}}`
	path := filepath.Join(dir, "Local State")
	if err := os.WriteFile(path, []byte(state), 0600); err != nil {
		t.Fatal(err)
	}

	got, err := readEncryptedKey(path)
	if err != nil {
		t.Fatalf("readEncryptedKey failed: %v", err)
	}
	if string(got) != "fake-dpapi-blob" {
		t.Fatalf("got %q", got)
	}

	// 文件不存在时降级返回错误
	if _, err := readEncryptedKey(filepath.Join(dir, "nonexistent")); err == nil {
		t.Fatal("expected error for missing Local State")
	}
}

// TestExtractLogins 构造临时 SQLite 库，端到端验证 Login Data 提取
func TestExtractLogins(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "Login Data")
	db, err := openSQLiteDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE logins (origin_url TEXT, username_value TEXT, password_value BLOB)`); err != nil {
		t.Fatal(err)
	}
	enc := gcmEncryptV10(t, key, []byte("hunter2"))
	if _, err := db.Exec(`INSERT INTO logins VALUES (?, ?, ?)`,
		"https://example.com/login", "alice", enc); err != nil {
		t.Fatal(err)
	}
	// 插入一条 v20 数据验证跳过逻辑
	if _, err := db.Exec(`INSERT INTO logins VALUES (?, ?, ?)`,
		"https://appbound.example.com", "bob", []byte("v20-appbound")); err != nil {
		t.Fatal(err)
	}
	db.Close()

	creds := extractLogins(dbPath, "Chrome", "Default", key)
	if len(creds) != 1 {
		t.Fatalf("expected 1 cred (v20 skipped), got %d", len(creds))
	}
	c := creds[0]
	if c.Browser != "Chrome" || c.Profile != "Default" ||
		c.URL != "https://example.com/login" || c.Username != "alice" || c.Password != "hunter2" {
		t.Fatalf("unexpected cred: %+v", c)
	}
}

// TestExtractCookies 构造临时 SQLite 库，验证 Cookie 提取及 SHA-256 前缀剥离
func TestExtractCookies(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "Cookies")
	db, err := openSQLiteDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE cookies (host_key TEXT, name TEXT, encrypted_value BLOB)`); err != nil {
		t.Fatal(err)
	}

	// Chrome 80+：明文前 32 字节是 host_key 的 SHA-256
	host := ".example.com"
	sum := sha256.Sum256([]byte(host))
	plainWithPrefix := append(sum[:], []byte("session-token-abc")...)
	enc := gcmEncryptV10(t, key, plainWithPrefix)
	if _, err := db.Exec(`INSERT INTO cookies VALUES (?, ?, ?)`, host, "sid", enc); err != nil {
		t.Fatal(err)
	}
	db.Close()

	cookies := extractCookies(dbPath, "Edge", "Profile 1", key)
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	c := cookies[0]
	if c.Host != host || c.Name != "sid" || c.Value != "session-token-abc" {
		t.Fatalf("unexpected cookie: %+v", c)
	}
}

// TestFindProfiles 验证 profile 目录发现逻辑
func TestFindProfiles(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{"Default", "Profile 1", "Profile 2"} {
		if err := os.MkdirAll(filepath.Join(dir, p), 0755); err != nil {
			t.Fatal(err)
		}
	}
	// 干扰项：不匹配前缀的目录
	if err := os.MkdirAll(filepath.Join(dir, "Crashpad"), 0755); err != nil {
		t.Fatal(err)
	}
	profiles := findProfiles(dir)
	if len(profiles) != 3 {
		t.Fatalf("expected 3 profiles, got %d: %v", len(profiles), profiles)
	}
}

// TestSafeStoragePasswordSkipped darwin 上跳过 security 命令测试
func TestSafeStoragePasswordSkipped(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("skipping security command on darwin")
	}
	if _, err := safeStoragePassword("Chrome Safe Storage"); err == nil {
		t.Fatal("expected error on non-darwin platform")
	}
}

// TestExtractBrowserCredentialsDegrades 验证在没有浏览器的环境下整体不报错
func TestExtractBrowserCredentialsDegrades(t *testing.T) {
	// 不管本机有没有浏览器，都不允许返回错误或 panic
	creds, cookies, err := ExtractBrowserCredentials()
	if err != nil {
		t.Fatalf("ExtractBrowserCredentials returned error: %v", err)
	}
	t.Logf("found %d creds, %d cookies", len(creds), len(cookies))
}
