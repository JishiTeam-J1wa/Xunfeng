package main

import (
	"encoding/base64"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ==================== 版本解析 ====================

func TestParseDottedVersion(t *testing.T) {
	cases := []struct {
		in   string
		want []int
		ok   bool
	}{
		{"5.15.0-91-generic", []int{5, 15, 0}, true},
		{"3.10.0-1160.el7.x86_64", []int{3, 10, 0}, true},
		{"10.15.7", []int{10, 15, 7}, true},
		{"4.8", []int{4, 8}, true},
		{"unknown", nil, false},
		{"", nil, false},
	}
	for _, c := range cases {
		got, err := parseDottedVersion(c.in)
		if c.ok && err != nil {
			t.Errorf("parseDottedVersion(%q) err: %v", c.in, err)
			continue
		}
		if !c.ok && err == nil {
			t.Errorf("parseDottedVersion(%q) should fail", c.in)
			continue
		}
		if c.ok {
			for i := range c.want {
				if got[i] != c.want[i] {
					t.Errorf("parseDottedVersion(%q) = %v, want %v", c.in, got, c.want)
					break
				}
			}
		}
	}
}

func TestDirtyCOWAffected(t *testing.T) {
	cases := []struct {
		v    []int
		want bool
	}{
		{[]int{2, 6, 21}, false},
		{[]int{2, 6, 22}, true},
		{[]int{2, 6, 32}, true},
		{[]int{3, 10, 0}, true}, // 此前遗漏的 3.10~3.19 区间
		{[]int{3, 19, 8}, true}, // 此前遗漏
		{[]int{4, 4, 0}, true},
		{[]int{4, 8, 3}, true},
		{[]int{4, 8, 4}, false},
		{[]int{5, 4, 0}, false},
	}
	for _, c := range cases {
		if got := dirtyCOWAffected(c.v); got != c.want {
			t.Errorf("dirtyCOWAffected(%v) = %v, want %v", c.v, got, c.want)
		}
	}
}

func TestDirtyPipeAffected(t *testing.T) {
	cases := []struct {
		v    []int
		want bool
	}{
		{[]int{5, 7, 0}, false},
		{[]int{5, 8, 0}, true},
		{[]int{5, 15, 30}, true},
		{[]int{5, 16, 10}, true},
		{[]int{5, 16, 11}, false},
		{[]int{5, 17, 0}, false},
	}
	for _, c := range cases {
		if got := dirtyPipeAffected(c.v); got != c.want {
			t.Errorf("dirtyPipeAffected(%v) = %v, want %v", c.v, got, c.want)
		}
	}
}

// ==================== sudo / polkit 版本 ====================

func TestParseSudoVersion(t *testing.T) {
	if sv, ok := parseSudoVersion("Sudo version 1.9.5p1"); !ok ||
		sv.nums[0] != 1 || sv.nums[1] != 9 || sv.nums[2] != 5 || sv.patch != 1 {
		t.Errorf("parseSudoVersion 1.9.5p1 = %+v, %v", sv, ok)
	}
	if sv, ok := parseSudoVersion("1.8.21p2"); !ok || sv.nums[1] != 8 || sv.nums[2] != 21 || sv.patch != 2 {
		t.Errorf("parseSudoVersion 1.8.21p2 = %+v, %v", sv, ok)
	}
	if _, ok := parseSudoVersion("not a version"); ok {
		t.Error("parseSudoVersion should fail on garbage")
	}
}

func TestBaronSameditAffected(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"Sudo version 1.8.1", false},
		{"Sudo version 1.8.2", true},
		{"Sudo version 1.8.21p2", true},
		{"Sudo version 1.8.31p2", true},
		{"Sudo version 1.8.32", false},
		{"Sudo version 1.9.0", true},
		{"Sudo version 1.9.5p1", true},
		{"Sudo version 1.9.5p2", false},
		{"Sudo version 1.9.15", false},
	}
	for _, c := range cases {
		sv, ok := parseSudoVersion(c.in)
		if !ok {
			t.Fatalf("parseSudoVersion(%q) failed", c.in)
		}
		if got := baronSameditAffected(sv); got != c.want {
			t.Errorf("baronSameditAffected(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestPwnKitAffected(t *testing.T) {
	v, ok := parsePolkitVersion("pkexec version 0.117")
	if !ok || v[0] != 0 || v[1] != 117 {
		t.Fatalf("parsePolkitVersion = %v, %v", v, ok)
	}
	if !pwnkitAffected(v) {
		t.Error("polkit 0.117 should be affected by PwnKit")
	}
	if pwnkitAffected([]int{0, 99}) {
		t.Error("polkit 0.99 should not be affected")
	}
	if pwnkitAffected([]int{0, 121}) {
		t.Error("polkit 0.121 should not be flagged by version heuristic")
	}
	if _, ok := parsePolkitVersion(""); ok {
		t.Error("empty version should fail to parse")
	}
}

// ==================== macOS CVE ====================

func TestMacOSCVEAffected(t *testing.T) {
	cases := []struct {
		cve  string
		v    []int
		want bool
	}{
		{"CVE-2020-9839", []int{10, 15, 4}, true},
		{"CVE-2020-9839", []int{10, 15, 5}, false},
		{"CVE-2020-9839", []int{10, 14, 6}, true},
		{"CVE-2020-9839", []int{11, 0, 0}, false},
		{"CVE-2022-46689", []int{13, 0, 1}, true},
		{"CVE-2022-46689", []int{13, 1, 0}, false},
		{"CVE-2022-46689", []int{12, 6, 1}, true},
		{"CVE-2022-46689", []int{12, 6, 2}, false},
		{"CVE-2022-46689", []int{14, 2, 1}, false},
		{"CVE-0000-0000", []int{10, 15, 4}, false},
	}
	for _, c := range cases {
		if got := macosCVEAffected(c.cve, c.v); got != c.want {
			t.Errorf("macosCVEAffected(%s, %v) = %v, want %v", c.cve, c.v, got, c.want)
		}
	}
}

// ==================== Windows UBR 补丁级匹配 ====================

func TestWindowsPatchVulnerable(t *testing.T) {
	// 未打补丁（UBR 低于修复值）
	if vul, known := windowsPatchVulnerable(19041, 1000, "CVE-2021-34527"); !known || !vul {
		t.Error("19041.1000 should be vulnerable to PrintNightmare")
	}
	// 已打补丁
	if vul, known := windowsPatchVulnerable(19041, 1083, "CVE-2021-34527"); !known || vul {
		t.Error("19041.1083 should be patched against PrintNightmare")
	}
	// UBR 未知（0）保守视为未修复
	if vul, known := windowsPatchVulnerable(18362, 0, "CVE-2020-0796"); !known || !vul {
		t.Error("18362 with unknown UBR should be conservatively vulnerable to SMBGhost")
	}
	// 构建号不在影响范围
	if vul, known := windowsPatchVulnerable(19045, 100, "CVE-2020-0796"); !known || vul {
		t.Error("19045 is not affected by SMBGhost")
	}
	// 无补丁数据的 CVE → known=false，调用方回退
	if _, known := windowsPatchVulnerable(7601, 0, "CVE-2019-1132"); known {
		t.Error("CVE-2019-1132 has no UBR data, known should be false")
	}
}

// ==================== exports / sudo -l 输出解析 ====================

func TestParseExportsNoRootSquash(t *testing.T) {
	content := `
# 注释行 no_root_squash 不算
/data 192.168.1.0/24(rw,sync,no_root_squash)
/srv *(ro,root_squash)
/home *(rw,no_subtree_check,no_root_squash)  # 尾部注释
`
	got := parseExportsNoRootSquash(content)
	if len(got) != 2 {
		t.Fatalf("expected 2 hits, got %d: %v", len(got), got)
	}
	if !strings.Contains(got[0], "/data") || !strings.Contains(got[1], "/home") {
		t.Errorf("unexpected hits: %v", got)
	}
	if parseExportsNoRootSquash("") != nil {
		t.Error("empty content should yield nil")
	}
}

func TestParseSudoListOutput(t *testing.T) {
	out := `
Matching Defaults entries for user on host:
    env_reset, mail_badpass

User user may run the following commands on host:
    (ALL : ALL) ALL
    (root) NOPASSWD: /usr/bin/systemctl restart nginx
`
	findings := parseSudoListOutput(out)
	if len(findings) < 2 {
		t.Fatalf("expected >=2 findings, got %d: %v", len(findings), findings)
	}
	var foundBroad, foundNopass bool
	for _, f := range findings {
		if f.Category != "Sudo" {
			t.Errorf("unexpected category %q", f.Category)
		}
		if strings.Contains(f.Title, "全部权限") {
			foundBroad = true
		}
		if strings.Contains(f.Title, "NOPASSWD") {
			foundNopass = true
		}
	}
	if !foundBroad || !foundNopass {
		t.Errorf("missing broad/nopasswd findings: %v", findings)
	}

	// 无 NOPASSWD 也无 (ALL) 时给出低危提示
	f2 := parseSudoListOutput("User bob may run the following commands on host:\n    (root) /usr/bin/less /var/log/syslog\n")
	if len(f2) != 1 || f2[0].Severity != "低" {
		t.Errorf("partial sudo rights should yield one low finding: %v", f2)
	}
}

// ==================== 凭证提取 ====================

func writeTemp(t *testing.T, rel, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// buildOpenSSHKey 构造最小 openssh-key-v1 blob 并包装为 PEM
func buildOpenSSHKey(cipher, kdf string) string {
	var blob []byte
	blob = append(blob, []byte(opensshKeyMagic)...)
	put := func(s string) {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(s)))
		blob = append(blob, l[:]...)
		blob = append(blob, s...)
	}
	put(cipher)
	put(kdf)
	put("") // kdfoptions
	return "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
		base64.StdEncoding.EncodeToString(blob) +
		"\n-----END OPENSSH PRIVATE KEY-----\n"
}

func TestExtractSSHPrivateKeyOpenSSH(t *testing.T) {
	// 未加密
	p := writeTemp(t, ".ssh/id_ed25519", buildOpenSSHKey("none", "none"))
	items := ExtractCredentialContent(p)
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %v", items)
	}
	if !strings.Contains(items[0].Summary, "未加密") {
		t.Errorf("expected 未加密, got %q", items[0].Summary)
	}
	if items[0].Kind != "SSH私钥" {
		t.Errorf("unexpected kind %q", items[0].Kind)
	}

	// 加密
	p2 := writeTemp(t, ".ssh/id_rsa", buildOpenSSHKey("aes256-ctr", "bcrypt"))
	items2 := ExtractCredentialContent(p2)
	if len(items2) != 1 || !strings.Contains(items2[0].Summary, "已加密") ||
		!strings.Contains(items2[0].Value, "aes256-ctr") {
		t.Errorf("expected encrypted openssh key, got %v", items2)
	}
}

func TestExtractSSHPrivateKeyPEM(t *testing.T) {
	pem := `-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,0123456789ABCDEF

dGVzdGRhdGE=
-----END RSA PRIVATE KEY-----
`
	p := writeTemp(t, ".ssh/id_rsa_old", pem)
	items := ExtractCredentialContent(p)
	if len(items) != 1 || !strings.Contains(items[0].Summary, "RSA") ||
		!strings.Contains(items[0].Summary, "已加密") {
		t.Errorf("expected encrypted PEM RSA key, got %v", items)
	}
}

func TestExtractSSHPublicKey(t *testing.T) {
	priv := writeTemp(t, ".ssh/id_ed25519", buildOpenSSHKey("none", "none"))
	// .pub 必须与私钥同目录同名
	pub := priv + ".pub"
	if err := os.WriteFile(pub, []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest user@example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	items := ExtractCredentialContent(priv)
	var pubItem *CredentialItem
	for i := range items {
		if items[i].Kind == "SSH公钥" {
			pubItem = &items[i]
		}
	}
	if pubItem == nil || pubItem.Value != "user@example.com" ||
		!strings.Contains(pubItem.Summary, "ssh-ed25519") {
		t.Errorf("expected pub comment item, got %v", items)
	}

	// 直接解析 .pub 文件
	items2 := ExtractCredentialContent(pub)
	if len(items2) != 1 || items2[0].Value != "user@example.com" {
		t.Errorf("direct .pub parse failed: %v", items2)
	}
}

func TestExtractAWSCredentials(t *testing.T) {
	content := `
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

[prod]
aws_access_key_id=AKIAI44QH8DHBEXAMPLE
aws_secret_access_key=je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY
aws_session_token=FQoGZXIvYXdzEExampleToken
`
	p := writeTemp(t, ".aws/credentials", content)
	items := ExtractCredentialContent(p)
	if len(items) != 5 {
		t.Fatalf("expected 5 items, got %d: %v", len(items), items)
	}
	var foundDefaultSecret, foundProdToken bool
	for _, it := range items {
		if it.Value == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" &&
			strings.Contains(it.Summary, `"default"`) {
			foundDefaultSecret = true
		}
		if it.Value == "FQoGZXIvYXdzEExampleToken" {
			foundProdToken = true
		}
	}
	if !foundDefaultSecret || !foundProdToken {
		t.Errorf("missing expected AWS items: %v", items)
	}
}

func TestExtractKubeConfig(t *testing.T) {
	content := `
apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTi...
    server: https://192.168.1.10:6443
  name: local
users:
- name: admin
  user:
    client-key-data: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVkt...
    token: eyJhbGciOiJSUzI1NiJ9.example
contexts: []
`
	p := writeTemp(t, ".kube/config", content)
	items := ExtractCredentialContent(p)
	var server, token, keyData bool
	for _, it := range items {
		switch {
		case it.Kind == "Kube集群" && it.Value == "https://192.168.1.10:6443":
			server = true
		case it.Kind == "Kube用户" && it.Value == "eyJhbGciOiJSUzI1NiJ9.example":
			token = true
		case strings.Contains(it.Summary, "client-key 内嵌"):
			keyData = true
		}
	}
	if !server || !token || !keyData {
		t.Errorf("kube config extraction incomplete: %v", items)
	}
}

func TestExtractDockerConfig(t *testing.T) {
	auth := base64.StdEncoding.EncodeToString([]byte("admin:s3cretP@ss"))
	content := `{"auths":{"https://index.docker.io/v1/":{"auth":"` + auth + `"}}}`
	p := writeTemp(t, ".docker/config.json", content)
	items := ExtractCredentialContent(p)
	if len(items) != 1 || items[0].Value != "admin:s3cretP@ss" {
		t.Errorf("expected decoded docker auth, got %v", items)
	}
	if !strings.Contains(items[0].Summary, "index.docker.io") {
		t.Errorf("summary should mention registry: %v", items[0])
	}
}

func TestExtractGitCredentials(t *testing.T) {
	content := `# comment
https://alice:plainpass@github.com
https://bob:p%40ss%2Fword@gitlab.com
notaurl
`
	p := writeTemp(t, ".git-credentials", content)
	items := ExtractCredentialContent(p)
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d: %v", len(items), items)
	}
	if items[0].Value != "alice:plainpass" {
		t.Errorf("unexpected first value %q", items[0].Value)
	}
	if items[1].Value != "bob:p@ss/word" {
		t.Errorf("expected URL-decoded password, got %q", items[1].Value)
	}
}

func TestExtractCredentialContentSniff(t *testing.T) {
	// 路径不匹配已知位置时按内容嗅探
	p := writeTemp(t, "random/backup.txt",
		"[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = secret123\n")
	items := ExtractCredentialContent(p)
	if len(items) != 2 {
		t.Errorf("content sniffing should find AWS creds, got %v", items)
	}
}

func TestExtractCredentialContentMissing(t *testing.T) {
	if items := ExtractCredentialContent("/nonexistent/path/id_rsa"); items != nil {
		t.Errorf("missing file should return nil, got %v", items)
	}
}
