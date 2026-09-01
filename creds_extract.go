package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// CredentialItem 从凭证文件中提取到的一条凭证
type CredentialItem struct {
	File    string // 来源文件路径
	Kind    string // SSH私钥 / SSH公钥 / AWS / Kube集群 / Kube用户 / Docker / Git
	Summary string // 人类可读的说明
	Value   string // 提取到的原始值（掩码由调用方负责）
}

// ExtractCredentialContent 读取凭证文件并提取内容。文件读不了或无法识别时返回 nil。
func ExtractCredentialContent(path string) []CredentialItem {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	base := filepath.Base(path)
	dir := filepath.Base(filepath.Dir(path))
	switch {
	case strings.HasSuffix(base, ".pub"):
		return parseSSHPublicKey(path, data)
	case dir == ".ssh" && strings.HasPrefix(base, "id_"):
		return parseSSHPrivateKey(path, data)
	case dir == ".aws" && base == "credentials":
		return parseAWSCredentials(path, data)
	case dir == ".kube" && base == "config":
		return parseKubeConfig(path, data)
	case dir == ".docker" && base == "config.json":
		return parseDockerConfig(path, data)
	case base == ".git-credentials":
		return parseGitCredentials(path, data)
	}

	// 路径不匹配时按内容嗅探
	return sniffCredentialContent(path, data)
}

// sniffCredentialContent 按文件内容判断类型并解析
func sniffCredentialContent(path string, data []byte) []CredentialItem {
	s := string(data)
	switch {
	case strings.Contains(s, "PRIVATE KEY-----"):
		return parseSSHPrivateKey(path, data)
	case strings.Contains(s, "aws_access_key_id"):
		return parseAWSCredentials(path, data)
	case strings.Contains(s, "apiVersion") && strings.Contains(s, "clusters:"):
		return parseKubeConfig(path, data)
	case strings.Contains(s, `"auths"`):
		return parseDockerConfig(path, data)
	case strings.Contains(s, "://") && strings.Contains(s, "@"):
		return parseGitCredentials(path, data)
	}
	return nil
}

// ==================== SSH ====================

const opensshKeyMagic = "openssh-key-v1\x00"

// readSSHString 读取 OpenSSH 二进制格式中的 uint32 长度前缀字符串
func readSSHString(b []byte) (val string, rest []byte, ok bool) {
	if len(b) < 4 {
		return "", nil, false
	}
	n := binary.BigEndian.Uint32(b)
	if uint64(n)+4 > uint64(len(b)) {
		return "", nil, false
	}
	return string(b[4 : 4+n]), b[4+n:], true
}

// parseOpenSSHKeyBlob 解析解码后的 openssh-key-v1 blob，返回 cipher 和 kdf
func parseOpenSSHKeyBlob(blob []byte) (cipher, kdf string, ok bool) {
	if !bytes.HasPrefix(blob, []byte(opensshKeyMagic)) {
		return "", "", false
	}
	rest := blob[len(opensshKeyMagic):]
	cipher, rest, ok = readSSHString(rest)
	if !ok {
		return "", "", false
	}
	kdf, _, ok = readSSHString(rest)
	if !ok {
		return "", "", false
	}
	return cipher, kdf, true
}

// pemBlockBody 提取 PEM 块 BEGIN/END 之间的 base64 内容
func pemBlockBody(data []byte) string {
	var body []string
	inBlock := false
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "-----BEGIN") {
			inBlock = true
			continue
		}
		if strings.HasPrefix(t, "-----END") {
			break
		}
		if inBlock && !strings.Contains(t, ":") { // 跳过 Proc-Type 等 PEM 头
			body = append(body, t)
		}
	}
	return strings.Join(body, "")
}

// parseSSHPrivateKey 解析私钥头：类型 + 是否加密
func parseSSHPrivateKey(path string, data []byte) []CredentialItem {
	var items []CredentialItem
	firstLine, _, _ := strings.Cut(string(data), "\n")
	firstLine = strings.TrimSpace(firstLine)

	if strings.Contains(firstLine, "BEGIN OPENSSH PRIVATE KEY") {
		summary := "OpenSSH 私钥"
		value := firstLine
		raw, err := base64.StdEncoding.DecodeString(pemBlockBody(data))
		if err == nil {
			if cipher, kdf, ok := parseOpenSSHKeyBlob(raw); ok {
				if cipher == "none" {
					summary = "OpenSSH 私钥（未加密）"
					value = "cipher=none"
				} else {
					summary = "OpenSSH 私钥（已加密）"
					value = fmt.Sprintf("cipher=%s kdf=%s", cipher, kdf)
				}
			}
		}
		items = append(items, CredentialItem{File: path, Kind: "SSH私钥", Summary: summary, Value: value})
	} else if strings.Contains(firstLine, "PRIVATE KEY-----") {
		// PEM 格式：-----BEGIN RSA PRIVATE KEY----- 等
		keyType := strings.TrimSuffix(strings.TrimPrefix(firstLine, "-----BEGIN "), " PRIVATE KEY-----")
		keyType = strings.TrimSpace(keyType)
		encrypted := strings.Contains(string(data), "Proc-Type: 4,ENCRYPTED") ||
			strings.Contains(firstLine, "ENCRYPTED")
		summary := fmt.Sprintf("PEM 私钥 (%s)", keyType)
		if encrypted {
			summary += "（已加密）"
		} else {
			summary += "（未加密）"
		}
		items = append(items, CredentialItem{File: path, Kind: "SSH私钥", Summary: summary, Value: firstLine})
	} else {
		return nil
	}

	// 对应的 .pub 公钥（读注释）
	if pub, err := os.ReadFile(path + ".pub"); err == nil {
		items = append(items, parseSSHPublicKey(path+".pub", pub)...)
	}
	return items
}

// parseSSHPublicKey 解析公钥：算法 + 注释
func parseSSHPublicKey(path string, data []byte) []CredentialItem {
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.HasPrefix(fields[0], "ssh-") && !strings.HasPrefix(fields[0], "ecdsa-") && !strings.HasPrefix(fields[0], "sk-") {
			continue
		}
		comment := ""
		if len(fields) >= 3 {
			comment = strings.Join(fields[2:], " ")
		}
		return []CredentialItem{{
			File: path, Kind: "SSH公钥",
			Summary: fmt.Sprintf("算法 %s", fields[0]),
			Value:   comment,
		}}
	}
	return nil
}

// ==================== AWS ====================

// parseAWSCredentials 解析 AWS INI 凭证，按 profile 提取密钥对
func parseAWSCredentials(path string, data []byte) []CredentialItem {
	profiles := make(map[string]map[string]string)
	var order []string
	section := ""
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, ";") || strings.HasPrefix(t, "#") {
			continue
		}
		if strings.HasPrefix(t, "[") && strings.Contains(t, "]") {
			section = strings.TrimSpace(t[1:strings.Index(t, "]")])
			if _, ok := profiles[section]; !ok {
				profiles[section] = make(map[string]string)
				order = append(order, section)
			}
			continue
		}
		k, v, ok := strings.Cut(t, "=")
		if !ok || section == "" {
			continue
		}
		profiles[section][strings.TrimSpace(k)] = strings.TrimSpace(v)
	}

	var items []CredentialItem
	for _, p := range order {
		kv := profiles[p]
		if v := kv["aws_access_key_id"]; v != "" {
			items = append(items, CredentialItem{
				File: path, Kind: "AWS",
				Summary: fmt.Sprintf("profile %q aws_access_key_id", p), Value: v})
		}
		if v := kv["aws_secret_access_key"]; v != "" {
			items = append(items, CredentialItem{
				File: path, Kind: "AWS",
				Summary: fmt.Sprintf("profile %q aws_secret_access_key", p), Value: v})
		}
		if v := kv["aws_session_token"]; v != "" {
			items = append(items, CredentialItem{
				File: path, Kind: "AWS",
				Summary: fmt.Sprintf("profile %q aws_session_token", p), Value: v})
		}
	}
	return items
}

// ==================== Kubeconfig ====================

// parseKubeConfig 提取 cluster server 地址、user token 及 client-key 内嵌情况
func parseKubeConfig(path string, data []byte) []CredentialItem {
	var items []CredentialItem
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		key, val, ok := strings.Cut(t, ":")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		if val == "" {
			continue
		}
		switch strings.TrimSpace(key) {
		case "server":
			items = append(items, CredentialItem{
				File: path, Kind: "Kube集群", Summary: "cluster server 地址", Value: val})
		case "token":
			items = append(items, CredentialItem{
				File: path, Kind: "Kube用户", Summary: "内嵌 token", Value: val})
		case "client-key-data":
			items = append(items, CredentialItem{
				File: path, Kind: "Kube用户", Summary: "client-key 内嵌（base64）", Value: val})
		case "client-key":
			items = append(items, CredentialItem{
				File: path, Kind: "Kube用户", Summary: "client-key 引用外部文件", Value: val})
		}
	}
	return items
}

// ==================== Docker ====================

// parseDockerConfig 解码 auths 中的 base64 auth，得到 user:password
func parseDockerConfig(path string, data []byte) []CredentialItem {
	var cfg struct {
		Auths map[string]struct {
			Auth string `json:"auth"`
		} `json:"auths"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil
	}
	var items []CredentialItem
	for reg, a := range cfg.Auths {
		if a.Auth == "" {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(a.Auth)
		if err != nil {
			continue
		}
		items = append(items, CredentialItem{
			File: path, Kind: "Docker",
			Summary: fmt.Sprintf("registry %q 的 auth", reg),
			Value:   string(decoded),
		})
	}
	return items
}

// ==================== Git ====================

// parseGitCredentials 解析每行 URL 中的 user:password
func parseGitCredentials(path string, data []byte) []CredentialItem {
	var items []CredentialItem
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		u, err := url.Parse(t)
		if err != nil || u.User == nil || u.Host == "" {
			continue
		}
		user := u.User.Username()
		pass, hasPass := u.User.Password()
		value := user
		if hasPass {
			value = user + ":" + pass
		}
		items = append(items, CredentialItem{
			File: path, Kind: "Git",
			Summary: fmt.Sprintf("host %q 的凭证", u.Host),
			Value:   value,
		})
	}
	return items
}
