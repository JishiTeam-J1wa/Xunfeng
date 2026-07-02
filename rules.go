package main

import (
	"regexp"
)

// Rule 带预筛选的规则
type Rule struct {
	pattern     *regexp.Regexp
	keywords    []string
	keywordsAC  *AhoCorasick // 预编译的 AC 匹配器
	minLen      int          // 最小匹配长度
	initialized bool
}

// 初始化规则的 AC 匹配器
func (r *Rule) init() {
	if r.initialized || len(r.keywords) == 0 {
		return
	}
	r.keywordsAC = NewAhoCorasick(r.keywords)
	r.initialized = true
}

func (r *Rule) preCheck(line string) bool {
	if len(r.keywords) == 0 {
		return true
	}
	// 使用 AC 算法进行快速匹配
	if r.keywordsAC != nil {
		return r.keywordsAC.ContainsAny(line)
	}
	// 回退到简单匹配 (不应该走到这里)
	for _, kw := range r.keywords {
		if containsIgnoreCase(line, kw) {
			return true
		}
	}
	return false
}

// 快速大小写不敏感包含检查
func containsIgnoreCase(s, substr string) bool {
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			c1, c2 := s[i+j], substr[j]
			if c1 >= 'A' && c1 <= 'Z' {
				c1 += 32
			}
			if c2 >= 'A' && c2 <= 'Z' {
				c2 += 32
			}
			if c1 != c2 {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// InitAllRules 初始化所有规则的 AC 匹配器
func InitAllRules() {
	for _, rule := range sensitiveRules {
		rule.init()
	}
}

var (
	// targetExtensions - 文本文件
	targetExtensions = map[string]bool{
		".xml": true, ".json": true, ".yml": true, ".yaml": true,
		".conf": true, ".cfg": true, ".ini": true, ".toml": true,
		".properties": true, ".env": true, ".config": true,
		".py": true, ".php": true, ".js": true, ".ts": true,
		".go": true, ".java": true, ".rb": true, ".sh": true,
		".bash": true, ".zsh": true, ".ps1": true, ".bat": true, ".cmd": true,
		".txt": true, ".md": true, ".log": true, ".sql": true, ".csv": true,
		".pem": true, ".key": true, ".crt": true, ".cer": true,
		".htaccess": true, ".htpasswd": true,
		".gradle": true, ".sbt": true, ".tf": true, ".tfvars": true,
	}

	// officeExtensions - Office文档
	officeExtensions = map[string]bool{
		".docx": true, ".xlsx": true,
		".doc": true, ".xls": true, // 旧版二进制格式
		".pptx": true, ".ppt": true, // PPT 文档
	}

	// nonScanExtensions - 敏感类型(直接报告，不扫描内容)
	// 后渗透高价值文件
	nonScanExtensions = map[string]bool{
		// 数据库文件
		".db": true, ".db3": true, ".sqlite": true, ".sqlite3": true, ".sqlitedb": true,
		".sqlite-wal": true, ".sqlite-shm": true, ".sqlite-journal": true, ".db-journal": true,
		".mdb": true, ".accdb": true, ".dbf": true,
		".frm": true, ".myd": true, ".myi": true, ".ibd": true,
		".ldf": true, ".mdf": true, ".ndf": true, // SQL Server
		".ora": true, ".orcl": true, ".dbx": true,
		".fdb": true, ".gdb": true, // Firebird/InterBase
		".sdf": true, // SQL Server Compact
		".wdb": true, // Microsoft Works
		// 密钥/证书
		".keystore": true, ".jks": true, ".kdbx": true, ".psafe3": true,
		".p12": true, ".pfx": true, ".keychain": true, ".ppk": true,
		".asc": true, ".gpg": true, ".pgp": true,
		// 抓包/内存
		".pcap": true, ".pcapng": true, ".cap": true,
		".dmp": true, ".mdmp": true, ".hdmp": true,
		// 远程连接
		".rdp": true, ".remmina": true,
		".ovpn": true, ".tblk": true, ".conf": false, // VPN
		// 备份文件 (高价值)
		".bak": true, ".backup": true, ".old": true, ".orig": true,
		".sql.gz": true, ".tar.gz": true, ".zip": true, ".rar": true, ".7z": true,
		".war": true, ".ear": true, ".jar": true, // Java包可能含配置
		// 日志文件
		".log": false, // 日志扫描内容
		// 配置备份
		".config.bak": true, ".conf.bak": true,
	}

	// highValueExtensions - 后渗透高价值文件后缀
	// 只报告路径，不重复输出（扫描内容时会输出匹配结果）
	highValueExtensions = map[string]string{
		// 凭证相关 (必报)
		".htpasswd": "ApachePass",
		".netrc":    "NetCreds",
		".pgpass":   "PgPass",
		// 私钥 (必报)
		".pem": "PEM",
		".key": "PrivateKey",
		// 云/IaC
		".tfstate": "TFState",
		".tfvars":  "TFVars",
	}

	// scanOnlyExtensions - 只扫描内容，不单独报告路径
	// 这些文件太多，只在发现敏感内容时报告
	scanOnlyExtensions = map[string]bool{
		".sql": true, ".config": true, ".conf": true, ".cfg": true,
		".ini": true, ".properties": true, ".xml": true, ".yml": true,
		".yaml": true, ".toml": true, ".json": true, ".env": true,
		".sh": true, ".bash": true, ".ps1": true, ".bat": true, ".cmd": true,
		".tf": true, ".crt": true, ".cer": true,
	}

	// sensitiveFilenamePatterns - 文件名模糊匹配（包含即命中）
	sensitiveFilenamePatterns = []string{
		"vpn", "proxy", "内网", "入职", "手册", "内部", "intranet", "tunnel",
		"shadowsocks", "v2ray", "clash", "wireguard", "openvpn",
		"账号", "密码", "口令", "密钥", "凭据", "credential",
	}

	// sensitiveFilenames - 敏感文件名 (更全面)
	sensitiveFilenames = map[string]bool{
		// 通用配置文件
		"web.config": true, "app.config": true, "applicationhost.config": true,
		"config.php": true, "wp-config.php": true, "configuration.php": true,
		"settings.py": true, "local_settings.py": true, "secrets.py": true,
		"database.yml": true, "secrets.yml": true, "credentials.yml": true,
		"appsettings.json": true, "secrets.json": true, "config.json": true,
		"settings.json": true, "settings.xml": true, "config.xml": true,
		"application.properties": true, "application.yml": true,
		"application.conf": true, "application.json": true,
		"local.properties": true, "gradle.properties": true, "pom.xml": true,
		"web.xml": true, "hibernate.cfg.xml": true, "mybatis-config.xml": true,
		// 凭证文件
		"credentials": true, "credential": true, ".htpasswd": true,
		"shadow": true, "passwd": true, "master.key": true,
		// SSH
		"id_rsa": true, "id_dsa": true, "id_ecdsa": true, "id_ed25519": true,
		"authorized_keys": true, "known_hosts": true,
		// 环境配置
		".env": true, ".env.local": true, ".env.production": true,
		".env.development": true, ".env.staging": true, ".env.backup": true,
		// 包管理
		".npmrc": true, ".pypirc": true, ".netrc": true, ".pgpass": true,
		".dockercfg": true, ".docker/config.json": true,
		// 服务配置
		"tomcat-users.xml": true, "server.xml": true, "context.xml": true,
		"standalone.xml": true, "domain.xml": true,
		"struts.xml": true, "spring-security.xml": true,
		// 云/容器
		"terraform.tfstate": true, "terraform.tfvars": true,
		"kubeconfig": true, "admin.conf": true,
		".git-credentials": true, ".gitconfig": true,
		"ansible.cfg": true, "vault.yml": true,
		"credentials.csv": true, "accesskeys.csv": true,
		// 数据库文件（按文件名）
		"login data": true, "logins.json": true, "key4.db": true,
		"cookies.sqlite": true, "places.sqlite": true, "formhistory.sqlite": true,
		"signons.sqlite": true, "permissions.sqlite": true,
		// 工具配置
		"filezilla.xml": true, "recentservers.xml": true, "sitemanager.xml": true,
		"mobaxterm.ini": true, "winscp.ini": true, "securecrt.ini": true,
		"connections.xml": true, "datagrip.xml": true,
		"sessions.xml": true, "user.config": true,
	}

	// sensitiveRules - 内容匹配规则 (更精准)
	sensitiveRules = map[string]*Rule{
		// ========== 通用凭证 ==========
		"Password": {
			pattern:  regexp.MustCompile(`(?i)(?:password|passwd|pwd|pass)\s*[:=]\s*['"]?([^'"\s\n\r<>(){}\[\]]{6,60})['"]?`),
			keywords: []string{"password", "passwd", "pwd", "pass="},
			minLen:   10,
		},
		"Secret": {
			pattern:  regexp.MustCompile(`(?i)(?:secret|private_key|privatekey)\s*[:=]\s*['"]?([^'"\s\n\r]{8,100})['"]?`),
			keywords: []string{"secret", "private_key", "privatekey"},
			minLen:   12,
		},
		"APIKey": {
			pattern:  regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|access[_-]?key|accesskey)\s*[:=]\s*['"]?([A-Za-z0-9_\-]{16,64})['"]?`),
			keywords: []string{"api_key", "apikey", "api-key", "access_key", "accesskey"},
			minLen:   20,
		},
		"Token": {
			pattern:  regexp.MustCompile(`(?i)(?:token|auth[_-]?token|bearer[_-]?token)\s*[:=]\s*['"]?([A-Za-z0-9_\-\.]{20,500})['"]?`),
			keywords: []string{"token", "auth_token", "bearer"},
			minLen:   24,
		},

		// ========== 数据库 ==========
		"DBConnStr": {
			pattern:  regexp.MustCompile(`(?i)(?:jdbc:|mongodb(?:\+srv)?://|redis://|mysql://|postgres(?:ql)?://|sqlserver://)[^\s'"<>]{10,300}`),
			keywords: []string{"jdbc:", "mongodb://", "mongodb+srv://", "redis://", "mysql://", "postgres", "sqlserver://"},
			minLen:   20,
		},
		"DBPassword": {
			pattern:  regexp.MustCompile(`(?i)(?:db[_-]?pass(?:word)?|database[_-]?pass(?:word)?|mysql[_-]?pass(?:word)?|pg[_-]?pass(?:word)?)\s*[:=]\s*['"]?([^'"\s\n]{4,50})['"]?`),
			keywords: []string{"db_pass", "db-pass", "database_pass", "mysql_pass", "pg_pass"},
			minLen:   8,
		},

		// ========== 云服务商 ==========
		"AWSKey": {
			pattern:  regexp.MustCompile(`\b(AKIA[0-9A-Z]{16})\b`),
			keywords: []string{"akia"},
			minLen:   20,
		},
		"AWSSecret": {
			pattern:  regexp.MustCompile(`(?i)(?:aws[_-]?secret[_-]?(?:access[_-]?)?key)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?`),
			keywords: []string{"aws_secret", "aws-secret"},
			minLen:   44,
		},
		"AliKey": {
			pattern:  regexp.MustCompile(`\b(LTAI[0-9A-Za-z]{12,20})\b`),
			keywords: []string{"ltai"},
			minLen:   16,
		},
		"TencentKey": {
			pattern:  regexp.MustCompile(`\b(AKID[0-9A-Za-z]{13,20})\b`),
			keywords: []string{"akid"},
			minLen:   17,
		},
		"AzureKey": {
			pattern:  regexp.MustCompile(`(?i)(?:azure[_-]?(?:storage[_-]?)?(?:account[_-]?)?key)\s*[:=]\s*['"]?([A-Za-z0-9+/=]{44,88})['"]?`),
			keywords: []string{"azure"},
			minLen:   48,
		},

		// ========== API Tokens ==========
		"GithubToken": {
			pattern:  regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b`),
			keywords: []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"},
			minLen:   40,
		},
		"GitlabToken": {
			pattern:  regexp.MustCompile(`\b(glpat-[A-Za-z0-9\-_]{20,})\b`),
			keywords: []string{"glpat-"},
			minLen:   26,
		},
		"SlackToken": {
			pattern:  regexp.MustCompile(`\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)\b`),
			keywords: []string{"xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"},
			minLen:   30,
		},
		"StripeKey": {
			pattern:  regexp.MustCompile(`\b(sk_live_[0-9a-zA-Z]{24,99})\b`),
			keywords: []string{"sk_live_"},
			minLen:   32,
		},
		"NPMToken": {
			pattern:  regexp.MustCompile(`\b(npm_[A-Za-z0-9]{36})\b`),
			keywords: []string{"npm_"},
			minLen:   40,
		},
		"HerokuKey": {
			pattern:  regexp.MustCompile(`(?i)heroku[_-]?api[_-]?key\s*[:=]\s*['"]?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})['"]?`),
			keywords: []string{"heroku"},
			minLen:   40,
		},
		"SendGridKey": {
			pattern:  regexp.MustCompile(`\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b`),
			keywords: []string{"sg."},
			minLen:   69,
		},
		"TwilioKey": {
			pattern:  regexp.MustCompile(`\b(SK[0-9a-fA-F]{32})\b`),
			keywords: []string{"sk"},
			minLen:   34,
		},
		"MailgunKey": {
			pattern:  regexp.MustCompile(`\b(key-[0-9a-zA-Z]{32})\b`),
			keywords: []string{"key-"},
			minLen:   36,
		},

		// ========== JWT/认证 ==========
		"JWT": {
			pattern:  regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\b`),
			keywords: []string{"eyj"},
			minLen:   36,
		},
		"BasicAuth": {
			pattern:  regexp.MustCompile(`(?i)(?:basic\s+)([A-Za-z0-9+/]{20,}={0,2})`),
			keywords: []string{"basic "},
			minLen:   24,
		},

		// ========== 私钥 ==========
		"PrivateKey": {
			pattern:  regexp.MustCompile(`-----BEGIN (?:RSA |OPENSSH |DSA |EC |ENCRYPTED )?PRIVATE KEY-----`),
			keywords: []string{"-----begin"},
			minLen:   27,
		},
		"PGPKey": {
			pattern:  regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`),
			keywords: []string{"-----begin pgp"},
			minLen:   37,
		},

		// ========== 框架特定 ==========
		"DjangoSecret": {
			pattern:  regexp.MustCompile(`(?i)SECRET_KEY\s*=\s*['"]([^'"]{20,100})['"]`),
			keywords: []string{"secret_key"},
			minLen:   24,
		},
		"LaravelKey": {
			pattern:  regexp.MustCompile(`(?i)APP_KEY\s*=\s*base64:([A-Za-z0-9+/=]{32,50})`),
			keywords: []string{"app_key", "base64:"},
			minLen:   40,
		},
		"RailsSecret": {
			pattern:  regexp.MustCompile(`(?i)secret_key_base\s*[:=]\s*['"]?([a-f0-9]{30,128})['"]?`),
			keywords: []string{"secret_key_base"},
			minLen:   34,
		},
		"SpringBoot": {
			pattern:  regexp.MustCompile(`(?i)spring\.datasource\.password\s*=\s*([^\s\n]+)`),
			keywords: []string{"spring.datasource.password"},
			minLen:   30,
		},

		// ========== 中文场景 ==========
		"CNPassword": {
			pattern:  regexp.MustCompile(`(?:密码|口令|pass)\s*[:=：]\s*['"]?([^\s'"]{4,30})['"]?`),
			keywords: []string{"密码", "口令"},
			minLen:   6,
		},
		"CNAccount": {
			pattern:  regexp.MustCompile(`(?:账号|用户名|账户)\s*[:=：]\s*['"]?([^\s'"]{2,30})['"]?.*(?:密码|口令)`),
			keywords: []string{"账号", "用户名", "账户"},
			minLen:   8,
		},
		"CNDatabase": {
			pattern:  regexp.MustCompile(`(?:数据库|mysql|oracle|sqlserver)\s*(?:地址|密码|账号|连接)\s*[:=：]\s*['"]?([^\s'"]{4,100})['"]?`),
			keywords: []string{"数据库", "mysql", "oracle", "sqlserver"},
			minLen:   10,
		},

		// ========== 潜在敏感文档/配置 ==========
		"VPNConfig": {
			pattern:  regexp.MustCompile(`(?i)(?:vpn|wireguard|openvpn|l2tp|pptp|ipsec|zerotier|tailscale)\s*(?:server|host|address|endpoint|config|conf|psk|secret|key|username|password)\s*[:=]\s*['"]?([^\s'"]{3,100})['"]?`),
			keywords: []string{"vpn", "wireguard", "openvpn", "ipsec", "zerotier", "tailscale"},
			minLen:   10,
		},
		"ProxyConfig": {
			pattern:  regexp.MustCompile(`(?i)(?:proxy|socks|http[_-]?proxy|https[_-]?proxy|all[_-]?proxy|no[_-]?proxy)\s*[:=]\s*['"]?([^\s'"]{5,200})['"]?`),
			keywords: []string{"proxy", "socks", "http_proxy", "https_proxy"},
			minLen:   10,
		},
		"IntranetInfo": {
			pattern:  regexp.MustCompile(`(?i)(内网|intranet|internal|内部门户|内网地址|内网系统|内网平台).*?(?:地址|url|ip|域名|domain|入口|登录|账号)`),
			keywords: []string{"内网", "intranet", "internal", "内部门户"},
			minLen:   10,
		},
		"OnboardingDoc": {
			pattern:  regexp.MustCompile(`(?i)(入职|onboarding|新人|员工入职|入职指南|入职手册|账号申请).*?(?:账号|密码|登录|vpn|邮箱|内网)`),
			keywords: []string{"入职", "onboarding", "新人", "入职指南"},
			minLen:   10,
		},
		"ManualDoc": {
			pattern:  regexp.MustCompile(`(?i)(手册|manual|运维手册|操作手册|部署手册|技术手册).*?(?:账号|密码|登录|地址|配置|vpn|代理|内网)`),
			keywords: []string{"手册", "manual", "运维手册", "操作手册"},
			minLen:   10,
		},
	}

	// processSeverityMap 把内置进程描述映射到报告类别（从而决定严重等级）
	processSeverityMap = map[string]string{
		// 远控 / RAT / C2 —— 严重
		"VNC":        "RemoteTool",
		"TeamViewer": "RemoteTool",
		"AnyDesk":    "RemoteTool",
		"ToDesk":     "RemoteTool",
		"Sunlogin":   "RemoteTool",
		"RustDesk":   "RemoteTool",
		"Gh0st":      "MalwareProc",
		"Cobalt":     "MalwareProc",
		"AsyncRAT":   "MalwareProc",
		"DcRat":      "MalwareProc",
		"BitRAT":     "MalwareProc",
		"DarkComet":  "MalwareProc",
		"NanoCore":   "MalwareProc",
		"njRAT":      "MalwareProc",
		"Remcos":     "MalwareProc",
		"Orcus":      "MalwareProc",
		"Quasar":     "MalwareProc",
		"XWorm":      "MalwareProc",
		"SparkRAT":   "MalwareProc",

		// 信息窃取器 —— 严重
		"Lumma":       "StealerProc",
		"Stealc":      "StealerProc",
		"RisePro":     "StealerProc",
		"MetaStealer": "StealerProc",
		"RedLine":     "StealerProc",
		"Raccoon":     "StealerProc",
		"Vidar":       "StealerProc",

		// 代理工具 —— 低危
		"Frp":         "ProxyTool",
		"NPS":         "ProxyTool",
		"Ngrok":       "ProxyTool",
		"Chisel":      "ProxyTool",
		"Clash":       "ProxyTool",
		"V2Ray":       "ProxyTool",
		"Cloudflared": "ProxyTool",
		"Stowaway":    "ProxyTool",
		"Gost":        "ProxyTool",
		"SSHTunnel":   "ProxyTool",

		// C2 框架 —— 严重
		"Sliver":     "C2Proc",
		"Havoc":      "C2Proc",
		"BruteRatel": "C2Proc",
		"Covenant":   "C2Proc",
		"Mythic":     "C2Proc",
		"Empire":     "C2Proc",

		// 渗透工具 —— 中危/高危
		"Nmap":       "PentestTool",
		"Masscan":    "PentestTool",
		"Fscan":      "PentestTool",
		"SQLMap":     "PentestTool",
		"Hydra":      "PentestTool",
		"Metasploit": "PentestTool",
		"Xray":       "PentestTool",
		"Goby":       "PentestTool",
		"Yakit":      "PentestTool",
		"BurpSuite":  "PentestTool",
		"Commix":     "PentestTool",
		"BeEF":       "PentestTool",

		// 凭据提取工具 —— 严重
		"Mimikatz":   "CredentialTool",
		"LaZagne":    "CredentialTool",
		"SharpHound": "CredentialTool",

		// 服务类 —— 低危/信息
		"MySQL":      "Process",
		"PostgreSQL": "Process",
		"MongoDB":    "Process",
		"Redis":      "Process",
		"Nginx":      "Process",
		"Apache":     "Process",
		"Tomcat":     "Process",
		"Docker":     "Process",

		// 面板
		"BaoTa":  "Process",
		"1Panel": "Process",

		// 开发
		"VSCode":     "Process",
		"JetBrains":  "Process",
		"FinalShell": "Process",

		// 通讯
		"Feishu":   "Process",
		"DingTalk": "Process",
		"WeCom":    "Process",
	}

	// interestingProcesses - 进程特征
	interestingProcesses = map[string]*regexp.Regexp{
		// 远控
		"VNC":        regexp.MustCompile(`(?i)\b(?:vnc|winvnc|tvnserver|ultravnc|tightvnc)(?:\.exe)?\b`),
		"TeamViewer": regexp.MustCompile(`(?i)\bteamviewer(?:\.exe)?\b`),
		"AnyDesk":    regexp.MustCompile(`(?i)\banydesk(?:\.exe)?\b`),
		"ToDesk":     regexp.MustCompile(`(?i)\btodesk(?:\.exe)?\b`),
		"Sunlogin":   regexp.MustCompile(`(?i)\bsunloginclient(?:\.exe)?\b`),
		"RustDesk":   regexp.MustCompile(`(?i)\brustdesk(?:\.exe)?\b`),
		"Gh0st":      regexp.MustCompile(`(?i)\bgh0st(?:\.exe)?\b`),
		"Cobalt":     regexp.MustCompile(`(?i)(?:beacon|cobaltstrike)`),
		"AsyncRAT":   regexp.MustCompile(`(?i)\basyncrat(?:\.exe)?\b`),
		"DcRat":      regexp.MustCompile(`(?i)\bdcrat(?:\.exe)?\b`),
		"BitRAT":     regexp.MustCompile(`(?i)\bbitrat(?:\.exe)?\b`),
		"DarkComet":  regexp.MustCompile(`(?i)\bdarkcomet(?:\.exe)?\b`),
		"NanoCore":   regexp.MustCompile(`(?i)\bnanocore(?:\.exe)?\b`),
		"njRAT":      regexp.MustCompile(`(?i)\bnjrat(?:\.exe)?\b`),
		"Remcos":     regexp.MustCompile(`(?i)\bremcos(?:\.exe)?\b`),
		"Orcus":      regexp.MustCompile(`(?i)\borcus(?:\.exe)?\b`),
		"Quasar":     regexp.MustCompile(`(?i)\bquasar(?:\.exe)?\b`),
		"XWorm":      regexp.MustCompile(`(?i)\bxworm(?:\.exe)?\b`),
		"SparkRAT":   regexp.MustCompile(`(?i)\bsparkrat(?:\.exe)?\b`),

		// 信息窃取器
		"Lumma":      regexp.MustCompile(`(?i)\blumma(?:stealer)?(?:\.exe)?\b`),
		"Stealc":     regexp.MustCompile(`(?i)\bstealc(?:\.exe)?\b`),
		"RisePro":    regexp.MustCompile(`(?i)\brisepro(?:\.exe)?\b`),
		"MetaStealer": regexp.MustCompile(`(?i)\bmetastealer(?:\.exe)?\b`),
		"RedLine":    regexp.MustCompile(`(?i)\bredline(?:stealer)?(?:\.exe)?\b`),
		"Raccoon":    regexp.MustCompile(`(?i)\braccoon(?:stealer)?(?:\.exe)?\b`),
		"Vidar":      regexp.MustCompile(`(?i)\bvidar(?:\.exe)?\b`),

		// 代理
		"Frp":       regexp.MustCompile(`(?i)\b(?:frpc|frps)(?:\.exe)?\b`),
		"NPS":       regexp.MustCompile(`(?i)\b(?:npc|nps)(?:\.exe)?\b`),
		"Ngrok":     regexp.MustCompile(`(?i)\bngrok(?:\.exe)?\b`),
		"Chisel":    regexp.MustCompile(`(?i)\bchisel(?:\.exe)?\b`),
		"Clash":     regexp.MustCompile(`(?i)\b(?:clash|mihomo)(?:\.exe)?\b`),
		"V2Ray":     regexp.MustCompile(`(?i)\bv2ray(?:\.exe)?\b`),
		"Cloudflared": regexp.MustCompile(`(?i)\bcloudflared(?:\.exe)?\b`),
		"Stowaway":  regexp.MustCompile(`(?i)\bstowaway(?:\.exe)?\b`),
		"Gost":      regexp.MustCompile(`(?i)\bgost(?:\.exe)?\b`),
		"SSHTunnel": regexp.MustCompile(`\bssh\b.*-[RLD]\s+\d+`),

		// C2 框架
		"Sliver":     regexp.MustCompile(`(?i)\bsliver(?:\.exe)?\b`),
		"Havoc":      regexp.MustCompile(`(?i)\bhavoc(?:\.exe)?\b`),
		"BruteRatel": regexp.MustCompile(`(?i)\bbruteratel(?:\.exe)?\b`),
		"Covenant":   regexp.MustCompile(`(?i)\bcovenant(?:\.exe)?\b`),
		"Mythic":     regexp.MustCompile(`(?i)\bmythic(?:\.exe)?\b`),
		"Empire":     regexp.MustCompile(`(?i)\bempire(?:\.exe)?\b`),

		// 渗透
		"Nmap":       regexp.MustCompile(`(?i)\bnmap(?:\.exe)?\b`),
		"Masscan":    regexp.MustCompile(`(?i)\bmasscan(?:\.exe)?\b`),
		"Fscan":      regexp.MustCompile(`(?i)\bfscan(?:\.exe)?\b`),
		"SQLMap":     regexp.MustCompile(`(?i)\bsqlmap\b`),
		"Hydra":      regexp.MustCompile(`(?i)\bhydra(?:\.exe)?\b`),
		"Metasploit": regexp.MustCompile(`(?i)(?:msfconsole|msfvenom|meterpreter)`),
		"Xray":       regexp.MustCompile(`(?i)\bxray(?:\.exe)?\b`),
		"Goby":       regexp.MustCompile(`(?i)\bgoby(?:\.exe)?\b`),
		"Yakit":      regexp.MustCompile(`(?i)\byakit(?:\.exe)?\b`),
		"BurpSuite":  regexp.MustCompile(`(?i)\b(?:burpsuite|burp suite)\b`),
		"Commix":     regexp.MustCompile(`(?i)\bcommix(?:\.exe)?\b`),
		"BeEF":       regexp.MustCompile(`(?i)\bbeef(?:\.exe)?\b`),

		// 密码
		"Mimikatz":   regexp.MustCompile(`(?i)(?:mimikatz|lsadump|sekurlsa)`),
		"LaZagne":    regexp.MustCompile(`(?i)\blazagne(?:\.exe)?\b`),
		"SharpHound": regexp.MustCompile(`(?i)\bsharphound(?:\.exe)?\b`),

		// 服务
		"MySQL":      regexp.MustCompile(`(?i)\bmysqld(?:\.exe)?\b`),
		"PostgreSQL": regexp.MustCompile(`(?i)\bpostgres(?:\.exe)?\b`),
		"MongoDB":    regexp.MustCompile(`(?i)\bmongod(?:\.exe)?\b`),
		"Redis":      regexp.MustCompile(`(?i)\bredis-server(?:\.exe)?\b`),
		"Nginx":      regexp.MustCompile(`(?i)\bnginx(?:\.exe)?\b`),
		"Apache":     regexp.MustCompile(`(?i)\b(?:httpd|apache2)(?:\.exe)?\b`),
		"Tomcat":     regexp.MustCompile(`(?i)(?:tomcat|catalina)`),
		"Docker":     regexp.MustCompile(`(?i)\bdockerd(?:\.exe)?\b`),

		// 面板
		"BaoTa":  regexp.MustCompile(`(?i)(?:bt-task|bt-panel)`),
		"1Panel": regexp.MustCompile(`(?i)\b1panel\b`),

		// 开发
		"VSCode":     regexp.MustCompile(`(?i)Visual Studio Code`),
		"JetBrains":  regexp.MustCompile(`(?i)(?:idea|pycharm|webstorm|goland|clion|phpstorm)`),
		"FinalShell": regexp.MustCompile(`(?i)\bfinalshell\b`),

		// 通讯
		"Feishu":   regexp.MustCompile(`(?i)\bfeishu\b`),
		"DingTalk": regexp.MustCompile(`(?i)\bdingtalk\b`),
		"WeCom":    regexp.MustCompile(`(?i)\bwecom\b`),
	}
)
