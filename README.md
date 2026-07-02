# XunFeng (寻风) v3.0

<p align="center">
  <img src="https://img.shields.io/badge/Version-3.0.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/Go-1.19+-00ADD8.svg" alt="Go Version">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
</p>

<p align="center">
  <b>高性能跨平台敏感信息扫描工具</b><br>
  <i>专为红队信息收集、内网渗透与安全审计设计</i>
</p>

```
   ██╗  ██╗██╗   ██╗███╗   ██╗███████╗███████╗███╗   ██╗ ██████╗
   ╚██╗██╔╝██║   ██║████╗  ██║██╔════╝██╔════╝████╗  ██║██╔════╝
    ╚███╔╝ ██║   ██║██╔██╗ ██║█████╗  █████╗  ██╔██╗ ██║██║  ███╗
    ██╔██╗ ██║   ██║██║╚██╗██║██╔══╝  ██╔══╝  ██║╚██╗██║██║   ██║
   ██╔╝ ██╗╚██████╔╝██║ ╚████║██║     ███████╗██║ ╚████║╚██████╔╝
   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝     ╚══════╝╚═╝  ╚═══╝ ╚═════╝
```

---

## 使用场景

| 场景 | 说明 |
|:----:|:-----|
| **红队信息收集** | 进入目标主机后快速盘点进程、网络、凭证、浏览器痕迹 |
| **内网渗透** | 发现可写 PATH/启动目录，为持久化和横向移动寻找落地点 |
| **安全审计** | 批量检查代码/配置文件中的密码、Token、云密钥 |
| **失陷主机排查** | 识别 Cobalt Strike / 远控 / 隧道 / 挖矿进程 |
| **敏感文件梳理** | 提取 Office 文档、压缩包、数据库文件中的敏感内容 |

---

## 特性亮点

- **极速扫描**: Aho-Corasick 多模式匹配 + 并发遍历，实测 40 万文件 30+ 秒
- **多维检测**: 进程、网络、凭证、环境变量、Shell 历史、浏览器、可写目录、文件系统
- **进程识别**: 内置 14,000+ 进程规则库（杀软/EDR/安全工具/远控/渗透工具等）
- **Office 支持**: 原生解析 `.docx/.xlsx/.pptx`，兼容旧格式 `.doc/.xls/.ppt`
- **补充模式**: 独立提取 IPv4、URL、凭据对（`admin:admin123`）、弱口令、邮箱
- **可写目录**: 识别启动目录、PATH 目录、公共目录等可写可执行路径
- **YARA 可选**: 支持 `-tags yara` 集成 YARA 规则扫描文件与进程内存
- **跨平台**: Windows / Linux / macOS 原生支持，无需 CGO 即可编译运行
- **低权限友好**: 自动跳过无权限目录，普通用户也能完整扫描自身数据
- **智能过滤**: 自动跳过无关目录，误报过滤，去重输出
- **多格式报告**: Markdown 表格 / JSON / TXT
- **隐匿模式**: 沙箱检测、调试器检测、随机延迟

---

## 快速开始

### 下载

从 [Releases](https://github.com/JishiTeam-J1wa/Xunfeng/releases) 下载对应平台的二进制文件：

| 平台 | 文件名 |
|:----:|:-------|
| macOS Intel | `xunfeng_darwin_amd64` |
| macOS Apple Silicon | `xunfeng_darwin_arm64` |
| Windows x64 | `xunfeng_windows_amd64.exe` |
| Windows x86 | `xunfeng_windows_386.exe` |
| Linux x64 | `xunfeng_linux_amd64` |
| Linux ARM64 | `xunfeng_linux_arm64` |

### 基础用法

```bash
# 全盘扫描（默认）
./xunfeng

# 指定目录
./xunfeng -p /path/to/scan

# 指定 Windows 目录
./xunfeng.exe -p C:/Users/Admin/Desktop

# 扫描单个文件
./xunfeng -p /path/to/file.docx

# 生成 Markdown 报告
./xunfeng -f md -o report.md

# 生成 JSON 报告
./xunfeng -f json -o report.json

# 隐匿模式（每操作随机延迟 50ms）
./xunfeng -s 50

# 使用 YARA 规则扫描（需使用 yara 构建标签重新编译）
./xunfeng -yara-rules ./rules
```

### 命令行参数

| 参数 | 说明 | 默认值 |
|:----:|:-----|:------:|
| `-p` | 扫描路径 (目录或文件) | 全盘 |
| `-w` | 工作线程数 | CPU*2 |
| `-s` | 隐匿延迟 (毫秒) | 0 |
| `-f` | 输出格式 (txt/json/md) | txt |
| `-o` | 输出文件 | xunfeng_report.txt |
| `-silent` | 静默模式 | false |
| `-skip-sandbox` | 跳过沙箱检测 | false |
| `-skip-debug` | 跳过调试检测 | false |
| `-yara-rules` | YARA 规则文件/目录（需 `-tags yara` 编译） | "" |

---

## 检测能力

### 扫描模块

| 模块 | 检测内容 | 典型风险 |
|:----:|:---------|:---------|
| **进程扫描** | 数据库、远控 RAT、代理隧道、渗透工具、杀软/EDR | 识别已运行木马、已知工具 |
| **网络扫描** | C2 外连、可疑端口监听 | 发现活跃后门通道 |
| **凭证扫描** | SSH 密钥、云凭证、Docker/K8s 配置 | 直接获取横向移动凭据 |
| **环境变量** | `PASSWORD`/`SECRET`/`TOKEN`/`KEY` 等 | 硬编码密钥 |
| **Shell 历史** | 命令行中的密码参数、curl 认证、数据库连接 | 历史命令泄露 |
| **浏览器** | Chrome/Edge 历史中的敏感 URL | 内部系统入口 |
| **可写目录** | 启动目录、PATH 目录、公共目录 | 持久化/劫持利用点 |
| **文件系统** | 配置文件、Office 文档、私钥、凭证文件 | 静态敏感信息 |

### 风险分级

| 等级 | 颜色 | 类型示例 |
|:----:|:----:|:---------|
| **CRITICAL** | 红色 | 私钥、数据库连接串、云平台密钥、启动目录可写、Cobalt Strike 进程 |
| **HIGH** | 橙色 | 密码、Token、API Key、PATH 目录可写 |
| **MEDIUM** | 黄色 | 中文密码、敏感配置、用户目录可写 |
| **LOW** | 青色 | 杀软/EDR 进程、内网文档、Temp 目录可写 |
| **INFO** | 灰色 | 浏览器历史、Shell 命令、IP/URL/邮箱 |

### 支持的敏感规则

<details>
<summary><b>点击展开完整规则列表</b></summary>

#### 通用凭证
- Password / Passwd / Secret
- API Key / Access Key
- Token / Auth Token / Bearer Token
- JWT Secret
- 凭据对（如 `admin:admin123`、`root Password1`）
- 弱口令（如 `admin123`、`password1`、`12345678`）

#### 云服务商
- AWS Access Key (`AKIA...`)
- AWS Secret Key
- 阿里云 AccessKey (`LTAI...`)
- 腾讯云密钥 (`AKID...`)
- Azure Storage Key
- GCP Service Account

#### API Tokens
- GitHub Token (`ghp_`/`gho_`/`ghu_`)
- GitLab Token (`glpat-`)
- Slack Token (`xoxb-`/`xoxp-`)
- Stripe Key (`sk_live_`)
- NPM Token (`npm_`)
- Heroku API Key

#### 数据库
- MongoDB Connection String
- PostgreSQL Connection String
- MySQL Connection String
- Redis URL
- JDBC Connection String

#### 私钥
- RSA Private Key
- EC Private Key
- PGP Private Key
- SSH Private Key

#### 中文特征
- 密码 / 口令
- 数据库地址
- 账号密码
- VPN / 代理 / 内网 / 入职 / 手册 / 账号 / 密码 / 凭据

#### 网络信息
- IPv4 地址
- URL（HTTP/HTTPS/FTP 等）
- 邮箱地址

</details>

---

## 输出示例

### CLI 输出

```
┌ SYSTEM INFO ───────────────────────────────┐
│ 当前用户:          JISHITEAM\93789
│ 权限级别:          普通用户
│ 主机名:           jishiteam
│ 操作系统:          windows
│ 网卡/IP:         以太网: 192.168.31.67
└────────────────────────────────────────────┘

━━━━━━━━━━ PROCESS SCAN ━━━━━━━━━━
[+] Process        MySQL                 PID:1234   /usr/local/mysql/bin/mysqld
[+] Process        Frp                   PID:5678   frpc -c /etc/frp/frpc.ini
[CRITICAL] Process        Cobalt                PID:11132  beacon_windows_amd64.exe

━━━━━━━━━━ WRITABLE DIRECTORIES ━━━━━━━━━━
[CRITICAL] WritableDirCritical C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp  CRITICAL 可写可执行目录
[HIGH] WritableDirHigh C:\Python27\Scripts  HIGH 可写可执行目录

━━━━━━━━━━ CREDENTIAL SCAN ━━━━━━━━━━
[+] SSHKey         PrivateKey            /Users/test/.ssh/id_rsa
[+] CloudCred      AWS                   /Users/test/.aws/credentials

━━━━━━━━━━ FILESYSTEM SCAN ━━━━━━━━━━
[CRIT] DBConnStr       /app/config.yml:12  mongodb://admin:pass@localhost:27017
[HIGH] Password        /app/.env:5         password = "SuperSecret123!"
[HIGH] APIKey          /app/.env:8         API_KEY=sk-xxxxxxxxxx

━━━━━━━━━━ SCAN COMPLETE ━━━━━━━━━━

  │ Scanned:  40000 files in 2.5s

  ┌ 敏感发现:
  │ 严重:  5 (私钥/连接串/云密钥)
  │ 高危:  23 (密码/Token/APIKey)
  │ 中危:  8 (配置文件/中文密码)
  ├──────────────────────────
  ╰ 合计:  36 个敏感发现

  ► Report saved: report.md
```

### Markdown 报告

生成专业的表格报告，INFO 级别自动折叠：

```markdown
# XunFeng 敏感信息扫描报告

## 风险概览

| 等级 | 数量 | 类型 |
|:----:|:----:|:-----|
| 🔴 严重 | **5** | 私钥 / DB连接串 / 云密钥 / 启动目录可写 |
| 🟠 高危 | **23** | 密码 / Token / API Key / PATH 可写 |
| 🟡 中危 | **8** | 配置文件 / 中文凭证 |

## 严重风险 (5)

| # | 类型 | 文件位置 | 敏感内容 |
|:-:|:----:|:---------|:---------|
| 1 | DBConnStr | `/app/config.yml:12` | `mongodb://admin:***@...` |
...
```

---

## 性能基准

| 规模 | 耗时 | 吞吐量 |
|:----:|:----:|:------:|
| 40,000 文件 | ~3s | ~13,000 文件/秒 |
| 110,000 文件 | ~8s | ~13,500 文件/秒 |
| 410,000 文件 | ~34s | ~12,000 文件/秒 |

**测试环境**: Windows 11, AMD Ryzen 7, SSD, 普通用户权限

### 性能优化技术

- **Aho-Corasick**: O(n) 多模式匹配
- **64-shard 去重**: 并发安全，减少锁竞争
- **零分配字符串**: 自定义 `toLowerASCII`
- **预筛选**: 字符掩码快速过滤无关内容
- **并发根目录遍历**: 多驱动器并行
- **模式扫描窗口**: 200KB 正则扫描上限，避免大文件拖慢

---

## 权限要求

| 操作系统 | 最小权限 | 推荐权限 |
|:--------:|:--------:|:--------:|
| macOS | 当前用户 | Full Disk Access |
| Linux | 当前用户 | root |
| Windows | 当前用户 | Administrator |

XunFeng 已针对**低权限环境**优化：默认跳过系统目录和其他用户目录，普通用户也能完整扫描自身数据，不会因权限不足而中断。

### macOS 特殊说明

1. **Full Disk Access**: 扫描 `~/Library/` 等受保护目录需要在 系统偏好设置 > 安全性与隐私 > 隐私 > 完全磁盘访问权限 中添加终端或程序
2. **浏览器数据**: 读取 Chrome/Edge 数据可能需要关闭浏览器
3. **Office 文档**: 使用系统自带 `textutil` 解析，无需额外安装

---

## 从源码编译

### 环境要求

- Go 1.19+
- CGO **可选**（默认使用纯 Go SQLite，无需 C 编译器）

### 编译步骤

```bash
# 克隆仓库
git clone https://github.com/JishiTeam-J1wa/Xunfeng.git
cd Xunfeng

# 当前平台编译（无需 CGO）
go build -ldflags="-s -w" -o xunfeng .

# Windows 示例
CGO_ENABLED=0 go build -o xunfeng.exe .

# 跨平台编译
chmod +x build.sh && ./build.sh
```

### 使用 CGO（可选）

如果本地有 C 编译器且希望使用 `mattn/go-sqlite3`：

```bash
# Linux
CGO_ENABLED=1 go build -o xunfeng .

# Windows (需 mingw-w64)
CGO_ENABLED=1 go build -o xunfeng.exe .
```

### 启用 YARA 支持（可选）

需要系统安装 libyara：

```bash
go build -tags yara -o xunfeng .
```

### 依赖说明

| 依赖 | 用途 |
|:----:|:-----|
| `github.com/fatih/color` | 彩色终端输出 |
| `github.com/mattn/go-sqlite3` | 浏览器数据库读取（CGO 模式） |
| `modernc.org/sqlite` | 浏览器数据库读取（纯 Go 模式） |
| `github.com/shirou/gopsutil` | 系统/进程/网络信息 |
| `github.com/hillu/go-yara/v4` | YARA 特征扫描（可选） |

---

## 项目结构

```
Xunfeng/
├── main.go              # 主程序入口和扫描逻辑
├── rules.go             # 敏感信息检测规则
├── reporter.go          # 报告生成器 (MD/JSON/TXT)
├── ahocorasick.go       # Aho-Corasick 多模式匹配算法
├── patterns.go          # IP/URL/凭据对/弱口令/邮箱提取
├── ole.go               # OLE 复合文档解析
├── biff.go              # Excel 97-2003 (.xls) 文本提取
├── perms.go             # 可写可执行目录检测
├── process_rules.go     # 进程规则加载
├── privilege_windows.go # Windows 权限信息
├── privilege_unix.go    # Linux/macOS 权限信息
├── sqlite_cgo.go        # CGO SQLite 适配
├── sqlite_nocgo.go      # 纯 Go SQLite 适配
├── yara_scan.go         # YARA 扫描（需 yara 构建标签）
├── yara_scan_stub.go    # YARA 无操作桩
├── assets/              # 进程规则 JSON
│   └── process_rules.json
├── scripts/             # 规则处理脚本
│   ├── merge_av_rules.py
│   └── parse_cna.py
├── xunfeng_test.go      # 单元测试
├── bench_test.go        # 性能基准测试
├── build.sh             # 跨平台编译脚本
├── README.md            # 项目文档
├── go.mod               # Go 模块定义
└── go.sum               # 依赖校验
```

---

## 自动排除

为提升扫描速度并减少低权限下的报错，自动跳过以下目录：

- **通用**: `node_modules`, `vendor`, `.git`, `.svn`, `__pycache__`
- **IDE**: `.idea`, `.vscode`
- **缓存**: `cache`, `.cache`, `tmp`, `temp`, `logs`
- **构建**: `dist`, `build`, `.next`, `target`
- **macOS**: `/System`, `/Library/Caches`, `~/Library/Caches`
- **Linux**: `/proc`, `/sys`, `/dev`, `/run`
- **Windows**: `Windows\System32`, `Windows\SysWOW64`, `ProgramData`, `$Recycle.Bin`, `Recovery`, 其他用户目录

---

## 隐匿特性

针对红队场景的隐匿设计：

| 特性 | 说明 |
|:----:|:-----|
| **沙箱检测** | 检测虚拟机/沙箱 (CPU核数、内存、运行时间、进程数) |
| **调试检测** | 检测 gdb/lldb/strace 等调试器 |
| **随机扫描** | 打乱目录扫描顺序 |
| **延迟模式** | `-s` 参数增加操作间隔 |

使用 `-skip-sandbox` 和 `-skip-debug` 跳过检测（调试用）。

---

## 贡献指南

欢迎提交 Issue 和 Pull Request！

### 开发流程

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add AmazingFeature'`)
4. 推送分支 (`git push origin feature/AmazingFeature`)
5. 创建 Pull Request

### 代码规范

- 使用 `go fmt` 格式化代码
- 运行 `go vet` 和 `staticcheck` 检查
- 添加单元测试 (`go test ./...`)
- 保持测试覆盖率 > 20%

---

## 免责声明

本工具仅用于**授权的安全测试**和**红队演练**。使用者需遵守当地法律法规，对使用本工具造成的任何后果自行承担责任。

**禁止用于**:
- 未经授权的系统入侵
- 非法数据窃取
- 任何违法活动

---

## 更新日志

### v3.0.0 (2026-07)

**新特性**
- 14,000+ 进程规则库，覆盖杀软/EDR/安全工具/远控/渗透工具
- 系统信息展示：当前用户、权限级别、操作系统、网卡/IP
- 可写可执行目录检测（启动目录/PATH/公共目录）
- 独立 IP / URL / 凭据对 / 弱口令 / 邮箱 提取
- 敏感关键词扩展：VPN、代理、内网、入职、手册、账号、密码、凭据
- Office 旧格式支持：`.doc` / `.xls` / `.ppt`
- YARA 可选集成（`-tags yara`）
- 纯 Go SQLite 支持，无需 CGO 即可跨平台编译

**优化**
- 低权限目录排除，弱化权限影响
- 并发根目录遍历，提升多驱动器扫描速度
- 200KB 模式扫描窗口，避免大文件正则拖慢
- 4KB 快速字符预筛选

**修复**
- 修复 Windows 下权限不足导致的扫描中断
- 修复 Office 旧文档解析失败
- 修复跨平台编译依赖 CGO 问题

### v3.0.0 (2026-06)

**新特性**
- Aho-Corasick 多模式匹配算法
- Office 文档扫描 (.docx/.xlsx/.doc/.xls)
- Markdown 表格报告格式
- 风险五级分类 (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- UTF-8 中文路径正确显示

**优化**
- 64-shard 并发去重
- 零分配字符串操作

### v2.0.0 (2025-10)

- 初始发布
- 多维度扫描 (进程/网络/凭证/文件)
- 隐匿模式支持

---

## 许可证

本项目采用 [MIT License](LICENSE) 开源。

---

<p align="center">
  <b>JishiTeam (击势安全团队)</b><br>
  <i>为安全而生</i>
</p>
