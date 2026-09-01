<div align="center">

```
   ██╗  ██╗██╗   ██╗███╗   ██╗███████╗███████╗███╗   ██╗ ██████╗
   ╚██╗██╔╝██║   ██║████╗  ██║██╔════╝██╔════╝████╗  ██║██╔════╝
    ╚███╔╝ ██║   ██║██╔██╗ ██║█████╗  █████╗  ██╔██╗ ██║██║  ███╗
    ██╔██╗ ██║   ██║██║╚██╗██║██╔══╝  ██╔══╝  ██║╚██╗██║██║   ██║
   ██╔╝ ██╗╚██████╔╝██║ ╚████║██║     ███████╗██║ ╚████║╚██████╔╝
   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝     ╚══════╝╚═╝  ╚═══╝ ╚═════╝
```

# XunFeng 寻风

**主机敏感信息收集工具**

专为红队信息收集、内网渗透与安全审计设计

[![Version](https://img.shields.io/badge/Version-4.0.0-blue.svg)](https://github.com/JishiTeam-J1wa/Xunfeng/releases)
[![Go](https://img.shields.io/badge/Go-1.25+-00ADD8.svg)](https://go.dev/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)](#-跨平台支持)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/JishiTeam-J1wa/Xunfeng?style=social)](https://github.com/JishiTeam-J1wa/Xunfeng/stargazers)

[下载](https://github.com/JishiTeam-J1wa/Xunfeng/releases) · [快速开始](#-快速开始) · [使用指南](#-使用指南) · [检测能力](#-检测能力) · [二次开发](#-二次开发嵌入)

</div>

---

## 📖 目录

- [项目简介](#-项目简介)
- [特性亮点](#-特性亮点)
- [快速开始](#-快速开始)
- [使用指南](#-使用指南)
  - [命令行参数](#命令行参数)
  - [基础用法](#基础用法)
  - [实战组合场景](#实战组合场景)
  - [输出说明](#输出说明)
- [检测能力](#-检测能力)
- [输出示例](#-输出示例)
- [性能基准](#-性能基准)
- [权限要求](#-权限要求)
- [从源码编译](#-从源码编译)
- [二次开发/嵌入](#-二次开发嵌入)
- [项目结构](#-项目结构)
- [常见问题](#-常见问题)
- [贡献指南](#-贡献指南)
- [免责声明](#-免责声明)

---

## 🎯 项目简介

XunFeng（寻风）是一个**单二进制、零依赖、开箱即用**的本机信息收集工具。拿到一台主机的 shell 之后，把 XunFeng 丢上去跑一遍，它会自动完成：

- 盘点正在运行的**进程**（识别杀软/EDR/远控/隧道/渗透工具）
- 检查**网络连接**中的可疑端口外连
- 翻找 **SSH 密钥、云凭证、Docker/K8s 配置**
- 提取**环境变量、Shell 历史、浏览器保存的密码与 Cookie**里的敏感信息
- 找出**可写可执行目录**（持久化/劫持落地点）
- 全盘扫描**文件内容**中的密码、Token、云密钥、数据库连接串
- 按系统版本给出**提权漏洞建议**
- 生成 **TXT / JSON / Markdown** 三种格式的报告

| 场景 | 说明 |
|:----:|:-----|
| **红队信息收集** | 进入目标主机后快速盘点进程、网络、凭证、浏览器痕迹 |
| **内网渗透** | 发现可写 PATH/启动目录，为持久化和横向移动寻找落地点 |
| **安全审计** | 批量检查代码/配置文件中的密码、Token、云密钥 |
| **失陷主机排查** | 识别 Cobalt Strike / 远控 / 隧道 / 挖矿进程 |
| **敏感文件梳理** | 提取 Office 文档、PDF、ZIP 包内的敏感内容，标记数据库等敏感文件位置 |

---

## ✨ 特性亮点

- 🚀 **极速扫描**：Aho-Corasick 多模式匹配 + 并发遍历，实测 40 万文件约 34 秒
- 🧠 **多维检测**：进程、网络、凭证、环境变量、Shell 历史、浏览器、可写目录、文件系统
- 🛡️ **进程识别**：内置 360+ 条进程规则、覆盖 1,400+ 进程特征（杀软/EDR/安全工具/远控/渗透工具）
- 📄 **文档解析**：原生解析 `.docx/.xlsx/.pptx` 与旧格式 `.doc/.xls/.ppt`（自研 OLE/BIFF/FIB 解析器），另支持 `.pdf` 文本流提取与 `.zip` 解包扫描
- 🔑 **浏览器凭证**：提取 Chrome/Edge 保存的密码与 Cookie（Windows DPAPI / macOS Keychain / Linux 自动适配）
- 🔎 **补充模式**：独立提取 IPv4、URL、凭据对（`admin:admin123`）、弱口令、邮箱
- 📂 **可写目录**：真实写入测试，识别启动目录、PATH 目录、公共目录等可写可执行路径
- 🧬 **YARA 可选**：支持 `-tags yara` 集成 YARA 规则扫描文件与进程内存
- 🌐 **跨平台**：Windows / Linux / macOS 原生支持，无需 CGO 即可编译运行
- 👤 **低权限友好**：自动跳过无权限目录，普通用户也能完整扫描自身数据
- 🧹 **智能过滤**：自动跳过无关目录，误报过滤，熵值校验，去重输出
- 📊 **多格式报告**：Markdown 表格 / JSON / TXT，另附实时日志便于断点排查
- 🥷 **隐匿模式**：沙箱检测、调试器检测（Linux/macOS）、随机延迟
- 🧩 **可嵌入**：提供 C 动态库（`.dll/.so/.dylib`）与 Go Plugin，可集成进自己的工具链

---

## 🚀 快速开始

### 方式一：下载预编译二进制（推荐）

从 [Releases](https://github.com/JishiTeam-J1wa/Xunfeng/releases) 下载对应平台：

| 平台 | 文件名 |
|:----:|:-------|
| macOS Intel | `xunfeng_darwin_amd64` |
| macOS Apple Silicon | `xunfeng_darwin_arm64` |
| Windows x64 | `xunfeng_windows_amd64.exe` |
| Windows x86 | `xunfeng_windows_386.exe` |
| Linux x64 | `xunfeng_linux_amd64` |
| Linux ARM64 | `xunfeng_linux_arm64` |

```bash
# macOS / Linux：赋予执行权限后直接运行
chmod +x xunfeng_darwin_arm64
./xunfeng_darwin_arm64

# Windows：直接运行
xunfeng_windows_amd64.exe
```

### 方式二：源码编译

```bash
git clone https://github.com/JishiTeam-J1wa/Xunfeng.git
cd Xunfeng
go build -ldflags="-s -w" -o xunfeng .
```

### 30 秒上手

```bash
./xunfeng -p ~/Documents -f md -o report.md
```

扫描「文档」目录，生成一份 Markdown 报告。就这么简单。

---

## 📚 使用指南

### 命令行参数

| 参数 | 说明 | 默认值 |
|:----:|:-----|:------:|
| `-p` | 扫描路径（目录或单个文件） | 全盘 |
| `-w` | 内容扫描工作线程数 | CPU 核数 × 2 |
| `-s` | 隐匿模式：每个目录条目延迟 N 毫秒（含随机抖动） | 0 |
| `-f` | 报告格式：`txt` / `json` / `md` | txt |
| `-o` | 报告输出文件路径 | `xunfeng_report.txt` |
| `-silent` | 静默模式，不输出 banner 和彩色日志 | false |
| `-skip-sandbox` | 跳过沙箱/虚拟机检测 | false |
| `-skip-debug` | 跳过调试器检测 | false |
| `-yara-rules` | YARA 规则文件或目录（需 `-tags yara` 编译，见下文） | 空 |
| `-jiwa` | 稽核模式：预统计文件数，显示进度条与 ETA | false |
| `-nodir` | 完整扫描：不排除任何目录 | false |
| `-show-secrets` | 报告中输出明文敏感值（默认掩码） | false |
| `-skip-cred-decrypt` | 跳过浏览器密码/Cookie 解密（避免 macOS Keychain 弹窗） | false |

### 基础用法

```bash
# 1. 全盘扫描（默认行为，什么参数都不加）
./xunfeng

# 2. 扫描指定目录
./xunfeng -p /path/to/scan
./xunfeng.exe -p C:/Users/Admin/Desktop

# 3. 扫描单个文件（支持 Office 文档）
./xunfeng -p ./secret.docx

# 4. 指定报告格式
./xunfeng -f txt -o report.txt      # 纯文本（默认）
./xunfeng -f json -o report.json    # JSON，适合程序处理
./xunfeng -f md -o report.md        # Markdown 表格，适合汇报

# 5. 调整线程数（默认 CPU×2，内容扫描上限 64 线程）
./xunfeng -w 32

# 6. 静默模式（无 banner、无彩色输出，适合重定向）
./xunfeng -silent -f json -o result.json
```

### 实战组合场景

#### 场景 1：红队落地快速盘点

拿到 shell 后，先摸清楚这台机器的状况，全程不落地多余文件：

```bash
./xunfeng -silent -f json -o /tmp/.xfs_cache.json
```

- `-silent`：不打印 banner 和彩色日志，避免在日志系统留下特征
- `-f json`：结构化输出，方便拿回本地后用 `jq` 筛选

拿回结果后本地分析：

```bash
# 只看严重级别发现
jq '.findings[] | select(.severity=="CRITICAL")' /tmp/.xfs_cache.json

# 统计各类发现数量
jq '.findings | group_by(.category) | map({category: .[0].category, count: length})' /tmp/.xfs_cache.json
```

#### 场景 2：高对抗环境隐匿扫描

目标有 EDR/审计，需要降低扫描行为特征：

```bash
./xunfeng -s 100 -silent -f txt -o report.txt
```

- `-s 100`：每处理一个目录条目随机延迟约 100ms，拉低磁盘 I/O 峰值
- 程序启动时自带沙箱检测，发现虚拟机/沙箱环境会拒绝运行（调试自己时用 `-skip-sandbox` 跳过）

#### 场景 3：内网本机敏感文件专项审计

只关心文档和代码目录里的硬编码密钥，生成可汇报的 Markdown：

```bash
./xunfeng -p /Users/dev -f md -o audit_$(date +%Y%m%d).md
```

支持直接投喂单个文档，快速确认某个 xls/ppt 里有没有敏感内容：

```bash
./xunfeng -p "./财务/账号清单.xls"
./xunfeng -p "./运维手册.pptx"
```

#### 场景 4：大批量主机稽核（进度可视）

需要扫描大盘、希望看到实时进度和预计完成时间：

```bash
./xunfeng -jiwa -f md -o audit_report.md
```

- `-jiwa` 稽核模式会先预统计目标文件数，然后渲染百分比进度条与 ETA
- 扫描过程实时写入 `xunfeng_live.txt`（与报告同目录的 `.live.txt` 文件），中途崩溃也能从日志恢复已发现结果

#### 场景 5：CI/CD 流水线卡密钥泄露

在流水线里对代码库做提交前/发布前检查：

```bash
# 扫代码仓库，JSON 输出
./xunfeng -p ./src -silent -f json -o scan.json

# 有 CRITICAL/HIGH 就失败退出
CRIT=$(jq '[.findings[] | select(.severity=="CRITICAL" or .severity=="HIGH")] | length' scan.json)
if [ "$CRIT" -gt 0 ]; then
  echo "发现 $CRIT 处高危敏感信息，阻断发布"
  exit 1
fi
```

#### 场景 6：YARA 深度扫描（高级）

默认二进制不含 YARA。需要用自己的 YARA 规则扫文件内容和进程内存时：

```bash
# 1. 安装 libyara（macOS: brew install yara；Debian: apt install libyara-dev）
# 2. 用 yara 标签重新编译
go build -tags yara -o xunfeng-yara .

# 3. 指定规则目录扫描
./xunfeng-yara -yara-rules ./my_rules/ -p /target
```

> ⚠️ 注意：普通构建下传 `-yara-rules` 不生效，必须用 `-tags yara` 编译的版本。

#### 场景 7：嵌入自己的工具链

XunFeng 可以编译成动态库或 Go Plugin，作为你自研平台的一个扫描引擎（详见[二次开发](#-二次开发嵌入)）：

```bash
./build_obfuscated.sh   # 同时产出普通二进制、.dylib/.so、.plugin
```

### 输出说明

一次扫描会产生三类输出：

| 输出 | 说明 |
|:----:|:-----|
| **终端输出** | 彩色分级日志（CRITICAL 红 / HIGH 橙 / MEDIUM 黄 / LOW 青 / INFO 灰），实时显示发现 |
| **报告文件** | 由 `-o`/`-f` 指定，TXT 分段落、JSON 结构化、Markdown 表格（INFO 级自动折叠） |
| **实时日志** | 报告路径旁自动生成 `*.live.txt`，每条发现即时落盘，进程崩溃也不丢结果 |

扫描行为约束（为了避免拖慢/拖垮目标机，内置了安全阈值）：

- 单文件最多读取前 **512KB**、前 **5000 行**
- 超过 **10MB** 的文件跳过内容扫描
- 二进制文件（魔数 + 非打印字符比例识别）自动跳过
- 每类发现在报告中有数量上限，避免报告体积爆炸

---

## 🔍 检测能力

### 扫描模块

| 模块 | 检测内容 | 典型风险 |
|:----:|:---------|:---------|
| **进程扫描** | 数据库、远控 RAT、代理隧道、渗透工具、杀软/EDR | 识别已运行木马、已知工具 |
| **网络扫描** | 可疑端口外连与监听（4444/5555/1080/3389/5900 等） | 发现活跃后门通道 |
| **凭证扫描** | SSH 密钥、云凭证、Docker/K8s 配置——提取内容并掩码展示 | 横向移动凭据 |
| **环境变量** | `PASSWORD`/`SECRET`/`TOKEN`/`KEY` 等（输出自动掩码） | 硬编码密钥 |
| **Shell 历史** | 命令行中的密码参数、curl 认证、数据库连接 | 历史命令泄露 |
| **浏览器** | Chrome/Edge 保存的密码、Cookie、历史敏感 URL | 会话劫持 / 内部系统入口 |
| **可写目录** | 启动目录、PATH 目录、公共目录（真实写入测试） | 持久化/劫持利用点 |
| **提权建议** | 本机真实检查（SUID/sudo/可写服务/注册表）+ 补丁级 CVE 匹配 | 权限提升路径 |
| **文件系统** | 配置文件、Office 文档、私钥、凭证文件 | 静态敏感信息 |

### 风险分级

| 等级 | 颜色 | 类型示例 |
|:----:|:----:|:---------|
| **CRITICAL** | 🔴 红色 | 私钥、数据库连接串、云平台密钥、启动目录可写、Cobalt Strike 进程 |
| **HIGH** | 🟠 橙色 | 密码、Token、API Key、PATH 目录可写 |
| **MEDIUM** | 🟡 黄色 | 中文密码、敏感配置、用户目录可写 |
| **LOW** | 🔵 青色 | 杀软/EDR 进程、内网文档、Temp 目录可写 |
| **INFO** | ⚪ 灰色 | 浏览器历史、Shell 命令、IP/URL/邮箱 |

### 支持的敏感规则

<details>
<summary><b>点击展开完整规则列表</b></summary>

#### 通用凭证
- Password / Passwd / Secret
- API Key / Access Key
- Token / Auth Token / Bearer Token
- JWT Secret
- 凭据对（如 `admin:admin123`、`root:Password1`）
- 弱口令（如 `admin123`、`password1`、`12345678`）

#### 云服务商
- AWS Access Key (`AKIA...`)
- AWS Secret Key
- 阿里云 AccessKey (`LTAI...`)
- 腾讯云密钥 (`AKID...`)
- Azure Storage Key

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

### 自动排除的目录

默认**只排除纯系统目录**，不按目录名排除任何位置——`node_modules`、`.git`、`tmp`、`logs`、`ProgramData`、`/var/lib`、`/boot`、`~/Library`、`Program Files`、其他用户家目录等全部纳入扫描（这些位置常有高价值数据或攻击者驻留痕迹，无权限的条目遍历时自动跳过）：

- **macOS**：`/System`、`/Library`、`/usr`、`/bin`、`/sbin`、`/opt`
- **Linux**：`/proc`、`/sys`、`/dev`、`/run`、`/usr`、`/lib`、`/var/cache` 等
- **Windows**：`C:\Windows`、`$Recycle.Bin`、`Recovery`、`Users\Default`

需要彻底放开时加 `-nodir`：不排除任何目录，连 `/proc`、`/sys`、`/dev` 等伪文件系统也一并遍历（注意：读取伪文件系统可能产生大量无效数据）。

```bash
# 完整扫描模式：连系统目录一起扫
./xunfeng -nodir -p /target
```

---

## 📸 输出示例

### 终端输出

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
[CRITICAL] WritableDirCritical C:\ProgramData\...\StartUp  CRITICAL 可写可执行目录
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
```

---

## ⚡ 性能基准

| 规模 | 耗时 | 吞吐量 |
|:----:|:----:|:------:|
| 40,000 文件 | ~3s | ~13,000 文件/秒 |
| 110,000 文件 | ~8s | ~13,500 文件/秒 |
| 410,000 文件 | ~34s | ~12,000 文件/秒 |

**测试环境**：Windows 11, AMD Ryzen 7, SSD, 普通用户权限

### 性能优化技术

- **Aho-Corasick**：O(n) 多模式匹配，一次扫描命中全部关键词
- **64-shard 去重**：FNV 哈希分片 + 双重检查，减少锁竞争
- **零分配字符串**：自定义 `toLowerASCII`，比标准库快约 4.7 倍
- **预筛选**：字符掩码快速过滤无关内容
- **并发根目录遍历**：多驱动器/多根目录并行
- **扫描窗口限制**：512KB 读取上限 + 200KB 正则窗口，避免大文件拖慢

---

## 🔐 权限要求

| 操作系统 | 最小权限 | 推荐权限 |
|:--------:|:--------:|:--------:|
| macOS | 当前用户 | Full Disk Access |
| Linux | 当前用户 | root |
| Windows | 当前用户 | Administrator |

XunFeng 已针对**低权限环境**优化：默认跳过系统目录，遍历时无权限的条目自动跳过不中断——普通用户会完整扫描自身数据，管理员/root 则可以覆盖其他用户的家目录（其中常有高价值数据）。

### macOS 特殊说明

1. **Full Disk Access**：扫描 `~/Library/` 等受保护目录需要在「系统设置 > 隐私与安全性 > 完全磁盘访问权限」中添加终端或程序
2. **浏览器数据**：读取 Chrome/Edge 历史前建议关闭浏览器（SQLite 锁）
3. **Office 旧格式**：系统自带 `textutil` 可增强 `.doc` 解析，无需额外安装

---

## 🛠️ 从源码编译

### 环境要求

- Go 1.25+
- CGO **可选**（默认使用纯 Go SQLite，无需 C 编译器）

### 常规编译

```bash
git clone https://github.com/JishiTeam-J1wa/Xunfeng.git
cd Xunfeng

# 当前平台（无需 CGO）
go build -ldflags="-s -w" -o xunfeng .

# 一键交叉编译 7 个平台到 build/
chmod +x build.sh && ./build.sh
```

### 混淆编译（对抗静态查杀）

```bash
# 需要 garble：go install mvdan.cc/garble@latest
chmod +x build_obfuscated.sh && ./build_obfuscated.sh
```

产出到 `build_obfuscated/`：7 平台混淆二进制 + C 动态库 + Go Plugin。

### 使用 CGO（可选）

本地有 C 编译器且希望使用 `mattn/go-sqlite3`：

```bash
# Linux
CGO_ENABLED=1 go build -o xunfeng .

# Windows（需 mingw-w64）
CGO_ENABLED=1 go build -o xunfeng.exe .
```

### 启用 YARA（可选）

需系统已安装 libyara：

```bash
go build -tags yara -o xunfeng .
./xunfeng -yara-rules ./rules/
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

## 🧩 二次开发/嵌入

XunFeng 不只是命令行工具，还可以作为扫描引擎嵌入你自己的平台。

### C 动态库（`.dll` / `.so` / `.dylib`）

```bash
# Linux
go build -buildmode=c-shared -o xunfeng.so .
# macOS
go build -buildmode=c-shared -o xunfeng.dylib .
# Windows（需 mingw-w64）
CGO_ENABLED=1 go build -buildmode=c-shared -o xunfeng.dll .
```

导出的 C 接口（见随产物生成的 `.h` 头文件）：

| 函数 | 说明 |
|:----:|:-----|
| `GetVersion()` | 返回版本号字符串 |
| `RunScan(target, output)` | 扫描目标路径，输出 TXT 报告，返回 0 表示成功 |
| `RunScanJSON(target, output)` | 同上，输出 JSON 报告 |

Python 调用示例：

```python
import ctypes

lib = ctypes.CDLL("./xunfeng.dylib")
lib.GetVersion.restype = ctypes.c_char_p
print(lib.GetVersion().decode())

ret = lib.RunScan(b"/Users/dev/Documents", b"report.txt")
print("exit code:", ret)
```

### Go Plugin（`.plugin`）

```bash
go build -buildmode=plugin -o xunfeng.plugin .
```

导出符号：`RunScanPlugin(target, output) string`、`RunScanPluginJSON(target, output) string`、`VersionPlugin() string`（返回空字符串表示成功，否则为错误信息）。

```go
p, _ := plugin.Open("xunfeng.plugin")
sym, _ := p.Lookup("RunScanPluginJSON")
run := sym.(func(string, string) string)
if errStr := run("/tmp/scan", "/tmp/out.json"); errStr != "" {
    log.Fatal(errStr)
}
```

> 嵌入模式下会自动跳过沙箱/调试器检测（`SkipSandbox`/`SkipDebug` 强制为 true）。

---

## 📁 项目结构

```
Xunfeng/
├── main.go              # 主程序入口和扫描逻辑
├── rules.go             # 敏感信息检测规则
├── reporter.go          # 报告生成器 (MD/JSON/TXT)
├── output.go            # 终端输出与实时日志
├── ahocorasick.go       # Aho-Corasick 多模式匹配算法
├── patterns.go          # IP/URL/凭据对/弱口令/邮箱提取
├── ole.go               # OLE 复合文档解析（含 mini-stream/DIFAT）
├── biff.go              # Excel 97-2003 (.xls) 文本提取（含 CONTINUE 记录）
├── doc.go               # Word 97-2003 (.doc) FIB/piece table 文本提取
├── pdf.go               # PDF 文本流提取
├── archive.go           # ZIP 解包内容扫描
├── browser_creds*.go    # 浏览器密码/Cookie 提取（DPAPI/Keychain）
├── creds_extract.go     # 凭证文件内容提取（SSH/AWS/K8s/Docker/Git）
├── antidebug_*.go       # 平台反调试检测
├── perms.go             # 可写可执行目录检测
├── privesc*.go          # 提权漏洞建议
├── privilege_*.go       # 平台权限信息
├── process_rules.go     # 进程规则加载（go:embed）
├── sqlite_cgo.go        # CGO SQLite 适配
├── sqlite_nocgo.go      # 纯 Go SQLite 适配
├── yara_scan.go         # YARA 扫描（需 yara 构建标签）
├── yara_scan_stub.go    # YARA 无操作桩（默认构建）
├── export.go            # C 动态库导出（cgo 构建）
├── export_plugin.go     # Go Plugin 导出
├── assets/              # 进程规则 JSON
├── scripts/             # 规则处理脚本（AV 规则合并、CNA 解析）
├── xunfeng_test.go      # 单元测试
├── bench_test.go        # 性能基准测试
├── build.sh             # 跨平台编译脚本
└── build_obfuscated.sh  # 混淆编译脚本
```

---

## 🥷 隐匿特性

针对红队场景的设计：

| 特性 | 说明 |
|:----:|:-----|
| **沙箱检测** | 检测虚拟机/沙箱（CPU 核数、内存、运行时间、进程数） |
| **调试检测** | Windows：IsDebuggerPresent/远程调试；Linux/macOS：调试器进程、TracerPid、P_TRACED |
| **随机扫描** | 打乱根目录扫描顺序 |
| **延迟模式** | `-s` 参数增加每个目录条目的操作间隔 |

调试自己的环境时用 `-skip-sandbox` 和 `-skip-debug` 跳过检测。

---

## ❓ 常见问题

**Q: 为什么 `-yara-rules` 没反应？**
默认发布的二进制未编译 YARA 支持（避免 libyara 依赖）。需自行 `go build -tags yara` 编译，详见[启用 YARA](#启用-yara可选)。

**Q: 为什么超过 10MB 的文件没被扫描？**
内置安全阈值：>10MB 的文件跳过内容扫描，单文件最多读前 512KB/5000 行，防止大文件拖垮扫描速度。`.zip` 会解包扫描文本成员（单成员 ≤5MB、总量 ≤32MB 防 zip bomb）；`.rar`/`.7z` 按类型标记路径但不解包。

**Q: macOS 上扫不到浏览器数据？**
需要授予终端「完全磁盘访问权限」，并先关闭浏览器释放 SQLite 锁。注意：解密保存的密码会触发 **Keychain 授权弹窗**（目标用户可见），隐匿场景请加 `-skip-cred-decrypt` 只扫历史。

**Q: 报告里的密码为什么打了星号？**
默认掩码输出（审计场景防二次泄露）。红队场景需要明文凭证时加 `-show-secrets`。

**Q: Windows 上为什么提示沙箱就退出了？**
程序检测到 CPU < 2 核 / 内存 < 2GB / 开机 < 120 秒 / 进程数 < 30 会判定为沙箱。虚拟机里调试请加 `-skip-sandbox`。

**Q: 扫描会影响目标机性能吗？**
正常模式下 I/O 集中在文件遍历。高对抗环境使用 `-s 100` 增加操作间隔，可显著降低 I/O 峰值。

**Q: 报告里的 `*.live.txt` 是什么？**
实时日志。每条发现即时落盘，扫描中途崩溃也能从该文件恢复已发现的结果，扫描结束后可删除。

---

## 🤝 贡献指南

欢迎提交 Issue 和 Pull Request！

1. Fork 本仓库
2. 创建特性分支（`git checkout -b feature/AmazingFeature`）
3. 提交更改（`git commit -m 'Add AmazingFeature'`）
4. 推送分支（`git push origin feature/AmazingFeature`）
5. 创建 Pull Request

**代码规范**

- 使用 `go fmt` 格式化代码
- 运行 `go vet` 和 `staticcheck` 检查
- 添加单元测试（`go test ./...`）
- 保持测试覆盖率 > 20%

---

## ⚠️ 免责声明

本工具仅用于**授权的安全测试**和**红队演练**。使用者需遵守当地法律法规，对使用本工具造成的任何后果自行承担责任。

**禁止用于**：
- 未经授权的系统入侵
- 非法数据窃取
- 任何违法活动

---

## 📜 更新日志

### v4.0.0 (2026-09) —— 主机敏感信息收集工具

**新特性**
- 浏览器凭证提取：Chrome/Edge 保存的密码与 Cookie（Windows DPAPI / macOS Keychain / Linux）
- 凭证文件内容提取：SSH 私钥/公钥、AWS credentials、kubeconfig、Docker auth、git-credentials（报告自动掩码）
- 本地提权真实检查：SUID/GTFOBins、sudo -l、可写系统文件、cron、NFS no_root_squash、AlwaysInstallElevated、可写服务路径
- CVE 补丁级匹配：Windows 读取 UBR、macOS 按 sw_vers 版本、Linux 补全 PwnKit/Samedit/GameOverlay 命中逻辑
- PDF 文本流提取（FlateDecode + Tj/TJ 操作符）
- ZIP 解包内容扫描（防 zip bomb）
- .doc 自研 FIB + piece table 解析，不再依赖外部工具
- `-nodir` 完整扫描模式：不排除任何目录
- `-show-secrets` 明文输出开关（默认掩码）与 `-skip-cred-decrypt` 跳过浏览器解密（规避 macOS Keychain 弹窗）
- Windows 反调试真实实现（IsDebuggerPresent / CheckRemoteDebuggerPresent）

**修复**
- xlsx 共享字符串索引未替换导致文本单元格扫不到
- xls SST 跨 CONTINUE 记录断裂；OLE 支持 mini-stream 与 DIFAT 链
- 网络扫描 `172.` 前缀误排公网地址（改用标准库私网判断）
- 默认排除目录过度（`.git`/`tmp`/`logs`/`ProgramData`/`/var/lib`/其他用户家目录等高价值位置已纳入扫描）
- 默认构建传 `-yara-rules` 时静默无效，现在会明确提示需 `-tags yara` 编译
- Dirty COW 内核区间遗漏 3.10~3.19

### v3.0.0 (2026-07)

**新特性**
- 360+ 条进程规则、1,400+ 进程特征，覆盖杀软/EDR/安全工具/远控/渗透工具
- 系统信息展示：当前用户、权限级别、操作系统、网卡/IP
- 可写可执行目录检测（启动目录/PATH/公共目录）
- 独立 IP / URL / 凭据对 / 弱口令 / 邮箱 提取
- 敏感关键词扩展：VPN、代理、内网、入职、手册、账号、密码、凭据
- Office 旧格式支持：`.doc` / `.xls` / `.ppt`
- YARA 可选集成（`-tags yara`）
- 纯 Go SQLite 支持，无需 CGO 即可跨平台编译
- `-jiwa` 稽核模式（进度条 + ETA）
- C 动态库 / Go Plugin 导出，支持嵌入第三方工具链
- garble 混淆编译脚本

**优化**
- 低权限目录排除，弱化权限影响
- 并发根目录遍历，提升多驱动器扫描速度
- 异步控制台输出与实时 live log
- 200KB 模式扫描窗口，避免大文件正则拖慢
- 4KB 快速字符预筛选

**修复**
- 修复 Windows 下权限不足导致的扫描中断
- 修复 Office 旧文档解析失败
- 修复跨平台编译依赖 CGO 问题

### v3.0.0-beta (2026-06)

**新特性**
- Aho-Corasick 多模式匹配算法
- Office 文档扫描（.docx/.xlsx/.doc/.xls）
- Markdown 表格报告格式
- 风险五级分类（CRITICAL/HIGH/MEDIUM/LOW/INFO）
- UTF-8 中文路径正确显示

**优化**
- 64-shard 并发去重
- 零分配字符串操作

### v2.0.0 (2025-10)

- 初始发布
- 多维度扫描（进程/网络/凭证/文件）
- 隐匿模式支持

---

## 📄 许可证

本项目采用 [MIT License](LICENSE) 开源。

---

<div align="center">

**JishiTeam（击势安全团队）**

*为安全而生*

如果这个项目对你有帮助，欢迎点个 ⭐ Star

</div>
