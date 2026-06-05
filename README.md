# XunFeng (寻风) v3.0

<p align="center">
  <img src="https://img.shields.io/badge/Version-3.0.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/Go-1.19+-00ADD8.svg" alt="Go Version">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
</p>

<p align="center">
  <b>高性能跨平台敏感信息扫描工具</b><br>
  <i>专为红队信息收集与安全审计设计</i>
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

## 特性亮点

- **极速扫描**: Aho-Corasick 多模式匹配算法，20000+ 文件/秒
- **多维检测**: 进程、网络、凭证、环境变量、Shell历史、浏览器、文件系统
- **Office 支持**: 原生解析 .docx/.xlsx/.pptx，兼容 .doc/.xls/.ppt
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
| Linux x64 | `xunfeng_linux_amd64` |

### 基础用法

```bash
# 全盘扫描
./xunfeng

# 指定目录
./xunfeng -p /path/to/scan

# 扫描单个文件
./xunfeng -p /path/to/file.docx

# 生成 Markdown 报告
./xunfeng -f md -o report.md

# 生成 JSON 报告
./xunfeng -f json -o report.json
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

---

## 检测能力

### 扫描模块

| 模块 | 检测内容 |
|:----:|:---------|
| **进程扫描** | 数据库(MySQL/Redis/MongoDB)、远控RAT、代理隧道、渗透工具 |
| **网络扫描** | C2外连、可疑端口监听、Meterpreter/Cobalt Strike 特征 |
| **凭证扫描** | SSH密钥、云凭证(AWS/Azure/GCP/阿里云/腾讯云)、Docker/K8s配置 |
| **环境变量** | PASSWORD/SECRET/TOKEN/KEY 等敏感变量 |
| **Shell历史** | 命令行中的密码参数、curl认证、数据库连接 |
| **浏览器** | Chrome/Edge 历史中的敏感URL |
| **文件系统** | 配置文件、Office文档、私钥、凭证文件 |

### 风险分级

| 等级 | 颜色 | 类型示例 |
|:----:|:----:|:---------|
| **CRITICAL** | 红色 | 私钥、数据库连接串、云平台密钥 |
| **HIGH** | 橙色 | 密码、Token、API Key |
| **MEDIUM** | 黄色 | 中文密码、敏感配置 |
| **INFO** | 灰色 | 浏览器历史、Shell命令 |

### 支持的敏感规则

<details>
<summary><b>点击展开完整规则列表</b></summary>

#### 通用凭证
- Password / Passwd / Secret
- API Key / Access Key
- Token / Auth Token / Bearer Token
- JWT Secret

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

</details>

---

## 输出示例

### CLI 输出

```
━━━━━━━━━━ PROCESS SCAN ━━━━━━━━━━
[+] Process        MySQL                 PID:1234   /usr/local/mysql/bin/mysqld
[+] Process        Frp                   PID:5678   frpc -c /etc/frp/frpc.ini

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
| 🔴 严重 | **5** | 私钥 / DB连接串 / 云密钥 |
| 🟠 高危 | **23** | 密码 / Token / API Key |
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
| 40,000 文件 | ~2.5s | 16,000 文件/秒 |
| 110,000 文件 | ~5.5s | 20,000 文件/秒 |

**测试环境**: macOS, Apple M1, 8GB RAM

### 性能优化技术

- **Aho-Corasick**: O(n) 多模式匹配，比朴素方法快 6x
- **64-shard 去重**: 并发安全，减少锁竞争
- **零分配字符串**: 自定义 toLowerASCII，比标准库快 5x
- **预筛选**: 字符掩码快速过滤无关内容
- **批量读取**: 一次性读取文件，避免多次系统调用

---

## 权限要求

| 操作系统 | 最小权限 | 推荐权限 |
|:--------:|:--------:|:--------:|
| macOS | 当前用户 | Full Disk Access |
| Linux | 当前用户 | root |
| Windows | 当前用户 | Administrator |

### macOS 特殊说明

1. **Full Disk Access**: 扫描 `~/Library/` 等受保护目录需要在 系统偏好设置 > 安全性与隐私 > 隐私 > 完全磁盘访问权限 中添加终端或程序
2. **浏览器数据**: 读取 Chrome/Edge 数据可能需要关闭浏览器
3. **Office 文档**: 使用系统自带 `textutil` 解析，无需额外安装

---

## 从源码编译

### 环境要求

- Go 1.19+
- CGO 支持 (用于 SQLite3 浏览器数据读取)

### 编译步骤

```bash
# 克隆仓库
git clone https://github.com/JishiTeam-J1wa/Xunfeng.git
cd Xunfeng

# 当前平台编译
go build -ldflags="-s -w" -o xunfeng .

# 跨平台编译
chmod +x build.sh && ./build.sh
```

### 依赖说明

| 依赖 | 用途 |
|:----:|:-----|
| `github.com/fatih/color` | 彩色终端输出 |
| `github.com/karrick/godirwalk` | 高性能目录遍历 |
| `github.com/mattn/go-sqlite3` | 浏览器数据库读取 (CGO) |
| `github.com/shirou/gopsutil` | 系统/进程/网络信息 |

---

## 项目结构

```
Xunfeng/
├── main.go           # 主程序入口和扫描逻辑
├── rules.go          # 敏感信息检测规则
├── reporter.go       # 报告生成器 (MD/JSON/TXT)
├── ahocorasick.go    # Aho-Corasick 多模式匹配算法
├── xunfeng_test.go   # 单元测试 (32个测试用例)
├── bench_test.go     # 性能基准测试
├── build.sh          # 跨平台编译脚本
├── README.md         # 项目文档
├── REVIEW.md         # 代码审查报告
├── go.mod            # Go 模块定义
└── go.sum            # 依赖校验
```

---

## 自动排除

为提升扫描速度，自动跳过以下目录：

- **通用**: `node_modules`, `vendor`, `.git`, `.svn`, `__pycache__`
- **IDE**: `.idea`, `.vscode`
- **缓存**: `cache`, `.cache`, `tmp`, `temp`, `logs`
- **构建**: `dist`, `build`, `.next`, `target`
- **macOS**: `/System`, `/Library/Caches`, `~/Library/Caches`
- **Linux**: `/proc`, `/sys`, `/dev`, `/run`
- **Windows**: `Windows`, `ProgramData`

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

### v3.0.0 (2026-06)

**新特性**
- Aho-Corasick 多模式匹配算法，速度提升 6x
- Office 文档扫描 (.docx/.xlsx/.doc/.xls)
- Markdown 表格报告格式
- 风险五级分类 (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- UTF-8 中文路径正确显示

**优化**
- 64-shard 并发去重，减少锁竞争
- 零分配字符串操作
- main() 函数从 182 行重构为 35 行

**修复**
- 修复 20+ 处错误处理
- 修复资源泄漏问题
- 测试覆盖率从 13% 提升至 22%

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
