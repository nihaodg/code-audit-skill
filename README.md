# Code Audit Skills

多语言代码安全审计 Skill 集合，每个 Skill 包含自动化漏洞扫描脚本和 OWASP 安全编码速查表。

## 包含的 Skill

| Skill | 扫描脚本 | 规则数 | 漏洞类别 |
|-------|---------|--------|---------|
| `php-code-audit` | `php_audit_scanner.py` | 28 | SQL注入、命令执行、代码执行、XSS、文件包含、SSRF、反序列化、文件上传、XXE、密码安全、信息泄露、配置安全 |
| `java-code-audit` | `java_audit_scanner.py` | 50 | SQL注入、命令执行、表达式注入(OGNL/SpEL/MVEL)、XSS、路径穿越、SSRF、反序列化、XXE、文件上传、密码安全、信息泄露、配置安全、权限控制 |
| `python-code-audit` | `python_audit_scanner.py` | 49 | SQL注入、命令执行、代码执行、SSTI、XSS、SSRF、反序列化、路径穿越、XXE、文件上传、密码安全、信息泄露、依赖安全 |
| `js-code-audit` | `js_audit_scanner.py` | 49 | SQL注入、命令执行、代码执行、XSS、路径穿越、SSRF、反序列化、原型污染、密码安全、配置安全、依赖安全 |
| `go-code-audit` | `go_audit_scanner.py` | 40 | SQL注入、命令执行、代码执行、路径穿越、SSRF、反序列化、XXE、密码安全、信息泄露、配置安全、并发安全 |
| `csharp-code-audit` | `csharp_audit_scanner.py` | 55 | SQL注入、命令执行、代码执行、XSS、路径穿越、SSRF、反序列化、XXE、文件上传、密码安全、信息泄露、配置安全、权限控制、会话安全 |

## 目录结构

每个 Skill 遵循标准 skill 目录结构：

```
{lang}-code-audit/
├── SKILL.md                        # skill 定义和使用说明
├── assets/                         # 静态资源目录（可扩展）
├── references/
│   └── owasp-cheatsheet.md         # OWASP 安全编码速查表
└── scripts/
    └── {lang}_audit_scanner.py     # 自动化漏洞扫描脚本
```

## 安装方式

### 方式一：扫码安装（推荐）

获取当前环境下已有的 Skill 列表，将需要的 Skill 通过扫码方式安装到项目中：

1. 在对话中执行 `/skills` 查看可用 Skill 列表
2. 将 zip 包解压到项目的 `.ai-ready/skills/` 目录
3. 重新加载后 Skill 自动生效

### 方式二：手动安装

将 zip 包解压到目标项目的 `.ai-ready/skills/` 目录下：

```bash
unzip php-code-audit.zip -d .ai-ready/skills/
unzip java-code-audit.zip -d .ai-ready/skills/
unzip python-code-audit.zip -d .ai-ready/skills/
unzip js-code-audit.zip -d .ai-ready/skills/
unzip go-code-audit.zip -d .ai-ready/skills/
unzip csharp-code-audit.zip -d .ai-ready/skills/
```

安装后的目录结构：

```
your-project/
└── .ai-ready/
    └── skills/
        ├── php-code-audit/
        ├── java-code-audit/
        ├── python-code-audit/
        ├── js-code-audit/
        ├── go-code-audit/
        └── csharp-code-audit/
```

## 使用方式

### 对话中调用

安装后直接在对话中提及对应语言的安全审计需求，Agent 会自动加载 Skill：

> "帮我审计这个 PHP 项目的安全问题"
> "扫描这个 Java 项目的代码漏洞"
> "对 Python 项目做一次安全审计"

### 手动执行扫描脚本

也可以直接在终端运行扫描脚本：

```bash
# 进入 Skill 目录
cd .ai-ready/skills/php-code-audit

# 基础扫描
python3 scripts/php_audit_scanner.py /path/to/php/project

# 导出 JSON 报告
python3 scripts/php_audit_scanner.py /path/to/php/project -o report.json

# 详细模式
python3 scripts/php_audit_scanner.py /path/to/php/project --verbose
```

### 扫描器参数

| 参数 | 说明 |
|------|------|
| `target` | 要扫描的项目路径（必填） |
| `-o, --output` | 导出 JSON 报告文件路径 |
| `-v, --verbose` | 详细输出模式，显示每条匹配的上下文 |

### 输出说明

扫描完成后输出：
- 按严重程度（严重/高危/中危/低危）四级统计
- 按漏洞类别分布统计
- 高风险发现（严重+高危）的具体列表（含文件路径和行号）

## 严重程度定义

| 级别 | 说明 | 示例 |
|------|------|------|
| 严重 | 可直接导致远程代码执行或数据泄露 | `eval()`、`Runtime.exec()`、`BinaryFormatter.Deserialize()` |
| 高危 | 可导致安全漏洞，但利用条件较苛刻 | SQL 字符串拼接、MyBatis `${}`、路径穿越 |
| 中危 | 安全隐患，影响面有限 | `display_errors=On`、`DEBUG=True`、弱随机数 |
| 低危 | 信息泄露或最佳实践违反 | `printStackTrace`、调试输出 |

## 局限性

- **静态分析**：仅做正则匹配，不执行动态分析
- **存在误报**：需要人工结合上下文确认漏洞是否真实可利用
- **不替代专业工具**：建议结合行业 SAST 工具进行深度检测

### 推荐配套工具

| 语言 | 推荐 SAST 工具 |
|------|---------------|
| PHP | RIPS、Psalm、PHPStan |
| Java | SpotBugs、FindSecBugs、CodeQL |
| Python | Bandit、Semgrep |
| JavaScript | ESLint Security Plugin、Snyk、npm audit |
| Go | gosec、staticcheck、govulncheck |
| C# | security-code-scan、Puma Scan、Fortify |

## 版本

- v1.0 — 2026-06-28 — 初始版本，6 语言覆盖
