---
name: go-code-audit
description: Go代码安全审计工具。自动扫描Go项目中的SQL注入、命令执行(os/exec)、代码执行(template)、路径穿越、SSRF(net/http)、反序列化(gob/json)、XXE、密码安全、并发安全等安全漏洞。
arguments:
  - name: target
    description: 要审计的Go项目路径（默认当前工作区）
    required: false
  - name: output_format
    description: 报告输出格式：json（默认，导出报告文件）或 summary（终端摘要输出）
    required: false
---

# Go 代码安全审计

对 Go 项目进行自动化安全漏洞扫描，快速定位危险函数和潜在风险点，辅助人工审计。

## 扫描能力

本 skill 内置 **40 条检测规则**，覆盖 **11 个漏洞类别**：

| 类别 | 规则数 | 典型检测项 |
|------|--------|-----------|
| SQL 注入 | 5 | `fmt.Sprintf` 拼接 SQL、`db.Query/Exec` 拼接、`database/sql` 拼接、GORM `.Raw()` 拼接、GORM `Expr` 拼接 |
| 命令执行 | 4 | `exec.Command()`、`exec.CommandContext()`、`os.StartProcess()`、`syscall.Exec/ForkExec()` |
| 代码执行 | 3 | `text/template Execute` 用户数据、`html/template Execute` 用户数据、`plugin.Open()` 动态加载 |
| 路径穿越 | 5 | `os.Open` 用户路径、`ioutil.ReadFile` 用户路径、`http.ServeFile`、`filepath.Join` 用户输入、Gin `c.File` |
| SSRF | 5 | `http.Get/Post` 用户 URL、`http.NewRequest` 用户 URL、`http.Client.Do`、resty、fasthttp/fiber 用户 URL |
| 反序列化 | 3 | `gob.NewDecoder()`、`json.Unmarshal` 无验证、`yaml.Unmarshal` 无验证 |
| XXE | 2 | `xml.NewDecoder()`、`xml.Unmarshal()` |
| 密码安全 | 5 | `crypto/md5`/`sha1` 密码、`math/rand` 生成令牌、硬编码密钥密码、DES/3DES/RC4 弱加密、`==` 比较密码 |
| 信息泄露 | 3 | `log.Println` 敏感信息、`panic()` 堆栈暴露、Gin `DebugMode` |
| 配置安全 | 3 | CORS `AllowAllOrigins: true`、TLS `InsecureSkipVerify`、CSRF 保护缺失 |
| 并发安全 | 2 | map 无锁并发读写、goroutine 泄漏风险 |

## 使用方法

### 基础扫描

```bash
python3 scripts/go_audit_scanner.py /workspace
```

### 导出 JSON 报告

```bash
python3 scripts/go_audit_scanner.py /workspace -o audit_report.json
```

### 详细模式

```bash
python3 scripts/go_audit_scanner.py /workspace --verbose

扫描脚本位于本 skill 的 `scripts/` 目录下：`scripts/go_audit_scanner.py`

## 注意事项

- 本工具用于**辅助定位**，不能替代专业人工审计
- 正则匹配存在误报可能，需结合上下文和 Goroutine 模型特性确认
- 不执行动态分析、不发送网络请求，为纯静态扫描
- Go 的标准库安全性较好（如 `html/template` 有自动转义），但仍需关注 `text/template` 的使用
- 并发安全问题多为模式匹配提示，需要人工确认实际是否存在数据竞争
- 建议结合 `gosec`、`staticcheck`、`govulncheck` 等专业 SAST 工具进行深度检测
