---
name: java-code-audit
description: Java代码安全审计工具。自动扫描Java项目中的SQL注入、命令执行、表达式注入(OGNL/SpEL/MVEL)、反序列化、SSRF、XXE、XSS、路径穿越等安全漏洞，覆盖Spring Boot/MyBatis/JPA等主流框架。
arguments:
  - name: target
    description: 要审计的Java项目路径（默认当前工作区）
    required: false
  - name: output_format
    description: 报告输出格式：json（默认，导出报告文件）或 summary（终端摘要输出）
    required: false
---

# Java 代码安全审计

对 Java 项目进行自动化安全漏洞扫描，快速定位危险函数和潜在风险点，辅助人工审计。

## 扫描能力

本 skill 内置 **50 条检测规则**，覆盖 **13 个漏洞类别**：

| 类别 | 规则数 | 典型检测项 |
|------|--------|-----------|
| SQL 注入 | 6 | `Statement` 字符串拼接、`executeQuery` 拼接、MyBatis `${}`、JPA `createNativeQuery`、`String.format` SQL、JdbcTemplate 拼接 |
| 命令执行 | 3 | `Runtime.exec()`、`ProcessBuilder`、`ProcessImpl` |
| 代码执行 | 5 | `ScriptEngine.eval()`、OGNL `getValue`/`setValue`、SpEL `parseExpression`、MVEL `eval`、EL `createValueExpression` |
| XSS | 3 | `response.getWriter().print` 用户参数、Model 输出用户参数、JSP EL 表达式 |
| 路径穿越 | 3 | `FileInputStream` 用户参数、`Files.read` 用户参数、`new File` 用户参数 |
| SSRF | 6 | `new URL` 用户参数、`HttpURLConnection`、`RestTemplate`、`HttpClient`、`WebClient`、OkHttp 用户 URL |
| 反序列化 | 5 | `ObjectInputStream.readObject`、`XMLDecoder`、Hessian/Burlap、Fastjson `JSON.parse`、Jackson `enableDefaultTyping` |
| XXE | 4 | `DocumentBuilderFactory`、`SAXParserFactory`、`XMLReaderFactory`、`TransformerFactory` 无安全配置 |
| 文件上传 | 2 | `MultipartFile.transferTo` 未校验、`FileOutputStream` 直接写入 |
| 密码安全 | 4 | `MessageDigest MD5/SHA1`、`Random` 生成令牌、硬编码密码密钥、DES/3DES/RC4 弱加密 |
| 信息泄露 | 3 | `printStackTrace`、`e.printStackTrace` 写入响应、日志敏感信息 |
| 配置安全 | 4 | Spring Boot Actuator 全暴露、CSRF 禁用、CORS 允许所有来源、不安全 HTTP 方法 |
| 权限控制 | 2 | 缺少 `@PreAuthorize`、`permitAll()` 全放行 |

## 使用方法

### 基础扫描

```bash
python3 scripts/java_audit_scanner.py /workspace
```

### 导出 JSON 报告

```bash
python3 scripts/java_audit_scanner.py /workspace -o audit_report.json
```

### 详细模式

```bash
python3 scripts/java_audit_scanner.py /workspace --verbose

扫描脚本位于本 skill 的 `scripts/` 目录下：`scripts/java_audit_scanner.py`

## 注意事项

- 本工具用于**辅助定位**，不能替代专业人工审计
- 正则匹配存在误报可能，需结合上下文和框架特性确认
- 不执行动态分析、不发送网络请求，为纯静态扫描
- 发现的漏洞需要人工判断是否真实可利用
- 建议结合 SpotBugs、FindSecBugs、CodeQL 等专业 SAST 工具进行深度检测
- Spring Boot 项目的配置安全检测需要人工校验 context
