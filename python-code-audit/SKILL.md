---
name: python-code-audit
description: Python代码安全审计工具。自动扫描Python项目中的SQL注入(f-string/%)、命令执行(subprocess/os)、代码执行(eval/exec)、SSTI(Jinja2/Django)、SSRF、反序列化(pickle/yaml)、XXE等安全漏洞。
arguments:
  - name: target
    description: 要审计的Python项目路径（默认当前工作区）
    required: false
  - name: output_format
    description: 报告输出格式：json（默认，导出报告文件）或 summary（终端摘要输出）
    required: false
---

# Python 代码安全审计

对 Python 项目进行自动化安全漏洞扫描，快速定位危险函数和潜在风险点，辅助人工审计。

## 扫描能力

本 skill 内置 **49 条检测规则**，覆盖 **13 个漏洞类别**：

| 类别 | 规则数 | 典型检测项 |
|------|--------|-----------|
| SQL 注入 | 7 | 字符串 `%s` 格式化拼接、`.format()` 拼接、f-string 拼接、Django `raw()`/`extra()`、SQLAlchemy `text()` f-string |
| 命令执行 | 5 | `os.system()`、`os.popen()`、`subprocess shell=True`、`os.exec` 系列、`commands` 模块 |
| 代码执行 | 5 | `eval()`、`exec()`、`compile()`、`__import__()`、`importlib.import_module()` |
| SSTI | 3 | Jinja2 `render_template_string`、Django `Template` 用户输入、Mako `Template` |
| XSS | 2 | Django `mark_safe` 用户输入、`HttpResponse` 直接输出用户输入 |
| SSRF | 5 | `requests.get/post` 用户 URL、`urllib.request.urlopen`、`httpx`、`aiohttp`、`urllib3` |
| 反序列化 | 6 | `pickle.loads()`、`cPickle`、`yaml.load()` 不安全 Loader、`dill.loads()`、`shelve.open()`、`marshal.loads()` |
| 路径穿越 | 2 | `open()` 用户路径、`os.path` 操作用户输入 |
| XXE | 3 | `lxml.etree.parse`、`xml.etree.ElementTree`、`xml.dom.minidom` |
| 文件上传 | 2 | `shutil/os` 写入上传文件、Django `request.FILES.save()` |
| 密码安全 | 3 | `hashlib.md5/sha1` 密码、`random` 模块生成令牌、硬编码密码密钥 |
| 信息泄露 | 5 | Django `DEBUG=True`、Flask `debug=True`、`print` 敏感信息、`logging` 敏感信息、Flask `SECRET_KEY` 硬编码 |
| 依赖安全 | 1 | `requirements.txt` 含有已知漏洞版本 |

## 使用方法

### 基础扫描

```bash
python3 scripts/python_audit_scanner.py /workspace
```

### 导出 JSON 报告

```bash
python3 scripts/python_audit_scanner.py /workspace -o audit_report.json
```

### 详细模式

```bash
python3 scripts/python_audit_scanner.py /workspace --verbose

扫描脚本位于本 skill 的 `scripts/` 目录下：`scripts/python_audit_scanner.py`

## 注意事项

- 本工具用于**辅助定位**，不能替代专业人工审计
- Python 动态特性导致误报率可能偏高，需结合上下文仔细确认
- 不执行动态分析、不发送网络请求，为纯静态扫描
- 对于 Django/Flask 框架，`request` 对象的来源有多种写法（`request.GET`、`request.POST`、`request.args`、`request.form` 等），正则已覆盖主要模式
- 建议结合 Bandit、Semgrep 等专业 SAST 工具进行深度检测
