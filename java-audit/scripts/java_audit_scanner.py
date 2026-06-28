#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Java代码审计辅助扫描脚本
在大型项目中先跑此脚本快速定位危险函数，再人工审计。

用法：
    python java_audit_scanner.py /path/to/java/project [-o report.json] [--verbose]
"""

import os
import re
import json
import sys
import argparse
from datetime import datetime
from pathlib import Path


# 危险函数规则定义
RULES = [
    {
        "id": "SQLI-01",
        "name": "SQL注入 - Statement.executeQuery拼接",
        "severity": "严重",
        "pattern": r'Statement\s+\w+\s*=\s*.*createStatement\(\)',
        "category": "SQL注入"
    },
    {
        "id": "SQLI-02",
        "name": "SQL注入 - MyBatis ${} 占位符",
        "severity": "严重",
        "pattern": r'\$\{[^}]+\}',
        "category": "SQL注入",
        "file_pattern": r".*\.(xml|mapper)$"
    },
    {
        "id": "SQLI-03",
        "name": "SQL注入 - JPA createNativeQuery拼接",
        "severity": "高危",
        "pattern": r'createNativeQuery\s*\(\s*[^,)]+\+',
        "category": "SQL注入"
    },
    {
        "id": "SQLI-04",
        "name": "SQL注入 - JdbcTemplate拼接",
        "severity": "高危",
        "pattern": r'jdbcTemplate\.(query|update|execute)\s*\([^,]+\+',
        "category": "SQL注入"
    },
    {
        "id": "SQLI-05",
        "name": "SQL注入 - 字符串拼接SQL",
        "severity": "高危",
        "pattern": r'(?:SELECT|INSERT|UPDATE|DELETE|WHERE|ORDER BY|GROUP BY).*\+.*(?:request|param|getParameter|getHeader|@PathVariable|@RequestParam)',
        "category": "SQL注入",
        "multiline": True
    },
    {
        "id": "RCE-01",
        "name": "命令执行 - Runtime.exec",
        "severity": "严重",
        "pattern": r'Runtime\.getRuntime\(\)\.exec|Runtime\.exec',
        "category": "命令执行"
    },
    {
        "id": "RCE-02",
        "name": "命令执行 - ProcessBuilder",
        "severity": "严重",
        "pattern": r'new\s+ProcessBuilder|ProcessBuilder\.command',
        "category": "命令执行"
    },
    {
        "id": "RCE-03",
        "name": "代码执行 - ScriptEngine.eval",
        "severity": "严重",
        "pattern": r'ScriptEngine.*eval|engine\.eval',
        "category": "代码执行"
    },
    {
        "id": "RCE-04",
        "name": "代码执行 - GroovyShell.evaluate",
        "severity": "严重",
        "pattern": r'GroovyShell.*evaluate|groovyShell\.evaluate',
        "category": "代码执行"
    },
    {
        "id": "RCE-05",
        "name": "SpEL注入 - parseExpression",
        "severity": "严重",
        "pattern": r'parseExpression|SpelExpressionParser',
        "category": "SpEL注入"
    },
    {
        "id": "RCE-06",
        "name": "表达式注入 - ELProcessor.eval",
        "severity": "严重",
        "pattern": r'ELProcessor|ExpressionFactory.*createValueExpression',
        "category": "表达式注入"
    },
    {
        "id": "DESER-01",
        "name": "反序列化 - ObjectInputStream.readObject",
        "severity": "严重",
        "pattern": r'ObjectInputStream.*readObject|readUnshared',
        "category": "反序列化"
    },
    {
        "id": "DESER-02",
        "name": "反序列化 - Fastjson JSON.parse",
        "severity": "严重",
        "pattern": r'JSON\.parse(?:Object)?\s*\(',
        "category": "反序列化"
    },
    {
        "id": "DESER-03",
        "name": "反序列化 - Jackson enableDefaultTyping",
        "severity": "严重",
        "pattern": r'enableDefaultTyping|activateDefaultTyping',
        "category": "反序列化"
    },
    {
        "id": "DESER-04",
        "name": "反序列化 - XStream.fromXML",
        "severity": "严重",
        "pattern": r'XStream.*fromXML',
        "category": "反序列化"
    },
    {
        "id": "DESER-05",
        "name": "反序列化 - SnakeYAML load",
        "severity": "严重",
        "pattern": r'new\s+Yaml\s*\(\).*\.load|Yaml\.load',
        "category": "反序列化"
    },
    {
        "id": "DESER-06",
        "name": "反序列化 - XMLDecoder",
        "severity": "严重",
        "pattern": r'new\s+XMLDecoder|XMLDecoder.*readObject',
        "category": "反序列化"
    },
    {
        "id": "XXE-01",
        "name": "XXE - DocumentBuilder.parse",
        "severity": "高危",
        "pattern": r'DocumentBuilder.*parse|newDocumentBuilder',
        "category": "XXE"
    },
    {
        "id": "XXE-02",
        "name": "XXE - SAXParser.parse",
        "severity": "高危",
        "pattern": r'SAXParser.*parse|newSAXParser',
        "category": "XXE"
    },
    {
        "id": "XXE-03",
        "name": "XXE - SAXReader (dom4j)",
        "severity": "高危",
        "pattern": r'new\s+SAXReader|SAXReader.*read',
        "category": "XXE"
    },
    {
        "id": "LFI-01",
        "name": "文件操作 - FileInputStream用户输入",
        "severity": "高危",
        "pattern": r'new\s+FileInputStream\s*\(.*(?:request|param|getParameter)',
        "category": "文件操作"
    },
    {
        "id": "LFI-02",
        "name": "文件操作 - Paths.get用户输入",
        "severity": "高危",
        "pattern": r'Paths\.get\s*\(.*(?:request|param|getParameter)',
        "category": "文件操作"
    },
    {
        "id": "UPLOAD-01",
        "name": "文件上传 - MultipartFile.transferTo",
        "severity": "高危",
        "pattern": r'MultipartFile.*transferTo',
        "category": "文件上传"
    },
    {
        "id": "UPLOAD-02",
        "name": "文件上传 - 未校验后缀",
        "severity": "中危",
        "pattern": r'@RequestParam\s*\(\s*"file"|@RequestPart.*MultipartFile',
        "category": "文件上传"
    },
    {
        "id": "SSRF-01",
        "name": "SSRF - URL.openConnection",
        "severity": "高危",
        "pattern": r'new\s+URL\s*\(.*(?:request|param|getParameter).*\.openConnection',
        "category": "SSRF",
        "multiline": True
    },
    {
        "id": "SSRF-02",
        "name": "SSRF - RestTemplate用户输入",
        "severity": "高危",
        "pattern": r'restTemplate\.(getForObject|exchange|execute)\s*\(.*\+',
        "category": "SSRF"
    },
    {
        "id": "SSRF-03",
        "name": "SSRF - JNDI lookup",
        "severity": "严重",
        "pattern": r'new\s+InitialContext.*lookup|JNDI.*lookup|Naming\.lookup',
        "category": "SSRF"
    },
    {
        "id": "SSTI-01",
        "name": "模板注入 - Velocity.evaluate",
        "severity": "严重",
        "pattern": r'Velocity.*evaluate|VelocityEngine.*evaluate',
        "category": "模板注入"
    },
    {
        "id": "SSTI-02",
        "name": "模板注入 - FreeMarker",
        "severity": "严重",
        "pattern": r'Configuration.*getTemplate|Template.*process|FreeMarker',
        "category": "模板注入"
    },
    {
        "id": "SSTI-03",
        "name": "模板注入 - Thymeleaf",
        "severity": "高危",
        "pattern": r'TemplateEngine.*process|Thymeleaf',
        "category": "模板注入"
    },
    {
        "id": "LDAP-01",
        "name": "LDAP注入 - InitialDirContext.search",
        "severity": "严重",
        "pattern": r'InitialDirContext.*search|InitialLdapContext.*search|LdapTemplate.*search',
        "category": "LDAP注入"
    },
    {
        "id": "XSS-01",
        "name": "XSS - PrintWriter直接输出",
        "severity": "高危",
        "pattern": r'getWriter\(\).*\.(print|println|write)\s*\(.*(?:request|param|getParameter)',
        "category": "XSS"
    },
    {
        "id": "XSS-02",
        "name": "XSS - JSP表达式输出",
        "severity": "高危",
        "pattern": r'<%=\s*.*(?:request|param|getParameter)',
        "category": "XSS",
        "file_pattern": r".*\.(jsp|jspx)$"
    },
    {
        "id": "XSS-03",
        "name": "XSS - EL表达式未转义",
        "severity": "高危",
        "pattern": r'\$\{[^}]+\}',
        "category": "XSS",
        "file_pattern": r".*\.(jsp|jspx|html|htm)$"
    },
    {
        "id": "WEAK-01",
        "name": "弱哈希 - MD5/SHA1",
        "severity": "高危",
        "pattern": r'MessageDigest\.getInstance\s*\(\s*[\'"](MD5|SHA1|SHA-1)[\'"]',
        "category": "密码安全"
    },
    {
        "id": "WEAK-02",
        "name": "弱加密 - DES/ECB",
        "severity": "严重",
        "pattern": r'Cipher\.getInstance\s*\(\s*[\'"](DES|AES/ECB)[\'"]',
        "category": "密码安全"
    },
    {
        "id": "WEAK-03",
        "name": "弱随机数 - Random",
        "severity": "中危",
        "pattern": r'new\s+Random\s*\(\)|Math\.random\s*\(\)',
        "category": "密码安全"
    },
    {
        "id": "INFO-01",
        "name": "信息泄露 - printStackTrace",
        "severity": "中危",
        "pattern": r'\.printStackTrace\s*\(\)',
        "category": "信息泄露"
    },
    {
        "id": "INFO-02",
        "name": "信息泄露 - 调试日志",
        "severity": "低危",
        "pattern": r'System\.out\.print|System\.err\.print',
        "category": "信息泄露"
    },
    {
        "id": "CONFIG-01",
        "name": "危险配置 - Actuator全暴露",
        "severity": "严重",
        "pattern": r'management\.endpoints\.web\.exposure\.include\s*:\s*\*',
        "category": "配置安全"
    },
    {
        "id": "CONFIG-02",
        "name": "危险配置 - devtools生产环境",
        "severity": "高危",
        "pattern": r'spring\.devtools\.restart\.enabled\s*:\s*true',
        "category": "配置安全"
    },
    {
        "id": "CONFIG-03",
        "name": "危险配置 - 堆栈信息泄露",
        "severity": "中危",
        "pattern": r'server\.error\.include-stacktrace\s*:\s*(always|on_trace_param)',
        "category": "配置安全"
    },
    {
        "id": "CONFIG-04",
        "name": "危险配置 - 明文数据库密码",
        "severity": "严重",
        "pattern": r'spring\.datasource\.(url|password)\s*:\s*[^$\{]',
        "category": "配置安全"
    },
    {
        "id": "REFLECT-01",
        "name": "反射 - Class.forName动态加载",
        "severity": "高危",
        "pattern": r'Class\.forName\s*\(.*(?:request|param|getParameter)',
        "category": "反射"
    },
    {
        "id": "REFLECT-02",
        "name": "反射 - Method.invoke",
        "severity": "高危",
        "pattern": r'Method.*invoke\s*\(',
        "category": "反射"
    },
]


def should_scan_file(filepath: str, rule: dict) -> bool:
    """检查文件是否匹配规则的文件模式"""
    file_pattern = rule.get("file_pattern")
    if not file_pattern:
        return True
    return bool(re.search(file_pattern, filepath, re.IGNORECASE))


def scan_file(filepath: str, verbose: bool = False) -> list:
    """扫描单个Java文件的危险函数"""
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        lines = content.split('\n')

        for rule in RULES:
            if not should_scan_file(filepath, rule):
                continue

            flags = re.MULTILINE | re.DOTALL if rule.get('multiline') else re.MULTILINE

            for match in re.finditer(rule['pattern'], content, flags):
                # 找到匹配的行号
                match_start = match.start()
                line_num = content[:match_start].count('\n') + 1

                # 提取上下文（前后各2行）
                ctx_start = max(0, line_num - 3)
                ctx_end = min(len(lines), line_num + 2)
                context = '\n'.join(lines[ctx_start:ctx_end])

                finding = {
                    "rule_id": rule["id"],
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "category": rule["category"],
                    "file": filepath,
                    "line": line_num,
                    "match": match.group()[:100],
                    "context": context.strip()
                }
                findings.append(finding)

                if verbose:
                    print(f"  [{rule['severity']}] {rule['name']}")
                    print(f"    文件: {filepath}:{line_num}")
                    print(f"    匹配: {match.group()[:80]}")
                    print()

    except Exception as e:
        if verbose:
            print(f"  读取文件失败: {filepath} - {e}")

    return findings


def scan_project(root_dir: str, verbose: bool = False) -> dict:
    """扫描整个Java项目"""
    root_path = Path(root_dir)

    if not root_path.exists():
        print(f"错误: 路径不存在 - {root_dir}")
        return {"error": "Path not found"}

    # 排除目录
    exclude_dirs = {
        'target', 'build', 'out', '.git', '.svn', '.idea', '.gradle',
        'node_modules', 'dist', 'bin', 'test', 'tests',
        '.mvn', 'gradle', 'wrapper'
    }

    # 扫描的文件扩展名
    scan_extensions = {'.java', '.xml', '.yml', '.yaml', '.properties', '.jsp', '.jspx'}

    all_findings = []
    file_count = 0

    print(f"开始扫描: {root_dir}")
    print(f"{'='*60}")

    for file_path in root_path.rglob('*'):
        if not file_path.is_file():
            continue

        # 检查扩展名
        if file_path.suffix.lower() not in scan_extensions:
            continue

        # 检查是否需要排除
        should_exclude = False
        for part in file_path.parts:
            if part.lower() in exclude_dirs:
                should_exclude = True
                break

        if should_exclude:
            continue

        file_count += 1

        if verbose:
            print(f"\n扫描: {file_path}")

        findings = scan_file(str(file_path), verbose)
        all_findings.extend(findings)

    # 统计信息
    summary = {
        "severity": {},
        "category": {}
    }

    for f in all_findings:
        sev = f["severity"]
        cat = f["category"]
        summary["severity"][sev] = summary["severity"].get(sev, 0) + 1
        summary["category"][cat] = summary["category"].get(cat, 0) + 1

    result = {
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target": root_dir,
        "files_scanned": file_count,
        "total_findings": len(all_findings),
        "summary": summary,
        "findings": all_findings
    }

    return result


def print_report(result: dict):
    """输出扫描结果摘要"""
    if "error" in result:
        print(f"\n扫描失败: {result['error']}")
        return

    print(f"\n{'='*60}")
    print(f"扫描完成!")
    print(f"目标目录: {result['target']}")
    print(f"扫描时间: {result['scan_time']}")
    print(f"扫描文件: {result['files_scanned']} 个")
    print(f"发现潜在风险: {result['total_findings']} 处")
    print(f"{'='*60}")

    # 按严重程度输出
    print("\n📊 按严重程度统计:")
    severity_order = ["严重", "高危", "中危", "低危"]
    for sev in severity_order:
        count = result["summary"]["severity"].get(sev, 0)
        icon = {"严重": "🔴", "高危": "🟠", "中危": "🟡", "低危": "🔵"}.get(sev, "⚪")
        bar = "█" * min(count, 20)
        print(f"  {icon} {sev}: {count}处 {bar}")

    # 按类别输出
    print("\n📂 按漏洞类别统计:")
    for cat, count in sorted(result["summary"]["category"].items(), key=lambda x: -x[1]):
        print(f"  • {cat}: {count}处")

    # 输出高风险发现
    high_findings = [f for f in result["findings"] if f["severity"] in ("严重", "高危")]
    if high_findings:
        print(f"\n⚠️  高风险发现 (严重/高危共{len(high_findings)}处):")
        for f in high_findings[:20]:  # 最多显示20条
            print(f"  [{f['severity']}] {f['name']}")
            print(f"      {f['file']}:{f['line']}")

        if len(high_findings) > 20:
            print(f"  ... 还有{len(high_findings) - 20}处高风险")


def main():
    parser = argparse.ArgumentParser(
        description='Java代码审计辅助扫描脚本',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python java_audit_scanner.py /path/to/spring-project
  python java_audit_scanner.py . -o report.json
  python java_audit_scanner.py . --verbose
        """
    )
    parser.add_argument('target', help='要扫描的Java项目路径')
    parser.add_argument('-o', '--output', help='输出JSON报告文件路径')
    parser.add_argument('-v', '--verbose', action='store_true', help='详细输出模式')

    args = parser.parse_args()

    result = scan_project(args.target, args.verbose)
    print_report(result)

    if args.output:
        # 移除context以减小文件体积
        output_result = {
            "scan_time": result["scan_time"],
            "target": result["target"],
            "files_scanned": result["files_scanned"],
            "total_findings": result["total_findings"],
            "summary": result["summary"],
            "findings": [
                {k: v for k, v in f.items() if k != 'context'}
                for f in result["findings"]
            ]
        }
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(output_result, f, ensure_ascii=False, indent=2)
        print(f"\n报告已保存到: {args.output}")


if __name__ == '__main__':
    main()
