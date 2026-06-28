#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Python代码审计辅助扫描脚本
在大型项目中先跑此脚本快速定位危险函数，再人工审计。

用法：
    python python_audit_scanner.py /path/to/python/project [-o report.json] [--verbose]
"""

import os
import re
import json
import sys
import argparse
from datetime import datetime
from pathlib import Path


RULES = [
    {
        "id": "SQLI-01",
        "name": "SQL注入 - f-string拼接SQL",
        "severity": "严重",
        "pattern": r'(?:execute|query|raw)\s*\(\s*f[\'"]',
        "category": "SQL注入"
    },
    {
        "id": "SQLI-02",
        "name": "SQL注入 - format拼接SQL",
        "severity": "严重",
        "pattern": r'(?:execute|query|raw)\s*\(\s*[\'"].*\.format\s*\(',
        "category": "SQL注入"
    },
    {
        "id": "SQLI-03",
        "name": "SQL注入 - %格式化拼接SQL",
        "severity": "严重",
        "pattern": r'(?:execute|query|raw)\s*\(\s*[\'"].*%\s*(?:\w+|\([^)]+\))',
        "category": "SQL注入"
    },
    {
        "id": "SQLI-04",
        "name": "SQL注入 - +拼接SQL",
        "severity": "严重",
        "pattern": r'(?:execute|query|raw)\s*\(\s*[\'"].*\+\s*(?:request|args|form|json|data)',
        "category": "SQL注入"
    },
    {
        "id": "SQLI-05",
        "name": "SQL注入 - Django extra拼接",
        "severity": "严重",
        "pattern": r'\.extra\s*\(\s*(?:where|tables|select|order_by)\s*=\s*\[',
        "category": "SQL注入"
    },
    {
        "id": "SQLI-06",
        "name": "SQL注入 - Django RawSQL拼接",
        "severity": "严重",
        "pattern": r'RawSQL\s*\(\s*[\'"].*\+',
        "category": "SQL注入"
    },
    {
        "id": "SQLI-07",
        "name": "SQL注入 - SQLAlchemy text拼接",
        "severity": "严重",
        "pattern": r'text\s*\(\s*[\'"].*\+',
        "category": "SQL注入"
    },
    {
        "id": "RCE-01",
        "name": "命令执行 - os.system",
        "severity": "严重",
        "pattern": r'os\.system\s*\(',
        "category": "命令执行"
    },
    {
        "id": "RCE-02",
        "name": "命令执行 - os.popen",
        "severity": "严重",
        "pattern": r'os\.popen\s*\(',
        "category": "命令执行"
    },
    {
        "id": "RCE-03",
        "name": "命令执行 - subprocess shell=True",
        "severity": "严重",
        "pattern": r'subprocess\.(?:call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True',
        "category": "命令执行"
    },
    {
        "id": "RCE-04",
        "name": "代码执行 - eval",
        "severity": "严重",
        "pattern": r'\beval\s*\(',
        "category": "代码执行"
    },
    {
        "id": "RCE-05",
        "name": "代码执行 - exec",
        "severity": "严重",
        "pattern": r'\bexec\s*\(',
        "category": "代码执行"
    },
    {
        "id": "DESER-01",
        "name": "反序列化 - pickle.loads",
        "severity": "严重",
        "pattern": r'pickle\.(?:loads|load)\s*\(',
        "category": "反序列化"
    },
    {
        "id": "DESER-02",
        "name": "反序列化 - yaml.load",
        "severity": "严重",
        "pattern": r'yaml\.load\s*\([^)]*\)',
        "category": "反序列化"
    },
    {
        "id": "DESER-03",
        "name": "反序列化 - marshal.loads",
        "severity": "严重",
        "pattern": r'marshal\.(?:loads|load)\s*\(',
        "category": "反序列化"
    },
    {
        "id": "SSTI-01",
        "name": "模板注入 - render_template_string",
        "severity": "严重",
        "pattern": r'render_template_string\s*\(',
        "category": "模板注入"
    },
    {
        "id": "SSTI-02",
        "name": "模板注入 - Jinja2 Template",
        "severity": "严重",
        "pattern": r'Template\s*\(\s*(?:request|args|form|json)',
        "category": "模板注入"
    },
    {
        "id": "XXE-01",
        "name": "XXE - lxml.etree.parse",
        "severity": "高危",
        "pattern": r'lxml\.etree\.(?:parse|fromstring|XML)\s*\(',
        "category": "XXE"
    },
    {
        "id": "XXE-02",
        "name": "XXE - xml.etree.parse",
        "severity": "高危",
        "pattern": r'xml\.etree\.ElementTree\.(?:parse|fromstring)\s*\(',
        "category": "XXE"
    },
    {
        "id": "LFI-01",
        "name": "文件操作 - open用户输入",
        "severity": "高危",
        "pattern": r'open\s*\(\s*(?:request|args|form|json|files)',
        "category": "文件操作"
    },
    {
        "id": "LFI-02",
        "name": "文件操作 - send_from_directory",
        "severity": "高危",
        "pattern": r'send_from_directory\s*\(',
        "category": "文件操作"
    },
    {
        "id": "UPLOAD-01",
        "name": "文件上传 - 未校验后缀",
        "severity": "中危",
        "pattern": r'request\.(?:FILES|files)',
        "category": "文件上传"
    },
    {
        "id": "SSRF-01",
        "name": "SSRF - requests.get用户输入",
        "severity": "高危",
        "pattern": r'requests\.(?:get|post|request)\s*\(\s*(?:request|args|form|json)',
        "category": "SSRF"
    },
    {
        "id": "SSRF-02",
        "name": "SSRF - urllib.request用户输入",
        "severity": "高危",
        "pattern": r'urllib\.request\.urlopen\s*\(\s*(?:request|args|form|json)',
        "category": "SSRF"
    },
    {
        "id": "XSS-01",
        "name": "XSS - mark_safe",
        "severity": "严重",
        "pattern": r'mark_safe\s*\(\s*(?:request|args|form|json)',
        "category": "XSS"
    },
    {
        "id": "XSS-02",
        "name": "XSS - HttpResponse直接输出",
        "severity": "高危",
        "pattern": r'HttpResponse\s*\(\s*(?:request|args|form|json)',
        "category": "XSS"
    },
    {
        "id": "XSS-03",
        "name": "XSS - |safe过滤器",
        "severity": "严重",
        "pattern": r'\{\{\s*.*\|\s*safe\s*\}\}',
        "category": "XSS",
        "file_pattern": r".*\.(html|htm|jinja2|j2)$"
    },
    {
        "id": "WEAK-01",
        "name": "弱哈希 - hashlib.md5",
        "severity": "高危",
        "pattern": r'hashlib\.md5\s*\(',
        "category": "密码安全"
    },
    {
        "id": "WEAK-02",
        "name": "弱哈希 - hashlib.sha1",
        "severity": "中危",
        "pattern": r'hashlib\.sha1\s*\(',
        "category": "密码安全"
    },
    {
        "id": "WEAK-03",
        "name": "弱随机数 - random",
        "severity": "中危",
        "pattern": r'random\.(?:random|randint|choice|seed)',
        "category": "密码安全"
    },
    {
        "id": "INFO-01",
        "name": "信息泄露 - DEBUG=True",
        "severity": "严重",
        "pattern": r'DEBUG\s*=\s*True',
        "category": "信息泄露"
    },
    {
        "id": "INFO-02",
        "name": "信息泄露 - SECRET_KEY硬编码",
        "severity": "严重",
        "pattern": r'SECRET_KEY\s*=\s*[\'"][^\'"]+[\'"]',
        "category": "信息泄露"
    },
    {
        "id": "INFO-03",
        "name": "信息泄露 - traceback.print_exc",
        "severity": "中危",
        "pattern": r'traceback\.print_exc\s*\(\)',
        "category": "信息泄露"
    },
    {
        "id": "CONFIG-01",
        "name": "危险配置 - ALLOWED_HOSTS全开放",
        "severity": "高危",
        "pattern": r'ALLOWED_HOSTS\s*=\s*\[\s*\*\s*\]',
        "category": "配置安全"
    },
    {
        "id": "CONFIG-02",
        "name": "危险配置 - CORS全开放",
        "severity": "高危",
        "pattern": r'CORS\s*\(\s*[^)]*origins\s*=\s*[\'"]\*[\'"]',
        "category": "配置安全"
    },
    {
        "id": "CONFIG-03",
        "name": "危险配置 - SSL验证跳过",
        "severity": "严重",
        "pattern": r'(?:verify|check_hostname)\s*=\s*False|CERT_NONE',
        "category": "配置安全"
    },
]


def should_scan_file(filepath: str, rule: dict) -> bool:
    file_pattern = rule.get("file_pattern")
    if not file_pattern:
        return True
    return bool(re.search(file_pattern, filepath, re.IGNORECASE))


def scan_file(filepath: str, verbose: bool = False) -> list:
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
                match_start = match.start()
                line_num = content[:match_start].count('\n') + 1
                ctx_start = max(0, line_num - 3)
                ctx_end = min(len(lines), line_num + 2)
                context = '\n'.join(lines[ctx_start:ctx_end])

                findings.append({
                    "rule_id": rule["id"],
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "category": rule["category"],
                    "file": filepath,
                    "line": line_num,
                    "match": match.group()[:100],
                    "context": context.strip()
                })

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
    root_path = Path(root_dir)
    if not root_path.exists():
        return {"error": "Path not found"}

    exclude_dirs = {'.git', '.svn', '.idea', '__pycache__', 'venv', '.venv', 'env', 
                    'node_modules', 'dist', 'build', '.tox', 'htmlcov', '.pytest_cache',
                    'migrations', 'static', 'media'}
    scan_extensions = {'.py', '.html', '.htm', '.jinja2', '.j2', '.yaml', '.yml', '.json', '.cfg', '.ini'}

    all_findings = []
    file_count = 0

    print(f"开始扫描: {root_dir}")
    print(f"{'='*60}")

    for file_path in root_path.rglob('*'):
        if not file_path.is_file():
            continue
        if file_path.suffix.lower() not in scan_extensions:
            continue
        if any(part.lower() in exclude_dirs for part in file_path.parts):
            continue

        file_count += 1
        if verbose:
            print(f"\n扫描: {file_path}")
        findings = scan_file(str(file_path), verbose)
        all_findings.extend(findings)

    summary = {"severity": {}, "category": {}}
    for f in all_findings:
        summary["severity"][f["severity"]] = summary["severity"].get(f["severity"], 0) + 1
        summary["category"][f["category"]] = summary["category"].get(f["category"], 0) + 1

    return {
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target": root_dir,
        "files_scanned": file_count,
        "total_findings": len(all_findings),
        "summary": summary,
        "findings": all_findings
    }


def print_report(result: dict):
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

    print("\n📊 按严重程度统计:")
    for sev in ["严重", "高危", "中危", "低危"]:
        count = result["summary"]["severity"].get(sev, 0)
        icon = {"严重": "🔴", "高危": "🟠", "中危": "🟡", "低危": "🔵"}.get(sev, "⚪")
        print(f"  {icon} {sev}: {count}处 {'█' * min(count, 20)}")

    print("\n📂 按漏洞类别统计:")
    for cat, count in sorted(result["summary"]["category"].items(), key=lambda x: -x[1]):
        print(f"  • {cat}: {count}处")

    high = [f for f in result["findings"] if f["severity"] in ("严重", "高危")]
    if high:
        print(f"\n⚠️  高风险发现 (严重/高危共{len(high)}处):")
        for f in high[:20]:
            print(f"  [{f['severity']}] {f['name']}")
            print(f"      {f['file']}:{f['line']}")
        if len(high) > 20:
            print(f"  ... 还有{len(high) - 20}处高风险")


def main():
    parser = argparse.ArgumentParser(description='Python代码审计辅助扫描脚本')
    parser.add_argument('target', help='要扫描的Python项目路径')
    parser.add_argument('-o', '--output', help='输出JSON报告文件路径')
    parser.add_argument('-v', '--verbose', action='store_true', help='详细输出模式')
    args = parser.parse_args()

    result = scan_project(args.target, args.verbose)
    print_report(result)

    if args.output:
        output_result = {
            "scan_time": result["scan_time"],
            "target": result["target"],
            "files_scanned": result["files_scanned"],
            "total_findings": result["total_findings"],
            "summary": result["summary"],
            "findings": [{k: v for k, v in f.items() if k != 'context'} for f in result["findings"]]
        }
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(output_result, f, ensure_ascii=False, indent=2)
        print(f"\n报告已保存到: {args.output}")


if __name__ == '__main__':
    main()
