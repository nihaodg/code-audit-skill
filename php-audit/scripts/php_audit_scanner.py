#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHP代码审计辅助扫描脚本
在大型项目中先跑此脚本快速定位危险函数，再人工审计。

用法：
    python php_audit_scanner.py /path/to/php/project [-o report.json] [--verbose]
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
        "name": "SQL注入 - mysql_query(废弃)",
        "severity": "严重",
        "pattern": r'mysql_query\s*\(',
        "category": "SQL注入"
    },
    {
        "id": "SQLI-02",
        "name": "SQL注入 - mysqli_query/query",
        "severity": "高危",
        "pattern": r'(?:mysqli_query|mysqli_real_query)\s*\(',
        "category": "SQL注入"
    },
    {
        "id": "SQLI-03",
        "name": "SQL注入 - 字符串拼接SQL",
        "severity": "高危",
        "pattern": r'(?:SELECT|INSERT|UPDATE|DELETE)\s+.*?\.\s*(?:\$|→get|→post|→input|→param|_GET|_POST|_REQUEST)',
        "category": "SQL注入",
        "multiline": True
    },
    {
        "id": "SQLI-04",
        "name": "SQL注入 - 原生查询",
        "severity": "高危",
        "pattern": r'(?:DB::(?:select|statement|unprepared)|Db::(?:execute|query)|whereRaw|orderRaw|havingRaw)',
        "category": "SQL注入"
    },
    {
        "id": "RCE-01",
        "name": "命令执行 - exec",
        "severity": "严重",
        "pattern": r'\bexec\s*\(',
        "category": "命令执行"
    },
    {
        "id": "RCE-02",
        "name": "命令执行 - system/passthru",
        "severity": "严重",
        "pattern": r'\b(?:system|passthru|shell_exec)\s*\(',
        "category": "命令执行"
    },
    {
        "id": "RCE-03",
        "name": "代码执行 - eval",
        "severity": "严重",
        "pattern": r'\beval\s*\(',
        "category": "代码执行"
    },
    {
        "id": "RCE-04",
        "name": "代码执行 - assert",
        "severity": "严重",
        "pattern": r'\bassert\s*\(',
        "category": "代码执行"
    },
    {
        "id": "RCE-05",
        "name": "命令执行 - popen/proc_open",
        "severity": "高危",
        "pattern": r'\b(?:popen|proc_open|pcntl_exec)\s*\(',
        "category": "命令执行"
    },
    {
        "id": "CE-01",
        "name": "代码执行 - create_function",
        "severity": "高危",
        "pattern": r'create_function\s*\(',
        "category": "代码执行"
    },
    {
        "id": "CE-02",
        "name": "代码执行 - preg_replace(/e)",
        "severity": "严重",
        "pattern": r'preg_replace\s*\(\s*[\'\"][\/\S]*e[\'\"\]]',
        "category": "代码执行"
    },
    {
        "id": "XSS-01",
        "name": "XSS - echo + 用户输入",
        "severity": "高危",
        "pattern": r'echo\s+.*?(?:\$_GET|\$_POST|\$_REQUEST|\$_COOKIE)',
        "category": "XSS"
    },
    {
        "id": "XSS-02",
        "name": "XSS - print + 用户输入",
        "severity": "高危",
        "pattern": r'print\s+.*?(?:\$_GET|\$_POST|\$_REQUEST|\$_COOKIE)',
        "category": "XSS"
    },
    {
        "id": "XSS-03",
        "name": "XSS - 短标签输出",
        "severity": "高危",
        "pattern": r'<\?=\s*.*?(?:\$_GET|\$_POST|\$_REQUEST|\$_COOKIE)',
        "category": "XSS"
    },
    {
        "id": "LFI-01",
        "name": "文件包含 - include用户输入",
        "severity": "高危",
        "pattern": r'(?:include|require|include_once|require_once)\s*\(.*?(?:\$_GET|\$_POST|\$_REQUEST|\$_COOKIE)',
        "category": "文件包含"
    },
    {
        "id": "LFI-02",
        "name": "文件包含 - 动态变量包含",
        "severity": "高危",
        "pattern": r'(?:include|require)\s*\(.*?\$',
        "category": "文件包含"
    },
    {
        "id": "SSRF-01",
        "name": "SSRF - curl_exec",
        "severity": "高危",
        "pattern": r'curl_exec\s*\(',
        "category": "SSRF"
    },
    {
        "id": "SSRF-02",
        "name": "SSRF - file_get_contents远程",
        "severity": "高危",
        "pattern": r'file_get_contents\s*\(.*?\$',
        "category": "SSRF"
    },
    {
        "id": "DANGER-01",
        "name": "反序列化 - unserialize",
        "severity": "严重",
        "pattern": r'unserialize\s*\(',
        "category": "反序列化"
    },
    {
        "id": "UPLOAD-01",
        "name": "文件上传 - move_uploaded_file",
        "severity": "高危",
        "pattern": r'move_uploaded_file\s*\(',
        "category": "文件上传"
    },
    {
        "id": "UPLOAD-02",
        "name": "文件上传 - $_FILES",
        "severity": "中危",
        "pattern": r'\$_FILES',
        "category": "文件上传"
    },
    {
        "id": "XXE-01",
        "name": "XXE - simplexml_load",
        "severity": "高危",
        "pattern": r'(?:simplexml_load_string|simplexml_load_file|DOMDocument::loadXML)\s*\(',
        "category": "XXE"
    },
    {
        "id": "WEAK-01",
        "name": "弱哈希 - md5/sha1密码",
        "severity": "高危",
        "pattern": r'md5\s*\(.*?\$.*?pass|sha1\s*\(.*?\$.*?pass',
        "category": "密码安全",
        "ignore_case": True
    },
    {
        "id": "WEAK-02",
        "name": "弱随机数 - rand/mt_rand",
        "severity": "中危",
        "pattern": r'(?:token|nonce|csrf|hash).*=\s*.*(?:rand|mt_rand|uniqid|time)\s*\(',
        "category": "密码安全",
        "ignore_case": True
    },
    {
        "id": "INFO-01",
        "name": "信息泄露 - phpinfo",
        "severity": "中危",
        "pattern": r'phpinfo\s*\(',
        "category": "信息泄露"
    },
    {
        "id": "INFO-02",
        "name": "信息泄露 - 调试输出",
        "severity": "低危",
        "pattern": r'(?:var_dump|print_r|var_export)\s*\(',
        "category": "信息泄露"
    },
    {
        "id": "CONFIG-01",
        "name": "危险配置 - allow_url_include",
        "severity": "高危",
        "pattern": r'allow_url_include\s*=\s*[Oo]n',
        "category": "配置安全"
    },
    {
        "id": "CONFIG-02",
        "name": "危险配置 - display_errors",
        "severity": "中危",
        "pattern": r'display_errors\s*=\s*[Oo]n',
        "category": "配置安全"
    },
]


def scan_file(filepath: str, verbose: bool = False) -> list:
    """扫描单个PHP文件的危险函数"""
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        lines = content.split('\n')

        for rule in RULES:
            flags = re.MULTILINE | re.DOTALL if rule.get('multiline') else re.MULTILINE
            if rule.get('ignore_case'):
                flags |= re.IGNORECASE

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
    """扫描整个PHP项目"""
    root_path = Path(root_dir)

    if not root_path.exists():
        print(f"错误: 路径不存在 - {root_dir}")
        return {"error": "Path not found"}

    # 排除目录
    exclude_dirs = {
        'vendor', 'node_modules', '.git', '.svn', 'runtime',
        'cache', 'upload', 'uploads', 'storage', 'backup',
        'tests', 'test'
    }

    all_findings = []
    php_file_count = 0
    scanned_dirs = set()

    print(f"开始扫描: {root_dir}")
    print(f"{'='*60}")

    for php_file in root_path.rglob('*.php'):
        # 检查是否需要排除
        should_exclude = False
        for part in php_file.parts:
            if part.lower() in exclude_dirs:
                should_exclude = True
                break

        if should_exclude:
            continue

        php_file_count += 1
        scanned_dirs.add(php_file.parent)

        if verbose:
            print(f"\n扫描: {php_file}")

        findings = scan_file(str(php_file), verbose)
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
        "php_files_scanned": php_file_count,
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
    print(f"扫描PHP文件: {result['php_files_scanned']} 个")
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
        description='PHP代码审计辅助扫描脚本',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python php_audit_scanner.py /var/www/project
  python php_audit_scanner.py . -o report.json
  python php_audit_scanner.py . --verbose
        """
    )
    parser.add_argument('target', help='要扫描的PHP项目路径')
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
            "php_files_scanned": result["php_files_scanned"],
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
