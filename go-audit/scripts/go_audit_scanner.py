#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Go代码审计辅助扫描脚本
在大型项目中先跑此脚本快速定位危险函数，再人工审计。

用法：
    python go_audit_scanner.py /path/to/go/project [-o report.json] [--verbose]
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
        "name": "SQL注入 - db.Query字符串拼接",
        "severity": "严重",
        "pattern": r'(?:db|DB|tx|Tx)\.(Query|QueryRow|Exec)\s*\(\s*(?:`[^`]*`|"[^"]*"|\'[^\']*\')\s*\+',
        "category": "SQL注入"
    },
    {
        "id": "SQLI-02",
        "name": "SQL注入 - fmt.Sprintf拼接SQL",
        "severity": "严重",
        "pattern": r'fmt\.Sprintf\s*\(\s*(?:`[^`]*`|"[^"]*")\s*[^)]*\+',
        "category": "SQL注入"
    },
    {
        "id": "SQLI-03",
        "name": "SQL注入 - GORM Where拼接",
        "severity": "严重",
        "pattern": r'\.Where\s*\(\s*(?:`[^`]*`|"[^"]*")\s*\+',
        "category": "SQL注入"
    },
    {
        "id": "SQLI-04",
        "name": "SQL注入 - Raw拼接",
        "severity": "严重",
        "pattern": r'\.Raw\s*\(\s*(?:`[^`]*`|"[^"]*")\s*\+',
        "category": "SQL注入"
    },
    {
        "id": "RCE-01",
        "name": "命令执行 - exec.Command",
        "severity": "严重",
        "pattern": r'exec\.Command(?:Context)?\s*\(',
        "category": "命令执行"
    },
    {
        "id": "RCE-02",
        "name": "命令执行 - os.StartProcess",
        "severity": "严重",
        "pattern": r'os\.StartProcess\s*\(',
        "category": "命令执行"
    },
    {
        "id": "RCE-03",
        "name": "命令执行 - syscall.Exec",
        "severity": "严重",
        "pattern": r'syscall\.Exec\s*\(|syscall\.ForkExec\s*\(',
        "category": "命令执行"
    },
    {
        "id": "DESER-01",
        "name": "反序列化 - json.Unmarshal到interface",
        "severity": "高危",
        "pattern": r'json\.Unmarshal\s*\([^,]+,\s*&(?:result|data|v|val)\s*\)',
        "category": "反序列化"
    },
    {
        "id": "DESER-02",
        "name": "反序列化 - gob.Decode",
        "severity": "严重",
        "pattern": r'gob\.NewDecoder|\.Decode\s*\(',
        "category": "反序列化"
    },
    {
        "id": "DESER-03",
        "name": "反序列化 - yaml.Unmarshal",
        "severity": "严重",
        "pattern": r'yaml\.Unmarshal\s*\(',
        "category": "反序列化"
    },
    {
        "id": "XXE-01",
        "name": "XXE - xml.Unmarshal",
        "severity": "高危",
        "pattern": r'xml\.Unmarshal\s*\(|xml\.NewDecoder',
        "category": "XXE"
    },
    {
        "id": "LFI-01",
        "name": "文件操作 - os.Open用户输入",
        "severity": "高危",
        "pattern": r'os\.(Open|Create|OpenFile)\s*\(.*(?:Query|Param|FormValue|GetString)',
        "category": "文件操作"
    },
    {
        "id": "LFI-02",
        "name": "文件操作 - filepath.Join未校验",
        "severity": "高危",
        "pattern": r'filepath\.Join\s*\([^,]+,\s*(?:.*(?:Query|Param|FormValue))',
        "category": "文件操作"
    },
    {
        "id": "SSRF-01",
        "name": "SSRF - http.Get用户输入",
        "severity": "高危",
        "pattern": r'http\.(Get|Post|PostForm)\s*\(.*(?:Query|Param|FormValue)',
        "category": "SSRF"
    },
    {
        "id": "SSRF-02",
        "name": "SSRF - http.Client.Do用户输入",
        "severity": "高危",
        "pattern": r'http\.NewRequest.*(?:Query|Param|FormValue)',
        "category": "SSRF",
        "multiline": True
    },
    {
        "id": "SSTI-01",
        "name": "模板注入 - text/template",
        "severity": "严重",
        "pattern": r'text/template.*\.Execute|template\.Must\s*\(template\.New',
        "category": "模板注入"
    },
    {
        "id": "XSS-01",
        "name": "XSS - fmt.Fprintf直接输出",
        "severity": "高危",
        "pattern": r'fmt\.Fprint(?:f)?\s*\(\s*(?:w|writer|rw).*\)',
        "category": "XSS"
    },
    {
        "id": "XSS-02",
        "name": "XSS - c.String用户输入(Gin)",
        "severity": "高危",
        "pattern": r'c\.String\s*\(\s*\d+\s*,\s*(?:.*(?:Query|Param|FormValue))',
        "category": "XSS"
    },
    {
        "id": "WEAK-01",
        "name": "弱哈希 - md5/sha1",
        "severity": "高危",
        "pattern": r'(?:md5|sha1)\.(Sum|New)\s*\(',
        "category": "密码安全"
    },
    {
        "id": "WEAK-02",
        "name": "弱随机数 - math/rand",
        "severity": "中危",
        "pattern": r'math/rand.*(?:Intn|Float64|Seed)',
        "category": "密码安全"
    },
    {
        "id": "WEAK-03",
        "name": "TLS跳过验证",
        "severity": "严重",
        "pattern": r'InsecureSkipVerify\s*:\s*true',
        "category": "配置安全"
    },
    {
        "id": "INFO-01",
        "name": "信息泄露 - gin.DebugMode",
        "severity": "中危",
        "pattern": r'gin\.SetMode\s*\(\s*gin\.DebugMode\s*\)',
        "category": "信息泄露"
    },
    {
        "id": "INFO-02",
        "name": "信息泄露 - pprof导入",
        "severity": "高危",
        "pattern": r'import\s+_\s+"net/http/pprof"',
        "category": "信息泄露"
    },
    {
        "id": "INFO-03",
        "name": "信息泄露 - debug.PrintStack",
        "severity": "中危",
        "pattern": r'debug\.PrintStack\s*\(\)',
        "category": "信息泄露"
    },
    {
        "id": "CORS-01",
        "name": "CORS全开放",
        "severity": "高危",
        "pattern": r'Access-Control-Allow-Origin.*\*|cors\.Default\s*\(\)',
        "category": "配置安全"
    },
    {
        "id": "RACE-01",
        "name": "竞争条件 - map并发读写",
        "severity": "中危",
        "pattern": r'go\s+func\s*\(\).*\{[^}]*map\[',
        "category": "竞争条件",
        "multiline": True
    },
    {
        "id": "REFLECT-01",
        "name": "反射 - reflect.Value.Call",
        "severity": "高危",
        "pattern": r'reflect\.Value.*Call\s*\(|reflect\.MethodByName',
        "category": "反射"
    },
    {
        "id": "UNSAFE-01",
        "name": "unsafe包使用",
        "severity": "高危",
        "pattern": r'unsafe\.Pointer|unsafe\.Sizeof|unsafe\.Offsetof',
        "category": "unsafe操作"
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

    exclude_dirs = {'vendor', '.git', '.svn', '.idea', 'bin', 'dist', 'node_modules', 'testdata'}
    scan_extensions = {'.go', '.mod', '.sum', '.yaml', '.yml', '.json', '.toml'}

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
    parser = argparse.ArgumentParser(description='Go代码审计辅助扫描脚本')
    parser.add_argument('target', help='要扫描的Go项目路径')
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
