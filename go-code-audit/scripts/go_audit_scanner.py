#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Go代码审计辅助扫描脚本
在大型Go项目中先跑此脚本快速定位危险函数/模式，再人工审计。

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
    # ========== SQL注入 ==========
    {
        "id": "SQLI-01",
        "name": "SQL注入 - fmt.Sprintf拼接SQL",
        "severity": "严重",
        "pattern": r'fmt\.Sprintf\s*\(\s*\"[^\"]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)\b',
        "category": "SQL注入",
        "ignore_case": True
    },
    {
        "id": "SQLI-02",
        "name": "SQL注入 - 字符串拼接SQL",
        "severity": "高危",
        "pattern": r'(?:Query|Exec|QueryRow|QueryContext|ExecContext|QueryRowContext)\s*\(\s*\"[^\"]*(?:SELECT|INSERT|UPDATE|DELETE)\b.*\"\s*\+',
        "category": "SQL注入"
    },
    {
        "id": "SQLI-03",
        "name": "SQL注入 - database/sql拼接",
        "severity": "高危",
        "pattern": r'(?:db|tx|stmt)\.(?:Query|Exec|QueryRow)\s*\([^)]*\+',
        "category": "SQL注入"
    },
    {
        "id": "SQLI-04",
        "name": "SQL注入 - GORM Raw查询",
        "severity": "高危",
        "pattern": r'\.Raw\s*\(\s*\"[^\"]*\"\s*\+',
        "category": "SQL注入"
    },
    {
        "id": "SQLI-05",
        "name": "SQL注入 - GORM Expr拼接",
        "severity": "中危",
        "pattern": r'gorm\.Expr\s*\(\s*\"[^\"]*\"\s*\+',
        "category": "SQL注入"
    },

    # ========== 命令执行 ==========
    {
        "id": "RCE-01",
        "name": "命令执行 - os/exec.Command",
        "severity": "严重",
        "pattern": r'exec\.Command\s*\(',
        "category": "命令执行"
    },
    {
        "id": "RCE-02",
        "name": "命令执行 - exec.CommandContext",
        "severity": "严重",
        "pattern": r'exec\.CommandContext\s*\(',
        "category": "命令执行"
    },
    {
        "id": "RCE-03",
        "name": "命令执行 - os.StartProcess",
        "severity": "严重",
        "pattern": r'os\.StartProcess\s*\(',
        "category": "命令执行"
    },
    {
        "id": "RCE-04",
        "name": "命令执行 - syscall.Exec",
        "severity": "严重",
        "pattern": r'syscall\.(?:Exec|ForkExec)\s*\(',
        "category": "命令执行"
    },

    # ========== 代码执行 ==========
    {
        "id": "CE-01",
        "name": "代码执行 - text/template用户数据",
        "severity": "高危",
        "pattern": r'(?:template\.New|Template\.New)\s*\(.*?\)\.(?:Parse|Execute)\s*\(',
        "category": "代码执行"
    },
    {
        "id": "CE-02",
        "name": "代码执行 - html/template Execute用户数据",
        "severity": "高危",
        "pattern": r'\.ExecuteTemplate?\s*\(\s*\w+\s*,\s*.*?(?:r\.(?:Form|PostForm|URL)|c\.(?:Query|FormValue|Param))',
        "category": "代码执行"
    },
    {
        "id": "CE-03",
        "name": "代码执行 - plugin.Open动态加载",
        "severity": "高危",
        "pattern": r'plugin\.Open\s*\(',
        "category": "代码执行"
    },

    # ========== 路径穿越 ==========
    {
        "id": "PATH-01",
        "name": "路径穿越 - os.Open用户路径",
        "severity": "高危",
        "pattern": r'os\.(?:Open|OpenFile|ReadFile|Create)\s*\([^)]*r\.(?:Form|PostForm|URL|Header)',
        "category": "路径穿越"
    },
    {
        "id": "PATH-02",
        "name": "路径穿越 - ioutil.ReadFile用户路径",
        "severity": "高危",
        "pattern": r'ioutil\.ReadFile\s*\([^)]*r\.',
        "category": "路径穿越"
    },
    {
        "id": "PATH-03",
        "name": "路径穿越 - http.ServeFile用户路径",
        "severity": "高危",
        "pattern": r'http\.ServeFile\s*(-?\([^)]*r\.)',
        "category": "路径穿越"
    },
    {
        "id": "PATH-04",
        "name": "路径穿越 - filepath.Join用户输入",
        "severity": "中危",
        "pattern": r'filepath\.Join\s*\([^)]*r\.',
        "category": "路径穿越"
    },
    {
        "id": "PATH-05",
        "name": "路径穿越 - gin.Context.File",
        "severity": "中危",
        "pattern": r'c\.File\s*\(\s*r\.',
        "category": "路径穿越"
    },

    # ========== SSRF ==========
    {
        "id": "SSRF-01",
        "name": "SSRF - http.Get用户URL",
        "severity": "高危",
        "pattern": r'http\.(?:Get|Head|Post|PostForm)\s*\([^)]*r\.',
        "category": "SSRF"
    },
    {
        "id": "SSRF-02",
        "name": "SSRF - http.NewRequest用户URL",
        "severity": "高危",
        "pattern": r'http\.NewRequest(?:WithContext)?\s*\([^)]*r\.',
        "category": "SSRF"
    },
    {
        "id": "SSRF-03",
        "name": "SSRF - http.Client.Do用户URL",
        "severity": "高危",
        "pattern": r'(?:http\.)?Client.*?\.(?:Do|Get|Post)\s*\([^)]*r\.',
        "category": "SSRF"
    },
    {
        "id": "SSRF-04",
        "name": "SSRF - resty用户URL",
        "severity": "高危",
        "pattern": r'\.(?:R\(\)|NewRequest)\s*\(\s*\)\s*\.(?:Get|Post|Put|Delete|SetPathParam)\s*\([^)]*r\.',
        "category": "SSRF"
    },
    {
        "id": "SSRF-05",
        "name": "SSRF - fasthttp用户URL",
        "severity": "高危",
        "pattern": r'(?:fasthttp|fiber)\.(?:Get|Post|Do)\s*\([^)]*ctx\.',
        "category": "SSRF"
    },

    # ========== 反序列化 ==========
    {
        "id": "DESER-01",
        "name": "反序列化 - gob.Decoder",
        "severity": "高危",
        "pattern": r'gob\.NewDecoder\s*\(',
        "category": "反序列化"
    },
    {
        "id": "DESER-02",
        "name": "反序列化 - json.Unmarshal无验证",
        "severity": "中危",
        "pattern": r'json\.Unmarshal\s*\([^)]*r\.',
        "category": "反序列化"
    },
    {
        "id": "DESER-03",
        "name": "反序列化 - yaml.Unmarshal无验证",
        "severity": "中危",
        "pattern": r'yaml\.Unmarshal\s*\([^)]*r\.',
        "category": "反序列化"
    },

    # ========== XXE (Go中较少，但xml解析) ==========
    {
        "id": "XXE-01",
        "name": "XXE - xml.NewDecoder",
        "severity": "高危",
        "pattern": r'xml\.NewDecoder\s*\(',
        "category": "XXE"
    },
    {
        "id": "XXE-02",
        "name": "XXE - xml.Unmarshal",
        "severity": "中危",
        "pattern": r'xml\.Unmarshal\s*\(',
        "category": "XXE"
    },

    # ========== 密码安全 ==========
    {
        "id": "CRYPTO-01",
        "name": "弱哈希 - crypto/md5/sha1密码",
        "severity": "高危",
        "pattern": r'(?:md5|sha1)\.(?:New|Sum)\s*\(',
        "category": "密码安全"
    },
    {
        "id": "CRYPTO-02",
        "name": "弱随机数 - math/rand生成令牌",
        "severity": "中危",
        "pattern": r'(?:token|nonce|csrf|session|secret)\s*:?=.*?rand\.(?:Int|Intn|Float|Read|String)\s*\(',
        "category": "密码安全",
        "ignore_case": True
    },
    {
        "id": "CRYPTO-03",
        "name": "硬编码密钥/密码",
        "severity": "高危",
        "pattern": r'(?:password|secret|token|apiKey|privateKey|accessKey)\s*[:=]?\s*\"[^\"]{6,}\"',
        "category": "密码安全",
        "ignore_case": True
    },
    {
        "id": "CRYPTO-04",
        "name": "DES/3DES/RC4弱加密",
        "severity": "高危",
        "pattern": r'(?:cipher|NewCipher)\s*\(\s*\"?(?:DES|3DES|RC4|Blowfish)',
        "category": "密码安全"
    },
    {
        "id": "CRYPTO-05",
        "name": "时间比较非恒定 - 密码对比",
        "severity": "中危",
        "pattern": r'password\s*(?:==|!=)\s*',
        "category": "密码安全",
        "ignore_case": True
    },

    # ========== 信息泄露 ==========
    {
        "id": "INFO-01",
        "name": "信息泄露 - log.Println敏感信息",
        "severity": "中危",
        "pattern": r'log\.(?:Print|Fatal|Panic)(?:f|ln)?\s*\([^)]*(?:password|secret|token|credential|apiKey)',
        "category": "信息泄露",
        "ignore_case": True
    },
    {
        "id": "INFO-02",
        "name": "信息泄露 - panic错误堆栈暴露",
        "severity": "低危",
        "pattern": r'panic\s*\(',
        "category": "信息泄露"
    },
    {
        "id": "INFO-03",
        "name": "信息泄露 - Gin Debug模式",
        "severity": "中危",
        "pattern": r'gin\.SetMode\s*\(\s*gin\.DebugMode\s*\)',
        "category": "信息泄露"
    },

    # ========== 配置安全 ==========
    {
        "id": "CONFIG-01",
        "name": "CORS允许所有来源",
        "severity": "中危",
        "pattern": r'AllowAllOrigins\s*:\s*true',
        "category": "配置安全"
    },
    {
        "id": "CONFIG-02",
        "name": "TLS不安全配置",
        "severity": "高危",
        "pattern": r'(?:InsecureSkipVerify|MinVersion\s*=\s*tls\.VersionSSL30|MaxVersion\s*=\s*tls\.VersionTLS10)\s*[=:]\s*true',
        "category": "配置安全"
    },
    {
        "id": "CONFIG-03",
        "name": "CSRF保护缺失",
        "severity": "中危",
        "pattern": r'CSRF\s*\(\s*\)\s*\)?\s*\n',
        "category": "配置安全"
    },

    # ========== 并发安全 ==========
    {
        "id": "CONC-01",
        "name": "并发安全 - map无锁并发读写",
        "severity": "高危",
        "pattern": r'var\s+\w+\s*=\s*make\s*\(\s*map\s*\[',
        "category": "并发安全"
    },
    {
        "id": "CONC-02",
        "name": "并发安全 - goroutine泄漏",
        "severity": "中危",
        "pattern": r'go\s+func\s*\([^)]*\)\s*\{',
        "category": "并发安全"
    },
]


GO_EXTENSIONS = {'.go', '.mod', '.sum', '.yaml', '.yml', '.toml', '.json'}

EXCLUDE_DIRS = {
    'vendor', '.git', '.svn', 'testdata', 'tests', 'test', '.idea',
    'node_modules', 'dist', 'bin', 'tmp', 'mocks'
}


def scan_file(filepath: str, verbose: bool = False) -> list:
    findings = []
    ext = Path(filepath).suffix.lower()
    if ext not in GO_EXTENSIONS:
        return findings

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        lines = content.split('\n')

        for rule in RULES:
            flags = re.MULTILINE | re.DOTALL if rule.get('multiline') else re.MULTILINE
            if rule.get('ignore_case'):
                flags |= re.IGNORECASE

            for match in re.finditer(rule['pattern'], content, flags):
                match_start = match.start()
                line_num = content[:match_start].count('\n') + 1

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
    root_path = Path(root_dir)

    if not root_path.exists():
        print(f"错误: 路径不存在 - {root_dir}")
        return {"error": "Path not found"}

    all_findings = []
    file_count = 0

    print(f"开始扫描: {root_dir}")
    print(f"{'='*60}")

    for ext in GO_EXTENSIONS:
        for source_file in root_path.rglob(f'*{ext}'):
            should_exclude = False
            for part in source_file.parts:
                if part.lower() in EXCLUDE_DIRS:
                    should_exclude = True
                    break

            if should_exclude:
                continue

            file_count += 1

            if verbose:
                print(f"\n扫描: {source_file}")

            findings = scan_file(str(source_file), verbose)
            all_findings.extend(findings)

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
    if "error" in result:
        print(f"\n扫描失败: {result['error']}")
        return

    print(f"\n{'='*60}")
    print(f"扫描完成!")
    print(f"目标目录: {result['target']}")
    print(f"扫描时间: {result['scan_time']}")
    print(f"扫描Go文件: {result['files_scanned']} 个")
    print(f"发现潜在风险: {result['total_findings']} 处")
    print(f"{'='*60}")

    print("\n按严重程度统计:")
    severity_order = ["严重", "高危", "中危", "低危"]
    for sev in severity_order:
        count = result["summary"]["severity"].get(sev, 0)
        bar = "#" * min(count, 20)
        print(f"  {sev}: {count}处 {bar}")

    print("\n按漏洞类别统计:")
    for cat, count in sorted(result["summary"]["category"].items(), key=lambda x: -x[1]):
        print(f"  - {cat}: {count}处")

    high_findings = [f for f in result["findings"] if f["severity"] in ("严重", "高危")]
    if high_findings:
        print(f"\n高风险发现 (严重/高危共{len(high_findings)}处):")
        for f in high_findings[:20]:
            print(f"  [{f['severity']}] {f['name']}")
            print(f"      {f['file']}:{f['line']}")

        if len(high_findings) > 20:
            print(f"  ... 还有{len(high_findings) - 20}处高风险")


def main():
    parser = argparse.ArgumentParser(
        description='Go代码审计辅助扫描脚本',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python go_audit_scanner.py /path/to/go/project
  python go_audit_scanner.py . -o report.json
  python go_audit_scanner.py . --verbose
        """
    )
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
