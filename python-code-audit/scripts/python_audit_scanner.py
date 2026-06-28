#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Python代码审计辅助扫描脚本
在大型Python项目中先跑此脚本快速定位危险函数/模式，再人工审计。

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
    # ========== SQL注入 ==========
    {
        "id": "SQLI-01",
        "name": "SQL注入 - 字符串格式化拼接SQL",
        "severity": "严重",
        "pattern": r'(?:cursor|c)\.(?:execute|executemany)\s*\(\s*(?:f\"[\s\S]*?SELECT|f\'[\s\S]*?SELECT|\"[^"]*%s[^"]*SELECT|\'[^\']*%s[^\']*SELECT)',
        "category": "SQL注入",
        "ignore_case": True
    },
    {
        "id": "SQLI-02",
        "name": "SQL注入 - %格式化拼接",
        "severity": "高危",
        "pattern": r'\.execute\s*\(\s*\"[^\"]*%(?:s|d|r)\b',
        "category": "SQL注入"
    },
    {
        "id": "SQLI-03",
        "name": "SQL注入 - .format拼接SQL",
        "severity": "高危",
        "pattern": r'\.execute\s*\(\s*\".*\{[^}]*\}[^\"]*\"\.format\s*\(',
        "category": "SQL注入"
    },
    {
        "id": "SQLI-04",
        "name": "SQL注入 - f-string拼接SQL",
        "severity": "高危",
        "pattern": r'\.execute\s*\(\s*f\"',
        "category": "SQL注入"
    },
    {
        "id": "SQLI-05",
        "name": "SQL注入 - Django raw查询",
        "severity": "高危",
        "pattern": r'(?:\.raw\s*\(|RawSQL\s*\()\s*.*?\+.*?(?:request|self\.)',
        "category": "SQL注入"
    },
    {
        "id": "SQLI-06",
        "name": "SQL注入 - Django extra查询",
        "severity": "高危",
        "pattern": r'\.extra\s*\(\s*.*?(?:select|where|tables)',
        "category": "SQL注入"
    },
    {
        "id": "SQLI-07",
        "name": "SQL注入 - SQLAlchemy text拼接",
        "severity": "高危",
        "pattern": r'(?:text|literal_column)\s*\(\s*f\"',
        "category": "SQL注入"
    },

    # ========== 命令执行 ==========
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
        "pattern": r'(?:subprocess\.(?:call|check_call|check_output|Popen|run)\s*\([^)]*shell\s*=\s*True|subprocess\.getoutput|subprocess\.getstatusoutput)\s*\(',
        "category": "命令执行"
    },
    {
        "id": "RCE-04",
        "name": "命令执行 - os.exec系列",
        "severity": "严重",
        "pattern": r'os\.(?:execv|execl|execvp|execlp|execvpe|execle)\s*\(',
        "category": "命令执行"
    },
    {
        "id": "RCE-05",
        "name": "命令执行 - commands模块",
        "severity": "高危",
        "pattern": r'commands\.(?:getoutput|getstatusoutput)\s*\(',
        "category": "命令执行"
    },

    # ========== 代码执行 ==========
    {
        "id": "CE-01",
        "name": "代码执行 - eval",
        "severity": "严重",
        "pattern": r'\beval\s*\(',
        "category": "代码执行"
    },
    {
        "id": "CE-02",
        "name": "代码执行 - exec",
        "severity": "严重",
        "pattern": r'\bexec\s*\(',
        "category": "代码执行"
    },
    {
        "id": "CE-03",
        "name": "代码执行 - compile + exec",
        "severity": "严重",
        "pattern": r'compile\s*\([^)]*\)\s*[,\)]',
        "category": "代码执行"
    },
    {
        "id": "CE-04",
        "name": "代码执行 - __import__动态导入",
        "severity": "高危",
        "pattern": r'__import__\s*\(',
        "category": "代码执行"
    },
    {
        "id": "CE-05",
        "name": "代码执行 - importlib动态导入",
        "severity": "中危",
        "pattern": r'importlib\.(?:import_module|reload)\s*\(',
        "category": "代码执行"
    },

    # ========== SSTI模板注入 ==========
    {
        "id": "SSTI-01",
        "name": "SSTI - Jinja2 render_template_string",
        "severity": "严重",
        "pattern": r'(?:render_template_string|Template\s*\([^)]*\)\.render)\s*\(',
        "category": "SSTI"
    },
    {
        "id": "SSTI-02",
        "name": "SSTI - Django Template用户输入",
        "severity": "高危",
        "pattern": r'Template\s*\(.*?(?:request\.(?:GET|POST)|user_input)',
        "category": "SSTI"
    },
    {
        "id": "SSTI-03",
        "name": "SSTI - Mako Template",
        "severity": "高危",
        "pattern": r'mako\.template\.Template\s*\(',
        "category": "SSTI"
    },

    # ========== XSS ==========
    {
        "id": "XSS-01",
        "name": "XSS - Django mark_safe用户输入",
        "severity": "高危",
        "pattern": r'mark_safe\s*\(.*?(?:request\.(?:GET|POST)|request\.data)',
        "category": "XSS"
    },
    {
        "id": "XSS-02",
        "name": "XSS - HttpResponse直接输出用户输入",
        "severity": "高危",
        "pattern": r'HttpResponse\s*\(.*?(?:request\.(?:GET|POST)|request\.data)',
        "category": "XSS"
    },

    # ========== SSRF ==========
    {
        "id": "SSRF-01",
        "name": "SSRF - requests.get用户URL",
        "severity": "高危",
        "pattern": r'requests\.(?:get|post|put|delete|head|patch|request)\s*\(.*?(?:request\.(?:args|form|json|data|GET|POST)|user_input|input\s*\()',
        "category": "SSRF"
    },
    {
        "id": "SSRF-02",
        "name": "SSRF - urllib.request.urlopen用户URL",
        "severity": "高危",
        "pattern": r'urllib\.request\.urlopen\s*\(',
        "category": "SSRF"
    },
    {
        "id": "SSRF-03",
        "name": "SSRF - httpx用户URL",
        "severity": "高危",
        "pattern": r'httpx\.(?:get|post|put|delete|Client)\s*\(.*?request\.',
        "category": "SSRF"
    },
    {
        "id": "SSRF-04",
        "name": "SSRF - aiohttp用户URL",
        "severity": "高危",
        "pattern": r'(?:aiohttp\.ClientSession|ClientSession\(\)).*?\.(?:get|post|fetch)\s*\(.*?request\.',
        "category": "SSRF"
    },
    {
        "id": "SSRF-05",
        "name": "SSRF - urllib3用户URL",
        "severity": "高危",
        "pattern": r'urllib3\.(?:PoolManager|ProxyManager).*?\.(?:request|urlopen)\s*\(',
        "category": "SSRF"
    },

    # ========== 反序列化 ==========
    {
        "id": "DESER-01",
        "name": "反序列化 - pickle.loads",
        "severity": "严重",
        "pattern": r'pickle\.(?:loads?|Unpickler\s*\()',
        "category": "反序列化"
    },
    {
        "id": "DESER-02",
        "name": "反序列化 - cPickle",
        "severity": "严重",
        "pattern": r'cPickle\.(?:loads?|Unpickler\s*\()',
        "category": "反序列化"
    },
    {
        "id": "DESER-03",
        "name": "反序列化 - yaml.load不安全的Loader",
        "severity": "高危",
        "pattern": r'yaml\.load\s*\(\s*(?!.*Loader\s*=\s*(?:yaml\.)?(?:Safe|CSafe|Full)Loader)',
        "category": "反序列化"
    },
    {
        "id": "DESER-04",
        "name": "反序列化 - dill.loads",
        "severity": "严重",
        "pattern": r'dill\.(?:loads?|Unpickler)\s*\(',
        "category": "反序列化"
    },
    {
        "id": "DESER-05",
        "name": "反序列化 - shelve.open",
        "severity": "高危",
        "pattern": r'shelve\.open\s*\(',
        "category": "反序列化"
    },
    {
        "id": "DESER-06",
        "name": "反序列化 - marshal.loads",
        "severity": "中危",
        "pattern": r'marshal\.loads\s*\(',
        "category": "反序列化"
    },

    # ========== 路径穿越 ==========
    {
        "id": "PATH-01",
        "name": "路径穿越 - open用户输入路径",
        "severity": "高危",
        "pattern": r'(?:open|io\.open)\s*\([^)]*request\.(?:args|form|json|GET|POST)',
        "category": "路径穿越"
    },
    {
        "id": "PATH-02",
        "name": "路径穿越 - os.path操作",
        "severity": "中危",
        "pattern": r'os\.path\.(?:join|dirname|abspath)\s*\([^)]*request\.',
        "category": "路径穿越"
    },

    # ========== XXE ==========
    {
        "id": "XXE-01",
        "name": "XXE - lxml.etree.parse",
        "severity": "高危",
        "pattern": r'(?:lxml\.etree|etree)\.(?:parse|fromstring|XML)\s*\(',
        "category": "XXE"
    },
    {
        "id": "XXE-02",
        "name": "XXE - xml.etree.ElementTree",
        "severity": "高危",
        "pattern": r'(?:xml\.etree\.ElementTree|ElementTree)\.(?:parse|fromstring)\s*\(',
        "category": "XXE"
    },
    {
        "id": "XXE-03",
        "name": "XXE - xml.dom.minidom",
        "severity": "中危",
        "pattern": r'(?:xml\.dom\.minidom|minidom)\.parse\s*\(',
        "category": "XXE"
    },

    # ========== 文件上传 ==========
    {
        "id": "UPLOAD-01",
        "name": "文件上传 - shutil/os写入上传文件",
        "severity": "高危",
        "pattern": r'(?:shutil\.(?:copy|move|copyfileobj)|os\.rename)\s*\(.*request\.files',
        "category": "文件上传"
    },
    {
        "id": "UPLOAD-02",
        "name": "文件上传 - Django file.save未校验",
        "severity": "中危",
        "pattern": r'(?:request\.FILES|uploaded_file)\.save\s*\(',
        "category": "文件上传"
    },

    # ========== 密码安全 ==========
    {
        "id": "CRYPTO-01",
        "name": "弱哈希 - hashlib.md5/sha1密码",
        "severity": "高危",
        "pattern": r'hashlib\.(?:md5|sha1)\s*\([^)]*password',
        "category": "密码安全",
        "ignore_case": True
    },
    {
        "id": "CRYPTO-02",
        "name": "弱随机数 - random模块生成令牌",
        "severity": "中危",
        "pattern": r'(?:token|nonce|csrf|session|secret|key|otp)\s*=\s*.*random\.(?:random|randint|choice|choices)\s*\(',
        "category": "密码安全",
        "ignore_case": True
    },
    {
        "id": "CRYPTO-03",
        "name": "硬编码密码/密钥",
        "severity": "高危",
        "pattern": r'(?:password|passwd|pwd|secret|token|api_key|private_key|access_key)\s*=\s*[\'\"][^\'\"]+[\'\"]',
        "category": "密码安全",
        "ignore_case": True
    },

    # ========== 信息泄露 ==========
    {
        "id": "INFO-01",
        "name": "信息泄露 - Django DEBUG=True",
        "severity": "高危",
        "pattern": r'DEBUG\s*=\s*True',
        "category": "信息泄露"
    },
    {
        "id": "INFO-02",
        "name": "信息泄露 - Flask debug模式",
        "severity": "高危",
        "pattern": r'app\.run\s*\([^)]*debug\s*=\s*True',
        "category": "信息泄露"
    },
    {
        "id": "INFO-03",
        "name": "信息泄露 - print输出敏感信息",
        "severity": "低危",
        "pattern": r'print\s*\(.*?(?:password|secret|token|key|credential)',
        "category": "信息泄露",
        "ignore_case": True
    },
    {
        "id": "INFO-04",
        "name": "信息泄露 - logging敏感信息",
        "severity": "中危",
        "pattern": r'logging\.(?:debug|info|warning|error|critical)\s*\(.*?(?:password|secret|token|apikey)',
        "category": "信息泄露",
        "ignore_case": True
    },
    {
        "id": "INFO-05",
        "name": "信息泄露 - Flask SECRET_KEY硬编码",
        "severity": "中危",
        "pattern": r'app\.(?:secret_key|config\[\"SECRET_KEY\"\])\s*=\s*[\'\"]',
        "category": "信息泄露"
    },

    # ========== 依赖安全 ==========
    {
        "id": "DEP-01",
        "name": "依赖安全 - requirements.txt含有已知漏洞版本",
        "severity": "中危",
        "pattern": r'(?:django|flask|jinja2|pillow|requests|pyyaml|numpy|tensorflow|torch)\s*==\s*\d+\.\d+\.\d+',
        "category": "依赖安全",
        "ignore_case": True
    },
]


PYTHON_EXTENSIONS = {'.py', '.pyw', '.pyx', '.cfg', '.ini', '.txt', '.yaml', '.yml', '.toml'}

EXCLUDE_DIRS = {
    '__pycache__', '.git', '.svn', '.tox', '.eggs', '.mypy_cache',
    '.pytest_cache', '.venv', 'venv', 'env', '.env', 'virtualenv',
    'node_modules', 'dist', 'build', 'egg-info', '.egg-info',
    'site-packages', 'Lib', 'tests', 'test', 'migrations'
}


def scan_file(filepath: str, verbose: bool = False) -> list:
    findings = []
    ext = Path(filepath).suffix.lower()
    if ext not in PYTHON_EXTENSIONS:
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

    for ext in PYTHON_EXTENSIONS:
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
    print(f"扫描Python文件: {result['files_scanned']} 个")
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
        description='Python代码审计辅助扫描脚本',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python python_audit_scanner.py /path/to/python/project
  python python_audit_scanner.py . -o report.json
  python python_audit_scanner.py . --verbose
        """
    )
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
