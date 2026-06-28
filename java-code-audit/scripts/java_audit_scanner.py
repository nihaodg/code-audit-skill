#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Java代码审计辅助扫描脚本
在大型Java项目中先跑此脚本快速定位危险函数/模式，再人工审计。

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


RULES = [
    # ========== SQL注入 ==========
    {
        "id": "SQLI-01",
        "name": "SQL注入 - Statement字符串拼接",
        "severity": "严重",
        "pattern": r'(?:Statement|PreparedStatement)\s+\w+\s*=\s*.*?(?:\"\\s*\+\s*|String\.format|StringBuilder|StringBuffer|\+)',
        "category": "SQL注入"
    },
    {
        "id": "SQLI-02",
        "name": "SQL注入 - JDBC原生查询拼接",
        "severity": "高危",
        "pattern": r'(?:executeQuery|executeUpdate|execute)\s*\(\s*\"[^\"]*\"\s*\+',
        "category": "SQL注入"
    },
    {
        "id": "SQLI-03",
        "name": "SQL注入 - MyBatis ${} 不安全占位",
        "severity": "高危",
        "pattern": r'\$\{[^}]*\}',
        "category": "SQL注入"
    },
    {
        "id": "SQLI-04",
        "name": "SQL注入 - JPA原生查询拼接",
        "severity": "高危",
        "pattern": r'(?:createNativeQuery|createQuery)\s*\(\s*\"[^\"]*\"\s*\+',
        "category": "SQL注入"
    },
    {
        "id": "SQLI-05",
        "name": "SQL注入 - String.format SQL构造",
        "severity": "高危",
        "pattern": r'String\.format\s*\(\s*\"\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)',
        "category": "SQL注入",
        "ignore_case": True
    },
    {
        "id": "SQLI-06",
        "name": "SQL注入 - JdbcTemplate拼接",
        "severity": "高危",
        "pattern": r'(?:jdbcTemplate|namedParameterJdbcTemplate)\.(?:query|update|execute)\s*\(\s*\"[^\"]*\"\s*\+',
        "category": "SQL注入"
    },

    # ========== 命令执行 ==========
    {
        "id": "RCE-01",
        "name": "命令执行 - Runtime.exec",
        "severity": "严重",
        "pattern": r'Runtime\.getRuntime\(\)\.exec\s*\(',
        "category": "命令执行"
    },
    {
        "id": "RCE-02",
        "name": "命令执行 - ProcessBuilder",
        "severity": "严重",
        "pattern": r'new\s+ProcessBuilder\s*\(',
        "category": "命令执行"
    },
    {
        "id": "RCE-03",
        "name": "命令执行 - ProcessImpl",
        "severity": "严重",
        "pattern": r'ProcessImpl\.(?:start|exec)\s*\(',
        "category": "命令执行"
    },

    # ========== 代码执行 ==========
    {
        "id": "CE-01",
        "name": "代码执行 - ScriptEngine.eval",
        "severity": "严重",
        "pattern": r'(?:ScriptEngine|Invocable).*?\.eval\s*\(',
        "category": "代码执行"
    },
    {
        "id": "CE-02",
        "name": "代码执行 - OGNL表达式",
        "severity": "严重",
        "pattern": r'Ognl\.(?:getValue|setValue|parseExpression)\s*\(',
        "category": "代码执行"
    },
    {
        "id": "CE-03",
        "name": "代码执行 - SpEL表达式",
        "severity": "严重",
        "pattern": r'(?:SpelExpressionParser|ExpressionParser).*?\.parse(?:Expression|Raw)\s*\(',
        "category": "代码执行"
    },
    {
        "id": "CE-04",
        "name": "代码执行 - MVEL表达式",
        "severity": "高危",
        "pattern": r'MVEL\.(?:eval|executeExpression|compileExpression)\s*\(',
        "category": "代码执行"
    },
    {
        "id": "CE-05",
        "name": "代码执行 - EL表达式",
        "severity": "高危",
        "pattern": r'(?:ExpressionFactory|ELProcessor).*?\.(?:createValueExpression|eval)\s*\(',
        "category": "代码执行"
    },

    # ========== XSS ==========
    {
        "id": "XSS-01",
        "name": "XSS - response.getWriter输出用户参数",
        "severity": "高危",
        "pattern": r'(?:response|HttpServletResponse).*?\.getWriter\(\).*?\.(?:print|write|println)\s*\(.*?(?:request\.getParameter|getQueryString)',
        "category": "XSS"
    },
    {
        "id": "XSS-02",
        "name": "XSS - 未转义直接输出到页面",
        "severity": "高危",
        "pattern": r'(?:ModelAndView|ModelMap|Model)\..*?(?:addObject|put|addAttribute)\s*\([^,]*,\s*(?:request\.getParameter|getQueryString)',
        "category": "XSS"
    },
    {
        "id": "XSS-03",
        "name": "XSS - JSP EL输出未转义",
        "severity": "中危",
        "pattern": r'\$\{(?!fn:escapeXml)[^}]*\}',
        "category": "XSS"
    },

    # ========== 路径穿越 ==========
    {
        "id": "PATH-01",
        "name": "路径穿越 - FileInputStream用户输入",
        "severity": "高危",
        "pattern": r'new\s+FileInputStream\s*\([^)]*request\.getParameter',
        "category": "路径穿越"
    },
    {
        "id": "PATH-02",
        "name": "路径穿越 - Files.read用户输入",
        "severity": "高危",
        "pattern": r'Files\.(?:read|newInputStream|newBufferedReader|lines|list)\s*\([^)]*request\.getParameter',
        "category": "路径穿越"
    },
    {
        "id": "PATH-03",
        "name": "路径穿越 - File用户输入",
        "severity": "中危",
        "pattern": r'new\s+File\s*\([^)]*request\.getParameter',
        "category": "路径穿越"
    },

    # ========== SSRF ==========
    {
        "id": "SSRF-01",
        "name": "SSRF - URLConnection打开用户URL",
        "severity": "高危",
        "pattern": r'new\s+URL\s*\([^)]*request\.getParameter',
        "category": "SSRF"
    },
    {
        "id": "SSRF-02",
        "name": "SSRF - HttpURLConnection用户URL",
        "severity": "高危",
        "pattern": r'(?:HttpURLConnection|HttpsURLConnection).*?new\s+URL\s*\([^)]*request\.getParameter',
        "category": "SSRF"
    },
    {
        "id": "SSRF-03",
        "name": "SSRF - RestTemplate用户URL",
        "severity": "高危",
        "pattern": r'restTemplate\.(?:getForObject|postForObject|exchange|execute)\s*\([^)]*request\.getParameter',
        "category": "SSRF"
    },
    {
        "id": "SSRF-04",
        "name": "SSRF - HttpClient用户URL",
        "severity": "高危",
        "pattern": r'(?:HttpClient|CloseableHttpClient).*?\.execute\s*\([^)]*request\.getParameter',
        "category": "SSRF"
    },
    {
        "id": "SSRF-05",
        "name": "SSRF - WebClient用户URL",
        "severity": "高危",
        "pattern": r'WebClient\.(?:create|builder)\s*\(\s*\".*\"\s*\+',
        "category": "SSRF"
    },
    {
        "id": "SSRF-06",
        "name": "SSRF - OkHttp用户URL",
        "severity": "高危",
        "pattern": r'new\s+Request\.Builder\(\)\.url\s*\([^)]*request\.getParameter',
        "category": "SSRF"
    },

    # ========== 反序列化 ==========
    {
        "id": "DESER-01",
        "name": "反序列化 - ObjectInputStream.readObject",
        "severity": "严重",
        "pattern": r'(?:new\s+ObjectInputStream|ObjectInputStream).*?\.readObject\s*\(',
        "category": "反序列化"
    },
    {
        "id": "DESER-02",
        "name": "反序列化 - XMLDecoder",
        "severity": "严重",
        "pattern": r'new\s+XMLDecoder\s*\(',
        "category": "反序列化"
    },
    {
        "id": "DESER-03",
        "name": "反序列化 - Hessian/Burlap",
        "severity": "高危",
        "pattern": r'(?:HessianInput|Hessian2Input|BurlapInput)\s*\(',
        "category": "反序列化"
    },
    {
        "id": "DESER-04",
        "name": "反序列化 - Fastjson无Type",
        "severity": "高危",
        "pattern": r'JSON\.(?:parse|parseObject)\s*\([^,)]*\)',
        "category": "反序列化"
    },
    {
        "id": "DESER-05",
        "name": "反序列化 - Jackson enableDefaultTyping",
        "severity": "高危",
        "pattern": r'(?:enableDefaultTyping|ObjectMapper\.DefaultTyping|@JsonTypeInfo)',
        "category": "反序列化"
    },

    # ========== XXE ==========
    {
        "id": "XXE-01",
        "name": "XXE - DocumentBuilder无安全配置",
        "severity": "高危",
        "pattern": r'DocumentBuilderFactory\.newInstance\(\)',
        "category": "XXE"
    },
    {
        "id": "XXE-02",
        "name": "XXE - SAXParser无安全配置",
        "severity": "高危",
        "pattern": r'SAXParserFactory\.newInstance\(\)',
        "category": "XXE"
    },
    {
        "id": "XXE-03",
        "name": "XXE - XMLReader无安全配置",
        "severity": "高危",
        "pattern": r'XMLReaderFactory\.createXMLReader\s*\(',
        "category": "XXE"
    },
    {
        "id": "XXE-04",
        "name": "XXE - TransformerFactory无安全配置",
        "severity": "中危",
        "pattern": r'TransformerFactory\.newInstance\(\)',
        "category": "XXE"
    },

    # ========== 文件上传 ==========
    {
        "id": "UPLOAD-01",
        "name": "文件上传 - MultipartFile未校验扩展名",
        "severity": "高危",
        "pattern": r'(?:MultipartFile|CommonsMultipartFile).*?\.(?:transferTo|getInputStream)\s*\(',
        "category": "文件上传"
    },
    {
        "id": "UPLOAD-02",
        "name": "文件上传 - 直接写入上传文件",
        "severity": "中危",
        "pattern": r'(?:FileOutputStream|Files\.copy|Files\.write).*?\.(?:getBytes|getInputStream)',
        "category": "文件上传"
    },

    # ========== 密码安全 ==========
    {
        "id": "CRYPTO-01",
        "name": "弱哈希 - MD5/SHA1密码",
        "severity": "高危",
        "pattern": r'MessageDigest\.getInstance\s*\(\s*\"(?:MD5|SHA-?1)\"',
        "category": "密码安全"
    },
    {
        "id": "CRYPTO-02",
        "name": "弱随机数 - Random生成令牌",
        "severity": "中危",
        "pattern": r'(?:token|nonce|csrf|session|secret|key).*=\s*.*new\s+Random\s*\(',
        "category": "密码安全",
        "ignore_case": True
    },
    {
        "id": "CRYPTO-03",
        "name": "硬编码密码/密钥",
        "severity": "高危",
        "pattern": r'(?:private|public|static|final)?\s*(?:String|string)\s+(?:password|passwd|pwd|secret|token|key|apikey|api_key|private_key)\s*=\s*\"[^\"]+\"',
        "category": "密码安全",
        "ignore_case": True
    },
    {
        "id": "CRYPTO-04",
        "name": "弱加密 - DES/3DES/RC4",
        "severity": "高危",
        "pattern": r'Cipher\.getInstance\s*\(\s*\"(?:DES|3DES|RC4|Blowfish)',
        "category": "密码安全"
    },

    # ========== 信息泄露 ==========
    {
        "id": "INFO-01",
        "name": "信息泄露 - printStackTrace输出",
        "severity": "低危",
        "pattern": r'\.printStackTrace\s*\(',
        "category": "信息泄露"
    },
    {
        "id": "INFO-02",
        "name": "信息泄露 - e.printStackTrace到响应",
        "severity": "中危",
        "pattern": r'e\.printStackTrace\s*\(\s*.+\.get(?:Writer|OutputStream)\s*\(',
        "category": "信息泄露"
    },
    {
        "id": "INFO-03",
        "name": "信息泄露 - 日志输出敏感信息",
        "severity": "中危",
        "pattern": r'(?:log|logger|LOGGER|LOG)\.(?:info|debug|warn|error)\s*\([^)]*(?:password|token|secret|apikey|credential)',
        "category": "信息泄露",
        "ignore_case": True
    },

    # ========== 配置安全 ==========
    {
        "id": "CONFIG-01",
        "name": "Spring Boot Actuator全部暴露",
        "severity": "高危",
        "pattern": r'management\.endpoints\.web\.exposure\.include\s*[=:]\s*\*',
        "category": "配置安全"
    },
    {
        "id": "CONFIG-02",
        "name": "Spring Security CSRF禁用",
        "severity": "高危",
        "pattern": r'\.csrf\(\)\.disable\(\)',
        "category": "配置安全"
    },
    {
        "id": "CONFIG-03",
        "name": "CORS允许所有来源",
        "severity": "中危",
        "pattern": r'(?:allowedOrigins|setAllowedOrigins)\s*\(\s*\"\*\"',
        "category": "配置安全"
    },
    {
        "id": "CONFIG-04",
        "name": "不安全的HTTP方法",
        "severity": "中危",
        "pattern": r'@RequestMapping\s*\(\s*method\s*=\s*RequestMethod\.(?:GET|POST)\s*\)',
        "category": "配置安全"
    },

    # ========== 权限绕过 ==========
    {
        "id": "AUTH-01",
        "name": "权限绕过 - 缺少@PreAuthorize注解",
        "severity": "中危",
        "pattern": r'@(?:GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping)\s*\(',
        "category": "权限控制"
    },
    {
        "id": "AUTH-02",
        "name": "权限绕过 - permitAll全部放行",
        "severity": "中危",
        "pattern": r'\.permitAll\s*\(\s*\)\s*\.',
        "category": "权限控制"
    },
]


JAVA_EXTENSIONS = {'.java', '.jsp', '.jspx', '.properties', '.xml', '.yml', '.yaml', '.gradle'}

EXCLUDE_DIRS = {
    'target', 'build', '.gradle', '.idea', '.settings', 'bin', 'out',
    'node_modules', '.git', '.svn', 'test', 'tests',
    'dist', 'resources/static', 'webapp/static'
}


def scan_file(filepath: str, verbose: bool = False) -> list:
    findings = []
    ext = Path(filepath).suffix.lower()
    if ext not in JAVA_EXTENSIONS:
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

    for ext in JAVA_EXTENSIONS:
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
    print(f"扫描Java文件: {result['files_scanned']} 个")
    print(f"发现潜在风险: {result['total_findings']} 处")
    print(f"{'='*60}")

    print("\n按严重程度统计:")
    severity_order = ["严重", "高危", "中危", "低危"]
    for sev in severity_order:
        count = result["summary"]["severity"].get(sev, 0)
        icon = {"严重": "严重", "高危": "高危", "中危": "中危", "低危": "低危"}.get(sev, "未知")
        bar = "#" * min(count, 20)
        print(f"  {icon}: {count}处 {bar}")

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
        description='Java代码审计辅助扫描脚本',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python java_audit_scanner.py /path/to/java/project
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
