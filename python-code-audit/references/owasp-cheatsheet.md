# Python OWASP 安全编码速查表

## OWASP Top 10 (2021) Python 对照

| OWASP 排名 | 漏洞 | Python 常见场景 |
|-----------|------|-------------|
| A01 | 访问控制失效 | Flask 路由缺少 `@login_required`、Django CBV 未设置 `permission_classes` |
| A02 | 加密失效 | `hashlib.md5(password)`、`random.random()` 生成令牌 |
| A03 | 注入 | f-string SQL、`os.system(userInput)`、`eval(userInput)` |
| A04 | 不安全设计 | API 无限频调用、无密码复杂度校验 |
| A05 | 安全配置错误 | Django `DEBUG=True`、Flask `debug=True`、SECRET_KEY 硬编码 |
| A06 | 脆弱和过时组件 | Django <= 3.2 未升级、Pillow 旧版本 |
| A07 | 身份识别和认证失败 | Flask session 未加密、JWT `algorithm=none` |
| A08 | 软件和数据完整性 | `pickle.loads()` 不可信数据、pip 包篡改 |
| A09 | 安全日志和监控失败 | `print()` 敏感信息、logging 未脱敏 |
| A10 | SSRF | `requests.get(userUrl)` 无校验白名单 |

## 注入速查

```python
# 危险 - SQL f-string 拼接
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# 危险 - SQL % 格式化
cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)

# 安全 - 参数化查询
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# Django 安全写法
User.objects.filter(id=user_id)  # ORM 自动参数化
User.objects.raw("SELECT * FROM users WHERE id = %s", [user_id])  # raw 也要参数化

# 危险 - 命令执行
os.system(f"ping {host}")
subprocess.call(f"ping {host}", shell=True)

# 安全 - 列表参数 + shell=False
subprocess.call(["ping", "-c", "1", host])
```

## 代码执行 / SSTI 速查

```python
# 危险 - eval/exec
eval(request.args.get('expr'))
exec(request.args.get('code'))
__import__(request.args.get('module'))

# 危险 - SSTI Jinja2
render_template_string(request.args.get('template'))

# 安全 - 使用静态模板
render_template('user_page.html', name=name)
# 或对 render_template_string 使用沙箱环境
```

## 反序列化速查

```python
# 危险 - pickle
pickle.loads(request.data)
pickle.load(open(request.files['file']))

# 危险 - PyYAML 不安全
yaml.load(user_input)  # 默认 Loader 不安全

# 安全 - PyYAML SafeLoader
yaml.load(user_input, Loader=yaml.SafeLoader)

# 危险 - dill / shelve / marshal
dill.loads(user_data)
shelve.open(user_path)
marshal.loads(user_data)

# 安全替代 - JSON
data = json.loads(user_input)
```

## SSRF 速查

```python
# 危险 - 用户 URL 直接请求
requests.get(request.args.get('url'))
urllib.request.urlopen(request.args.get('url'))

# 安全 - 白名单校验
from urllib.parse import urlparse

url = request.args.get('url')
parsed = urlparse(url)
if parsed.hostname not in ['api.trusted.com']:
    raise ValueError("URL not allowed")
# 辅以私有 IP 检测
import ipaddress
ip = socket.gethostbyname(parsed.hostname)
if ipaddress.ip_address(ip).is_private:
    raise ValueError("Private IP not allowed")
```

## 密码处理

```python
# 危险
import hashlib
hashlib.md5(password.encode()).hexdigest()
hashlib.sha1(password.encode()).hexdigest()

# 安全 - bcrypt
import bcrypt
hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# 安全 - Django
from django.contrib.auth.hashers import make_password
hash = make_password(password)

# 危险 - 弱随机令牌
import random
token = ''.join(random.choices(string.ascii_letters, k=32))

# 安全 - secrets 模块
import secrets
token = secrets.token_hex(32)
```

## 路径穿越速查

```python
# 危险
open(request.args.get('file')).read()
open(os.path.join('/var/www', request.args.get('file'))).read()

# 安全
import os
base = '/var/www/uploads/'
filename = request.args.get('file')
filepath = os.path.normpath(os.path.join(base, filename))
if not filepath.startswith(base):
    raise ValueError("Path traversal detected")
open(filepath).read()
```

## 参考资源

- [OWASP Python Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Python_Security_Cheat_Sheet.html)
- [Bandit SAST](https://bandit.readthedocs.io/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [Django Security](https://docs.djangoproject.com/en/stable/topics/security/)
