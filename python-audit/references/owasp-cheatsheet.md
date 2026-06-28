# OWASP Top 10 (2021) Python审计备忘单

## A01:2021 – 权限控制失效 (Broken Access Control)

### Django常见模式
```python
# 危险：未校验资源归属
def get_user(request, user_id):
    user = User.objects.get(id=user_id)  # 未校验是否属于当前用户
    return JsonResponse({"user": user.username})

# 安全做法
@login_required
def get_user(request, user_id):
    user = get_object_or_404(User, id=user_id, id=request.user.id)
    return JsonResponse({"user": user.username})
```

### Flask常见模式
```python
# 危险：未校验资源归属
@app.route('/user/<int:user_id>')
def get_user(user_id):
    user = User.query.get(user_id)  # 未校验
    return jsonify(user.to_dict())

# 安全做法
@app.route('/user/<int:user_id>')
@login_required
def get_user(user_id):
    user = User.query.filter_by(id=user_id, owner_id=current_user.id).first_or_404()
    return jsonify(user.to_dict())
```

### 检测清单
- [ ] View/Handler是否校验当前用户身份与资源归属关系？
- [ ] 是否存在IDOR模式？
- [ ] Django的 `@login_required` / `@permission_required` 是否遗漏？
- [ ] DRF的 `IsAuthenticated` / `IsOwner` 权限类是否遗漏？
- [ ] Flask-Login的 `@login_required` 是否遗漏？

---

## A02:2021 – 加密机制失效 (Cryptographic Failures)

### Python常见模式
```python
# 危险：使用弱哈希
import hashlib
hash = hashlib.md5(password.encode()).hexdigest()

# 危险：伪随机数
import random
token = random.randint(100000, 999999)

# 安全做法
import bcrypt
hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# 安全随机数
import secrets
token = secrets.token_urlsafe(32)
```

### 检测清单
- [ ] 密码使用 `bcrypt`/`argon2`/`scrypt` 而非 `md5`/`sha1`？
- [ ] Token使用 `secrets` 而非 `random`？
- [ ] 重要ID是否使用 `secrets.token_hex()`？
- [ ] HTTPS是否强制启用？
- [ ] Django `SECRET_KEY` / Flask `secret_key` 是否强随机？

---

## A03:2021 – 注入 (Injection)

### SQL注入防护 (Python)
```python
# ✅ Django ORM（安全）
User.objects.filter(username=username)

# ✅ SQLAlchemy（安全）
session.query(User).filter(User.name == name)

# ✅ 参数化查询（安全）
cursor.execute("SELECT * FROM users WHERE id = %s", (id,))

# ❌ f-string拼接（危险）
cursor.execute(f"SELECT * FROM users WHERE id = {id}")

# ❌ format拼接（危险）
cursor.execute("SELECT * FROM users WHERE id = {}".format(id))

# ❌ %格式化拼接（危险）
cursor.execute("SELECT * FROM users WHERE id = %s" % id)

# ❌ Django raw拼接（危险）
User.objects.raw("SELECT * FROM users WHERE id = " + id)

# ❌ Django extra拼接（危险）
User.objects.extra(where=["id = " + id])
```

### ORDER BY注入
```python
# 必须使用白名单
ALLOWED_COLUMNS = {'id', 'name', 'email', 'created_at'}

def get_users(order_by):
    if order_by not in ALLOWED_COLUMNS:
        order_by = 'id'
    # 注意：ORDER BY仍需拼接，但已白名单校验
    return User.objects.order_by(order_by)
```

---

## A04:2021 – 不安全的设计

### 检测清单
- [ ] 密码重置流程：Token是否在URL中？是否有时效性？
- [ ] 支付流程：金额是否在服务端校验？
- [ ] 多步骤操作：是否存在步骤跳过风险？
- [ ] 速率限制：Django Axes / Flask-Limiter 是否配置？

---

## A05:2021 – 安全配置错误

### Django 安全配置
```python
# settings.py 安全配置
DEBUG = False
ALLOWED_HOSTS = ['example.com']
SECRET_KEY = os.environ.get('SECRET_KEY')  # 从环境变量读取

# Cookie安全
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True

# HTTPS强制
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# 安全头
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = 'DENY'

# 密码验证
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator', 'OPTIONS': {'min_length': 12}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]
```

### Flask 安全配置
```python
from flask import Flask
from flask_talisman import Talisman

app = Flask(__name__)
app.config['DEBUG'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

# 安全HTTP头
Talisman(app, force_https=True, strict_transport_security=True, content_security_policy={
    'default-src': "'self'"
})
```

---

## A06:2021 – 易受攻击和过时的组件

### Python版本安全
| Python版本 | 状态 | 建议 |
|-----------|------|------|
| Python 2.7 | 已停止维护 | 立即升级 |
| Python 3.6 | 已停止维护 | 升级 |
| Python 3.7 | 已停止维护 | 升级 |
| Python 3.8 | 已停止维护 | 升级 |
| Python 3.9 | 维护中 | 可用 |
| Python 3.10 | 维护中 | 可用 |
| Python 3.11 | 维护中 | 推荐 |
| Python 3.12 | 维护中 | 推荐 |

### 依赖漏洞扫描
```bash
# pip-audit
pip install pip-audit
pip-audit

# Safety
pip install safety
safety check

# Bandit静态分析
pip install bandit
bandit -r .

# Semgrep
pip install semgrep
semgrep --config=auto .
```

---

## A07:2021 – 身份认证和会话管理失效

### Django会话安全
```python
# settings.py
SESSION_ENGINE = 'django.contrib.sessions.backends.db'
SESSION_COOKIE_AGE = 3600  # 1小时
SESSION_SAVE_EVERY_REQUEST = True
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

# 登录视图
from django.contrib.auth import authenticate, login
from django_ratelimit.decorators import ratelimit

@ratelimit(key='ip', rate='5/m', method='POST')
def user_login(request):
    username = request.POST.get('username')
    password = request.POST.get('password')
    user = authenticate(request, username=username, password=password)
    if user is not None:
        login(request, user)
        return redirect('home')
    return render(request, 'login.html', {'error': 'Invalid credentials'})
```

### JWT安全 (PyJWT)
```python
import jwt
from datetime import datetime, timedelta

# 危险：弱密钥
SECRET_KEY = "123456"

# 安全做法
SECRET_KEY = secrets.token_urlsafe(64)

# 签发Token
token = jwt.encode(
    {"user_id": user.id, "exp": datetime.utcnow() + timedelta(hours=1)},
    SECRET_KEY,
    algorithm="HS512"
)

# 验证Token（强制校验算法）
try:
    payload = jwt.decode(token, SECRET_KEY, algorithms=["HS512"])
except jwt.ExpiredSignatureError:
    # Token过期
    pass
except jwt.InvalidTokenError:
    # Token无效
    pass
```

---

## A08:2021 – 软件和数据完整性失效

### Python反序列化防护
```python
# ❌ 危险：pickle处理用户输入
import pickle
data = pickle.loads(request.body)

# ❌ 危险：yaml.load默认Loader
import yaml
data = yaml.load(request.body)

# ✅ 安全替代：使用json
import json
data = json.loads(request.body)

# ✅ 必须反序列化时：yaml.safe_load
data = yaml.safe_load(request.body)

# ✅ 必须pickle时：签名验证
import hmac
import hashlib

expected = hmac.new(SECRET_KEY, request.body, hashlib.sha256).hexdigest()
if not hmac.compare_digest(expected, request.headers.get('X-Signature')):
    raise ValueError("Invalid signature")
data = pickle.loads(request.body)
```

---

## A09:2021 – 日志记录和监控不足

### 安全日志 (Python)
```python
import logging

logger = logging.getLogger('security')

# 认证事件
logger.warning("Login failed", extra={"user": username, "ip": request.META.get('REMOTE_ADDR')})

# 权限变更
logger.warning("Role changed", extra={"user_id": user_id, "from": old_role, "to": new_role})

# 敏感操作
logger.info("Payment processed", extra={"user_id": user_id, "amount": amount, "order": order_id})

# ❌ 危险：记录密码
logger.info("Login attempt", extra={"password": password})  # 绝对禁止！
```

### Django日志脱敏
```python
# settings.py
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'filters': {
        'mask_sensitive': {
            '()': 'myapp.log.MaskSensitiveFilter',
        },
    },
    'handlers': {
        'security_file': {
            'level': 'WARNING',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': '/var/log/django/security.log',
            'filters': ['mask_sensitive'],
        },
    },
}
```
