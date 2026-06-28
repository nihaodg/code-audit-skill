# Python 危险函数（Sink）速查表

## SQL注入相关

| 函数/方法 | 风险等级 | 说明 |
|-----------|---------|------|
| `cursor.execute(query % param)` | 严重 | %格式化拼接 |
| `cursor.execute(query.format(param))` | 严重 | format拼接 |
| `cursor.execute(f"...{param}")` | 严重 | f-string拼接 |
| `cursor.execute("..." + param)` | 严重 | 字符串拼接 |
| `cursor.executemany(query, params)` | 高危 | 参数化是安全的 |
| `session.execute(text("..." + param))` (SQLAlchemy) | 严重 | text拼接 |
| `Model.objects.raw("..." + param)` (Django) | 严重 | raw拼接 |
| `Model.objects.extra(where=[...])` (Django) | 严重 | extra拼接 |
| `RawSQL("..." + param)` (Django) | 严重 | RawSQL拼接 |
| `connection.cursor().execute(query, params)` | 低危 | 参数化安全 ✅ |
| `Model.objects.filter(name=param)` (Django) | 低危 | ORM安全 ✅ |
| `session.query(Model).filter(Model.name == param)` | 低危 | SQLAlchemy安全 ✅ |

## 命令/代码执行

| 函数/方法 | 风险等级 | 说明 |
|-----------|---------|------|
| `os.system()` | 严重 | 执行系统命令 |
| `os.popen()` | 严重 | 执行系统命令 |
| `os.spawn*()` | 严重 | 执行系统命令 |
| `subprocess.call(cmd, shell=True)` | 严重 | shell=True危险 |
| `subprocess.run(cmd, shell=True)` | 严重 | 同上 |
| `subprocess.Popen(cmd, shell=True)` | 严重 | 同上 |
| `subprocess.check_output(cmd, shell=True)` | 严重 | 同上 |
| `subprocess.call([cmd, arg])` | 中危 | 列表传参较安全 |
| `eval()` | 严重 | 执行任意Python代码 |
| `exec()` | 严重 | 同上 |
| `compile()` + `exec()` | 严重 | 动态编译执行 |
| `__import__()` | 高危 | 动态导入 |
| `importlib.import_module()` | 中危 | 动态导入 |
| `pickle.loads()` | 严重 | 反序列化执行 |
| `marshal.loads()` | 严重 | 反序列化 |
| `shelve.open()` | 高危 | 基于pickle的存储 |

## 模板注入 (SSTI)

| 函数/方法 | 风险等级 | 说明 |
|-----------|---------|------|
| `render_template_string()` (Flask) | 严重 | 字符串模板渲染 |
| `Template(string).render()` (Jinja2) | 严重 | Jinja2模板执行 |
| `Environment.from_string(string).render()` | 严重 | 同上 |
| `render_to_string()` (Django) 拼接用户输入 | 严重 | Django模板 |
| `Template(user_input).render(Context())` | 严重 | Django模板 |
| `MakoTemplate(user_input).render()` | 严重 | Mako模板 |
| `render_template()` (Flask) | 低危 | 文件模板较安全 |
| `render()` (Django) | 低危 | 文件模板较安全 |

## 反序列化

| 函数/方法 | 风险等级 | 说明 |
|-----------|---------|------|
| `pickle.loads()` | 严重 | 任意代码执行 |
| `pickle.load()` | 严重 | 同上 |
| `cPickle.loads()` | 严重 | 同上（Python 2） |
| `yaml.load()` (PyYAML < 5.1) | 严重 | 默认Loader不安全 |
| `yaml.load(stream, Loader=yaml.Loader)` | 严重 | 不安全Loader |
| `yaml.unsafe_load()` | 严重 | 显式不安全 |
| `yaml.safe_load()` | 低危 | 安全 ✅ |
| `json.loads()` | 中危 | 到不安全类型时危险 |
| `json.load()` | 中危 | 同上 |
| `marshal.loads()` | 严重 | 任意对象 |
| `marshal.load()` | 严重 | 同上 |
| `shelve.open()` | 高危 | 基于pickle |
| `ast.literal_eval()` | 低危 | 安全替代eval ✅ |

## XML / XXE

| 函数/方法 | 风险等级 | 说明 |
|-----------|---------|------|
| `xml.etree.ElementTree.parse()` | 高危 | Python 3.7+已修复 |
| `xml.etree.ElementTree.fromstring()` | 高危 | 同上 |
| `xml.dom.minidom.parseString()` | 高危 | 默认安全 |
| `xml.sax.make_parser().parse()` | 高危 | 需禁用DTD |
| `lxml.etree.parse()` | 严重 | 默认解析外部实体 |
| `lxml.etree.fromstring()` | 严重 | 同上 |
| `lxml.etree.XML()` | 严重 | 同上 |
| `defusedxml.ElementTree.parse()` | 低危 | 安全库 ✅ |
| `defusedxml.lxml.parse()` | 低危 | 安全库 ✅ |

## 文件操作

| 函数/方法 | 风险等级 | 说明 |
|-----------|---------|------|
| `open(path, 'w')` | 高危 | 任意文件写入 |
| `open(path, 'r')` | 高危 | 路径穿越读取 |
| `open(path, 'a')` | 高危 | 任意文件追加 |
| `os.open()` | 高危 | 底层文件操作 |
| `os.rename()` | 中危 | 文件重命名 |
| `os.remove()` / `os.unlink()` | 中危 | 文件删除 |
| `shutil.copy()` | 中危 | 文件复制 |
| `shutil.move()` | 中危 | 文件移动 |
| `os.path.join(base, user_input)` | 高危 | 未校验时路径穿越 |
| `pathlib.Path(base) / user_input` | 高危 | 同上 |
| `send_from_directory()` (Flask) | 高危 | 路径穿越 |
| `zipfile.ZipFile.extractall()` | 高危 | Zip Slip |
| `tarfile.TarFile.extractall()` | 高危 | Tar Slip |
| `werkzeug.FileStorage.save()` | 高危 | 文件上传 |

## SSRF

| 函数/方法 | 风险等级 | 说明 |
|-----------|---------|------|
| `requests.get()` | 高危 | HTTP请求 |
| `requests.post()` | 高危 | 同上 |
| `requests.request()` | 高危 | 同上 |
| `urllib.request.urlopen()` | 高危 | 同上 |
| `urllib.request.Request()` | 高危 | 同上 |
| `httpx.get()` | 高危 | 异步HTTP请求 |
| `httpx.post()` | 高危 | 同上 |
| `aiohttp.ClientSession.get()` | 高危 | 异步HTTP |
| `http.client.HTTPConnection()` | 高危 | 底层HTTP |
| `urllib3.PoolManager().request()` | 高危 | urllib3请求 |
| `socket.create_connection()` | 高危 | TCP连接 |
| `ftplib.FTP()` | 高危 | FTP连接 |
| `smtplib.SMTP()` | 高危 | SMTP连接 |

## 输出 / XSS

| 函数/方法 | 风险等级 | 说明 |
|-----------|---------|------|
| `HttpResponse(user_input)` (Django) | 高危 | 直接输出 |
| `render(request, template, context)` | 中危 | 依赖模板转义 |
| `mark_safe(user_input)` (Django) | 严重 | 禁用转义 |
| `|safe` (Jinja2/Django模板) | 严重 | 禁用转义 |
| `|striptags` (Django) | 中危 | HTML标签过滤 |
| `json.dumps()` 未转义HTML | 高危 | JSON中的XSS |
| `make_response()` (Flask) | 中危 | 响应构造 |
| `Response(content, mimetype='text/html')` | 高危 | HTML响应 |
| `print(user_input)` (WSGI) | 高危 | 直接输出 |
| `self.write(user_input)` (Tornado) | 高危 | 直接输出 |

## 日志 / 信息泄露

| 函数/方法 | 风险等级 | 说明 |
|-----------|---------|------|
| `logging.info()` / `debug()` | 中危 | 日志中记录敏感信息 |
| `print()` | 低危 | 标准输出泄露 |
| `traceback.print_exc()` | 中危 | 堆栈信息泄露 |
| `traceback.format_exc()` | 中危 | 同上 |
| `django.conf.settings.DEBUG` | 中危 | 调试模式 |
| `app.debug = True` (Flask) | 中危 | 调试模式 |
| `app.run(debug=True)` | 中危 | 调试模式 |

## 加密 / 随机数

| 函数/方法 | 风险等级 | 说明 |
|-----------|---------|------|
| `random.random()` | 中危 | 伪随机数 |
| `random.randint()` | 中危 | 同上 |
| `random.choice()` | 中危 | 同上 |
| `os.urandom()` | 低危 | 密码学安全 ✅ |
| `secrets.randbelow()` | 低危 | 密码学安全 ✅ |
| `secrets.token_hex()` | 低危 | 密码学安全 ✅ |
| `hashlib.md5()` | 高危 | 弱哈希 |
| `hashlib.sha1()` | 中危 | 弱哈希 |
| `hashlib.sha256()` | 低危 | 安全哈希 ✅ |
| `hashlib.pbkdf2_hmac()` | 低危 | 密钥派生 ✅ |
| `cryptography.fernet.Fernet` | 低危 | 安全加密 ✅ |
| `bcrypt.hashpw()` | 低危 | 安全密码哈希 ✅ |
| `argon2.PasswordHasher()` | 低危 | 安全密码哈希 ✅ |

## 网络 / 通信

| 函数/方法 | 风险等级 | 说明 |
|-----------|---------|------|
| `socket.socket()` | 中危 | 原始套接字 |
| `socket.create_connection()` | 高危 | TCP连接 |
| `ssl._create_unverified_context()` | 严重 | 跳过证书验证 |
| `ssl.SSLContext.verify_mode = ssl.CERT_NONE` | 严重 | 同上 |
| `CORS(app, resources={r"/*": {...}})` | 高危 | CORS配置 |
| `@cross_origin()` | 高危 | Flask-CORS |
| `django-cors-headers` 全开放 | 高危 | CORS全开放 |

## 不安全的配置

| 配置项 | 风险等级 | 说明 |
|--------|---------|------|
| `DEBUG = True` (Django) | 严重 | 调试模式 |
| `SECRET_KEY` 硬编码 | 严重 | 密钥泄露 |
| `ALLOWED_HOSTS = ['*']` | 高危 | 允许所有Host |
| `SESSION_COOKIE_SECURE = False` | 中危 | Cookie非HTTPS |
| `CSRF_COOKIE_SECURE = False` | 中危 | CSRF Cookie非HTTPS |
| `SECURE_SSL_REDIRECT = False` | 中危 | 不强制HTTPS |
| `X_FRAME_OPTIONS = None` | 中危 | 无点击劫持防护 |
| `SECURE_CONTENT_TYPE_NOSNIFF = False` | 低危 | MIME嗅探 |
| `SECURE_BROWSER_XSS_FILTER = False` | 低危 | XSS过滤 |
| `app.config['DEBUG'] = True` (Flask) | 严重 | 调试模式 |
| `app.secret_key` 硬编码 | 严重 | 密钥泄露 |
| `TEMPLATES_AUTO_RELOAD = True` 生产环境 | 中危 | 模板热加载 |
