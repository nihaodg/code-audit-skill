# OWASP Top 10 (2021) PHP审计备忘单

## A01:2021 – 权限控制失效 (Broken Access Control)

### PHP常见模式
```php
// 危险：仅检查是否登录，未检查权限级别
if (isset($_SESSION['user'])) { /* 执行操作 */ }

// 危险：isset在值为0/false时返回true
if (isset($_SESSION['is_admin'])) { /* 管理操作 */ }

// 安全做法
if (!empty($_SESSION['role']) && $_SESSION['role'] === 'admin') { /* … */ }
```

### 越权检测清单
- [ ] API端点是否校验当前用户身份与资源归属关系？
- [ ] 是否存在IDOR模式：`/api/user/{id}` 未校验 `id` 是否属于当前登录用户？
- [ ] 管理后台是否在前端隐藏而非后端鉴权？
- [ ] 是否使用 `base64` 编码的ID而不是强随机令牌？

---

## A02:2021 – 加密机制失效 (Cryptographic Failures)

### PHP常见模式
```php
// 危险：使用弱哈希
$hash = md5($password);
$hash = sha1($password);

// 安全做法
$hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
```

### 检测清单
- [ ] 密码使用 `password_hash()` 而非 `md5`/`sha1`？
- [ ] Token使用 `random_bytes()` 或 `random_int()` 而非 `rand()`/`mt_rand()`？
- [ ] 重要ID是否使用随机UUID而非自增ID？
- [ ] `openssl_random_pseudo_bytes()` 是否检查强随机标志？

---

## A03:2021 – 注入 (Injection)

### SQL注入防护 (PHP)
```php
// ✅ PDO参数化绑定（安全）
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');
$stmt->execute(['id' => $id]);

// ✅ MySQLi参数化（安全）
$stmt = $mysqli->prepare('SELECT * FROM users WHERE id = ?');
$stmt->bind_param('i', $id);

// ❌ 字符串拼接（危险）
$sql = "SELECT * FROM users WHERE id = " . $_GET['id'];
```

### ORDER BY/LIMIT注入（无法参数化的场景）
```php
// 必须使用白名单
$allowedColumns = ['id', 'name', 'email', 'created_at'];
$orderBy = in_array($_GET['order'], $allowedColumns) ? $_GET['order'] : 'id';

// ❌ 危险：直接拼接
$sql = "SELECT * FROM users ORDER BY " . $_GET['order'];
```

### LIKE注入
```php
// 危险：用户输入直接拼入LIKE
$sql = "SELECT * FROM users WHERE name LIKE '%" . $_GET['q'] . "%'";

// 安全做法：先转义再拼接
$q = str_replace(['%', '_'], ['\%', '\_'], $search);
$stmt = $pdo->prepare('SELECT * FROM users WHERE name LIKE CONCAT("%", :q, "%")');
```

### 宽字节注入
```php
// 危险：GBK编码 + addslashes
mysql_set_charset('gbk');
$name = addslashes($_GET['name']);
$sql = "SELECT * FROM users WHERE name = '$name'";
// 输入 %bf%27 可吃掉转义反斜杠 -> %bf%5c%27 -> 運'

// 安全做法：使用参数化绑定 + UTF-8
```

---

## A04:2021 – 不安全的设计 (Insecure Design)

### 检测清单
- [ ] 密码重置流程：Token是否在URL中？是否有时效性？
- [ ] 支付流程：金额是否在服务端校验而非依赖前端回传？
- [ ] 多步骤操作：是否存在步骤跳过风险？
- [ ] 速率限制：登录/注册/API是否有频率限制？

---

## A05:2021 – 安全配置错误 (Security Misconfiguration)

### php.ini 安全配置
```ini
; 必须配置
display_errors = Off
log_errors = On
error_reporting = E_ALL & ~E_DEPRECATED & ~E_STRICT
allow_url_include = Off
allow_url_fopen = On   ; 按需，SSRF风险
session.cookie_httponly = 1
session.cookie_secure = 1   ; HTTPS时
session.use_only_cookies = 1
session.cookie_samesite = "Lax"
expose_php = Off
disable_functions = exec,passthru,shell_exec,system,popen,proc_open,curl_exec,curl_multi_exec,parse_file,show_source
```

### HTTP安全头
```php
// Nginx/Apache配置或PHP header()
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('X-XSS-Protection: 1; mode=block');
header('Content-Security-Policy: default-src \'self\'');
header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
```

---

## A06:2021 – 易受攻击和过时的组件 (Vulnerable and Outdated Components)

### PHP版本安全下线时间
| PHP版本 | 安全支持终止 | 风险 |
|---------|------------|------|
| 5.6 | 2018-12-31 | 严重，大量已知漏洞 |
| 7.0 | 2019-01-28 | 严重 |
| 7.1 | 2019-12-01 | 严重 |
| 7.2 | 2020-11-30 | 高危 |
| 7.3 | 2021-12-06 | 高危 |
| 7.4 | 2022-11-28 | 高/中危 |
| 8.0 | 2023-11-26 | 中危 |
| 8.1 | 2024-12-31 | 低危 |
| 8.2+ | 活跃 | 安全 |

### Composer审计
```bash
composer audit                    # 检查已知漏洞
composer outdated --direct        # 列出过时依赖
```

---

## A07:2021 – 身份认证和会话管理失效 (Identification and Authentication Failures)

### 会话安全
```php
// ✅ 安全配置
session_start([
    'cookie_httponly' => true,
    'cookie_secure' => true,
    'cookie_samesite' => 'Strict',
    'use_strict_mode' => true
]);

// ❌ 危险
session_id($_GET['sessid']);  // 会话固定
```

### 密码策略
```php
// 推荐：至少12位，含大小写+数字+特殊字符
// 安全存储：password_hash() + PASSWORD_BCRYPT/PASSWORD_ARGON2ID
// 登录频率限制：sleep(1) 或 Redis计数器
```

---

## A08:2021 – 软件和数据完整性失效 (Software and Data Integrity Failures)

### PHP反序列化防护
```php
// ❌ 危险
$data = unserialize($_GET['data']);

// ✅ 安全替代：使用JSON
$data = json_decode($_GET['data'], true);

// 必须反序列化时：使用hash校验
$expected = hash_hmac('sha256', $_GET['data'], SECRET_KEY);
if ($expected !== $_GET['hash']) { die('Invalid data'); }
$data = unserialize($_GET['data']);
```

### Phar反序列化
```php
// 以下函数传入phar://协议会触发反序列化
file_exists('phar://evil.phar/file.txt');
file_get_contents('phar://evil.phar/file.txt');
is_dir('phar://evil.phar/file.txt');
```

---

## A09:2021 – 日志记录和监控不足 (Insufficient Logging & Monitoring)

### 必须记录的事件
```php
// 认证事件
error_log("[AUTH] Login failed: user={$_POST['username']}, ip={$_SERVER['REMOTE_ADDR']}");

// 权限变更
error_log("[PRIV] Role changed: user={$uid}, from={$oldRole}, to={$newRole}");

// 敏感操作
error_log("[SENSITIVE] Payment: user={$uid}, amount={$amount}, order={$orderId}");

// ❌ 危险：记录密码
error_log("Login: " . $_POST['password']);  // 绝对禁止！
```
