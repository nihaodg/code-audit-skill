# Go OWASP 安全编码速查表

## OWASP Top 10 (2021) Go 对照

| OWASP 排名 | 漏洞 | Go 常见场景 |
|-----------|------|-------------|
| A01 | 访问控制失效 | Gin 中间件链缺失鉴权、`net/http` Handler 无权限校验 |
| A02 | 加密失效 | `crypto/md5` 哈希密码、`math/rand` 生成令牌 |
| A03 | 注入 | `fmt.Sprintf` SQL 拼接、`exec.Command("sh", "-c", userInput)` |
| A04 | 不安全设计 | 无速率限制、缺失输入长度边界 |
| A05 | 安全配置错误 | CORS `AllowAllOrigins:true`、TLS `InsecureSkipVerify` |
| A06 | 脆弱和过时组件 | `go.sum` 未锁定版本、使用已归档的第三方库 |
| A07 | 身份识别和认证失败 | `==` 比较密码(时序攻击)、JWT 密钥硬编码 |
| A08 | 软件和数据完整性 | `gob.NewDecoder()` 不可信输入、模块供应链攻击 |
| A09 | 安全日志和监控失败 | `log.Println(password)` 泄露、`panic` 堆栈暴露 |
| A10 | SSRF | `http.Get(userUrl)` 无 URL 校验 |

## SQL 注入速查

```go
// 危险 - fmt.Sprintf 拼接
query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID)
db.Query(query)

// 危险 - 字符串拼接
db.Query("SELECT * FROM users WHERE name = '" + userName + "'")

// 安全 - 占位符参数化
db.Query("SELECT * FROM users WHERE id = ?", userID)

// 危险 - GORM Raw 拼接
db.Raw("SELECT * FROM users WHERE id = " + userID).Scan(&user)

// 安全 - GORM 链式调用
db.Where("id = ?", userID).First(&user)

// 安全 - GORM Raw 参数化
db.Raw("SELECT * FROM users WHERE id = ?", userID).Scan(&user)
```

## 命令执行速查

```go
// 危险 - shell 包装用户输入
exec.Command("sh", "-c", "ping "+userHost).Run()

// 危险 - 用户可控命令名
exec.Command(userCmd, userArgs...).Run()

// 安全 - 固定命令 + 参数分离
exec.Command("ping", "-c", "1", userHost).Run()

// 安全 - 输入校验
if matched, _ := regexp.MatchString(`^[a-zA-Z0-9.-]+$`, userHost); !matched {
    return errors.New("invalid host")
}
exec.Command("ping", "-c", "1", userHost).Run()
```

## 模板注入速查

```go
// 危险 - text/template (无 HTML 转义)
tmpl := template.Must(template.New("").Parse(userTemplate))
tmpl.Execute(w, data)

// 较安全 - html/template (自动转义)
tmpl := template.Must(template.New("").Parse(userTemplate))
tmpl.Execute(w, data)

// 最佳安全 - 服务端预定义模板，用户仅提供数据
tmpl := template.Must(template.ParseFiles("templates/page.html"))
tmpl.Execute(w, userData)
```

## 路径穿越速查

```go
// 危险
http.ServeFile(w, r, r.URL.Path)
os.Open(filepath.Join("/var/www", r.URL.Query().Get("file")))

// 安全 - 路径清理 + 前缀校验
basePath := "/var/www/uploads/"
filePath := filepath.Clean(filepath.Join(basePath, fileName))
if !strings.HasPrefix(filePath, basePath) {
    http.Error(w, "Forbidden", 403)
    return
}
http.ServeFile(w, r, filePath)
```

## SSRF 速查

```go
// 危险
http.Get(r.URL.Query().Get("url"))
http.NewRequest("GET", userUrl, nil)

// 安全 - URL 白名单
parsed, _ := url.Parse(userUrl)
if parsed.Host != "api.trusted.com" {
    return errors.New("URL not allowed")
}
// 辅以 DNS 解析 + 内网 IP 检测
ips, _ := net.LookupIP(parsed.Hostname())
for _, ip := range ips {
    if ip.IsPrivate() || ip.IsLoopback() {
        return errors.New("private IP not allowed")
    }
}
http.Get(userUrl)
```

## 密码处理

```go
// 危险
import "crypto/md5"
hash := md5.Sum([]byte(password))

import "crypto/sha1"
hash := sha1.Sum([]byte(password))

// 安全 - bcrypt
import "golang.org/x/crypto/bcrypt"
hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

// 危险 - 时序攻击
if inputPassword == storedPassword { }

// 安全 - 恒定时间比较
import "crypto/subtle"
if subtle.ConstantTimeCompare([]byte(inputPassword), []byte(storedPassword)) == 1 { }

// 危险 - math/rand 令牌
import "math/rand"
token := rand.Int63()

// 安全 - crypto/rand
import "crypto/rand"
b := make([]byte, 32)
rand.Read(b)
token := hex.EncodeToString(b)
```

## 并发安全速查

```go
// 危险 - map 无锁并发
var cache = make(map[string]string)
// goroutine 1: cache["key"] = "val"
// goroutine 2: _ = cache["key"]

// 安全 - sync.RWMutex
var (
    cache = make(map[string]string)
    mu    sync.RWMutex
)
mu.Lock()
cache["key"] = "val"
mu.Unlock()

// 安全 - sync.Map
var cache sync.Map
cache.Store("key", "val")
```

## 参考资源

- [OWASP Go Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Go_Security_Cheat_Sheet.html)
- [gosec](https://github.com/securego/gosec)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [Go Security Policy](https://go.dev/doc/security/)
