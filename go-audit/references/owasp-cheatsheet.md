# OWASP Top 10 (2021) Go审计备忘单

## A01:2021 – 权限控制失效 (Broken Access Control)

### Go常见模式
```go
// 危险：仅检查是否登录，未检查权限级别
if c.GetString("user_id") != "" { /* 执行操作 */ }

// 危险：未校验资源归属关系
func GetUser(c *gin.Context) {
    id := c.Param("id")
    user := db.Find(&User{}, id) // 未校验id是否属于当前用户
    c.JSON(200, user)
}

// 安全做法
func GetUser(c *gin.Context) {
    id := c.Param("id")
    currentUser := c.GetString("user_id")
    user := db.Where("id = ? AND owner_id = ?", id, currentUser).First(&User{})
    if user.Error != nil {
        c.JSON(403, gin.H{"error": "forbidden"})
        return
    }
    c.JSON(200, user)
}
```

### 越权检测清单
- [ ] Handler是否校验当前用户身份与资源归属关系？
- [ ] 是否存在IDOR模式：`/api/user/:id` 未校验 `id` 是否属于当前登录用户？
- [ ] 管理后台是否在前端隐藏而非后端鉴权？
- [ ] 中间件是否正确挂载到所有路由？
- [ ] JWT Token中的权限声明是否被服务端校验？

---

## A02:2021 – 加密机制失效 (Cryptographic Failures)

### Go常见模式
```go
// 危险：使用弱哈希
import "crypto/md5"
hash := md5.Sum([]byte(password))

// 危险：伪随机数
import "math/rand"
token := rand.Intn(1000000)

// 安全做法
import "golang.org/x/crypto/bcrypt"
hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

// 安全随机数
import "crypto/rand"
b := make([]byte, 16)
rand.Read(b)
token := hex.EncodeToString(b)
```

### 检测清单
- [ ] 密码使用 `bcrypt`/`scrypt`/`argon2` 而非 `MD5`/`SHA1`？
- [ ] Token使用 `crypto/rand` 而非 `math/rand`？
- [ ] 重要ID是否使用随机UUID而非自增ID？
- [ ] TLS是否强制启用且未设置 `InsecureSkipVerify: true`？
- [ ] 密钥是否硬编码在代码中？

---

## A03:2021 – 注入 (Injection)

### SQL注入防护 (Go)
```go
// ✅ database/sql 参数化（安全）
rows, err := db.Query("SELECT * FROM users WHERE id = ?", id)

// ✅ GORM 参数化（安全）
db.Where("name = ? AND age = ?", name, age).Find(&users)

// ❌ 字符串拼接（危险）
sql := "SELECT * FROM users WHERE id = " + c.Query("id")
rows, err := db.Query(sql)

// ❌ GORM 拼接（危险）
db.Where("name = '" + name + "'").Find(&users)

// ❌ fmt.Sprintf 拼接（危险）
sql := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
```

### ORDER BY注入（无法参数化的场景）
```go
// 必须使用白名单
var allowedColumns = map[string]bool{
    "id": true, "name": true, "email": true, "created_at": true,
}

func GetUsers(orderBy string) ([]User, error) {
    if !allowedColumns[orderBy] {
        orderBy = "id"
    }
    // 注意：ORDER BY仍需拼接，但已白名单校验
    return db.Order(orderBy).Find(&users).Error
}
```

---

## A04:2021 – 不安全的设计 (Insecure Design)

### 检测清单
- [ ] 密码重置流程：Token是否在URL中？是否有时效性？
- [ ] 支付流程：金额是否在服务端校验而非依赖前端回传？
- [ ] 多步骤操作：是否存在步骤跳过风险？
- [ ] 速率限制：登录/注册/API是否有频率限制？
- [ ] 文件上传：是否检查文件内容而非仅后缀？

---

## A05:2021 – 安全配置错误 (Security Misconfiguration)

### Go/Gin 安全配置
```go
// 生产环境配置
gin.SetMode(gin.ReleaseMode)

// 安全HTTP头
r.Use(func(c *gin.Context) {
    c.Header("X-Frame-Options", "DENY")
    c.Header("X-Content-Type-Options", "nosniff")
    c.Header("X-XSS-Protection", "1; mode=block")
    c.Header("Content-Security-Policy", "default-src 'self'")
    c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    c.Next()
})

// CORS安全配置（非全开放）
r.Use(cors.New(cors.Config{
    AllowOrigins:     []string{"https://example.com"},
    AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},
    AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
    AllowCredentials: true,
    MaxAge:           12 * time.Hour,
}))
```

### 禁止生产环境配置
```go
// ❌ 危险：调试模式
gin.SetMode(gin.DebugMode)

// ❌ 危险：pprof未授权
import _ "net/http/pprof"

// ❌ 危险：TLS跳过验证
&tls.Config{InsecureSkipVerify: true}

// ❌ 危险：CORS全开放
c.Header("Access-Control-Allow-Origin", "*")
```

---

## A06:2021 – 易受攻击和过时的组件

### Go版本安全
| Go版本 | 状态 | 建议 |
|--------|------|------|
| Go 1.18 | 已停止维护 | 升级 |
| Go 1.19 | 已停止维护 | 升级 |
| Go 1.20 | 已停止维护 | 升级 |
| Go 1.21 | 已停止维护 | 升级 |
| Go 1.22 | 维护中 | 可用 |
| Go 1.23 | 维护中 | 推荐 |

### 依赖漏洞扫描
```bash
# 官方漏洞扫描工具
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...

# 检查可更新依赖
go list -m -u all

# 更新依赖
go get -u ./...
go mod tidy
```

### 高危依赖速查
| 依赖 | 问题 | 替代方案 |
|-----|------|---------|
| github.com/dgrijalva/jwt-go | 已废弃，有漏洞 | github.com/golang-jwt/jwt/v5 |
| gopkg.in/yaml.v2 | 反序列化风险 | gopkg.in/yaml.v3 |
| github.com/go-yaml/yaml | 旧版本风险 | 升级到最新 |

---

## A07:2021 – 身份认证和会话管理失效

### JWT安全 (Go)
```go
import "github.com/golang-jwt/jwt/v5"

// 危险：弱密钥
var secret = []byte("123456")

// 安全做法
var secret = make([]byte, 64)
crypto.Read(secret)

// 安全JWT配置
token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
tokenString, err := token.SignedString(secret)

// 验证时强制校验算法
func parseToken(tokenString string) (*jwt.Token, error) {
    return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        // 强制校验算法
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return secret, nil
    })
}
```

### Cookie安全
```go
http.SetCookie(w, &http.Cookie{
    Name:     "session",
    Value:    token,
    HttpOnly: true,
    Secure:   true,  // HTTPS时
    SameSite: http.SameSiteStrictMode,
    MaxAge:   3600,
    Path:     "/",
})
```

---

## A08:2021 – 软件和数据完整性失效

### Go反序列化防护
```go
// ❌ 危险：反序列化到interface{}
var result interface{}
json.Unmarshal(data, &result)

// ✅ 安全：反序列化到具体结构体
type User struct {
    ID   int    `json:"id"`
    Name string `json:"name"`
}
var user User
json.Unmarshal(data, &user)

// ✅ 更安全的做法：使用Decoder+DisallowUnknownFields
decoder := json.NewDecoder(bytes.NewReader(data))
decoder.DisallowUnknownFields()
err := decoder.Decode(&user)
```

---

## A09:2021 – 日志记录和监控不足

### 安全日志 (Go)
```go
import "go.uber.org/zap"

logger, _ := zap.NewProduction()

// 认证事件
logger.Warn("login failed",
    zap.String("user", username),
    zap.String("ip", c.ClientIP()),
)

// 权限变更
logger.Warn("role changed",
    zap.String("user_id", userID),
    zap.String("from", oldRole),
    zap.String("to", newRole),
)

// ❌ 危险：记录密码
logger.Info("login", zap.String("password", password)) // 绝对禁止！
```

### 日志脱敏
```go
// 使用zap的Hook进行脱敏
logger, _ := zap.NewProduction(zap.Hooks(func(entry zapcore.Entry) error {
    // 脱敏处理
    return nil
}))
```
