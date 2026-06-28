# OWASP Top 10 (2021) Java审计备忘单

## A01:2021 – 权限控制失效 (Broken Access Control)

### Java常见模式
```java
// 危险：仅检查是否登录，未检查权限级别
if (session.getAttribute("user") != null) { /* 执行操作 */ }

// 危险：未校验资源归属关系
@RequestMapping("/api/user/{id}")
public User getUser(@PathVariable Long id) {
    return userService.findById(id); // 未校验id是否属于当前用户
}

// 安全做法
@RequestMapping("/api/user/{id}")
@PreAuthorize("#id == authentication.principal.id or hasRole('ADMIN')")
public User getUser(@PathVariable Long id) {
    return userService.findById(id);
}
```

### 越权检测清单
- [ ] API端点是否校验当前用户身份与资源归属关系？
- [ ] 是否存在IDOR模式：`/api/user/{id}` 未校验 `id` 是否属于当前登录用户？
- [ ] 管理后台是否在前端隐藏而非后端鉴权？
- [ ] Spring Security的 `@PreAuthorize` / `@PostAuthorize` 是否正确配置？
- [ ] Shiro的权限注解 `@RequiresPermissions` 是否遗漏？
- [ ] JWT Token中的权限声明是否被服务端校验？

---

## A02:2021 – 加密机制失效 (Cryptographic Failures)

### Java常见模式
```java
// 危险：使用弱哈希
String hash = DigestUtils.md5Hex(password);

// 危险：ECB模式
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

// 安全做法
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
```

### 检测清单
- [ ] 密码使用 `BCryptPasswordEncoder` 或 `PBKDF2` 而非 `MD5`/`SHA1`？
- [ ] Token使用 `SecureRandom` 而非 `Random`/`Math.random()`？
- [ ] 重要ID是否使用随机UUID而非自增ID？
- [ ] 加密算法是否使用 `AES/GCM` 而非 `AES/ECB`？
- [ ] HTTPS是否强制启用（HSTS）？
- [ ] 密钥是否硬编码在代码中？

---

## A03:2021 – 注入 (Injection)

### SQL注入防护 (Java)
```java
// ✅ PreparedStatement参数化绑定（安全）
String sql = "SELECT * FROM users WHERE id = ?";
PreparedStatement stmt = conn.prepareStatement(sql);
stmt.setLong(1, id);
ResultSet rs = stmt.executeQuery();

// ✅ MyBatis #{} 预编译（安全）
// SELECT * FROM users WHERE id = #{id}

// ❌ 字符串拼接（危险）
String sql = "SELECT * FROM users WHERE id = " + request.getParameter("id");
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(sql);

// ❌ MyBatis ${} 拼接（危险）
// SELECT * FROM users WHERE id = ${id}
```

### ORDER BY/LIMIT注入（无法参数化的场景）
```java
// 必须使用白名单
private static final List<String> ALLOWED_COLUMNS = 
    Arrays.asList("id", "name", "email", "created_at");

public List<User> getUsers(String orderBy) {
    String column = ALLOWED_COLUMNS.contains(orderBy) ? orderBy : "id";
    String sql = "SELECT * FROM users ORDER BY " + column;
    // 注意：即使白名单，也不要直接拼接，使用枚举更安全
}
```

### LIKE注入
```java
// 危险：用户输入直接拼入LIKE
String sql = "SELECT * FROM users WHERE name LIKE '%" + input + "%'";

// 安全做法：先转义再拼接或使用CONCAT
String sql = "SELECT * FROM users WHERE name LIKE CONCAT('%', ?, '%')";
PreparedStatement stmt = conn.prepareStatement(sql);
stmt.setString(1, input.replace("%", "\%").replace("_", "\_"));
```

### JPA/JPQL注入
```java
// 危险：JPQL拼接
String jpql = "SELECT u FROM User u WHERE u.name = '" + name + "'";
Query query = entityManager.createQuery(jpql);

// 安全做法：参数化
String jpql = "SELECT u FROM User u WHERE u.name = :name";
Query query = entityManager.createQuery(jpql);
query.setParameter("name", name);
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

### Spring Boot 安全配置
```yaml
# application.yml 安全配置
server:
  error:
    include-stacktrace: never  # 禁止堆栈信息泄露
    include-message: always

spring:
  devtools:
    restart:
      enabled: false  # 生产环境关闭热加载
  mvc:
    log-request-details: false
  jackson:
    serialization:
      indent-output: false
      write-dates-as-timestamps: false

management:
  endpoints:
    web:
      exposure:
        include: health,info  # 仅暴露必要端点
  endpoint:
    health:
      show-details: when_authorized

logging:
  level:
    root: WARN
    org.springframework.web: WARN
```

### HTTP安全头 (Spring Security)
```java
http
    .headers(headers -> headers
        .frameOptions(frameOptions -> frameOptions.deny())
        .contentTypeOptions(contentTypeOptions -> {})
        .xssProtection(xss -> xss.headerValue(XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK))
        .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'"))
        .httpStrictTransportSecurity(hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(31536000))
    );
```

---

## A06:2021 – 易受攻击和过时的组件 (Vulnerable and Outdated Components)

### Java版本安全下线时间
| Java版本 | 安全支持终止 | 风险 |
|---------|------------|------|
| Java 7 | 2022-07 | 严重 |
| Java 8 (LTS) | 2030-12 (Oracle) | 低危（需更新补丁） |
| Java 11 (LTS) | 2032-01 | 安全 |
| Java 17 (LTS) | 2029-09 | 安全 |
| Java 21 (LTS) | 2031-09 | 安全 |

### Maven/Gradle审计
```bash
# Maven依赖漏洞检查
mvn org.owasp:dependency-check-maven:check

# Gradle依赖漏洞检查
gradle dependencyCheckAnalyze
```

### 高危组件版本速查
| 组件 | 安全版本 | 已知漏洞 |
|-----|---------|---------|
| Fastjson | >= 2.0.43 | 反序列化RCE |
| Jackson-databind | >= 2.15.2 | 反序列化RCE |
| Log4j2 | >= 2.17.1 | Log4Shell (CVE-2021-44228) |
| Spring Framework | >= 5.3.27 | Spring4Shell |
| Spring Boot | >= 2.7.12 | 多个CVE |
| Apache Shiro | >= 1.12.0 | 反序列化 |
| XStream | >= 1.4.20 | 反序列化 |
| Apache Commons Collections | >= 4.4 | Gadget链 |

---

## A07:2021 – 身份认证和会话管理失效 (Identification and Authentication Failures)

### 会话安全 (Spring Security)
```java
http
    .sessionManagement(session -> session
        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
        .maximumSessions(1)
        .maxSessionsPreventsLogin(false)
        .sessionFixation(sessionFixation -> sessionFixation.migrateSession())
    )
    .logout(logout -> logout
        .deleteCookies("JSESSIONID")
        .invalidateHttpSession(true)
        .clearAuthentication(true)
    );
```

### Cookie安全配置
```java
// Servlet Cookie配置
cookie.setHttpOnly(true);
cookie.setSecure(true);  // HTTPS时
cookie.setSameSite(Cookie.SameSite.STRICT);
cookie.setMaxAge(3600);  // 合理过期时间
```

### JWT安全
```java
// 危险：弱密钥
String secret = "123456";  // 太短

// 安全做法
Key key = Keys.secretKeyFor(SignatureAlgorithm.HS512);  // 足够长度
// 或使用非对称密钥
KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.RS256);
```

---

## A08:2021 – 软件和数据完整性失效 (Software and Data Integrity Failures)

### Java反序列化防护
```java
// ❌ 危险
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject();

// ✅ 安全替代：使用JSON
ObjectMapper mapper = new ObjectMapper();
User user = mapper.readValue(jsonString, User.class);
// 关闭默认类型
mapper.disableDefaultTyping();

// 必须反序列化时：使用白名单
public class SafeObjectInputStream extends ObjectInputStream {
    private static final Set<String> ALLOWED_CLASSES = Set.of(
        "com.example.User", "com.example.Order"
    );

    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) {
        if (!ALLOWED_CLASSES.contains(desc.getName())) {
            throw new SecurityException("Class not allowed: " + desc.getName());
        }
        return super.resolveClass(desc);
    }
}
```

---

## A09:2021 – 日志记录和监控不足 (Insufficient Logging & Monitoring)

### 必须记录的事件
```java
// 认证事件
log.warn("[AUTH] Login failed: user={}, ip={}", username, request.getRemoteAddr());

// 权限变更
log.warn("[PRIV] Role changed: user={}, from={}, to={}", userId, oldRole, newRole);

// 敏感操作
log.info("[SENSITIVE] Payment: user={}, amount={}, order={}", userId, amount, orderId);

// ❌ 危险：记录密码
log.info("Login password: {}", password);  // 绝对禁止！
```

### 日志脱敏
```java
// 使用MaskingPatternLayout (Logback)
<appender name="CONSOLE" class="ch.qos.logback.core.ConsoleAppender">
    <encoder class="ch.qos.logback.core.encoder.LayoutWrappingEncoder">
        <layout class="com.example.MaskingPatternLayout">
            <maskPattern>password=([^&\s]*)</maskPattern>
            <maskPattern>token=([^&\s]*)</maskPattern>
            <maskPattern>\b\d{17}[\dXx]\b</maskPattern>  <!-- 身份证号 -->
        </layout>
    </encoder>
</appender>
```
