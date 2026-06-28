# Java OWASP 安全编码速查表

## OWASP Top 10 (2021) Java 对照

| OWASP 排名 | 漏洞 | Java 常见场景 |
|-----------|------|-------------|
| A01 | 访问控制失效 | Controller 缺少 `@PreAuthorize`、直接暴露管理 API |
| A02 | 加密失效 | `MessageDigest.getInstance("MD5")`、`new Random()` 生成令牌 |
| A03 | 注入 | MyBatis `${}`、JDBC 字符串拼接、JPA `createNativeQuery` 拼接 |
| A04 | 不安全设计 | 未限制 API 调用频率、缺失密码强度策略 |
| A05 | 安全配置错误 | Actuator 全暴露、CSRF 禁用、CORS `*` |
| A06 | 脆弱和过时组件 | Log4j <= 2.14.1、Spring Framework 旧版本、Fastjson < 1.2.83 |
| A07 | 身份识别和认证失败 | JWT 密钥硬编码、Session 固定 |
| A08 | 软件和数据完整性 | 反序列化 RCE (ysoserial)、Maven 依赖投毒 |
| A09 | 安全日志和监控失败 | `e.printStackTrace()` 泄露信息、日志未脱敏 |
| A10 | SSRF | `RestTemplate.getForObject(userUrl)` 无校验 |

## SQL 注入速查

```java
// 危险 - JDBC 字符串拼接
String sql = "SELECT * FROM users WHERE id = " + request.getParameter("id");
stmt.executeQuery(sql);

// 安全 - PreparedStatement
String sql = "SELECT * FROM users WHERE id = ?";
PreparedStatement pstmt = conn.prepareStatement(sql);
pstmt.setInt(1, Integer.parseInt(request.getParameter("id")));

// 危险 - MyBatis ${}（字符串替换，非参数化）
@Select("SELECT * FROM users WHERE name = '${name}'")

// 安全 - MyBatis #{}（参数化）
@Select("SELECT * FROM users WHERE name = #{name}")

// 危险 - JPA native query 拼接
entityManager.createNativeQuery("SELECT * FROM users WHERE id = " + id);

// 安全 - JPA 参数绑定
Query q = entityManager.createNativeQuery("SELECT * FROM users WHERE id = :id");
q.setParameter("id", id);
```

## 命令执行速查

```java
// 危险 - 直接执行用户输入
Runtime.getRuntime().exec("ping " + request.getParameter("host"));

// 安全 - 白名单 + 参数化
String host = request.getParameter("host");
if (host.matches("^[a-zA-Z0-9.-]+$")) {
    new ProcessBuilder("ping", "-c", "1", host).start();
}
```

## 表达式注入速查

```java
// 危险 - OGNL 用户可控表达式
Ognl.getValue(request.getParameter("expr"), context, root);

// 危险 - SpEL 用户可控表达式
parser.parseExpression(request.getParameter("expr")).getValue(ctx);

// 安全 - 使用受限表达式上下文或禁用表达式解析
```

## 反序列化速查

```java
// 危险 - 无类型白名单
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject();

// 危险 - Fastjson 无 Type
JSON.parse(userInput);

// 安全 - Fastjson 1.2.83+ 默认关闭 autotype
JSON.parse(userInput, Feature.SupportAutoType);

// 危险 - Jackson enableDefaultTyping
objectMapper.enableDefaultTyping();

// 安全 - 禁用多态类型或使用白名单
objectMapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

// 危险 - 所有 BinaryFormatter 等同物
new XMLDecoder(inputStream);
```

## XXE 速查

```java
// 危险 - 默认配置
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(inputStream);

// 安全 - 禁用外部实体
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
```

## SSRF 速查

```java
// 危险 - 用户 URL 直接请求
restTemplate.getForObject(request.getParameter("url"), String.class);

// 安全 - URL 白名单校验
String url = request.getParameter("url");
if (!url.startsWith("https://api.trusted.com/")) {
    throw new SecurityException("URL not allowed");
}
// 辅以内网地址黑名单过滤
```

## 密码处理

```java
// 危险
MessageDigest.getInstance("MD5").digest(password.getBytes());
new Random().nextInt();  // 用于安全令牌

// 安全 - BCrypt/Argon2
BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
String hash = encoder.encode(password);

// 安全 - SecureRandom
SecureRandom random = new SecureRandom();
byte[] token = new byte[32];
random.nextBytes(token);
```

## 参考资源

- [OWASP Java Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Java_Security_Cheat_Sheet.html)
- [OWASP Dependency Check](https://owasp.org/www-project-dependency-check/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [ysoserial](https://github.com/frohoff/ysoserial)
