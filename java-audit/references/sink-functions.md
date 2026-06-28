# Java 危险函数（Sink）速查表

## SQL注入相关

| 函数/方法 | 风险等级 | 说明 |
|-----------|---------|------|
| `Statement.executeQuery()` | 严重 | 直接拼接SQL，无预编译 |
| `Statement.executeUpdate()` | 严重 | 同上 |
| `Statement.execute()` | 严重 | 同上 |
| `Connection.createStatement().executeQuery()` | 严重 | 原始Statement拼接 |
| `Query.setParameter()` 绕过 | 高危 | JPA/Hibernate中绕过参数化 |
| `EntityManager.createNativeQuery()` | 高危 | 原生SQL，拼接时危险 |
| `JdbcTemplate.query()` | 高危 | Spring JdbcTemplate拼接 |
| `JdbcTemplate.update()` | 高危 | 同上 |
| `NamedParameterJdbcTemplate` 误用 | 高危 | 参数名注入 |
| `MyBatis ${}` | 严重 | 占位符拼接，等同直接SQL |
| `MyBatis #{}` 绕过 | 高危 | OGNL表达式注入绕过 |
| `MyBatis orderBy ${}` | 高危 | ORDER BY无法预编译 |
| `MyBatis <bind>` 拼接 | 高危 | XML中动态拼接 |
| `MyBatis ${param}` in `WHERE` | 严重 | 任意位置拼接 |
| `JPA Query.createQuery(String)` | 高危 | JPQL拼接 |
| `JPA Criteria` 绕过 | 中危 | 不规范使用时 |
| `Hibernate SQLQuery` | 高危 | 原生SQL |
| `Spring Data @Query` 拼接 | 高危 | SpEL注入到查询中 |

## 命令/代码执行

| 函数/方法 | 风险等级 | 说明 |
|-----------|---------|------|
| `Runtime.exec()` | 严重 | 执行系统命令 |
| `Runtime.getRuntime().exec()` | 严重 | 同上 |
| `ProcessBuilder.start()` | 严重 | 更灵活的命令执行 |
| `ProcessBuilder.command()` | 严重 | 命令拼接 |
| `ScriptEngine.eval()` | 严重 | JS/Groovy/SpEL脚本执行 |
| `ScriptEngineManager.getEngineByName().eval()` | 严重 | 同上 |
| `GroovyShell.evaluate()` | 严重 | Groovy代码执行 |
| `GroovyClassLoader.parseClass()` | 严重 | 动态加载Groovy类 |
| `javax.script.Compilable.compile()` | 高危 | 脚本编译执行 |
| `Method.invoke()` | 高危 | 反射调用任意方法 |
| `Class.forName().newInstance()` | 高危 | 动态类加载 |
| `ClassLoader.loadClass()` | 高危 | 自定义类加载 |
| `Unsafe.allocateInstance()` | 高危 | 绕过构造方法实例化 |
| `ExpressionFactory.createValueExpression().getValue()` | 严重 | JUEL/EL表达式执行 |
| `ELProcessor.eval()` | 严重 | EL表达式执行 |

## SpEL / 表达式注入

| 函数/方法 | 风险等级 | 说明 |
|-----------|---------|------|
| `SpelExpressionParser.parseExpression()` | 严重 | Spring SpEL解析 |
| `StandardEvaluationContext` | 严重 | SpEL标准上下文，可执行代码 |
| `SimpleEvaluationContext` | 低危 | 受限上下文，安全 |
| `Expression.getValue()` | 严重 | 执行解析后的表达式 |
| `Expression.setValue()` | 高危 | 表达式赋值 |
| `@Value("#{...}")` | 高危 | 注解中的SpEL |
| `@PreAuthorize("#{...}")` | 高危 | 安全注解中的SpEL |
| `@Query("#{...}")` | 严重 | 查询注解中的SpEL |
| `Spring Data REST SpEL` | 严重 | REST端点SpEL |

## 反序列化

| 函数/方法 | 风险等级 | 说明 |
|-----------|---------|------|
| `ObjectInputStream.readObject()` | 严重 | Java原生反序列化 |
| `ObjectInputStream.readUnshared()` | 严重 | 同上 |
| `XStream.fromXML()` | 严重 | XML反序列化 |
| `XStream.toXML()` | 中危 | 序列化（信息泄露） |
| `JSON.parseObject()` (Fastjson) | 严重 | Fastjson反序列化 |
| `JSON.parse()` (Fastjson) | 严重 | 同上 |
| `JSONObject.parseObject()` | 严重 | 同上 |
| `ObjectMapper.readValue()` (Jackson) | 高危 | 配置不当导致RCE |
| `ObjectMapper.enableDefaultTyping()` | 严重 | 开启默认类型 |
| `@JsonTypeInfo` 配置不当 | 高危 | Jackson多态反序列化 |
| `Yaml.load()` (SnakeYAML) | 严重 | YAML反序列化RCE |
| `SerializationUtils.deserialize()` | 严重 | Spring序列化工具 |
| `HessianInput.readObject()` | 严重 | Hessian协议反序列化 |
| `Hessian2Input.readObject()` | 严重 | 同上 |
| `Kryo.readClassAndObject()` | 严重 | Kryo反序列化 |
| `JYaml.load()` | 严重 | YAML反序列化 |
| `XMLDecoder.readObject()` | 严重 | XML反序列化 |
| `readResolve()` / `readObject()` | 高危 | 自定义反序列化方法 |

## XML / XXE

| 函数/方法 | 风险等级 | 说明 |
|-----------|---------|------|
| `DocumentBuilder.parse()` | 高危 | 默认解析外部实体 |
| `DocumentBuilderFactory.newDocumentBuilder()` | 高危 | 需禁用DTD |
| `SAXParser.parse()` | 高危 | 同上 |
| `SAXParserFactory.newSAXParser()` | 高危 | 同上 |
| `XMLReader.parse()` | 高危 | 同上 |
| `XMLInputFactory.createXMLStreamReader()` | 高危 | StAX解析 |
| `Transformer.transform()` | 高危 | XSLT转换 |
| `SchemaFactory.newSchema()` | 中危 | Schema验证 |
| `Validator.validate()` | 中危 | XML验证 |
| `XPath.evaluate()` | 高危 | XPath注入 |
| `SAXReader.read()` (dom4j) | 高危 | 默认解析外部实体 |
| `Digester.parse()` (Apache Commons) | 高危 | 同上 |

## 文件操作

| 函数/方法 | 风险等级 | 说明 |
|-----------|---------|------|
| `FileInputStream()` | 高危 | 路径穿越 |
| `FileOutputStream()` | 高危 | 任意文件写入 |
| `FileReader()` | 高危 | 路径穿越读取 |
| `FileWriter()` | 高危 | 任意文件写入 |
| `RandomAccessFile()` | 高危 | 读写任意文件 |
| `Paths.get()` | 高危 | 路径拼接 |
| `File.createTempFile()` | 中危 | 临时文件安全 |
| `Files.copy()` | 高危 | 文件复制 |
| `Files.move()` | 高危 | 文件移动 |
| `Files.delete()` | 中危 | 文件删除 |
| `Files.readAllBytes()` | 高危 | 任意文件读取 |
| `Files.write()` | 高危 | 任意文件写入 |
| `File.renameTo()` | 中危 | 文件重命名 |
| `File.delete()` | 中危 | 文件删除 |
| `ZipInputStream.getNextEntry()` | 高危 | Zip Slip |
| `ZipFile.getInputStream()` | 高危 | 同上 |
| `JarInputStream.getNextJarEntry()` | 高危 | Jar Slip |
| `MultipartFile.transferTo()` | 高危 | 文件上传 |
| `MultipartFile.getInputStream()` | 高危 | 上传文件读取 |
| `ServletContext.getRealPath()` | 中危 | 路径获取 |

## SSRF

| 函数/方法 | 风险等级 | 说明 |
|-----------|---------|------|
| `URL.openConnection()` | 高危 | 打开任意URL |
| `URL.openStream()` | 高危 | 同上 |
| `HttpURLConnection.connect()` | 高危 | HTTP请求 |
| `HttpClient.execute()` | 高危 | Apache HttpClient |
| `HttpClient.send()` | 高危 | Java 11+ HttpClient |
| `RestTemplate.getForObject()` | 高危 | Spring REST请求 |
| `RestTemplate.exchange()` | 高危 | 同上 |
| `WebClient.get()` (WebFlux) | 高危 | 响应式HTTP请求 |
| `OpenConnection` 子类 | 高危 | FTP/SMB/JAR协议 |
| `ImageIO.read()` | 高危 | 图片URL请求 |
| `JdbcTemplate.execute()` | 高危 | JDBC URL连接（H2/hsqldb RCE） |
| `DriverManager.getConnection()` | 高危 | JDBC连接 |
| `JNDI.lookup()` | 严重 | JNDI注入 |
| `InitialContext.lookup()` | 严重 | 同上 |
| `Naming.lookup()` | 严重 | RMI/JNDI lookup |
| `RMIConnector.connect()` | 严重 | RMI连接 |

## 模板注入 (SSTI)

| 函数/方法 | 风险等级 | 说明 |
|-----------|---------|------|
| `Velocity.evaluate()` | 严重 | Velocity模板执行 |
| `VelocityEngine.evaluate()` | 严重 | 同上 |
| `Template.merge()` | 严重 | Velocity模板合并 |
| `FreeMarkerTemplateUtils.processTemplateIntoString()` | 严重 | FreeMarker执行 |
| `Configuration.getTemplate().process()` | 严重 | 同上 |
| `TemplateEngine.process()` (Thymeleaf) | 高危 | Thymeleaf模板 |
| `ITemplateEngine.process()` | 高危 | 同上 |
| `StringTemplateLoader.putTemplate()` | 高危 | 动态模板加载 |
| `PebbleEngine.getTemplate().evaluate()` | 严重 | Pebble模板 |
| `Handlebars.compile().apply()` | 严重 | Handlebars模板 |
| `Mustache.compile().execute()` | 高危 | Mustache模板 |

## JNDI / LDAP 注入

| 函数/方法 | 风险等级 | 说明 |
|-----------|---------|------|
| `InitialDirContext.search()` | 严重 | LDAP查询 |
| `InitialLdapContext.search()` | 严重 | 同上 |
| `LdapTemplate.search()` (Spring) | 严重 | 同上 |
| `LdapTemplate.authenticate()` | 高危 | LDAP认证注入 |
| `DirContext.search()` | 严重 | JNDI目录搜索 |
| `Context.lookup()` | 严重 | JNDI lookup |
| `Registry.lookup()` | 严重 | RMI registry |

## 输出 / XSS

| 函数/方法 | 风险等级 | 说明 |
|-----------|---------|------|
| `PrintWriter.print()` / `println()` | 高危 | Servlet直接输出 |
| `ServletOutputStream.write()` | 高危 | 字节流输出 |
| `HttpServletResponse.getWriter().write()` | 高危 | 响应输出 |
| `ModelAndView.addObject()` | 中危 | 模板变量（依赖模板引擎） |
| `Model.addAttribute()` | 中危 | 同上 |
| `request.setAttribute()` | 中危 | 请求属性传递 |
| `JspWriter.print()` | 高危 | JSP直接输出 |
| `out.print()` (JSP) | 高危 | 同上 |
| `<%= ... %>` (JSP表达式) | 高危 | JSP表达式输出 |
| `${...}` (EL表达式) | 高危 | 未转义的EL |
| `c:out` (JSTL) | 低危 | 默认转义 |
| `fn:escapeXml()` | 低危 | 安全转义函数 |

## 日志 / 信息泄露

| 函数/方法 | 风险等级 | 说明 |
|-----------|---------|------|
| `Logger.info()` / `debug()` | 中危 | 日志中记录敏感信息 |
| `System.out.println()` | 低危 | 标准输出泄露 |
| `e.printStackTrace()` | 中危 | 堆栈信息泄露 |
| `Throwable.printStackTrace()` | 中危 | 同上 |
| `getClass().getName()` | 低危 | 类名信息泄露 |
| `Object.toString()` | 低危 | 对象信息泄露 |
| `System.getenv()` | 中危 | 环境变量读取 |
| `System.getProperty()` | 中危 | 系统属性读取 |
| `InetAddress.getLocalHost()` | 低危 | 内网信息泄露 |

## 加密 / 随机数

| 函数/方法 | 风险等级 | 说明 |
|-----------|---------|------|
| `Random.nextInt()` | 中危 | 伪随机数，可预测 |
| `Math.random()` | 中危 | 同上 |
| `SecureRandom` | 低危 | 密码学安全随机数 ✅ |
| `MessageDigest.getInstance("MD5")` | 高危 | 弱哈希 |
| `MessageDigest.getInstance("SHA1")` | 中危 | 弱哈希 |
| `Cipher.getInstance("DES")` | 严重 | 弱加密算法 |
| `Cipher.getInstance("AES/ECB/...")` | 高危 | ECB模式不安全 |
| `KeyPairGenerator.getInstance("RSA")` 低密钥长度 | 高危 | 密钥长度过短 |
| `Base64.getEncoder()` | 低危 | 仅编码非加密 |
| `new String(password)` | 中危 | 密码以String存储 |
| `char[]` 密码存储 | 低危 | 推荐做法 ✅ |

## 反射 / 动态加载

| 函数/方法 | 风险等级 | 说明 |
|-----------|---------|------|
| `Class.forName()` | 高危 | 动态加载类 |
| `ClassLoader.loadClass()` | 高危 | 同上 |
| `Method.invoke()` | 高危 | 反射调用方法 |
| `Constructor.newInstance()` | 高危 | 反射创建实例 |
| `Field.set()` / `Field.get()` | 高危 | 反射修改/读取字段 |
| `Array.newInstance()` | 中危 | 动态数组创建 |
| `Proxy.newProxyInstance()` | 中危 | 动态代理 |
| `Instrumentation.retransformClasses()` | 高危 | 类字节码修改 |
| `Unsafe` 类操作 | 严重 | 绕过安全检查 |

## 不安全的配置

| 配置项 | 风险等级 | 说明 |
|--------|---------|------|
| `spring.http.multipart.enabled=true` | 中危 | 文件上传开启 |
| `server.error.include-stacktrace=always` | 中危 | 堆栈信息泄露 |
| `management.endpoints.web.exposure.include=*` | 严重 | Actuator全暴露 |
| `spring.devtools.restart.enabled=true` | 高危 | 热加载（生产环境） |
| `spring.data.rest.basePath` | 中危 | REST路径配置 |
| `logging.level.root=DEBUG` | 低危 | 调试日志泄露 |
| `debug=true` (Spring Boot) | 中危 | 调试模式 |
| `spring.jackson.serialization.write-dates-as-timestamps` | 低危 | 日期格式 |
| `spring.datasource.url` 包含密码 | 严重 | 明文数据库密码 |
| `spring.mail.password` | 严重 | 明文邮件密码 |
