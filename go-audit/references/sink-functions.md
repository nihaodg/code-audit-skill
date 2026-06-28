# Go 危险函数（Sink）速查表

## SQL注入相关

| 函数/方法 | 风险等级 | 说明 |
|-----------|---------|------|
| `db.Query()` | 严重 | 字符串拼接SQL |
| `db.QueryRow()` | 严重 | 同上 |
| `db.Exec()` | 严重 | 同上 |
| `db.Prepare()` + 拼接 | 严重 | 预处理后仍拼接 |
| `gorm.DB.Raw()` | 严重 | 原生SQL拼接 |
| `gorm.DB.Where("..." + input)` | 严重 | GORM拼接 |
| `gorm.DB.Order(input)` | 高危 | ORDER BY拼接 |
| `gorm.DB.Group(input)` | 高危 | GROUP BY拼接 |
| `sqlx.DB.Queryx()` | 严重 | 拼接时危险 |
| `sqlx.NamedQuery()` | 高危 | 命名参数误用 |
| `ent.Client.Query()` | 中危 | ent框架通常安全 |
| `bun.DB.NewRaw()` | 严重 | Bun框架原生SQL |
| `fmt.Sprintf("SELECT...%s", input)` | 严重 | 字符串格式化拼接 |
| `strings.Join([]string{"SELECT...", input}, "")` | 严重 | 字符串拼接 |

## 命令执行

| 函数/方法 | 风险等级 | 说明 |
|-----------|---------|------|
| `exec.Command()` | 严重 | 执行系统命令 |
| `exec.CommandContext()` | 严重 | 带上下文的命令执行 |
| `exec.LookPath()` | 中危 | 路径查找 |
| `os.StartProcess()` | 严重 | 底层进程启动 |
| `syscall.Exec()` | 严重 | 系统调用执行 |
| `syscall.ForkExec()` | 严重 | 同上 |
| `plugin.Open()` | 高危 | 动态加载插件 |

## 代码执行 / 反射

| 函数/方法 | 风险等级 | 说明 |
|-----------|---------|------|
| `reflect.Value.Call()` | 高危 | 反射调用 |
| `reflect.MethodByName().Call()` | 高危 | 动态方法调用 |
| `reflect.New()` | 中危 | 动态创建实例 |
| `unsafe.Pointer()` | 严重 | 指针绕过类型安全 |
| `unsafe.Sizeof()` | 低危 | 仅获取大小 |
| `unsafe.Offsetof()` | 低危 | 仅获取偏移 |
| `unsafe.Alignof()` | 低危 | 仅获取对齐 |
| `yaegi.Eval()` | 严重 | Go解释器执行 |
| `go/ast` 动态解析 | 中危 | AST操作 |

## 反序列化

| 函数/方法 | 风险等级 | 说明 |
|-----------|---------|------|
| `json.Unmarshal()` | 高危 | 到interface{}风险 |
| `json.NewDecoder().Decode()` | 高危 | 流式解码 |
| `gob.NewDecoder().Decode()` | 严重 | Go原生序列化 |
| `gob.NewEncoder().Encode()` | 中危 | 序列化 |
| `proto.Unmarshal()` | 中危 | Protobuf通常安全 |
| `protojson.Unmarshal()` | 中危 | Protobuf JSON |
| `yaml.Unmarshal()` (gopkg.in/yaml.v2) | 严重 | YAML反序列化 |
| `yaml.v3.Unmarshal()` | 高危 | YAML反序列化 |
| `xml.Unmarshal()` | 高危 | XML反序列化 |
| `xml.NewDecoder().Decode()` | 高危 | 流式XML解码 |
| `bson.Unmarshal()` | 高危 | BSON反序列化 |
| `msgpack.Unmarshal()` | 高危 | MessagePack |

## XML / XXE

| 函数/方法 | 风险等级 | 说明 |
|-----------|---------|------|
| `xml.Unmarshal()` | 高危 | Go 1.17+已修复XXE |
| `xml.NewDecoder().Decode()` | 高危 | 同上 |
| `xml.NewDecoder().Token()` | 高危 | 手动Token解析 |
| `encoding/xml.Decoder` | 高危 | 自定义Decoder |

## 文件操作

| 函数/方法 | 风险等级 | 说明 |
|-----------|---------|------|
| `os.Open()` | 高危 | 路径穿越 |
| `os.Create()` | 高危 | 任意文件创建 |
| `os.OpenFile()` | 高危 | 打开任意文件 |
| `os.Remove()` | 中危 | 文件删除 |
| `os.Rename()` | 中危 | 文件重命名 |
| `ioutil.ReadFile()` | 高危 | 任意文件读取 |
| `ioutil.WriteFile()` | 高危 | 任意文件写入 |
| `os.ReadFile()` (Go 1.16+) | 高危 | 任意文件读取 |
| `os.WriteFile()` (Go 1.16+) | 高危 | 任意文件写入 |
| `filepath.Join()` | 高危 | 路径拼接（未校验时） |
| `filepath.Clean()` | 低危 | 路径清理 |
| `archive/zip.OpenReader()` | 高危 | Zip Slip |
| `archive/tar.NewReader()` | 高危 | Tar Slip |
| `io.Copy()` | 中危 | 文件复制 |

## SSRF

| 函数/方法 | 风险等级 | 说明 |
|-----------|---------|------|
| `http.Get()` | 高危 | 发送GET请求 |
| `http.Post()` | 高危 | 发送POST请求 |
| `http.PostForm()` | 高危 | 发送Form请求 |
| `http.Client.Do()` | 高危 | 自定义请求 |
| `http.NewRequest()` + `Client.Do()` | 高危 | 完整请求控制 |
| `url.Parse()` | 中危 | URL解析（需校验） |
| `net.Dial()` | 高危 | TCP连接 |
| `net.DialTCP()` | 高危 | TCP连接 |
| `tls.Dial()` | 高危 | TLS连接 |
| `grpc.Dial()` | 高危 | gRPC连接 |
| `smtp.SendMail()` | 高危 | SMTP连接 |
| `ftp.Dial()` | 高危 | FTP连接 |

## 模板注入 (SSTI)

| 函数/方法 | 风险等级 | 说明 |
|-----------|---------|------|
| `template.Execute()` (text/template) | 严重 | 文本模板可执行Go代码 |
| `template.ExecuteTemplate()` (text/template) | 严重 | 同上 |
| `template.Must(template.New().Parse())` | 严重 | 模板解析 |
| `html/template.Execute()` | 低危 | HTML模板默认转义 ✅ |
| `html/template.ExecuteTemplate()` | 低危 | 同上 |
| `pongo2.FromString().Execute()` | 严重 | Django风格模板 |
| `jet.Set.GetTemplate().Execute()` | 严重 | Jet模板引擎 |

## 输出 / XSS

| 函数/方法 | 风险等级 | 说明 |
|-----------|---------|------|
| `fmt.Fprintf(w, ...)` | 高危 | 直接写入响应 |
| `fmt.Fprint(w, ...)` | 高危 | 同上 |
| `w.Write([]byte(...))` | 高危 | 字节写入 |
| `c.String()` (Gin) | 高危 | 字符串响应 |
| `c.HTML()` (Gin) | 高危 | HTML响应 |
| `c.Data()` (Gin) | 中危 | 数据响应 |
| `c.JSON()` (Gin) | 低危 | JSON响应（需关注Content-Type） |
| `echo.Context.String()` | 高危 | Echo框架 |
| `echo.Context.HTML()` | 高危 | Echo框架 |
| `ctx.WriteString()` (Fiber) | 高危 | Fiber框架 |
| `ctx.Render()` (Fiber/Beego) | 高危 | 模板渲染 |
| `http.Error()` | 中危 | 错误响应 |

## 日志 / 信息泄露

| 函数/方法 | 风险等级 | 说明 |
|-----------|---------|------|
| `log.Printf()` | 中危 | 标准日志 |
| `log.Println()` | 中危 | 同上 |
| `fmt.Println()` | 低危 | 标准输出 |
| `zap.Logger.Info()` | 中危 | 结构化日志 |
| `logrus.Info()` | 中危 | 同上 |
| `debug.PrintStack()` | 中危 | 堆栈打印 |
| `runtime.Stack()` | 中危 | 获取堆栈 |
| `pprof` 端点 | 高危 | 性能分析端点 |

## 加密 / 随机数

| 函数/方法 | 风险等级 | 说明 |
|-----------|---------|------|
| `math/rand.Intn()` | 中危 | 伪随机数 |
| `math/rand.Seed()` | 中危 | 可预测种子 |
| `crypto/rand.Int()` | 低危 | 密码学安全 ✅ |
| `crypto/rand.Read()` | 低危 | 密码学安全 ✅ |
| `md5.Sum()` | 高危 | 弱哈希 |
| `sha1.Sum()` | 中危 | 弱哈希 |
| `crypto/sha256` | 低危 | 安全哈希 ✅ |
| `crypto/sha512` | 低危 | 安全哈希 ✅ |
| `bcrypt.GenerateFromPassword()` | 低危 | 安全密码哈希 ✅ |
| `scrypt.Key()` | 低危 | 安全密钥派生 ✅ |
| `argon2.IDKey()` | 低危 | 安全密钥派生 ✅ |
| `crypto/aes` ECB模式 | 严重 | ECB不安全 |
| `crypto/aes` GCM模式 | 低危 | 安全 ✅ |
| `crypto/tls.Config` InsecureSkipVerify | 严重 | 跳过证书验证 |

## 网络 / 通信

| 函数/方法 | 风险等级 | 说明 |
|-----------|---------|------|
| `net.Listen()` | 中危 | 监听端口 |
| `net/http.ListenAndServe()` | 中危 | HTTP服务（无TLS） |
| `net/http.ListenAndServeTLS()` | 低危 | HTTPS服务 ✅ |
| `cors.Default()` | 高危 | 默认允许所有来源 |
| `cors.New(cors.Options{AllowedOrigins: []string{"*"}})` | 高危 | CORS全开放 |
| `websocket.Upgrader.CheckOrigin` | 高危 | WebSocket来源校验 |

## 不安全的配置

| 配置项 | 风险等级 | 说明 |
|--------|---------|------|
| `gin.SetMode(gin.DebugMode)` | 中危 | 调试模式 |
| `gin.SetMode(gin.TestMode)` | 低危 | 测试模式 |
| `debug = true` | 中危 | 调试开关 |
| `GIN_MODE=debug` | 中危 | 环境变量调试 |
| `pprof` 未授权导入 | 严重 | 性能分析端点暴露 |
| `InsecureSkipVerify: true` | 严重 | TLS跳过验证 |
| `MaxHeaderBytes` 过小 | 低危 | 请求头限制 |
| `ReadTimeout` / `WriteTimeout` 未设置 | 中危 | 超时配置 |
