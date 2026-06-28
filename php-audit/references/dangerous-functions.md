# PHP危险函数速查表

## SQL注入相关函数

| 函数/方法 | 风险等级 | 说明 |
|-----------|---------|------|
| `mysql_query()` | 严重 | PHP 5.5已废弃，无参数化支持 |
| `mysqli_query()` | 高危 | 需配合预处理语句使用时才安全 |
| `mysqli_multi_query()` | 严重 | 支持多条语句，易导致堆叠注入 |
| `PDO::query()` | 高危 | 绕过参数化绑定时危险 |
| `PDO::exec()` | 高危 | 返回受影响行数，无参数化 |
| `DB::select(DB::raw())` | 高危 | Laravel原生查询，绕过Eloquent防护 |
| `DB::statement()` | 高危 | Laravel原生语句执行 |
| `whereRaw()` / `orderRaw()` | 高危 | ThinkPHP原生查询 |
| `Db::raw()` | 高危 | ThinkPHP原生查询 |
| `create_function()` | 高危 | 内部使用eval，PHP 7.2+废弃 |
| `mysql_set_charset('gbk')` | 中危 | 存在宽字节注入风险 |

## 命令/代码执行函数

| 函数 | 风险等级 | 说明 |
|------|---------|------|
| `eval()` | 严重 | 执行任意PHP代码 |
| `assert()` | 严重 | PHP 7.2前可执行代码（字符串模式） |
| `preg_replace('/e')` | 严重 | /e修饰符执行代码，PHP 7.0移除 |
| `create_function()` | 严重 | PHP 7.2废弃，内部eval |
| `exec()` | 严重 | 执行系统命令，返回最后一行 |
| `shell_exec()` (\`\`) | 严重 | 执行系统命令，返回全部输出 |
| `system()` | 严重 | 执行系统命令，直接输出 |
| `passthru()` | 严重 | 执行系统命令，输出原始二进制 |
| `popen()` | 高危 | 单向管道执行命令 |
| `proc_open()` | 高危 | 更灵活的命令执行 |
| `pcntl_exec()` | 高危 | 当前进程替换执行 |
| `call_user_func()` | 高危 | 动态调用，可作为利用链环节 |
| `call_user_func_array()` | 高危 | 同上 |
| `array_map()` | 中危 | 配合恶意回调函数 |
| `array_filter()` | 中危 | 同上 |
| `usort()` / `uksort()` | 中危 | PHP 8.0前可传入字符串回调 |

## 文件操作函数

| 函数 | 风险等级 | 说明 |
|------|---------|------|
| `include()` | 高危 | 动态包含导致LFI/RFI |
| `include_once()` | 高危 | 同上 |
| `require()` | 高危 | 同上 |
| `require_once()` | 高危 | 同上 |
| `file_get_contents()` | 高危 | 可读任意文件/SSRF |
| `fopen()` | 高危 | 可打开远程文件 |
| `readfile()` | 高危 | 读取并输出文件 |
| `file()` | 中危 | 读取文件到数组 |
| `parse_ini_file()` | 中危 | 读取ini文件 |
| `fgets()` | 中危 | 逐行读取 |
| `move_uploaded_file()` | 高危 | 文件上传写入 |
| `rename()` | 中危 | 文件重命名/移动 |
| `unlink()` | 中危 | 文件删除 |
| `copy()` | 中危 | 文件复制 |
| `file_put_contents()` | 高危 | 文件写入 |
| `fwrite()` / `fputs()` | 高危 | 文件写入 |
| `chmod()` | 中危 | 权限修改 |

## 输出函数（XSS相关）

| 函数 | 风险等级 | 说明 |
|------|---------|------|
| `echo` | 高危 | 未转义直接输出导致XSS |
| `print` | 高危 | 同上 |
| `printf()` | 高危 | 格式化输出，参数可控时危险 |
| `vprintf()` | 高危 | 同上 |
| `print_r()` | 中危 | 变量打印 |
| `var_dump()` | 中危 | 变量调试输出 |
| `var_export()` | 中危 | 变量导出 |
| `<?=` | 高危 | 短标签输出 |
| `exit()` / `die()` | 中危 | 参数内容可被输出 |

## 反序列化相关

| 函数/魔术方法 | 风险等级 | 说明 |
|--------------|---------|------|
| `unserialize()` | 严重 | 用户可控数据反序列化 |
| `__destruct()` | 高危 | 反序列化自动触发 |
| `__wakeup()` | 高危 | 反序列化自动触发 |
| `__toString()` | 高危 | 对象转字符串触发 |
| `__call()` | 高危 | 调用不可访问方法触发 |
| `__get()` / `__set()` | 高危 | 访问不可访问属性触发 |
| `__invoke()` | 高危 | 对象作为函数调用触发 |
| `SoapClient()` | 高危 | 原生类SSRF利用 |
| `SimpleXMLElement()` | 中危 | XXE利用 |

## XXE相关函数

| 函数 | 风险等级 | 说明 |
|------|---------|------|
| `simplexml_load_string()` | 高危 | 默认解析外部实体 |
| `simplexml_load_file()` | 高危 | 默认解析外部实体 |
| `DOMDocument::loadXML()` | 高危 | 默认解析外部实体 |
| `DOMDocument::load()` | 高危 | 默认解析外部实体 |
| `SimpleXMLElement()` | 高危 | 默认解析外部实体 |
| `xml_parse()` | 高危 | 默认解析外部实体 |
| `XMLReader::read()` | 中危 | 配置不当可导致XXE |

## SSRF相关函数

| 函数 | 风险等级 | 说明 |
|------|---------|------|
| `curl_exec()` | 高危 | URL用户可控时危险 |
| `curl_setopt(CURLOPT_URL)` | 高危 | URL用户可控时危险 |
| `file_get_contents()` | 高危 | `allow_url_fopen=On`时 |
| `fsockopen()` | 高危 | 可连接任意主机端口 |
| `readfile()` | 中危 | 远程文件读取 |
| `get_headers()` | 中危 | HTTP头请求 |

## 文件上传相关

| 函数 | 风险等级 | 说明 |
|------|---------|------|
| `move_uploaded_file()` | 高危 | 上传文件写入 |
| `$_FILES` | 高危 | 文件上传入口 |
| `finfo_file()` / `mime_content_type()` | 中危 | MIME类型检测，可被绕过 |
| `exif_imagetype()` | 中危 | 图片类型检测 |
| `getimagesize()` | 中危 | 图片尺寸检测，可执行PHP代码 |
| `pathinfo()` | 中危 | 路径信息获取，可能被绕过 |
| `basename()` | 中危 | 路径操作 |
