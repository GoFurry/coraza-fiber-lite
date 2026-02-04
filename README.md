# coraza-fiber-lite

[![Last Version](https://img.shields.io/github/releases/GoFurry/coraza-fiber-lite/all.svg?logo=github&color=brightgreen)](https://github.com/GoFurry/coraza-fiber-lite/releases)
[![License](https://img.shields.io/github/license/GoFurry/coraza-fiber-lite)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-%3E%3D1.24-blue)](go.mod)


Lightweight Coraza WAF middleware for Fiber, single-file and easy to use <br/>
轻量级 Coraza WAF 中间件, 专为 Fiber 设计, 单文件、即插即用

---

## 特性 | Features

* 全局 WAF 中间件, Fiber 即插即用
* Single-file design, easy to integrate with Fiber
* 基于 Coraza WAF, 兼容 OWASP CRS 规则
* Built on Coraza WAF, compatible with OWASP CRS rules
* 可自定义拦截信息
* Customizable block message

---

## 安装 | Installation

```bash
go get github.com/GoFurry/coraza-fiber-lite
```

---

## 🚀快速开始 | Quick Start

```go
func main() {
    // ----------------------------------------------------------------
    // Create Fiber application | 创建 Fiber 应用
    // ----------------------------------------------------------------
    app := fiber.New()
    
    // ----------------------------------------------------------------
    // Initialize global WAF instance | 初始化全局 WAF 实例
    //
    // You may pass a custom configuration here. | 支持在此处传入自定义配置
    // ----------------------------------------------------------------
    corazalite.InitGlobalWAFWithCfg(corazalite.CorazaCfg{
        // Path to Coraza directives file
        // Coraza 规则配置文件路径
		DirectivesFile: []string{
			"./conf/coraza.conf",
            "./conf/coreruleset-4.22.0-minimal/crs-setup.conf.example",
            "./conf/coreruleset-4.22.0-minimal/rules/*.conf",
        },
        
        // Enable request body inspection
        // 启用请求体检测
        RequestBodyAccess: true,
        
        // Disable response body inspection for better performance
        // 默认关闭响应体检测以提升性能
        ResponseBodyAccess: false,
    })
    
    // ----------------------------------------------------------------
    // Optional: Set custom block response message | 设置自定义拦截返回信息
    // ----------------------------------------------------------------
    corazalite.InitWAFBlockMessage("Request blocked by CorazaLite WAF")
    
    // ----------------------------------------------------------------
    // Register global WAF middleware | 注册全局 WAF 中间件
    // ----------------------------------------------------------------
    app.Use(corazalite.CorazaMiddleware())
    
    // ----------------------------------------------------------------
    // Example route: simple GET endpoint | 基础 GET 接口
    // ----------------------------------------------------------------
    app.Get("/", func(c *fiber.Ctx) error {
        return c.SendString("Hello, Fiber with CorazaLite WAF!")
    })
    
    // ----------------------------------------------------------------
    // Example route: POST endpoint | POST 接口
    // ----------------------------------------------------------------
    app.Post("/submit", func(c *fiber.Ctx) error {
        name := c.FormValue("name")
        return c.JSON(fiber.Map{
            "message": fmt.Sprintf("Received name: %s", name),
        })
    })
    
    // ----------------------------------------------------------------
    // Start Fiber HTTP server | 启动 Fiber HTTP 服务
    // ----------------------------------------------------------------
    port := 8080
    log.Printf("Fiber app running on http://localhost:%d\n", port)
    if err := app.Listen(fmt.Sprintf(":%d", port)); err != nil {
        log.Fatalf("Failed to start Fiber app: %v", err)
    }
}
```

---

## 🧭配置文件 | Configuration

`conf/coraza.conf` 示例:

```conf
# ===============================
# 基础配置 | Core Configuration
# ===============================
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off

SecRequestBodyLimit 10485760
SecRequestBodyNoFilesLimit 1048576

SecDebugLogLevel 6
SecDebugLog logs/debug.log
SecAuditEngine On
SecAuditLog logs/coraza.log
SecAuditLogParts ABIJDEFHZ

# ===============================
# 官方推荐规则 | Recommended Rules
# ===============================

# JSON 请求体解析 | JSON Body Parsing
SecRule REQUEST_HEADERS:Content-Type "^application/json" \
"id:210001,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON"

# 请求体解析失败拦截 | Deny if request body parsing fails
SecRule REQBODY_ERROR "!@eq 0" \
"id:210002,phase:2,log,deny,status:400,msg:'Failed to parse request body',severity:2"

# 参数数量限制 | Limit number of parameters
SecRule &ARGS "@gt 20" \
"id:210003,phase:2,deny,status:403,msg:'Too many parameters'"

# SQL 注入 | SQL Injection
SecRule ARGS "@rx (?i)(union\s+select|select.+from|insert\s+into|update.+set|delete\s+from|or\s+1=1|sleep\(|benchmark\()" \
"id:200002,phase:2,deny,status:403,msg:'SQL Injection detected'"

# XSS 攻击 | XSS Attack
SecRule ARGS "@rx (?i)(<script|<img|javascript:|onerror=|onload=|alert\()" \
"id:200003,phase:2,deny,status:403,msg:'XSS detected'"
```

> ⚠️ 注意：`DirectivesFile` 路径是相对于**启动程序时的工作目录**, 通常建议在 `example/basic` 目录下运行：
>
> ```bash
> cd example/basic
> go run .
> ```

---

## 测试 | Testing

### 1. 正常请求 | Normal request

```bash
curl http://localhost:8080/
```

返回 | Response:

```
Hello, Fiber with CorazaLite WAF!
```

### 2. POST 请求 | POST request

```bash
curl -X POST http://localhost:8080/submit \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=Faolan"
```

返回 | Response:

```json
{"message":"Received name: Faolan"}
```

### 3. 攻击测试 | WAF block test

#### SQL 注入测试 | SQL Injection

```bash
curl "http://localhost:8080/?id=1 OR 1=1"
```

#### XSS 测试 | XSS

```bash
curl -X POST http://localhost:8080/submit \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=<script>alert(1)</script>"
```

返回 | Response:

```
Request blocked by CorazaLite WAF
```

> 以上命令会触发 `coraza.conf` 中的拦截规则, 验证 WAF 生效。

---

## 📑Documentation References
- [Coraza Docs](https://coraza.io)
- [OWASP Core Ruleset](https://coraza.io/docs/tutorials/coreruleset)
- [Download OWASP Core Ruleset](https://github.com/coreruleset/coreruleset)
  
## 🐺License | 许可证

This project is open-sourced under the [Apache License 2.0](LICENSE)

