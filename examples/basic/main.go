package main

import (
	"fmt"
	"log"

	"github.com/GoFurry/coraza-fiber-lite"
	"github.com/gofiber/fiber/v2"
)

// ====================================================================
// Example: Basic usage of CorazaLite global WAF middleware in Fiber
// 示例: 在 Fiber 应用中使用 CorazaLite 全局 WAF 中间件
//
// This example demonstrates how to initialize and use the global
// Coraza WAF middleware in a Fiber application.
//
// 本示例演示了如何在 Fiber 应用中初始化并使用
// CorazaLite 提供的全局 WAF 中间件
//
// NOTE:
// The coraza.conf file under the conf directory contains multiple
// security rules and corresponding curl-based attack test cases
// (e.g. SQLi, XSS, command injection) for validation.
//
// 注意:
// conf/coraza.conf 中已包含多种安全规则, 并配套编写了
// 多个 curl 攻击测试用例(如 SQL 注入、XSS、命令注入等)
// 可直接用于验证 WAF 拦截效果
//
// Test cmd(see more in coraza.conf):
// curl "http://localhost:8080/?id=1 OR 1=1"
// curl -X POST http://localhost:8080/submit \
//  -H "Content-Type: application/x-www-form-urlencoded" \
//  -d "name=<script>alert(1)</script>"
// ====================================================================

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
		DirectivesFile: []string{"./conf/coraza.conf"},

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
