// Copyright 2026 GoFurry
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package corazalite

import (
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/experimental"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"
)

// ==========================================================
// Global variables & initialization 全局变量与初始化
// ==========================================================

// globalWAF is the singleton instance of Coraza WAF
// Coraza WAF 的全局单例实例
var (
	globalWAF  coraza.WAF
	wafOnce    sync.Once
	wafInitErr error
)

// wafBlockMessage defines the response message returned when a request is blocked
// 定义请求被 WAF 拦截时返回的提示信息
var wafBlockMessage = "Request blocked by Web Application Firewall"

// InitWAFBlockMessage initializes custom block message (optional)
// InitWAFBlockMessage 用于初始化自定义拦截提示信息(可选)
func InitWAFBlockMessage(msg ...string) {
	if len(msg) > 0 && msg[0] != "" {
		wafBlockMessage = msg[0]
	}
}

// ==========================================================
// Configuration 配置结构体
// ==========================================================

// CorazaCfg defines the configuration of the WAF middleware | 定义 WAF 中间件的配置项
type CorazaCfg struct {
	// Core configuration
	// 核心配置
	DirectivesFile []string // WAF rule file path / WAF 规则文件路径
	RuleEngine     string   // Rule engine mode / 规则引擎模式
	RootFS         fs.FS    // Root filesystem / 规则文件使用的根文件系统

	// Request body configuration
	// 请求体配置
	RequestBodyAccess        bool
	RequestBodyLimit         int
	RequestBodyInMemoryLimit int

	// Response body configuration
	// 响应体配置
	ResponseBodyAccess    bool
	ResponseBodyLimit     int
	ResponseBodyMimeTypes []string

	// Logging configuration
	// 日志配置
	DebugLogger    debuglog.Logger
	EnableErrorLog bool
}

// DefaultCorazaCfg returns default configuration | 返回默认配置
func DefaultCorazaCfg() CorazaCfg {
	return CorazaCfg{
		DirectivesFile: []string{"./conf/coraza.conf"},
		RuleEngine:     "On",

		RequestBodyAccess:        true,
		RequestBodyLimit:         10 * 1024 * 1024,
		RequestBodyInMemoryLimit: 128 * 1024,

		ResponseBodyAccess:    false,
		ResponseBodyLimit:     512 * 1024,
		ResponseBodyMimeTypes: []string{"text/html", "text/plain", "application/json", "application/xml"},

		EnableErrorLog: true,
	}
}

// ==========================================================
// WAF Initialization 初始化
// ==========================================================

// InitGlobalWAFWithCfg initializes the global WAF using config | 使用配置初始化全局 WAF
func InitGlobalWAFWithCfg(cfg CorazaCfg) {
	wafOnce.Do(func() {
		globalWAF, wafInitErr = createWAFWithCfg(cfg)
		if wafInitErr != nil {
			slog.Error("[CorazaWAF] initialization failed", wafInitErr.Error())
		}
	})
}

// InitGlobalWAF initializes WAF with directive file path or default config | 使用规则文件路径或默认配置初始化 WAF
func InitGlobalWAF(path ...string) {
	if len(path) > 0 {
		InitGlobalWAFWithCfg(CorazaCfg{DirectivesFile: path})
	} else {
		InitGlobalWAFWithCfg(DefaultCorazaCfg())
	}
}

// ==========================================================
// Fiber Middleware 中间件实现
// ==========================================================

// CorazaMiddleware returns a Fiber handler with Coraza WAF enabled | 返回启用 Coraza WAF 的 Fiber 中间件
func CorazaMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if wafInitErr != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
				"code": 0,
				"msg":  "WAF initialization failed",
			})
		}

		if globalWAF == nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
				"code": 0,
				"msg":  "WAF instance not initialized",
			})
		}

		newTX := func(*http.Request) types.Transaction {
			return globalWAF.NewTransaction()
		}

		if ctxwaf, ok := globalWAF.(experimental.WAFWithOptions); ok {
			newTX = func(r *http.Request) types.Transaction {
				return ctxwaf.NewTransactionWithOptions(experimental.Options{
					Context: r.Context(),
				})
			}
		}

		stdReq, err := convertFasthttpToStdRequest(c)
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
				"code": 0,
				"msg":  "Failed to convert request",
			})
		}

		tx := newTX(stdReq)
		defer func() {
			if r := recover(); r != nil {
				slog.Error(fmt.Sprintf("WAF panic: %v", r))
			}
			tx.ProcessLogging()
			_ = tx.Close()
		}()

		if tx.IsRuleEngineOff() {
			return c.Next()
		}

		if it, err := processRequest(tx, stdReq); err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
				"code": 0,
				"msg":  "WAF request processing failed",
			})
		} else if it != nil {
			status := obtainStatusCodeFromInterruptionOrDefault(it, http.StatusForbidden)
			c.Set("X-WAF-Blocked", "true")
			return c.Status(status).JSON(fiber.Map{
				"code": 0,
				"msg":  wafBlockMessage,
			})
		}

		return c.Next()
	}
}

// ==========================================================
// Internal helpers 内部辅助方法
// ==========================================================

// logError handles matched WAF rules | 处理 WAF 规则命中日志
func logError(error types.MatchedRule) {
	slog.Warn("WAF rule matched",
		slog.String("severity", string(error.Rule().Severity())),
		slog.String("error_log", error.ErrorLog()),
		slog.Int("rule_id", error.Rule().ID()),
	)
}

// processRequest processes request through Coraza transaction | 使用 Coraza 事务处理请求
func processRequest(tx types.Transaction, req *http.Request) (*types.Interruption, error) {
	var client string
	var cport int

	if idx := strings.LastIndexByte(req.RemoteAddr, ':'); idx != -1 {
		client = req.RemoteAddr[:idx]
		cport, _ = strconv.Atoi(req.RemoteAddr[idx+1:])
	}

	tx.ProcessConnection(client, cport, "", 0)
	tx.ProcessURI(req.URL.String(), req.Method, req.Proto)

	for k, vr := range req.Header {
		for _, v := range vr {
			tx.AddRequestHeader(k, v)
		}
	}

	if req.Host != "" {
		tx.AddRequestHeader("Host", req.Host)
		tx.SetServerName(req.Host)
	}

	if req.TransferEncoding != nil {
		tx.AddRequestHeader("Transfer-Encoding", req.TransferEncoding[0])
	}

	if in := tx.ProcessRequestHeaders(); in != nil {
		return in, nil
	}

	if tx.IsRequestBodyAccessible() && req.Body != nil && req.Body != http.NoBody {
		it, _, err := tx.ReadRequestBodyFrom(req.Body)
		if err != nil {
			return nil, err
		}
		if it != nil {
			return it, nil
		}
		rbr, _ := tx.RequestBodyReader()
		req.Body = io.NopCloser(io.MultiReader(rbr, req.Body))
	}

	return tx.ProcessRequestBody()
}

// obtainStatusCodeFromInterruptionOrDefault determines HTTP status code | 根据拦截结果确定 HTTP 状态码
func obtainStatusCodeFromInterruptionOrDefault(it *types.Interruption, defaultStatusCode int) int {
	if it.Action == "deny" {
		if it.Status != 0 {
			return it.Status
		}
		return http.StatusForbidden
	}
	return defaultStatusCode
}

// convertFasthttpToStdRequest converts Fiber request to net/http request | 将 Fiber 请求转换为标准 HTTP 请求
func convertFasthttpToStdRequest(c *fiber.Ctx) (*http.Request, error) {
	req, err := adaptor.ConvertRequest(c, false)
	if err != nil {
		return nil, err
	}
	req.RemoteAddr = net.JoinHostPort(c.IP(), c.Port())
	if req.Host == "" {
		req.Host = c.Hostname()
	}
	return req, nil
}

// createWAFWithCfg creates a Coraza WAF instance | 根据配置创建 Coraza WAF 实例
func createWAFWithCfg(cfg CorazaCfg) (coraza.WAF, error) {

	for idx := range cfg.DirectivesFile {
		if _, err := os.Stat(cfg.DirectivesFile[idx]); err != nil {
			panic("WAF directives file not found")
		}
	}

	wafConfig := coraza.NewWAFConfig()

	if cfg.EnableErrorLog {
		wafConfig = wafConfig.WithErrorCallback(logError)
	}
	if cfg.RequestBodyAccess {
		wafConfig = wafConfig.WithRequestBodyAccess()
	}
	if cfg.RequestBodyLimit > 0 {
		wafConfig = wafConfig.WithRequestBodyLimit(cfg.RequestBodyLimit)
	}
	if cfg.RequestBodyInMemoryLimit > 0 {
		wafConfig = wafConfig.WithRequestBodyInMemoryLimit(cfg.RequestBodyInMemoryLimit)
	}
	if cfg.ResponseBodyAccess {
		wafConfig = wafConfig.WithResponseBodyAccess()
	}
	if cfg.ResponseBodyLimit > 0 {
		wafConfig = wafConfig.WithResponseBodyLimit(cfg.ResponseBodyLimit)
	}
	if len(cfg.ResponseBodyMimeTypes) > 0 {
		wafConfig = wafConfig.WithResponseBodyMimeTypes(cfg.ResponseBodyMimeTypes)
	}
	if cfg.RootFS != nil {
		wafConfig = wafConfig.WithRootFS(cfg.RootFS)
	}
	if cfg.DebugLogger != nil {
		wafConfig = wafConfig.WithDebugLogger(cfg.DebugLogger)
	}

	for idx := range cfg.DirectivesFile {
		wafConfig = wafConfig.WithDirectivesFromFile(cfg.DirectivesFile[idx])
	}
	return coraza.NewWAF(wafConfig)
}
