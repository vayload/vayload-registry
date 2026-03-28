package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/helmet"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	httplogger "github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/vayload/plug-registry/config"
	cfg "github.com/vayload/plug-registry/config"
	"github.com/vayload/plug-registry/internal/infrastructure/database"
	"github.com/vayload/plug-registry/internal/shared/container"
	"github.com/vayload/plug-registry/internal/transport"
	"github.com/vayload/plug-registry/internal/transport/middleware"
	"github.com/vayload/plug-registry/pkg/httpi"
	"github.com/vayload/plug-registry/pkg/logger"
	"github.com/vayload/plug-registry/pkg/operator"
	"github.com/vayload/plug-registry/pkg/queue"
)

var WORKDIR = os.Getenv("WORKDIR")

// @title           Plug Registry API
// @version         1.0
// @description     Registry service for managing plugins.
// @host            localhost:8080
// @BasePath        /v1

// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization
func main() {
	// Load config
	cfg, err := config.GetConfig("config.toml")
	if err != nil {
		log.Fatal("Failed to load config: ", err)
	}

	logLevel := logger.ParseLevel(cfg.Server.LogLevel)
	logger.Init(logger.Config{
		Level:      logLevel,
		FilePath:   "./logs/app.log",
		MaxSize:    100,
		MaxBackups: 3,
		MaxAge:     28,
		Compress:   true,
		Console:    logLevel == logger.DebugLevel,
		TimeFormat: time.RFC3339,
	})

	appCtx := context.Background()

	container := container.New(appCtx)
	db, err := database.NewConnection(cfg.Database.URL)
	if err != nil {
		logger.F(err, logger.Fields{"context": "database connection started"})
	}

	msgQueue, err := queue.NewMessageQueue(queue.PersistentQueueConfig{
		BufferSize:     1024,
		WALPath:        filepath.Join(cfg.DataDir, "queue_wal.jsonl"),
		DeadLetterPath: filepath.Join(cfg.DataDir, "dlp_wal.jsonl"),
		MaxRetries:     2,
	})
	if err != nil {
		logger.F(err, logger.Fields{"context": "message queue creation"})
	}

	if err := msgQueue.Start(context.Background()); err != nil {
		logger.F(err, logger.Fields{"context": "Start msdQueue"})
	}

	container.Set(queue.SERVICE_NAME, msgQueue)
	container.Set(database.SERVICE_NAME, db)

	httpServer := CreateHttpServer(cfg)

	// Register the http transport of plugins and users
	if err := transport.Register(httpServer, cfg, container, db, msgQueue); err != nil {
		log.Fatal(err)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		fmt.Printf("Http server start listening in http://localhost:%d\n", cfg.Server.Port)
		if err := httpServer.Listen(fmt.Sprintf(":%d", cfg.Server.Port)); err != nil && err != http.ErrServerClosed {
			logger.F(err, logger.Fields{"context": "http_server"})
		}
	}()

	<-stop
	log.Println("Shutting down server...")

	// Flush resources in container (execute if object implement Closer interfaces or ContextCloser)
	container.Flush()
	msgQueue.Stop(appCtx)

	ctx, cancel := context.WithTimeout(appCtx, 5*time.Second)
	defer cancel()

	if err := httpServer.ShutdownWithContext(ctx); err != nil {
		log.Fatalf("Server Shutdown Failed:%+v", err)
	}

	log.Println("Server exited gracefully")
}

var startTime time.Time

func init() {
	startTime = time.Now().UTC()
}

const MaxBodySize = 60 * 1024 * 1024 // 60 MB

func CreateHttpServer(config *cfg.Config) *fiber.App {
	server := fiber.New(fiber.Config{
		AppName:               "vayload-registry",
		DisableStartupMessage: true,
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			return httpi.HttpErrorHandler(httpi.NewHttpRequest(c), httpi.NewHttpResponse(c), err)
		},
		JSONEncoder: json.Marshal,
		JSONDecoder: json.Unmarshal,
		// TrustedProxies:          config.Server.TrustedProxies,
		EnableTrustedProxyCheck: true, // Enable trusted proxy check for security
		BodyLimit:               MaxBodySize,
	})

	server.Use(httplogger.New())
	server.Use(cors.New(cors.Config{
		AllowOrigins:     strings.Join(config.Server.AllowOrigins, ","),
		AllowMethods:     "GET,POST,PUT,DELETE,OPTIONS,PATCH",
		AllowCredentials: true,
	}))
	server.Use(helmet.New())
	server.Use(httpi.FiberWrap(middleware.NewCsrfGuard()))
	server.Use(recover.New(recover.Config{
		EnableStackTrace: true,
		StackTraceHandler: func(c *fiber.Ctx, e interface{}) {
			err := fmt.Sprintf("panic: %v\n\n%s\n", e, debug.Stack())
			_, _ = os.Stderr.WriteString(err) //nolint:errcheck
			logger.E(errors.New(err), logger.Fields{"context": "panic-recover"})
		},
	}))

	// Global rate limiter
	server.Use(limiter.New(limiter.Config{
		Next: func(c *fiber.Ctx) bool {
			// For local development
			return c.IP() == "127.0.0.1"
		},
		Max:        100,
		Expiration: 30 * time.Second,
		KeyGenerator: func(c *fiber.Ctx) string {
			request := httpi.NewHttpRequest(c)
			if request.Auth() != nil && !request.Auth().UserId.IsZero() {
				return request.Auth().UserId.String()
			}

			return operator.Coalesce(
				request.GetHeader("x-forwarded-for"),
				request.GetHeader("x-real-ip"),
				request.GetIP(),
			)
		},
		LimitReached: func(c *fiber.Ctx) error {
			return httpi.ErrTooManyRequests(errors.New("rate limit exceeded"))
		},
	}))

	server.Get("/health", func(c *fiber.Ctx) error {
		uptime := time.Since(startTime).Truncate(time.Second).String()

		if strings.Contains(c.Get("Accept"), "text/html") {
			c.Set("Content-Type", "text/html")
			return c.Status(http.StatusOK).SendString(fmt.Sprintf(
				"<html><body><h2>Status: Healthy</h2><p>Uptime: %s</p></body></html>",
				uptime,
			))
		}

		return c.Status(http.StatusOK).JSON(fiber.Map{
			"status": "healthy",
			"uptime": uptime,
		})
	})

	return server
}
