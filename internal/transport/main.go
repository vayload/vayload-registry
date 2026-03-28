package transport

import (
	"context"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/vayload/plug-registry/config"
	"github.com/vayload/plug-registry/internal/domain"
	"github.com/vayload/plug-registry/internal/infrastructure/database"
	"github.com/vayload/plug-registry/internal/infrastructure/events"
	"github.com/vayload/plug-registry/internal/infrastructure/persistence"
	"github.com/vayload/plug-registry/internal/infrastructure/security"
	"github.com/vayload/plug-registry/internal/infrastructure/storage"
	"github.com/vayload/plug-registry/internal/services"
	"github.com/vayload/plug-registry/internal/services/packager"
	"github.com/vayload/plug-registry/internal/services/processors"
	unitofwork "github.com/vayload/plug-registry/internal/services/unit-of-work"
	"github.com/vayload/plug-registry/internal/shared/container"
	"github.com/vayload/plug-registry/internal/transport/controllers"
	"github.com/vayload/plug-registry/pkg/email"
	"github.com/vayload/plug-registry/pkg/httpi"
	"github.com/vayload/plug-registry/pkg/queue"
)

func Register(httpServer *fiber.App, cfg *config.Config, container *container.Container, db *database.Wrapper, queue queue.Queue) error {
	hasher := security.NewScryptHasher()
	jwtManager, err := security.NewJwtManager(
		cfg.Security.JwtPrivateKey,
		cfg.Security.JwtPublicKey,
		time.Duration(cfg.Security.JwtExpirationTime)*time.Minute,
		time.Duration(cfg.Security.JwtRefreshExpirationDays)*time.Hour*24,
	)
	if err != nil {
		return fmt.Errorf("Fails to created jwt manager: %w", err)
	}

	container.Set(security.JWT_SERVICE_NAME, jwtManager)

	pluginStorage, err := storage.NewStorage(storage.StorageConfig{
		S3Endpoint:  cfg.Storage.R2Endpoint,
		S3AccessKey: cfg.Storage.R2AccessKey,
		S3SecretKey: cfg.Storage.R2SecretKey,
		BucketName:  cfg.Storage.BucketName,
		// For local (used in test)
		BaseLocalPath:   cfg.Storage.LocalDir,
		LocalHMACSecret: cfg.Storage.LocalSecretKey,
		LocalEndpoint:   cfg.Storage.LocalEndpoint,
	})
	if err != nil {
		return fmt.Errorf("fail to start storage manager: %w", err)
	}

	container.Set(storage.SERVICE_NAME, pluginStorage)

	userRepo := persistence.NewUserRepository(db)
	pluginRepo := persistence.NewPluginRepository(db)
	tokenRepo := persistence.NewApiTokenRepository(db)
	objectRepo := persistence.NewObjectsRepository(db)

	// Email and Queue setup
	verifier := security.NewVerificationTokenManager(cfg.Security.JwtPrivateKeyBase64) // Using existing key as secret

	oauthStrategy := security.NewOAuthStrategy(cfg)
	authService := services.NewAuthService(
		userRepo,
		tokenRepo,
		hasher,
		oauthStrategy,
		jwtManager,
		verifier,
		queue,
	)

	uow := unitofwork.NewUnitOfWork(db, func(q database.Queryer) *unitofwork.RepositoryProvider {
		return &unitofwork.RepositoryProvider{
			Plugins: persistence.NewPluginRepository(q),
			Objects: persistence.NewObjectsRepository(q),
		}
	})
	pluginService := services.NewPluginService(pluginRepo, objectRepo, pluginStorage, packager.NewDefaultPackager(), uow)
	userService := services.NewUserService(userRepo)
	statsService := services.NewStatsService(userRepo, pluginRepo)

	container.Set(services.AUTH_SERVICE_NAME, authService)

	authController := controllers.NewAuthController(authService, userService, statsService, container, cfg)
	pluginController := controllers.NewPluginController(pluginService, container)

	api := httpServer.Group("/v1")

	httpi.RegisterController(api, authController)
	httpi.RegisterController(api, pluginController)

	emailClient := email.NewResendClient(cfg.Email.ResendAPIKey, cfg.Email.FromEmail)
	consumers := []domain.QueueConsumers{
		processors.NewEmailProcessor(emailClient, processors.EmailProcessorConfig{
			BaseURL: cfg.Email.AppBaseURL,
			AppName: "Vayload Registry",
		}),
	}

	listener := events.NewQueueListener(consumers, queue)
	listener.Listen(context.Background())

	return nil
}
