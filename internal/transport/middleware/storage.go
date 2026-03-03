package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
)

func SignedURLMiddleware(secret []byte, basePath string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		key := c.Params("*")
		expStr := c.Query("exp")
		sig := c.Query("sig")

		exp, err := strconv.ParseInt(expStr, 10, 64)
		if err != nil {
			return fiber.ErrUnauthorized
		}

		if time.Now().Unix() > exp {
			return fiber.ErrUnauthorized
		}

		msg := fmt.Sprintf("%s:%d", key, exp)
		mac := hmac.New(sha256.New, secret)
		mac.Write([]byte(msg))
		expectedSig := base64.URLEncoding.EncodeToString(mac.Sum(nil))

		if !hmac.Equal([]byte(expectedSig), []byte(sig)) {
			return fiber.ErrUnauthorized
		}

		return c.SendFile(filepath.Join(basePath, key))
	}
}
