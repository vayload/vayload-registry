package logger

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

func RedactEmail(email string) string {
	if email == "" {
		return ""
	}

	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return "***@***.***"
	}

	local := parts[0]
	domain := parts[1]

	maskedLocal := maskString(local)

	domainParts := strings.Split(domain, ".")
	if len(domainParts) >= 2 {
		maskedDomain := maskString(domainParts[0])
		tld := domainParts[len(domainParts)-1]
		return maskedLocal + "@" + maskedDomain + "." + tld
	}

	return maskedLocal + "@" + maskString(domain)
}

func RedactIP(ipStr string) string {
	if ipStr == "" {
		return ""
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "xxx.xxx.xxx.xxx"
	}

	if ip4 := ip.To4(); ip4 != nil {
		return fmt.Sprintf("%d.%d.xxx.xxx", ip4[0], ip4[1])
	}

	if ip.To16() != nil {
		parts := strings.Split(ipStr, ":")
		if len(parts) >= 4 {
			return strings.Join(parts[:4], ":") + ":xxxx:xxxx:xxxx:xxxx"
		}
	}

	return "xxx.xxx.xxx.xxx"
}

func HashForLog(value string) string {
	if value == "" {
		return ""
	}
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])[:12]
}

func maskString(s string) string {
	if len(s) <= 2 {
		return "***"
	}
	return string(s[0]) + "***" + string(s[len(s)-1])
}

func RedactToken(token string) string {
	if len(token) <= 8 {
		return "********"
	}
	return token[:4] + "..." + token[len(token)-4:]
}

func RedactUserAgent(ua string) string {
	if ua == "" {
		return ""
	}
	if len(ua) > 50 {
		return ua[:50] + "..."
	}
	return ua
}

func SensitiveFields(fields Fields) Fields {
	redacted := make(Fields, len(fields))
	for k, v := range fields {
		switch k {
		case "email", "user_email", "Email":
			if s, ok := v.(string); ok {
				redacted[k] = RedactEmail(s)
			} else {
				redacted[k] = v
			}
		case "ip", "ip_address", "IP", "client_ip":
			if s, ok := v.(string); ok {
				redacted[k] = RedactIP(s)
			} else {
				redacted[k] = v
			}
		case "token", "access_token", "refresh_token", "api_key":
			if s, ok := v.(string); ok {
				redacted[k] = RedactToken(s)
			} else {
				redacted[k] = v
			}
		case "password", "secret", "credential":
			redacted[k] = "[REDACTED]"
		default:
			redacted[k] = v
		}
	}
	return redacted
}
