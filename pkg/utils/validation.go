package utils

import (
	"regexp"
	"strings"
)

func IsValidEmail(email string) bool {
	if email == "" {
		return false
	}
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}
	localPart, domain := parts[0], parts[1]
	if localPart == "" || domain == "" {
		return false
	}
	if strings.ContainsAny(localPart, " !\"#$%&'()*+,/:;<=>?@[\\]^`{|}~") {
		return false
	}
	if strings.Contains(domain, " ") || !strings.Contains(domain, ".") {
		return false
	}
	return true
}

func IsValidPhone(phone string) bool {
	if phone == "" {
		return false
	}
	if len(phone) < 3 || len(phone) > 15 {
		return false
	}

	e164Regex := `^\+?[1-9]\d{1,14}$`
	re := regexp.MustCompile(e164Regex)
	phone = strings.ReplaceAll(phone, " ", "")

	return re.Find([]byte(phone)) != nil
}
