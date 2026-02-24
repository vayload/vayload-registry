package utils

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/goccy/go-json"
)

func DumpJson[T any](v T) {
	js, _ := json.MarshalIndent(v, "", "  ")
	fmt.Printf("%s", string(js))
}

func NormalizePhone(raw string, withPlus bool) (string, error) {
	if raw == "" {
		return "", errors.New("phone is empty")
	}

	clean := strings.Map(func(r rune) rune {
		if unicode.IsDigit(r) || r == '+' {
			return r
		}
		return -1
	}, raw)

	clean = strings.TrimPrefix(clean, "+")

	if clean == "" {
		return "", errors.New("phone missing digits")
	}

	if withPlus {
		return "+" + clean, nil
	}

	return clean, nil
}
