package utils

import (
	"os"
	"strings"
)

func FileExists(filename string) bool {
	_, err := os.Stat(filename)
	if err == nil {
		return true
	}

	if os.IsNotExist(err) {
		return false
	}

	return false
}

func FileExistsStartingWith(dir string, prefix string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}

	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), prefix) {
			return true, nil
		}
	}

	return false, nil
}
