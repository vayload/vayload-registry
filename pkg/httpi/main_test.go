package httpi

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	// Setup any global test configuration here

	// Run all tests
	code := m.Run()

	// Cleanup any global test resources here

	os.Exit(code)
}
