//go:build !postgres

package persistence

import (
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

func NewConnection(url string) (*sqlx.DB, error) {
	return sqlx.Connect("sqlite3", url)
}
