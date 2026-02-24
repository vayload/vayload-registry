//go:build postgres

package persistence

import (
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

func NewConnection(url string) (*sqlx.DB, error) {
	return sqlx.Connect("postgres", url)
}
