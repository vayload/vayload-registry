//go:build turso
// +build turso

package database

import (
	"database/sql"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/tursodatabase/go-libsql"
)

func NewConnection(url string) (*Wrapper, error) {
	connector, err := sql.Open("libsql", url)
	if err != nil {
		return nil, err
	}

	db := sqlx.NewDb(connector, "libsql")
	db.SetConnMaxIdleTime(9 * time.Second)

	return NewWrapper(db), nil
}
