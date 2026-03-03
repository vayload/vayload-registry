//go:build !turso
// +build !turso

package database

import (
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

func NewConnection(url string) (*Wrapper, error) {
	db, err := sqlx.Connect("sqlite3", url)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	return NewWrapper(db), nil
}
