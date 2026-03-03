package database

import (
	"context"
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"
)

type Wrapper struct {
	*sqlx.DB
}

func NewWrapper(db *sqlx.DB) *Wrapper {
	return &Wrapper{db}
}

func (w *Wrapper) Transaction(ctx context.Context, fn func(ctx context.Context, tx Queryer) error) error {
	tx, err := w.DB.BeginTxx(ctx, nil)
	if err != nil {
		return err
	}

	defer func() {
		if r := recover(); r != nil {
			_ = tx.Rollback()
			panic(r)
		}
	}()

	if err := fn(ctx, tx); err != nil {
		_ = tx.Rollback()
		return err
	}

	return tx.Commit()
}

func (w *Wrapper) Begin() (*sqlx.Tx, error) {
	return w.DB.Beginx()
}

func (w *Wrapper) Commit(tx *sqlx.Tx) error {
	return tx.Commit()
}

func (w *Wrapper) Rollback(tx *sqlx.Tx) error {
	return tx.Rollback()
}

func (w *Wrapper) SelectContext(ctx context.Context, dest any, query string, args ...any) error {
	return w.DB.SelectContext(ctx, dest, query, args...)
}

func (w *Wrapper) GetContext(ctx context.Context, dest any, query string, args ...any) error {
	return w.DB.GetContext(ctx, dest, query, args...)
}

func (w *Wrapper) Insert(ctx context.Context, table string, data map[string]any) error {
	if len(data) == 0 {
		return fmt.Errorf("insert data cannot be empty")
	}

	columns := make([]string, 0, len(data))
	placeholders := make([]string, 0, len(data))

	for col := range data {
		columns = append(columns, col)
		placeholders = append(placeholders, ":"+col)
	}

	query := fmt.Sprintf(
		"INSERT INTO %s (%s) VALUES (%s)",
		table,
		strings.Join(columns, ", "),
		strings.Join(placeholders, ", "),
	)

	_, err := w.DB.NamedExecContext(ctx, query, data)
	return err
}
