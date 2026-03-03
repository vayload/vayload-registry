package persistence

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/goccy/go-json"
	"github.com/vayload/plug-registry/internal/domain"
	"github.com/vayload/plug-registry/internal/infrastructure/database"
)

type ObjectsRepository struct {
	database database.Queryer
}

func NewObjectsRepository(db database.Queryer) domain.ObjectRepository {
	return &ObjectsRepository{
		database: db,
	}
}

func (r *ObjectsRepository) UpsertObjects(ctx context.Context, objects []domain.BlobObject) error {
	if len(objects) == 0 {
		return nil
	}

	query := "INSERT OR REPLACE INTO storage_objects (id, type, size_bytes, mime_type, blob, created_at) VALUES "
	vals := []any{}

	placeholders := make([]string, 0, len(objects))
	for _, obj := range objects {
		placeholders = append(placeholders, "(?, ?, ?, ?, ?, ?)")
		vals = append(vals, obj.ObjectHash, obj.Type, obj.SizeBytes, obj.MimeType, obj.Blob, obj.CreatedAt)
	}

	query += fmt.Sprintf("%s;", strings.Join(placeholders, ","))
	_, err := r.database.ExecContext(ctx, query, vals...)
	return err
}

func (r *ObjectsRepository) GetObject(ctx context.Context, objectHash string) (*domain.BlobObject, error) {
	query := "SELECT id, type, size_bytes, mime_type, blob, created_at FROM storage_objects WHERE object_hash = ?"
	var obj domain.BlobObject
	err := r.database.QueryRowContext(ctx, query, objectHash).Scan(&obj.ObjectHash, &obj.Type, &obj.SizeBytes, &obj.MimeType, &obj.Blob, &obj.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &obj, nil
}

type ObjectModel struct {
	ObjectHash string    `db:"id"`
	Type       string    `db:"type"`
	SizeBytes  int64     `db:"size_bytes"`
	MimeType   string    `db:"mime_type"`
	Blob       []byte    `db:"blob"`
	CreatedAt  time.Time `db:"created_at"`
}

func (ob *ObjectModel) AsString() string {
	if ob.Blob == nil {
		return ""
	}
	return string(ob.Blob)
}

func (ob *ObjectModel) AsMap() (map[string]any, error) {
	if ob.Blob == nil {
		return nil, nil
	}
	var res map[string]any
	err := json.Unmarshal(ob.Blob, &res)
	return res, err
}

func (ob *ObjectModel) AsInterface() any {
	if ob.Blob == nil {
		return nil
	}

	switch {
	case strings.Contains(ob.MimeType, "json"):
		m, err := ob.AsMap()
		if err != nil {
			return ob.AsString()
		}
		return m
	case strings.HasPrefix(ob.MimeType, "text/"):
		return ob.AsString()
	default:
		return ob.Blob
	}
}
