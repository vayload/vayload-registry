package unitofwork

import (
	"context"

	"github.com/vayload/plug-registry/internal/domain"
	"github.com/vayload/plug-registry/internal/infrastructure/database"
)

type RepositoryProvider struct {
	Plugins domain.PluginRepository
	Objects domain.ObjectRepository
}

type RepositoryFactory func(database.Queryer) *RepositoryProvider

type UnitOfWork struct {
	db      database.Transactor
	factory RepositoryFactory
}

func NewUnitOfWork(db database.Transactor, factory RepositoryFactory) *UnitOfWork {
	return &UnitOfWork{
		db:      db,
		factory: factory,
	}
}

func (u *UnitOfWork) NewWork() *UnitOfWork {
	return NewUnitOfWork(u.db, u.factory)
}

func (u *UnitOfWork) Do(ctx context.Context, fn func(ctx context.Context, repos *RepositoryProvider) error) error {
	return u.db.Transaction(ctx, func(ctx context.Context, tx database.Queryer) error {
		repos := u.factory(tx)
		return fn(ctx, repos)
	})
}
