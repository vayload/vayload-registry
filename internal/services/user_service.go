package services

import (
	"context"

	"github.com/vayload/plug-registry/internal/domain"
)

type UserService struct {
	userRepo domain.UserRepository
}

func NewUserService(userRepo domain.UserRepository) *UserService {
	return &UserService{
		userRepo: userRepo,
	}
}

func (s *UserService) GetUser(ctx context.Context, id domain.UserID) (*domain.User, error) {
	return s.userRepo.GetByID(ctx, id)
}

func (s *UserService) UpdateProfile(ctx context.Context, id domain.UserID, usernameStr, email string) error {
	if usernameStr != "" {
		username, err := domain.NewUsername(usernameStr)
		if err != nil {
			return err
		}
		if err := s.userRepo.UpdateUsername(ctx, id, username); err != nil {
			return err
		}
	}
	if email != "" {
		if err := s.userRepo.UpdateEmail(ctx, id, email); err != nil {
			return err
		}
	}
	return nil
}
