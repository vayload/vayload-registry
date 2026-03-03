package services

import (
	"context"
	"time"

	"github.com/vayload/plug-registry/internal/domain"
)

type UserStats struct {
	TotalPlugins   int               `json:"total_plugins"`
	TotalDownloads int               `json:"total_downloads"`
	TotalVersions  int               `json:"total_versions"`
	Reputation     int               `json:"reputation"`
	MemberSince    time.Time         `json:"member_since"`
	RecentActivity []domain.AuditLog `json:"recent_activity"`
}

type StatsService struct {
	userRepo   domain.UserRepository
	pluginRepo domain.PluginRepository
}

func NewStatsService(userRepo domain.UserRepository, pluginRepo domain.PluginRepository) *StatsService {
	return &StatsService{
		userRepo:   userRepo,
		pluginRepo: pluginRepo,
	}
}

func (s *StatsService) GetUserStats(ctx context.Context, userID domain.UserID) (*UserStats, error) {
	user, err := s.userRepo.FindUserBy(ctx, domain.NewUserFilterBy().WithID(userID))
	if err != nil || user == nil {
		return nil, domain.ErrNotFound
	}

	totalPlugins, totalDownloads, totalVersions, err := s.pluginRepo.GetAggregatedStats(ctx, userID.String())
	if err != nil {
		return nil, err
	}

	activities, err := s.pluginRepo.GetLatestAuditLogs(ctx, userID.String(), 4)
	if err != nil {
		return nil, err
	}

	reputation := s.calculateReputation(totalDownloads, totalPlugins)

	return &UserStats{
		TotalPlugins:   totalPlugins,
		TotalDownloads: totalDownloads,
		TotalVersions:  totalVersions,
		Reputation:     reputation,
		MemberSince:    user.CreatedAt,
		RecentActivity: activities,
	}, nil
}

func (s *StatsService) calculateReputation(downloads, plugins int) int {
	// Basic formula: 10 points per plugin + 1 point per 100 downloads
	return (plugins * 10) + (downloads / 100)
}
