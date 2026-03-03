package services

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/vayload/plug-registry/internal/domain"
	"github.com/vayload/plug-registry/internal/services/packager"
	unitofwork "github.com/vayload/plug-registry/internal/services/unit-of-work"
	"github.com/vayload/plug-registry/internal/shared"
	"github.com/vayload/plug-registry/internal/shared/errors"
	"github.com/vayload/plug-registry/internal/shared/identity"
	"github.com/vayload/plug-registry/pkg/optional"
)

type IPluginPackager interface {
	Package(ctx context.Context, file *shared.File) (*packager.PackageResult, error)
}

type PublishOptions struct {
	Access  string
	IsDraft bool
}

// A background worker periodically checks for pending publish_tasks.
//
//	If it detects that:
//	   - The plugin/version exists in storage but not fully reflected in the database,
//	it reconciles the state by:
//	   - Updating the publish_task to "completed"
//	   - Marking the plugin as "published".

type IPluginService interface {
	// POST /plugins/publish
	// Publish workflow:
	// 1. The request receives a file reader.
	// 2. The file is passed to the Packager, which:
	//    - Normalizes the package.
	//    - Validates its structure.
	//    - Converts it from .zip to .tar.gz.
	//    - Extracts all required metadata.
	//
	// 3. Authorization is verified:
	//    - Ensure the user ID is the owner, OR
	//    - Validate that the API token provided in the header is valid and belongs to the user.
	//
	// 4. If the plugin does not exist, it is created.
	//
	// 5. If the plugin exists:
	//    - Check whether the provided version already exists in the database.
	//    - If the version already exists, reject the request.
	//    - If the version does not exist, create a new version entry.
	//
	// 6. A publish task record is inserted into the database (publish_tasks table)
	//    with status "pending", including all relevant plugin metadata.
	//
	// 7. The packaged file is uploaded to R2 (or local storage) using the path:
	//       {plugin_name}/{version}.tar.gz
	//    inside the "vr-plugins" bucket.
	//
	// 8. Both public and private plugins are uploaded to R2.
	//
	// 9. After a successful upload:
	//    - The publish_task status is updated to "completed".
	//    - The plugin status is set to "published",
	//      unless the developer explicitly specifies via query parameter that
	//      the release is a draft (e.g., still in development, not beta).
	//
	// 10. The plugin creation and version creation occur inside a database transaction.
	//     If any step fails, the transaction is rolled back.
	//     However, the publish_task may remain in "pending" state.
	//
	Publish(ctx context.Context, userID string, file *shared.File, options PublishOptions) (*domain.Plugin, error)

	// GET /plugins
	Search(ctx context.Context, filter domain.PluginFilter) ([]domain.Plugin, error)

	// GET /plugins/me
	SearchByOwnerId(ctx context.Context, filter domain.PluginFilter) ([]domain.Plugin, error)

	// GET /plugins/{name}
	GetDetail(ctx context.Context, name string) (*domain.Plugin, error)

	// GET /plugins/{name}/download
	GetDownloadURL(ctx context.Context, name string, version *string) (string, error)

	UpdateStatus(ctx context.Context, userID, name, version, status string) error
	DeleteVersion(ctx context.Context, userID, name, version string) error
}

type PluginService struct {
	repository domain.PluginRepository
	objects    domain.ObjectRepository
	storage    domain.IPluginStorage
	packager   IPluginPackager
	uow        *unitofwork.UnitOfWork
}

func NewPluginService(repository domain.PluginRepository, objects domain.ObjectRepository, storage domain.IPluginStorage, packager IPluginPackager, uow *unitofwork.UnitOfWork) *PluginService {
	return &PluginService{
		repository: repository,
		objects:    objects,
		storage:    storage,
		packager:   packager,
		uow:        uow,
	}
}

type PublishInput struct {
	UserID  string
	Scope   string
	Reader  io.ReadSeekCloser
	Size    int64
	Options PublishOptions
}

func (s *PluginService) Publish(ctx context.Context, userID domain.UserID, file *shared.File, options PublishOptions, scope *domain.KeyScope) (*domain.Plugin, error) {
	// !TODO: If first time is best idea read only name and version for first check
	pluginPackage, err := s.packager.Package(ctx, file)
	if err != nil {
		return nil, err
	}

	name, err := domain.NewPluginName(pluginPackage.Metadata.Name)
	if err != nil {
		return nil, err
	}

	plugin, err := s.repository.FindPluginSummary(ctx, *domain.NewPluginFindBy().WithName(name.String()))
	if err != nil && !errors.Is(err, domain.ErrNotResultSet) {
		// Reject any errors if is not
		return nil, err
	}

	var pluginID *string
	if plugin != nil {
		id := plugin.ID.String()
		pluginID = &id
	}
	if canPerms := scope.HasScope(domain.ScopeReadWrite, pluginID); !canPerms {
		return nil, errors.Unauthorized("You are not authorized to publish this plugin")
	}

	// Checking is plugin publicable
	if plugin != nil {
		if plugin.Owner.ID != userID.String() {
			return nil, errors.Unauthorized("You are not the owner of this plugin")
		}

		// Check if version already exists
		filters := domain.NewPluginFindBy().WithName(plugin.Name.String()).WithVersion(pluginPackage.Metadata.Version)
		exists, err := s.repository.HasMatchingPlugin(ctx, *filters)
		if err != nil {
			return nil, err
		}
		if exists {
			return nil, errors.AlreadyExists(fmt.Sprintf("Version %s already exists", pluginPackage.Metadata.Version))
		}
	}

	isNew := plugin == nil
	if plugin == nil {
		respository := optional.Map(optional.OfPtr(pluginPackage.Metadata.Repository), func(s domain.Repository) *string {
			return &s.URL
		}).OrElse(nil)

		plugin = domain.NewPlugin(
			domain.PluginId(identity.MustNew().String()),
			name,
			domain.PluginOwner{ID: userID.String()},
			&pluginPackage.Metadata.Description,
			pluginPackage.Metadata.Homepage,
			respository,
			nil,
			domain.PluginVisibilityPublic,
			[]string{},
		)
		if options.Access == "private" {
			plugin.Visibility = domain.PluginVisibilityPrivate
		}

		// When developer publish a plugin, without IsDraft option, we need to update the latest versions for fast find stable, beta versions
		if !options.IsDraft {
			plugin.Status = domain.PluginStatusPublished
		}
	}

	// Once the plugin package has been validated and confirmed to be in a correct format,
	// we proceed with the publication process.
	//
	// This is currently handled synchronously, but the logic is isolated so it can be
	// moved to a background worker in the future to support asynchronous processing
	// and large-scale concurrent uploads.
	plugin, err = s.processPublish(ctx, plugin, pluginPackage, file, options, isNew)
	if err != nil {
		return nil, err
	}

	return plugin, nil
}

type MetadataBlobs struct {
	Manifest *domain.BlobObject
	Readme   *domain.BlobObject
	License  *domain.BlobObject
}

func createMetadataBlobs(pluginPackage *packager.PackageResult) (MetadataBlobs, []domain.BlobObject) {
	meta := MetadataBlobs{}

	blobs := make([]domain.BlobObject, 3)

	blob := []byte(pluginPackage.Manifest)
	hash := calcSHA256(blob)
	meta.Manifest = domain.NewBlobObject(hash, "manifest", "application/json", blob)
	blobs[0] = *meta.Manifest

	if pluginPackage.Readme != nil {
		blob := []byte(*pluginPackage.Readme)
		hash := calcSHA256(blob)
		meta.Readme = domain.NewBlobObject(hash, "readme", "text/markdown", blob)
		blobs[1] = *meta.Readme
	}

	if pluginPackage.License != nil {
		blob := []byte(*pluginPackage.License)
		hash := calcSHA256(blob)
		meta.License = domain.NewBlobObject(hash, "license", "text/plain", blob)
		blobs[2] = *meta.License
	}

	return meta, blobs
}

func calcSHA256(data []byte) string {
	h := sha256.New()
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

func (s *PluginService) processPublish(ctx context.Context, plugin *domain.Plugin, pluginPackage *packager.PackageResult, file *shared.File, options PublishOptions, isNew bool) (*domain.Plugin, error) {
	storageKey := fmt.Sprintf("%s/%s.tar.gz", plugin.Name.String(), pluginPackage.Metadata.Version)
	if err := s.storage.Put(ctx, storageKey, "application/gzip", pluginPackage.Reader); err != nil {
		return nil, err
	}

	err := s.uow.Do(ctx, func(ctx context.Context, repos *unitofwork.RepositoryProvider) error {
		meta, blobs := createMetadataBlobs(pluginPackage)
		if err := repos.Objects.UpsertObjects(ctx, blobs); err != nil {
			return err
		}

		if isNew {
			if _, err := repos.Plugins.CreatePlugin(ctx, *plugin); err != nil {
				return err
			}
		}

		version := domain.NewPluginVersion(
			identity.MustNew().String(),
			plugin.ID,
			pluginPackage.Metadata.Version,
			pluginPackage.Checksum(),
			storageKey,
			uint64(file.Size),
			int32(pluginPackage.FileCount),
		)

		version.ManifestObject = meta.Manifest.ObjectHash
		version.ReadmeObject = &meta.Readme.ObjectHash
		version.LicenseObject = &meta.License.ObjectHash

		if _, err := repos.Plugins.CreateVersion(ctx, version); err != nil {
			return err
		}

		// When user publish a plugin, we need to update the latest versions for fast find stable, beta versions
		if !options.IsDraft {
			if err := repos.Plugins.UpdateLatestVersions(ctx, plugin.ID, pluginPackage.Metadata.Version); err != nil {
				return err
			}
		}

		return nil
	})

	if err != nil {
		// Try to delete the uploaded file, because we failed to create the plugin
		_ = s.storage.Delete(ctx, storageKey)
		return nil, err
	}

	return plugin, nil
}

func (s *PluginService) Search(ctx context.Context, filter domain.PluginFilter) ([]domain.Plugin, error) {
	return s.repository.SearchWithFilters(ctx, filter)
}

func (s *PluginService) SearchByOwnerId(ctx context.Context, ownerId domain.UserID) ([]domain.Plugin, error) {
	return s.repository.ListByOwner(ctx, ownerId.String())
}

func (s *PluginService) GetDetail(ctx context.Context, name string) (*domain.Plugin, error) {
	pName, err := domain.NewPluginName(name)
	if err != nil {
		return nil, err
	}
	return s.repository.FindPluginSummary(ctx, *domain.NewPluginFindBy().WithName(pName.String()))
}

func (s *PluginService) GetPluginSummary(ctx context.Context, name string) (*domain.Plugin, error) {
	pName, err := domain.NewPluginName(name)
	if err != nil {
		return nil, err
	}

	plugin, err := s.repository.FindPluginSummary(ctx, *domain.NewPluginFindBy().WithName(pName.String()))
	if err != nil {
		return nil, err
	}
	if plugin == nil {
		return nil, errors.NotFound("Plugin not exists")
	}

	return plugin, nil
}

type PackageMeta struct {
	ID            string       `json:"id"`
	Name          string       `json:"name"`
	Version       string       `json:"version"`
	LatestVersion string       `json:"latest_version"`
	Artifact      ArtifactMeta `json:"artifact"`
}

type ArtifactMeta struct {
	URL       string `json:"url"`
	ExpiresAt int64  `json:"expires_at"`
	Size      int64  `json:"size_bytes"`
	Integrity string `json:"integrity"`
	Algorithm string `json:"algorithm"`
}

func (s *PluginService) GetDownloadURL(ctx context.Context, name string, version *string) (*PackageMeta, error) {
	pName, err := domain.NewPluginName(name)
	if err != nil {
		return nil, err
	}

	filter := domain.NewPluginFindBy().WithName(pName.String())
	plugin, err := s.repository.FindPluginSummary(ctx, *filter)
	if err != nil || plugin == nil {
		return nil, errors.NotFound("plugin not found").Cause(err)
	}

	targetVersion := ""
	if safeString(version) != "" {
		targetVersion = *version
	} else if plugin.LatestStableVersion != nil {
		targetVersion = *plugin.LatestStableVersion
	}

	if targetVersion == "" {
		return nil, errors.NotFound("no stable version available")
	}

	ver, err := s.repository.GetVersion(ctx, plugin.ID, targetVersion)
	if err != nil {
		if errors.Is(err, domain.ErrNotResultSet) {
			return nil, errors.NotFound("version not found")
		}

		return nil, errors.Internal("failed to get version").Cause(err)
	}

	downloadURL, err := s.storage.GetSignedURL(ctx, ver.Filename)
	if err != nil {
		return nil, errors.Internal("failed to generate download link").Cause(err)
	}

	// Update total downloads in background
	go func(pID domain.PluginId, v string) {
		updateCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := s.repository.UpdateDownloads(updateCtx, pID, v, 1); err != nil {
			log.Printf("async error: failed to update downloads for %s@%s: %v", pID, v, err)
		}
	}(plugin.ID, ver.Version)

	integrity := base64.RawURLEncoding.EncodeToString(ver.Integrity[:])
	return &PackageMeta{
		ID:            plugin.ID.String(),
		Name:          plugin.Name.String(),
		Version:       ver.Version,
		LatestVersion: safeString(plugin.LatestStableVersion),
		Artifact: ArtifactMeta{
			URL:       downloadURL,
			ExpiresAt: 5,
			Size:      int64(ver.SizeBytes),
			Integrity: fmt.Sprintf("sha256-%s", integrity),
			Algorithm: "SHA-256",
		},
	}, nil
}

func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (s *PluginService) UpdateStatus(ctx context.Context, userID, name, version, status string) error {
	pName, err := domain.NewPluginName(name)
	if err != nil {
		return err
	}

	plugin, err := s.repository.FindPluginSummary(ctx, *domain.NewPluginFindBy().WithName(pName.String()))
	if err != nil || plugin == nil {
		return errors.NotFound("Plugin not found").Cause(err)
	}

	if plugin.Owner.ID != userID {
		return errors.Unauthorized("You are not the owner of this plugin")
	}

	nextStatus, err := domain.ParsePluginStatus(status)
	if err != nil {
		return err
	}

	if !plugin.Status.CanTransitionTo(nextStatus) {
		return errors.BadRequest(fmt.Sprintf("Cannot transition from %s to %s", plugin.Status, status))
	}

	return s.repository.UpdateStatus(ctx, plugin.ID, nextStatus)
}

func (s *PluginService) DeleteVersion(ctx context.Context, userID, name, version string) error {
	pName, err := domain.NewPluginName(name)
	if err != nil {
		return err
	}

	filters := domain.NewPluginFindBy().WithName(pName.String()).WithVersion(version)
	plugin, err := s.repository.FindPluginSummary(ctx, *filters)
	if err != nil || plugin == nil {
		return errors.NotFound("Plugin not found").Cause(err)
	}

	// Only the owner can delete a plugin version
	if plugin.Owner.ID != userID {
		return errors.Unauthorized("You are not the owner of this plugin")
	}

	return s.repository.UpdateStatus(ctx, plugin.ID, domain.PluginStatusArchived)
}

func (s *PluginService) GetPlugin(ctx context.Context, name string) (*domain.Plugin, error) {
	return s.GetDetail(ctx, name)
}

func (s *PluginService) FetchFile(ctx context.Context, name, version string) (io.ReadCloser, error) {
	key := fmt.Sprintf("%s/%s.tar.gz", name, version)
	return s.storage.Get(ctx, key)
}

func ptr[T any](v T) *T {
	return &v
}
