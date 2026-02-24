package services

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/vayload/plug-registry/internal/domain"
	"github.com/vayload/plug-registry/pkg/ids"
)

type IPackageResult struct {
	Reader   io.Reader      // El .tar.gz normalizado
	Metadata PluginMetadata // Datos del plugin.json
	Manifest string         // Raw JSON
	Readme   *string        // Contenido README
	License  *string        // Contenido LICENSE
	Checksum func() string  // SHA256 final (se llama tras consumir el Reader)
}

type IPluginPackager interface {
	// Procesa ZIP/TAR, extrae metadata y normaliza a Stream TarGz
	Package(ctx context.Context, r io.Reader, size int64) (*IPackageResult, error)
}

type IPluginStorage interface {
	Put(ctx context.Context, key string, r io.Reader) error
	Get(ctx context.Context, key string) (io.ReadCloser, error)
	GetSignedURL(ctx context.Context, key string) (string, error)
	Delete(ctx context.Context, key string) error
}

type PublishOptions struct {
	Access  string
	IsDraft bool
}

type IPluginService interface {
	// POST /plugins/publish
	// Publis funciona asi; llega el file reader, le pasamos al Packager para que normalize, valide el paquete pasando de zip a tar.gz y extreyendo toda la metadata necesaria
	// Deemos revizar si el userid es dueño, o la api token que viene en el header es valida y pertenece al usuario
	// Si el plugin no existe, se crea
	// Si el plugin existe, se asigna una nueva version, para esto tenemos que revizar que el plugin no tenga esa version en base de datos.
	// Si el plugin existe y tiene la version, se debe rechazar la peticion
	// Si el plugin existe y no tiene la version, se debe crear la version
	// // registramos un log en base de datos en la tabla publish_tasks y guardamos la metadata del plugin con estado pending
	// Subimos el archivo a r2 con el nombre {plugin_name}/{version}.tar.gz en el bucket vr-plugins o en local storage
	// privado o publico se suben a r2, y cuando el plugin subio de forma exitosa, se pasa el plugin_task a completed y plugin published, a menos que por query param explicitamente el developer haya dicho que es draft, porque esta en desarrollo, ni beta
	// Se crea el plugin si no existe, y tambien se crea la nueva version, en este punto estamos seguros de que el plugin existe o no, y la version es nueva. en un transaction, si falla algo se revierte todo. pero plugin_tasks queda en pending, es un caso muy raro por eso hay un worker que se encargar de revizar los task no completados y revizar si no esta en la base de datos y pero el plugin si se subio, entonces se actualiza el plugin_task a completed y plugin published
	Publish(ctx context.Context, userID string, file io.ReadSeeker, size int64, options PublishOptions) (*domain.Plugin, error)

	// GET /plugins
	Search(ctx context.Context, filter domain.PluginFilter) ([]domain.Plugin, error)

	// GET /plugins/me
	SearchByOwnerId(ctx context.Context, filter domain.PluginFilter) ([]domain.Plugin, error)

	// GET /plugins/{name}
	GetDetail(ctx context.Context, name string) (*domain.Plugin, error)

	// GET /plugins/{name}/download
	//  Responde con un redirect al la url firmada 5 minutos, si el plugin es publico, si es privado, debe estar autenticado y autorizado
	// si el plugin no existe, se debe rechazar la peticion
	// si el plugin existe y no tiene la version, se debe rechazar la peticion, sila version no se especifica, se trae la ultima stable
	GetDownloadURL(ctx context.Context, name string, version *string) (string, error)

	// PATCH /plugins/{name}/{version}/status
	// actualiza el estado del plugin, solo el dueño puede hacerlo, o tiene reglas de transition
	/**
		 pub fn can_transition_to(&self, next: PluginStatus) -> bool {
	        match (self, next) {
	            (PluginStatus::Draft, PluginStatus::Published) => true,
	            (PluginStatus::Published, PluginStatus::Deprecated) => true,
	            (PluginStatus::Published, PluginStatus::Archived) => true,
	            (PluginStatus::Deprecated, PluginStatus::Archived) => true,
	            (_, PluginStatus::Yanked) => true,
	            (a, b) => a.eq(&b),
	        }
	    }
		**/
	UpdateStatus(ctx context.Context, userID, name, version, status string) error
	DeleteVersion(ctx context.Context, userID, name, version string) error
}

const (
	LimitFreeBytes       = 10 * 1024 * 1024 // 10 MB
	MaxFiles             = 200
	MaxSingleFileSize    = 5 * 1024 * 1024   // 5 MB
	MaxUncompressedTotal = 100 * 1024 * 1024 // 100 MB
)

type PluginMetadata struct {
	Name        string  `json:"name"`
	DisplayName string  `json:"display_name"`
	Namespace   string  `json:"namespace"` // user for isolate plugins
	Version     string  `json:"version"`
	Description *string `json:"description"`
	License     *string `json:"license"` // The license of the plugin (MIT, Apache 2.0, etc)
	Homepage    *string `json:"homepage"`
	Repository  *string `json:"repository"`
	Access      *string `json:"access"` // public, private // get from query params
}

type Extracted struct {
	Manifest string
	Readme   *string
	License  *string
}

// PluginService provides methods for managing plugins, including publication,
// search, and status updates. It coordinates between the repository,
// storage, and packager.
type PluginService struct {
	repository domain.PluginRepository
	storage    domain.StorageProvider
	packager   IPluginPackager
}

func NewPluginService(repository domain.PluginRepository, storage domain.StorageProvider) *PluginService {
	return &PluginService{
		repository: repository,
		storage:    storage,
		packager:   NewDefaultPackager(),
	}
}

func (s *PluginService) Publish(ctx context.Context, userID string, file io.ReadSeeker, size int64, options PublishOptions) (*domain.Plugin, error) {
	if size > LimitFreeBytes {
		return nil, domain.NewValidationError("Upload too large")
	}

	res, err := s.packager.Package(ctx, file, size)
	if err != nil {
		return nil, err
	}

	name, err := domain.NewPluginName(res.Metadata.Name)
	if err != nil {
		return nil, err
	}

	// 2. Revisar si el plugin existe y el usuario es dueño
	plugin, err := s.repository.GetByName(ctx, name)
	if err != nil {
		return nil, err
	}

	isNew := false
	if plugin == nil {
		isNew = true
		plugin = domain.NewPlugin(
			domain.PluginId(ids.New().String()),
			name,
			domain.PluginOwner{ID: userID},
			res.Metadata.Description,
			res.Metadata.Homepage,
			res.Metadata.Repository,
			nil,
			res.Readme,
			res.License,
			domain.PluginVisibilityPublic,
			nil,
		)
		if options.Access == "private" {
			plugin.Visibility = domain.PluginVisibilityPrivate
		}
	} else {
		if plugin.Owner.ID != userID {
			return nil, domain.NewUnauthorizedError("You are not the owner of this plugin")
		}

		// 3. Revisar si la versión ya existe
		exists, err := s.repository.HasVersionUploaded(ctx, name, res.Metadata.Version)
		if err != nil {
			return nil, err
		}
		if exists {
			return nil, domain.NewAlreadyExistsError(fmt.Sprintf("Version %s already exists", res.Metadata.Version))
		}
	}

	// 4. Crear PluginTask en pending
	taskID := ids.New().String()
	task := domain.PluginTask{
		ID:        taskID,
		PluginID:  plugin.ID,
		Version:   res.Metadata.Version,
		UserID:    userID,
		Status:    domain.PluginTaskStatusPending,
		Metadata:  res.Manifest,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	if err := s.repository.CreateTask(ctx, task); err != nil {
		return nil, err
	}

	// 5. Iniciar publicación (idealmente en una transacción si la DB lo soporta para plugin + version)
	// Pero el storage es externo.

	// Subimos el archivo
	_, filesize, sha256Hex, err := s.storage.Upload(ctx, name.String(), res.Metadata.Version, res.Reader)
	if err != nil {
		_ = s.repository.UpdateTaskStatus(ctx, taskID, domain.PluginTaskStatusFailed, ptr(err.Error()))
		return nil, err
	}

	if isNew {
		if _, err := s.repository.Create(ctx, *plugin); err != nil {
			return nil, err
		}
	}

	// Crear versión
	version := domain.NewPluginVersion(
		ids.New().String(),
		plugin.ID,
		res.Metadata.Version,
		res.Manifest,
		"sha256-"+sha256Hex,
		fmt.Sprintf("%s-%s.tar.gz", name, res.Metadata.Version),
		uint64(filesize),
		0, // count files... if we had it
		nil, nil, nil,
	)

	if _, err := s.repository.CreateVersion(ctx, version); err != nil {
		return nil, err
	}

	// Actualizar latest versions
	if !options.IsDraft {
		if err := s.repository.UpdateLatestVersions(ctx, plugin.ID, res.Metadata.Version); err != nil {
			return nil, err
		}
	}

	// 6. Marcar task como completado
	if err := s.repository.UpdateTaskStatus(ctx, taskID, domain.PluginTaskStatusCompleted, nil); err != nil {
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
	return s.repository.GetByName(ctx, pName)
}

func (s *PluginService) GetDownloadURL(ctx context.Context, name string, version *string) (string, error) {
	pName, err := domain.NewPluginName(name)
	if err != nil {
		return "", err
	}

	plugin, err := s.repository.GetByName(ctx, pName)
	if err != nil || plugin == nil {
		return "", domain.NewNotFoundError("Plugin not found")
	}

	v := ""
	if version == nil {
		if plugin.LatestStableVersion == nil {
			return "", domain.NewNotFoundError("No stable version available")
		}
		v = *plugin.LatestStableVersion
	} else {
		v = *version
	}

	// Check if version exists
	ver, err := s.repository.GetVersion(ctx, plugin.ID, v)
	if err != nil || ver == nil {
		return "", domain.NewNotFoundError("Version not found")
	}

	return s.storage.GetSignedURL(ctx, ver.Filename)
}

func (s *PluginService) UpdateStatus(ctx context.Context, userID, name, version, status string) error {
	pName, err := domain.NewPluginName(name)
	if err != nil {
		return err
	}

	plugin, err := s.repository.GetByName(ctx, pName)
	if err != nil || plugin == nil {
		return domain.NewNotFoundError("Plugin not found")
	}

	if plugin.Owner.ID != userID {
		return domain.NewUnauthorizedError("You are not the owner of this plugin")
	}

	nextStatus, err := domain.ParsePluginStatus(status)
	if err != nil {
		return err
	}

	if !plugin.Status.CanTransitionTo(nextStatus) {
		return domain.NewValidationError(fmt.Sprintf("Cannot transition from %s to %s", plugin.Status, status))
	}

	return s.repository.UpdateStatus(ctx, plugin.ID, nextStatus)
}

func (s *PluginService) DeleteVersion(ctx context.Context, userID, name, version string) error {
	pName, err := domain.NewPluginName(name)
	if err != nil {
		return err
	}

	plugin, err := s.repository.GetByName(ctx, pName)
	if err != nil || plugin == nil {
		return domain.NewNotFoundError("Plugin not found")
	}

	if plugin.Owner.ID != userID {
		return domain.NewUnauthorizedError("You are not the owner of this plugin")
	}

	// Simply mark as archived for now
	return s.repository.UpdateStatus(ctx, plugin.ID, domain.PluginStatusArchived)
}

// Para usar en el controller
func (s *PluginService) GetPlugin(ctx context.Context, name string) (*domain.Plugin, error) {
	return s.GetDetail(ctx, name)
}

func (s *PluginService) FetchFile(ctx context.Context, name, version string) (io.ReadCloser, error) {
	return s.storage.Fetch(ctx, name, version)
}

func ptr[T any](v T) *T {
	return &v
}
