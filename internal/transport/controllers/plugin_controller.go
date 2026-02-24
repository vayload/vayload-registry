package controllers

import (
	"fmt"
	"strings"

	"github.com/vayload/plug-registry/internal/domain"
	"github.com/vayload/plug-registry/internal/services"
	"github.com/vayload/plug-registry/internal/shared/container"
	"github.com/vayload/plug-registry/internal/transport/middleware"
	"github.com/vayload/plug-registry/pkg/httpi"
)

// PluginController handles plugin-related HTTP requests.
type PluginController struct {
	pluginService *services.PluginService
	registry      *container.Container
}

func NewPluginController(pluginService *services.PluginService, registry *container.Container) *PluginController {
	return &PluginController{
		pluginService: pluginService,
		registry:      registry,
	}
}

func (c *PluginController) Path() string {
	return "/plugins"
}

func (c *PluginController) Middlewares() []httpi.HttpHandler {
	return nil
}

func (c *PluginController) Routes() []httpi.HttpRoute {
	authGuard := middleware.NewAuthGuard(c.registry)
	publishGuard := middleware.NewPublishGuard(c.registry)

	return []httpi.HttpRoute{
		{
			Path:    "/",
			Method:  httpi.GET,
			Handler: c.SearchPlugins,
		},
		{
			Path:    "/:name",
			Method:  httpi.GET,
			Handler: c.GetPlugin,
		},
		{
			Path:       "/me",
			Method:     httpi.GET,
			Handler:    c.ListMyPlugins,
			Middleware: []httpi.HttpHandler{authGuard},
		},
		{
			Path:       "/publish",
			Method:     httpi.POST,
			Handler:    c.PublishPlugin,
			Middleware: []httpi.HttpHandler{publishGuard},
		},
		{
			Path:    "/:name/download",
			Method:  httpi.GET,
			Handler: c.DownloadPlugin,
		},
		{
			Path:       "/:name/:version/status",
			Method:     httpi.PATCH,
			Handler:    c.UpdatePluginStatus,
			Middleware: []httpi.HttpHandler{authGuard},
		},
		{
			Path:       "/:name/:version",
			Method:     httpi.DELETE,
			Handler:    c.DeletePlugin,
			Middleware: []httpi.HttpHandler{authGuard},
		},
		{
			Path:    "/storage/get/:filename",
			Method:  httpi.GET,
			Handler: c.ServeStorage,
		},
	}
}

// SearchPlugins godoc
// @Summary      Search plugins
// @Description  Search plugins with optional filters
// @Tags         Plugins
// @Accept       json
// @Produce      json
// @Param        q       query     string  false  "Search query"
// @Param        limit   query     int     false  "Limit"
// @Param        offset  query     int     false  "Offset"
// @Success      200     {array}   domain.Plugin
// @Failure      500     {object}  httpi.ErrorResponse
// @Router       /plugins [get]
func (c *PluginController) SearchPlugins(req httpi.HttpRequest, res httpi.HttpResponse) error {
	query := req.GetQuery("q")
	limit := req.GetQueryInt("limit", 20)
	offset := req.GetQueryInt("offset", 0)

	plugins, err := c.pluginService.Search(req.Context(), domain.PluginFilter{
		Query:  &query,
		Limit:  uint32(limit),
		Offset: uint32(offset),
	})
	if err != nil {
		return res.Status(500).JSON(map[string]any{"error": err.Error()})
	}

	return res.JSON(plugins)
}

// GetPlugin godoc
// @Summary      Get plugin detail
// @Description  Get detailed information about a plugin by name
// @Tags         Plugins
// @Accept       json
// @Produce      json
// @Param        name  path      string  true  "Plugin Name"
// @Success      200   {object}  domain.Plugin
// @Failure      404   {object}  httpi.ErrorResponse
// @Router       /plugins/{name} [get]
func (c *PluginController) GetPlugin(req httpi.HttpRequest, res httpi.HttpResponse) error {
	name := req.GetParam("name")
	plugin, err := c.pluginService.GetPlugin(req.Context(), name)
	if err != nil {
		return httpi.MapFromAppException(err)
	}

	return res.Status(200).Json(httpi.NewResponseBody(plugin))
}

// PublishPlugin godoc
// @Summary      Publish plugin
// @Description  Publish a new plugin
// @Tags         Plugins
// @Accept       multipart/form-data
// @Produce      json
// @Param        file formData file true "Plugin file"
// @Success      201  {object}  domain.Plugin
// @Failure      400  {object}  httpi.ErrorResponse
// @Failure      401  {object}  httpi.ErrorResponse
// @Failure      500  {object}  httpi.ErrorResponse
// @Router       /plugins/publish [post]
func (c *PluginController) PublishPlugin(req httpi.HttpRequest, res httpi.HttpResponse) error {
	auth, err := req.TryAuth()
	if err != nil {
		return httpi.ErrUnauthorized(nil, "Unauthorized")
	}

	file, err := req.File("file")
	if err != nil {
		return httpi.ErrBadRequest(nil, "Missing file")
	}

	f, err := file.Open()
	if err != nil {
		return httpi.ErrInternal(nil, "Failed to open file")
	}
	defer f.Close()

	access := req.GetQuery("access")
	isDraft := req.GetQuery("draft", "false") == "true"

	p, err := c.pluginService.Publish(req.Context(), auth.UserId.String(), f, file.Size, services.PublishOptions{
		Access:  access,
		IsDraft: isDraft,
	})
	if err != nil {
		return httpi.ErrBadRequest(nil, err.Error())
	}

	return res.Status(201).Json(p)
}

// DownloadPlugin godoc
// @Summary      Download plugin
// @Description  Get a download URL for a plugin version
// @Tags         Plugins
// @Param        name     path      string  true   "Plugin Name"
// @Param        version  query     string  false  "Version"
// @Success      302      {string}  string  "Redirect to download URL"
// @Failure      404      {object}  httpi.ErrorResponse
// @Router       /plugins/{name}/download [get]
func (c *PluginController) DownloadPlugin(req httpi.HttpRequest, res httpi.HttpResponse) error {
	name := req.GetParam("name")
	version := req.GetQuery("version")
	var v *string
	if version != "" {
		v = &version
	}

	url, err := c.pluginService.GetDownloadURL(req.Context(), name, v)
	if err != nil {
		return httpi.ErrNotFound(nil, err.Error())
	}

	return res.Redirect(url, 302)
}

// ListMyPlugins godoc
// @Summary      List my plugins
// @Description  List plugins owned by the authenticated user
// @Tags         Plugins
// @Accept       json
// @Produce      json
// @Security     ApiKeyAuth
// @Success      200  {array}   domain.Plugin
// @Failure      401  {object}  httpi.ErrorResponse
// @Failure      500  {object}  httpi.ErrorResponse
// @Router       /plugins/me [get]
func (c *PluginController) ListMyPlugins(req httpi.HttpRequest, res httpi.HttpResponse) error {
	auth := req.Auth()
	if auth == nil || auth.UserId.IsZero() {
		return res.Status(401).JSON(map[string]any{"error": "Unauthorized"})
	}

	userID := auth.UserId.String()
	plugins, err := c.pluginService.Search(req.Context(), domain.PluginFilter{
		OwnerId: &userID,
	})
	if err != nil {
		return res.Status(500).JSON(map[string]any{"error": err.Error()})
	}
	return res.JSON(plugins)
}

// UpdatePluginStatus godoc
// @Summary      Update plugin status
// @Description  Update the status of a plugin version (e.g., published, deprecated)
// @Tags         Plugins
// @Accept       json
// @Produce      json
// @Security     ApiKeyAuth
// @Param        name     path      string  true  "Plugin Name"
// @Param        version  path      string  true  "Version"
// @Param        body     body      struct{Status string `json:"status"`}  true  "New status"
// @Success      200      {object}  map[string]string
// @Failure      400      {object}  httpi.ErrorResponse
// @Failure      401      {object}  httpi.ErrorResponse
// @Router       /plugins/{name}/{version}/status [patch]
func (c *PluginController) UpdatePluginStatus(req httpi.HttpRequest, res httpi.HttpResponse) error {
	auth, err := req.TryAuth()
	if err != nil {
		return httpi.ErrUnauthorized(nil, "Unauthorized")
	}

	name := req.GetParam("name")
	version := req.GetParam("version")

	var body struct {
		Status string `json:"status"`
	}
	if err := req.ParseBody(&body); err != nil {
		return httpi.ErrBadRequest(nil, "Invalid body")
	}

	err = c.pluginService.UpdateStatus(req.Context(), auth.UserId.String(), name, version, body.Status)
	if err != nil {
		return httpi.ErrBadRequest(nil, err.Error())
	}

	return res.JSON(map[string]string{"message": "Status updated"})
}

// DeletePlugin godoc
// @Summary      Delete plugin version
// @Description  Delete/Archive a specific plugin version
// @Tags         Plugins
// @Produce      json
// @Security     ApiKeyAuth
// @Param        name     path  string  true  "Plugin Name"
// @Param        version  path  string  true  "Version"
// @Success      204      "No Content"
// @Failure      400      {object}  httpi.ErrorResponse
// @Failure      401      {object}  httpi.ErrorResponse
// @Router       /plugins/{name}/{version} [delete]
func (c *PluginController) DeletePlugin(req httpi.HttpRequest, res httpi.HttpResponse) error {
	auth, err := req.TryAuth()
	if err != nil {
		return httpi.ErrUnauthorized(nil, "Unauthorized")
	}

	name := req.GetParam("name")
	version := req.GetParam("version")

	err = c.pluginService.DeleteVersion(req.Context(), auth.UserId.String(), name, version)
	if err != nil {
		return httpi.ErrBadRequest(nil, err.Error())
	}

	return res.Status(204).JSON(nil)
}

// ServeStorage godoc
// @Summary      Serve storage file
// @Description  Serve a plugin file from storage (local dev)
// @Tags         Storage
// @Param        filename  path  string  true  "Filename"
// @Success      200       {file}  file
// @Failure      400       {object}  httpi.ErrorResponse
// @Failure      404       {object}  httpi.ErrorResponse
// @Router       /plugins/storage/get/{filename} [get]
func (c *PluginController) ServeStorage(req httpi.HttpRequest, res httpi.HttpResponse) error {
	filename := req.GetParam("filename")
	parts := strings.Split(strings.TrimSuffix(filename, ".tar.gz"), "-")
	if len(parts) < 2 {
		return httpi.ErrBadRequest(nil, "Invalid filename")
	}
	name := parts[0]
	version := parts[1]

	reader, err := c.pluginService.FetchFile(req.Context(), name, version)
	if err != nil {
		return httpi.ErrNotFound(nil, err.Error())
	}
	defer reader.Close()

	res.SetHeader("Content-Type", "application/gzip")
	res.SetHeader("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	return res.Stream(reader)
}
