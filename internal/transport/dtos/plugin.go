package dtos

type UpdatePluginStatusRequest struct {
	Status string `json:"status" validate:"required"`
}

type PublishPluginResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}
