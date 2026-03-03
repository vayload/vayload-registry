package storage

const SERVICE_NAME = "storage"

type StorageConfig struct {
	S3Endpoint  string
	S3AccessKey string
	S3SecretKey string

	BucketName string

	// Local
	BaseLocalPath   string
	LocalHMACSecret []byte
	LocalEndpoint   string
}

func NewStorageConfig() *StorageConfig {
	return &StorageConfig{
		S3Endpoint:      "https://s3.amazonaws.com",
		S3AccessKey:     "",
		S3SecretKey:     "",
		BucketName:      "",
		BaseLocalPath:   "",
		LocalHMACSecret: []byte{},
	}
}
