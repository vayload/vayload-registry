//go:build r2_storage
// +build r2_storage

package storage

import (
	"context"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/transfermanager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/vayload/plug-registry/internal/domain"
)

type R2Storage struct {
	Client     *s3.Client
	BucketName string
}

// NewStorage creates a new instance of R2Storage.
func NewStorage(scfg StorageConfig) (*R2Storage, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithCredentialsProvider(
			aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
				return aws.Credentials{
					AccessKeyID:     scfg.S3AccessKey,
					SecretAccessKey: scfg.S3SecretKey,
				}, nil
			}),
		),
		config.WithRegion("auto"),
	)
	if err != nil {
		return nil, err
	}

	return &R2Storage{
		Client: s3.NewFromConfig(cfg, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(scfg.S3Endpoint)
		}),
		BucketName: scfg.BucketName,
	}, nil
}

func (r *R2Storage) Put(ctx context.Context, key string, mimeType string, body io.Reader) error {
	uploader := transfermanager.New(r.Client)
	_, err := uploader.UploadObject(ctx, &transfermanager.UploadObjectInput{
		Bucket:      &r.BucketName,
		Key:         &key,
		Body:        body,
		ContentType: aws.String(mimeType),
	})

	return err
}

func (r *R2Storage) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	out, err := r.Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &r.BucketName,
		Key:    &key,
	})
	if err != nil {
		return nil, err
	}
	return out.Body, nil
}

func (r *R2Storage) GetSignedURL(ctx context.Context, key string) (string, error) {
	presign := s3.NewPresignClient(r.Client)
	req, err := presign.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: &r.BucketName,
		Key:    &key,
	}, s3.WithPresignExpires(5*time.Minute))
	if err != nil {
		return "", err
	}
	return req.URL, nil
}

func (r *R2Storage) Delete(ctx context.Context, key string) error {
	_, err := r.Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &r.BucketName,
		Key:    &key,
	})
	return err
}

var _ domain.IPluginStorage = (*R2Storage)(nil)
