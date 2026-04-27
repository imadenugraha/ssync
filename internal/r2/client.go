package r2

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/user/ssync/internal"
)

// ErrNotFound is returned when a requested object does not exist in R2.
var ErrNotFound = errors.New("object not found")

// ConnectionError wraps network/connection errors and signals exit code 2.
type ConnectionError struct {
	Cause error
}

func (e *ConnectionError) Error() string {
	return fmt.Sprintf("connection error: %v", e.Cause)
}

func (e *ConnectionError) Unwrap() error {
	return e.Cause
}

// R2Client defines the interface for interacting with Cloudflare R2 object storage.
type R2Client interface {
	Upload(key string, data []byte) error
	Download(key string) ([]byte, error)
	List() ([]string, error)
	Delete(key string) error
}

type r2Client struct {
	s3     *s3.Client
	bucket string
}

// NewR2Client constructs an R2Client configured with the provided credentials.
func NewR2Client(creds internal.R2Credentials) (R2Client, error) {
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion("auto"),
		config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(
				creds.AccessKeyID,
				creds.SecretAccessKey,
				"",
			),
		),
	)
	if err != nil {
		return nil, &ConnectionError{Cause: err}
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(creds.EndpointURL)
		o.UsePathStyle = true
	})

	return &r2Client{
		s3:     client,
		bucket: creds.BucketName,
	}, nil
}

// Upload stores data at the given key in the R2 bucket.
func (c *r2Client) Upload(key string, data []byte) error {
	_, err := c.s3.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(data),
	})
	if err != nil {
		return wrapError(err)
	}
	return nil
}

// Download retrieves the object at the given key from the R2 bucket.
func (c *r2Client) Download(key string) ([]byte, error) {
	out, err := c.s3.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, wrapError(err)
	}
	defer out.Body.Close()

	data, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, &ConnectionError{Cause: err}
	}
	return data, nil
}

// List returns all object keys in the R2 bucket.
func (c *r2Client) List() ([]string, error) {
	var keys []string
	paginator := s3.NewListObjectsV2Paginator(c.s3, &s3.ListObjectsV2Input{
		Bucket: aws.String(c.bucket),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			return nil, wrapError(err)
		}
		for _, obj := range page.Contents {
			if obj.Key != nil {
				keys = append(keys, *obj.Key)
			}
		}
	}
	return keys, nil
}

// Delete removes the object at the given key from the R2 bucket.
func (c *r2Client) Delete(key string) error {
	_, err := c.s3.DeleteObject(context.Background(), &s3.DeleteObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return wrapError(err)
	}
	return nil
}

// wrapError translates S3 SDK errors into domain errors.
func wrapError(err error) error {
	if err == nil {
		return nil
	}

	// Check for not-found errors.
	var noSuchKey *types.NoSuchKey
	if errors.As(err, &noSuchKey) {
		return ErrNotFound
	}

	// Check for not-found via generic S3 error code.
	var apiErr interface{ ErrorCode() string }
	if errors.As(err, &apiErr) {
		if apiErr.ErrorCode() == "NoSuchKey" || apiErr.ErrorCode() == "NotFound" {
			return ErrNotFound
		}
	}

	// All other errors are treated as connection/I/O errors (exit code 2).
	return &ConnectionError{Cause: err}
}
