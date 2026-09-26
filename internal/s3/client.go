package s3

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// Client wraps the AWS S3 client with tenant-specific config
type Client struct {
	s3Client *s3.Client
	presign  *s3.PresignClient
	bucket   string
}

// NewClient creates an S3 client from the provided connection parameters.
// Supports both AWS S3 and S3-compatible endpoints (MinIO, Ceph, etc.).
func NewClient(endpoint, protocol, accessKey, secretKey, region, bucket string) (*Client, error) {
	if region == "" {
		region = "us-east-1" // default for S3-compatible services
	}

	baseURL := fmt.Sprintf("%s://%s", protocol, endpoint)

	cfg := aws.Config{
		Region:      region,
		Credentials: credentials.NewStaticCredentialsProvider(accessKey, secretKey, ""),
	}

	s3Client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(baseURL)
		o.UsePathStyle = true // required for custom S3 endpoints like MinIO
	})

	return &Client{
		s3Client: s3Client,
		presign:  s3.NewPresignClient(s3Client),
		bucket:   bucket,
	}, nil
}

// Upload puts an object into S3 and returns the key.
func (c *Client) Upload(ctx context.Context, key string, data []byte, contentType string) error {
	return c.upload(ctx, key, data, contentType, "")
}

// UploadGzipped stores data compressed, tagged so that clients transparently
// decompress it.
//
// Session recordings are Guacamole protocol streams: long runs of repetitive
// text instructions wrapping base64 image data, which compress well. Setting
// Content-Encoding means a browser fetching the object through a presigned URL
// inflates it itself, so the player needs no change and still receives the raw
// stream it expects.
func (c *Client) UploadGzipped(ctx context.Context, key string, data []byte, contentType string) (int, error) {
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return 0, fmt.Errorf("gzip writer: %w", err)
	}
	if _, err := zw.Write(data); err != nil {
		return 0, fmt.Errorf("gzip write: %w", err)
	}
	if err := zw.Close(); err != nil {
		return 0, fmt.Errorf("gzip close: %w", err)
	}

	if err := c.upload(ctx, key, buf.Bytes(), contentType, "gzip"); err != nil {
		return 0, err
	}
	return buf.Len(), nil
}

func (c *Client) upload(ctx context.Context, key string, data []byte, contentType, contentEncoding string) error {
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	in := &s3.PutObjectInput{
		Bucket:      aws.String(c.bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(data),
		ContentType: aws.String(contentType),
		ACL:         types.ObjectCannedACLPrivate,
	}
	if contentEncoding != "" {
		in.ContentEncoding = aws.String(contentEncoding)
	}

	_, err := c.s3Client.PutObject(ctx, in)
	return err
}

// Download fetches an object from S3 and returns its raw bytes.
func (c *Client) Download(ctx context.Context, key string) ([]byte, error) {
	out, err := c.s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, err
	}
	defer out.Body.Close()
	return io.ReadAll(out.Body)
}

// TestConnection verifies the bucket is reachable and the credentials are valid.
func (c *Client) TestConnection(ctx context.Context) error {
	_, err := c.s3Client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(c.bucket),
	})
	return err
}

// PresignedURL generates a pre-signed GET URL valid for the given duration.
func (c *Client) PresignedURL(ctx context.Context, key string, expiry time.Duration) (string, error) {
	req, err := c.presign.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(key),
	}, s3.WithPresignExpires(expiry))
	if err != nil {
		return "", err
	}
	return req.URL, nil
}
