// Package storage wraps the S3 client (Cloudflare R2 in production, MinIO locally).
package storage

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

var ErrNotFound = errors.New("object not found")

type Storage struct {
	client  *s3.Client
	presign *s3.PresignClient
	bucket  string
}

func New(endpoint, region, keyID, secret, bucket string) *Storage {
	client := s3.New(s3.Options{
		BaseEndpoint: aws.String(endpoint),
		Region:       region,
		Credentials:  credentials.NewStaticCredentialsProvider(keyID, secret, ""),
		UsePathStyle: true, // SPEC 2: path-style for both R2 and MinIO
		// No automatic CRC32 checksums: they would end up in presigned URLs, which the
		// browser's PUT cannot satisfy, and R2 does not need them.
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
		RetryMaxAttempts:           3,
	})
	return &Storage{client: client, presign: s3.NewPresignClient(client), bucket: bucket}
}

// PresignPut signs Content-Type and Content-Length, so the bucket accepts only a body of
// exactly `size` bytes with exactly that type, for as long as the URL lives.
func (s *Storage) PresignPut(ctx context.Context, key, contentType string, size int64, ttl time.Duration) (string, error) {
	req, err := s.presign.PresignPutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.bucket), Key: aws.String(key),
		ContentType: aws.String(contentType), ContentLength: aws.Int64(size),
	}, s3.WithPresignExpires(ttl))
	if err != nil {
		return "", err
	}
	return req.URL, nil
}

// PresignGet forces Content-Disposition: attachment so the bucket origin never renders a file inline.
func (s *Storage) PresignGet(ctx context.Context, key string, ttl time.Duration) (string, error) {
	req, err := s.presign.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket), Key: aws.String(key), ResponseContentDisposition: aws.String("attachment"),
	}, s3.WithPresignExpires(ttl))
	if err != nil {
		return "", err
	}
	return req.URL, nil
}

// Size returns the stored object's size, or ErrNotFound.
func (s *Storage) Size(ctx context.Context, key string) (int64, error) {
	out, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)})
	if err != nil {
		var re *smithyhttp.ResponseError
		if errors.As(err, &re) && re.HTTPStatusCode() == http.StatusNotFound {
			return 0, ErrNotFound
		}
		return 0, err
	}
	return aws.ToInt64(out.ContentLength), nil
}

// Delete is idempotent: deleting a missing object succeeds.
func (s *Storage) Delete(ctx context.Context, key string) error {
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)})
	return err
}
