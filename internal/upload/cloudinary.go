package upload

import (
	"context"
	"fmt"
	"mime/multipart"
	"os"
	"path/filepath"
	"time"

	"github.com/cloudinary/cloudinary-go/v2"
	"github.com/cloudinary/cloudinary-go/v2/api/uploader"
	"go.uber.org/zap"
)

type Service struct {
	cld    *cloudinary.Cloudinary
	logger *zap.Logger
}

func NewService(logger *zap.Logger) (*Service, error) {
	cloudinaryURL := os.Getenv("CLOUDINARY_URL")
	if cloudinaryURL == "" {
		logger.Warn("CLOUDINARY_URL not set, image uploads will be disabled")
		return &Service{logger: logger}, nil
	}

	cld, err := cloudinary.NewFromURL(cloudinaryURL)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Cloudinary: %w", err)
	}

	logger.Info("Cloudinary service initialized")
	return &Service{
		cld:    cld,
		logger: logger,
	}, nil
}

// UploadImage uploads an image to Cloudinary
func (s *Service) UploadImage(file *multipart.FileHeader, folder string) (string, error) {
	if s.cld == nil {
		return "", fmt.Errorf("cloudinary not configured")
	}

	// Open the uploaded file
	src, err := file.Open()
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer src.Close()

	// Generate unique public ID
	publicID := fmt.Sprintf("%s/%d_%s", folder, time.Now().Unix(), filepath.Base(file.Filename))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Upload to Cloudinary
	uploadResult, err := s.cld.Upload.Upload(ctx, src, uploader.UploadParams{
		PublicID:     publicID,
		ResourceType: "image",
		Folder:       folder,
	})
	if err != nil {
		return "", fmt.Errorf("failed to upload to cloudinary: %w", err)
	}

	s.logger.Info("Image uploaded to Cloudinary",
		zap.String("public_id", uploadResult.PublicID),
		zap.String("url", uploadResult.SecureURL))

	return uploadResult.SecureURL, nil
}

// DeleteImage deletes an image from Cloudinary
func (s *Service) DeleteImage(publicID string) error {
	if s.cld == nil {
		return fmt.Errorf("cloudinary not configured")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := s.cld.Upload.Destroy(ctx, uploader.DestroyParams{
		PublicID: publicID,
	})
	if err != nil {
		return fmt.Errorf("failed to delete from cloudinary: %w", err)
	}

	s.logger.Info("Image deleted from Cloudinary", zap.String("public_id", publicID))
	return nil
}
