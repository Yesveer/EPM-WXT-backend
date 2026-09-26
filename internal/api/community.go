package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/vsay/vsay-agent-backend/internal/store"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
)

// CreateIssue creates a new issue
func (h *Handler) CreateIssue(c *gin.Context) {
	userIDStr := c.GetString("user_id")
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		h.logger.Error("Invalid user ID", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	// Get username from context (provided by vsay-auth)
	username := c.GetString("username")

	var req struct {
		Title       string   `json:"title" binding:"required"`
		Description string   `json:"description" binding:"required"`
		Status      string   `json:"status"`
		Images      []string `json:"images"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("Invalid request body", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Set default status if not provided
	if req.Status == "" {
		req.Status = "open"
	}

	issue := &store.Issue{
		Title:       req.Title,
		Description: req.Description,
		Status:      req.Status,
		AuthorID:    userID,
		AuthorName:  username,
		Images:      req.Images,
	}

	if err := h.store.CreateIssue(issue); err != nil {
		h.logger.Error("Failed to create issue", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create issue"})
		return
	}

	h.logger.Info("Issue created",
		zap.String("issue_id", issue.ID.Hex()),
		zap.String("user_id", userIDStr),
		zap.String("title", issue.Title))

	c.JSON(http.StatusCreated, gin.H{
		"message": "Issue created successfully",
		"issue":   issue,
	})
}

// GetAllIssues retrieves all issues with pagination
func (h *Handler) GetAllIssues(c *gin.Context) {
	// Get pagination parameters
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))

	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 10
	}

	skip := (page - 1) * limit

	issues, err := h.store.GetAllIssues(limit, skip)
	if err != nil {
		h.logger.Error("Failed to get issues", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get issues"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"issues": issues,
		"page":   page,
		"limit":  limit,
	})
}

// GetIssueByID retrieves a single issue by ID
func (h *Handler) GetIssueByID(c *gin.Context) {
	issueID := c.Param("id")
	objID, err := primitive.ObjectIDFromHex(issueID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid issue ID"})
		return
	}

	issue, err := h.store.GetIssueByID(objID)
	if err != nil {
		h.logger.Error("Issue not found", zap.String("issue_id", issueID), zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": "Issue not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"issue": issue})
}

// UpdateIssue updates an existing issue
func (h *Handler) UpdateIssue(c *gin.Context) {
	userIDStr := c.GetString("user_id")
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	issueID := c.Param("id")
	objID, err := primitive.ObjectIDFromHex(issueID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid issue ID"})
		return
	}

	// Get existing issue
	issue, err := h.store.GetIssueByID(objID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Issue not found"})
		return
	}

	// Check if user is the author
	if issue.AuthorID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Not authorized to update this issue"})
		return
	}

	var req struct {
		Title       string   `json:"title"`
		Description string   `json:"description"`
		Status      string   `json:"status"`
		Images      []string `json:"images"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Build updates map
	updates := make(map[string]interface{})
	if req.Title != "" {
		updates["title"] = req.Title
	}
	if req.Description != "" {
		updates["description"] = req.Description
	}
	if req.Status != "" {
		updates["status"] = req.Status
	}
	if req.Images != nil {
		updates["images"] = req.Images
	}

	if err := h.store.UpdateIssue(objID, updates); err != nil {
		h.logger.Error("Failed to update issue", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update issue"})
		return
	}

	h.logger.Info("Issue updated",
		zap.String("issue_id", issueID),
		zap.String("user_id", userIDStr))

	c.JSON(http.StatusOK, gin.H{"message": "Issue updated successfully"})
}

// DeleteIssue deletes an issue
func (h *Handler) DeleteIssue(c *gin.Context) {
	userIDStr := c.GetString("user_id")
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	issueID := c.Param("id")
	objID, err := primitive.ObjectIDFromHex(issueID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid issue ID"})
		return
	}

	// Get existing issue
	issue, err := h.store.GetIssueByID(objID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Issue not found"})
		return
	}

	// Check if user is the author
	if issue.AuthorID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Not authorized to delete this issue"})
		return
	}

	if err := h.store.DeleteIssue(objID); err != nil {
		h.logger.Error("Failed to delete issue", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete issue"})
		return
	}

	h.logger.Info("Issue deleted",
		zap.String("issue_id", issueID),
		zap.String("user_id", userIDStr))

	c.JSON(http.StatusOK, gin.H{"message": "Issue deleted successfully"})
}

// CreateFix creates a new fix/solution for an issue
func (h *Handler) CreateFix(c *gin.Context) {
	userIDStr := c.GetString("user_id")
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	// Get username from context (provided by vsay-auth)
	username := c.GetString("username")

	issueID := c.Param("id")
	issueObjID, err := primitive.ObjectIDFromHex(issueID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid issue ID"})
		return
	}

	// Verify issue exists
	_, err = h.store.GetIssueByID(issueObjID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Issue not found"})
		return
	}

	var req struct {
		Content string   `json:"content" binding:"required"`
		Images  []string `json:"images"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	fix := &store.Fix{
		IssueID:    issueObjID,
		AuthorID:   userID,
		AuthorName: username,
		Content:    req.Content,
		Images:     req.Images,
	}

	if err := h.store.CreateFix(fix); err != nil {
		h.logger.Error("Failed to create fix", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create fix"})
		return
	}

	h.logger.Info("Fix created",
		zap.String("fix_id", fix.ID.Hex()),
		zap.String("issue_id", issueID),
		zap.String("user_id", userIDStr))

	c.JSON(http.StatusCreated, gin.H{
		"message": "Fix created successfully",
		"fix":     fix,
	})
}

// GetFixesByIssue retrieves all fixes for an issue
func (h *Handler) GetFixesByIssue(c *gin.Context) {
	issueID := c.Param("id")
	objID, err := primitive.ObjectIDFromHex(issueID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid issue ID"})
		return
	}

	fixes, err := h.store.GetFixesByIssue(objID)
	if err != nil {
		h.logger.Error("Failed to get fixes", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get fixes"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"fixes": fixes})
}

// LikeFix adds a like to a fix
func (h *Handler) LikeFix(c *gin.Context) {
	// Get username from context (provided by vsay-auth)
	username := c.GetString("username")

	fixID := c.Param("fix_id")
	objID, err := primitive.ObjectIDFromHex(fixID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid fix ID"})
		return
	}

	if err := h.store.LikeFix(objID, username); err != nil {
		h.logger.Error("Failed to like fix", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to like fix"})
		return
	}

	h.logger.Info("Fix liked",
		zap.String("fix_id", fixID),
		zap.String("user", username))

	c.JSON(http.StatusOK, gin.H{"message": "Fix liked successfully"})
}

// UnlikeFix removes a like from a fix
func (h *Handler) UnlikeFix(c *gin.Context) {
	// Get username from context (provided by vsay-auth)
	username := c.GetString("username")

	fixID := c.Param("fix_id")
	objID, err := primitive.ObjectIDFromHex(fixID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid fix ID"})
		return
	}

	if err := h.store.UnlikeFix(objID, username); err != nil {
		h.logger.Error("Failed to unlike fix", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to unlike fix"})
		return
	}

	h.logger.Info("Fix unliked",
		zap.String("fix_id", fixID),
		zap.String("user", username))

	c.JSON(http.StatusOK, gin.H{"message": "Fix unliked successfully"})
}

// MarkFixAsAccepted marks a fix as the accepted solution
func (h *Handler) MarkFixAsAccepted(c *gin.Context) {
	userIDStr := c.GetString("user_id")
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	issueID := c.Param("id")
	issueObjID, err := primitive.ObjectIDFromHex(issueID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid issue ID"})
		return
	}

	// Get issue to verify ownership
	issue, err := h.store.GetIssueByID(issueObjID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Issue not found"})
		return
	}

	// Check if user is the issue author
	if issue.AuthorID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Only issue author can mark fixes as accepted"})
		return
	}

	fixID := c.Param("fix_id")
	fixObjID, err := primitive.ObjectIDFromHex(fixID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid fix ID"})
		return
	}

	if err := h.store.MarkFixAsAccepted(fixObjID, issueObjID); err != nil {
		h.logger.Error("Failed to mark fix as accepted", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to mark fix as accepted"})
		return
	}

	// Update issue status to "closed"
	if err := h.store.UpdateIssue(issueObjID, map[string]interface{}{"status": "closed"}); err != nil {
		h.logger.Warn("Failed to update issue status", zap.Error(err))
	}

	h.logger.Info("Fix marked as accepted",
		zap.String("fix_id", fixID),
		zap.String("issue_id", issueID))

	c.JSON(http.StatusOK, gin.H{"message": "Fix marked as accepted"})
}

// UploadImage handles image upload to Cloudinary
func (h *Handler) UploadImage(c *gin.Context) {
	file, err := c.FormFile("image")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No image provided"})
		return
	}

	// Validate file size (max 10MB)
	if file.Size > 10*1024*1024 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "File size exceeds 10MB limit"})
		return
	}

	// Validate file type
	contentType := file.Header.Get("Content-Type")
	if contentType != "image/jpeg" && contentType != "image/png" && contentType != "image/jpg" && contentType != "image/webp" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid file type. Only JPEG, PNG, and WebP are allowed"})
		return
	}

	h.logger.Info("Image upload requested",
		zap.String("filename", file.Filename),
		zap.Int64("size", file.Size),
		zap.String("content_type", contentType))

	// Upload to Cloudinary
	imageURL, err := h.uploadService.UploadImage(file, "vsay/community")
	if err != nil {
		h.logger.Error("Failed to upload image", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to upload image"})
		return
	}

	h.logger.Info("Image uploaded successfully", zap.String("url", imageURL))

	c.JSON(http.StatusOK, gin.H{
		"message": "Image uploaded successfully",
		"url":     imageURL,
	})
}
