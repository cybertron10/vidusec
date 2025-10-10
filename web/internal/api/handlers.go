package api

import (
	"log"
	"net/http"
	"strconv"

	"vidusec/web/internal/auth"
	"vidusec/web/internal/scanner"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	scannerService *scanner.Service
	authService    *auth.Service
}

func NewHandler(scannerService *scanner.Service, authService *auth.Service) *Handler {
	return &Handler{
		scannerService: scannerService,
		authService:    authService,
	}
}

// Register handles user registration
func (h *Handler) Register(c *gin.Context) {
	var req auth.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request data",
			"details": err.Error(),
		})
		return
	}

	response, err := h.authService.Register(&req)
	if err != nil {
		if err == auth.ErrUserExists {
			c.JSON(http.StatusConflict, gin.H{
				"error": "User already exists",
			})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to create user",
			})
		}
		return
	}

	c.JSON(http.StatusCreated, response)
}

// Login handles user login
func (h *Handler) Login(c *gin.Context) {
	var req auth.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request data",
		})
		return
	}

	response, err := h.authService.Login(&req)
	if err != nil {
		if err == auth.ErrUserNotFound || err == auth.ErrInvalidPassword {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid credentials",
			})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Login failed",
			})
		}
		return
	}

	c.JSON(http.StatusOK, response)
}

// Logout handles user logout
func (h *Handler) Logout(c *gin.Context) {
	// In a stateless JWT system, logout is handled client-side
	// We could implement token blacklisting here if needed
	c.JSON(http.StatusOK, gin.H{
		"message": "Logged out successfully",
	})
}

// GetProfile returns the current user's profile
func (h *Handler) GetProfile(c *gin.Context) {
	userID := c.GetInt("user_id")
	
	user, err := h.authService.GetUserByID(userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "User not found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user": user,
	})
}

// StartScan initiates a new security scan
func (h *Handler) StartScan(c *gin.Context) {
	userID := c.GetInt("user_id")

	var req scanner.ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request data",
			"details": err.Error(),
		})
		return
	}

	// Set defaults
	if req.MaxDepth == 0 {
		req.MaxDepth = 10
	}
	if req.MaxPages == 0 {
		req.MaxPages = 20000
	}

	response, err := h.scannerService.StartScan(userID, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to start scan",
		})
		return
	}

	c.JSON(http.StatusCreated, response)
}

// GetScans retrieves scans for the current user
func (h *Handler) GetScans(c *gin.Context) {
	userID := c.GetInt("user_id")

	// Parse pagination parameters
	limit := 20
	offset := 0

	if limitStr := c.Query("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}

	if offsetStr := c.Query("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	scans, err := h.scannerService.GetScans(userID, limit, offset)
	if err != nil {
		log.Printf("Error retrieving scans for user %d: %v", userID, err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve scans",
		})
		return
	}

	log.Printf("Retrieved %d scans for user %d: %v", len(scans), userID, scans)
	c.JSON(http.StatusOK, gin.H{
		"scans": scans,
		"pagination": gin.H{
			"limit":  limit,
			"offset": offset,
		},
	})
}

// GetScan retrieves a specific scan
func (h *Handler) GetScan(c *gin.Context) {
	userID := c.GetInt("user_id")

	scanIDStr := c.Param("id")
	scanID, err := strconv.Atoi(scanIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid scan ID",
		})
		return
	}

	scan, err := h.scannerService.GetScan(scanID, userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Scan not found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"scan": scan,
	})
}

// DeleteScan deletes a specific scan
func (h *Handler) DeleteScan(c *gin.Context) {
	userID := c.GetInt("user_id")

	scanIDStr := c.Param("id")
	scanID, err := strconv.Atoi(scanIDStr)
	if err != nil {
		log.Printf("Invalid scan ID in delete request: %s", scanIDStr)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid scan ID",
		})
		return
	}

	log.Printf("Delete scan request - UserID: %d, ScanID: %d", userID, scanID)
	
	// First check if scan exists
	_, err = h.scannerService.GetScan(scanID, userID)
	if err != nil {
		log.Printf("Scan not found for deletion - UserID: %d, ScanID: %d, Error: %v", userID, scanID, err)
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Scan not found",
		})
		return
	}

	// Delete the scan
	err = h.scannerService.DeleteScan(scanID, userID)
	if err != nil {
		log.Printf("Error deleting scan - UserID: %d, ScanID: %d, Error: %v", userID, scanID, err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to delete scan",
		})
		return
	}

	log.Printf("Successfully deleted scan - UserID: %d, ScanID: %d", userID, scanID)
	c.JSON(http.StatusOK, gin.H{
		"message": "Scan deleted successfully",
	})
}

// GetScanStatus returns the status of a specific scan
func (h *Handler) GetScanStatus(c *gin.Context) {
	userID := c.GetInt("user_id")

	scanIDStr := c.Param("id")
	scanID, err := strconv.Atoi(scanIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid scan ID",
		})
		return
	}

	scan, err := h.scannerService.GetScan(scanID, userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Scan not found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"scan_id":  scan.ID,
		"status":   scan.Status,
		"progress": scan.Progress,
		"started_at":   scan.StartedAt,
		"completed_at": scan.CompletedAt,
	})
}

// GetScanResults returns the results of a specific scan
func (h *Handler) GetScanResults(c *gin.Context) {
	userID := c.GetInt("user_id")
	scanIDStr := c.Param("id")
	
	log.Printf("GetScanResults called - UserID: %d, ScanID: %s", userID, scanIDStr)
	
	scanID, err := strconv.Atoi(scanIDStr)
	if err != nil {
		log.Printf("Invalid scan ID: %s", scanIDStr)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid scan ID",
		})
		return
	}

	log.Printf("Getting scan results for scan %d, user %d", scanID, userID)
	results, err := h.scannerService.GetScanResults(scanID, userID)
	if err != nil {
		log.Printf("Error getting scan results: %v", err)
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Scan not found",
		})
		return
	}

	log.Printf("Found %d results for scan %d", len(results), scanID)
	c.JSON(http.StatusOK, gin.H{
		"scan_id": scanID,
		"results": results,
		"count":   len(results),
	})
}

// RescanScan restarts a scan with the same parameters
func (h *Handler) RescanScan(c *gin.Context) {
	userID := c.GetInt("user_id")
	scanIDStr := c.Param("id")
	
	log.Printf("RescanScan called - UserID: %d, ScanID: %s", userID, scanIDStr)
	
	scanID, err := strconv.Atoi(scanIDStr)
	if err != nil {
		log.Printf("Invalid scan ID for rescan: %s", scanIDStr)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid scan ID",
		})
		return
	}

	// Parse request body for scan parameters
	var req struct {
		MaxDepth int `json:"max_depth"`
		MaxPages int `json:"max_pages"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("Error parsing rescan request: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request body",
		})
		return
	}

	// Set defaults
	if req.MaxDepth == 0 {
		req.MaxDepth = 10
	}
	if req.MaxPages == 0 {
		req.MaxPages = 20000
	}

	// Create ScanRequest struct
	scanReq := &scanner.ScanRequest{
		MaxDepth: req.MaxDepth,
		MaxPages: req.MaxPages,
		Headers:  make(map[string]string), // Empty headers for rescan
	}

	log.Printf("Starting rescan for scan %d, user %d", scanID, userID)
	response, err := h.scannerService.RescanScan(scanID, userID, scanReq)
	if err != nil {
		log.Printf("Error starting rescan: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to start rescan",
		})
		return
	}

	log.Printf("Rescan started successfully for scan %d", scanID)
	c.JSON(http.StatusOK, response)
}

// ExportScanResults exports scan results in various formats
func (h *Handler) ExportScanResults(c *gin.Context) {
	userID := c.GetInt("user_id")

	scanIDStr := c.Param("id")
	scanID, err := strconv.Atoi(scanIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid scan ID",
		})
		return
	}

	format := c.Query("format")
	if format == "" {
		format = "json"
	}

	// Verify scan exists and belongs to user
	_, err = h.scannerService.GetScan(scanID, userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Scan not found",
		})
		return
	}

	// For now, return JSON format
	// TODO: Implement CSV and other export formats
	if format == "json" {
		results, err := h.scannerService.GetScanResults(scanID, userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to export results",
			})
			return
		}

		c.Header("Content-Type", "application/json")
		c.Header("Content-Disposition", "attachment; filename=scan_results.json")
		c.JSON(http.StatusOK, gin.H{
			"scan_id": scanID,
			"results": results,
		})
	} else {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Unsupported export format",
		})
	}
}

// GetDashboardStats returns dashboard statistics
func (h *Handler) GetDashboardStats(c *gin.Context) {
	userID := c.GetInt("user_id")

	stats, err := h.scannerService.GetDashboardStats(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve dashboard statistics",
		})
		return
	}

	c.JSON(http.StatusOK, stats)
}
