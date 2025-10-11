package api

import (
	"log"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"vidusec/web/internal/auth"
	"vidusec/web/internal/scanner"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
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

// Input validation functions
func isValidURL(urlStr string) bool {
	u, err := url.Parse(urlStr)
	return err == nil && u.Scheme != "" && u.Host != ""
}

func sanitizeString(input string) string {
	// Remove potentially dangerous characters
	input = strings.TrimSpace(input)
	input = strings.ReplaceAll(input, "<", "&lt;")
	input = strings.ReplaceAll(input, ">", "&gt;")
	input = strings.ReplaceAll(input, "\"", "&quot;")
	input = strings.ReplaceAll(input, "'", "&#x27;")
	input = strings.ReplaceAll(input, "&", "&amp;")
	return input
}

func isValidScanID(idStr string) bool {
	matched, _ := regexp.MatchString(`^\d+$`, idStr)
	return matched
}

func isValidUUID(uuidStr string) bool {
	_, err := uuid.Parse(uuidStr)
	return err == nil
}

func normalizeURL(urlStr string) string {
	u, err := url.Parse(urlStr)
	if err != nil {
		return urlStr
	}
	
	// Normalize to just scheme + host for host-based matching
	// This ensures http://example.com/ and http://example.com are treated as the same
	normalized := u.Scheme + "://" + u.Host
	
	// Remove trailing slash to ensure consistency
	if strings.HasSuffix(normalized, "/") {
		normalized = normalized[:len(normalized)-1]
	}
	
	return normalized
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

	// Set the auth token as a cookie for web authentication
	c.SetCookie("auth_token", response.Token, 3600*24*7, "/", "", false, true) // 7 days, httpOnly

	c.JSON(http.StatusOK, response)
}

// Logout handles user logout
func (h *Handler) Logout(c *gin.Context) {
	// Clear the auth token cookie
	c.SetCookie("auth_token", "", -1, "/", "", false, true) // Expire immediately
	
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

	// Validate and sanitize input
	if !isValidURL(req.TargetURL) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid target URL",
		})
		return
	}

	// Sanitize and normalize URL
	req.TargetURL = sanitizeString(req.TargetURL)
	normalizedURL := normalizeURL(req.TargetURL)

	// Validate limits
	if req.MaxDepth < 1 || req.MaxDepth > 50 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Max depth must be between 1 and 50",
		})
		return
	}

	if req.MaxPages < 1 || req.MaxPages > 100000 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Max pages must be between 1 and 100000",
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

	// Check if there's an existing scan for the same host
	log.Printf("Checking for existing scan - UserID: %d, NormalizedURL: %s", userID, normalizedURL)
	existingScan, err := h.scannerService.GetScanByHost(userID, normalizedURL)
	if err == nil && existingScan != nil {
		// Overwrite existing scan instead of creating new one
		log.Printf("Found existing scan %d (UUID: %s) for host %s, overwriting...", existingScan.ID, existingScan.ScanUUID, normalizedURL)
		_, err := h.scannerService.RescanScanByUUID(existingScan.ScanUUID, userID, &req)
		if err != nil {
			log.Printf("Error overwriting existing scan: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to update existing scan",
			})
			return
		}
		
		c.JSON(http.StatusOK, gin.H{
			"scan_id": existingScan.ID,
			"status":  "overwritten",
			"message": "Existing scan updated successfully",
		})
		return
	} else if err != nil {
		log.Printf("Error checking for existing scan: %v", err)
	} else {
		log.Printf("No existing scan found for host %s, creating new scan", normalizedURL)
	}

	// Create new scan if no existing scan found
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

// GetScan retrieves a specific scan by UUID
func (h *Handler) GetScan(c *gin.Context) {
	userID := c.GetInt("user_id")

	scanUUID := c.Param("id")
	
	// Validate UUID format
	if !isValidUUID(scanUUID) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid scan ID format",
		})
		return
	}

	// Get scan with authorization check
	scan, err := h.scannerService.GetScanByUUID(scanUUID, userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Scan not found or access denied",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"scan": scan,
	})
}

// DeleteScan deletes a specific scan by UUID
func (h *Handler) DeleteScan(c *gin.Context) {
	userID := c.GetInt("user_id")

	scanUUID := c.Param("id")
	
	// Validate UUID format
	if !isValidUUID(scanUUID) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid scan ID format",
		})
		return
	}

	log.Printf("Delete scan request - UserID: %d, ScanUUID: %s", userID, scanUUID)
	
	// Verify ownership before deletion
	err := h.scannerService.VerifyScanOwnership(scanUUID, userID)
	if err != nil {
		log.Printf("Scan access denied for deletion - UserID: %d, ScanUUID: %s, Error: %v", userID, scanUUID, err)
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Scan not found or access denied",
		})
		return
	}

	// Delete the scan
	err = h.scannerService.DeleteScanByUUID(scanUUID, userID)
	if err != nil {
		log.Printf("Error deleting scan - UserID: %d, ScanUUID: %s, Error: %v", userID, scanUUID, err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to delete scan",
		})
		return
	}

	log.Printf("Successfully deleted scan - UserID: %d, ScanUUID: %s", userID, scanUUID)
	c.JSON(http.StatusOK, gin.H{
		"message": "Scan deleted successfully",
	})
}

// GetScanStatus returns the status of a specific scan by UUID
func (h *Handler) GetScanStatus(c *gin.Context) {
	userID := c.GetInt("user_id")

	scanUUID := c.Param("id")
	
	// Validate UUID format
	if !isValidUUID(scanUUID) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid scan ID format",
		})
		return
	}

	scan, err := h.scannerService.GetScanByUUID(scanUUID, userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Scan not found or access denied",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"scan_id":  scan.ScanUUID,
		"status":   scan.Status,
		"progress": scan.Progress,
		"started_at":   scan.StartedAt,
		"completed_at": scan.CompletedAt,
	})
}

// GetScanResults returns the results of a specific scan by UUID
func (h *Handler) GetScanResults(c *gin.Context) {
	userID := c.GetInt("user_id")
	scanUUID := c.Param("id")
	
	log.Printf("GetScanResults called - UserID: %d, ScanUUID: %s", userID, scanUUID)
	
	// Validate UUID format
	if !isValidUUID(scanUUID) {
		log.Printf("Invalid scan UUID: %s", scanUUID)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid scan ID format",
		})
		return
	}

	// Verify ownership first
	err := h.scannerService.VerifyScanOwnership(scanUUID, userID)
	if err != nil {
		log.Printf("Scan access denied - UserID: %d, ScanUUID: %s, Error: %v", userID, scanUUID, err)
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Scan not found or access denied",
		})
		return
	}

	log.Printf("Getting scan results for scan %s, user %d", scanUUID, userID)
	results, err := h.scannerService.GetScanResultsByUUID(scanUUID, userID)
	if err != nil {
		log.Printf("Error getting scan results: %v", err)
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Scan not found",
		})
		return
	}

	log.Printf("Found %d results for scan %s", len(results), scanUUID)
	c.JSON(http.StatusOK, gin.H{
		"scan_id": scanUUID,
		"results": results,
		"count":   len(results),
	})
}

// RescanScan restarts a scan with the same parameters by UUID
func (h *Handler) RescanScan(c *gin.Context) {
	userID := c.GetInt("user_id")
	scanUUID := c.Param("id")
	
	log.Printf("RescanScan called - UserID: %d, ScanUUID: %s", userID, scanUUID)
	
	// Validate UUID format
	if !isValidUUID(scanUUID) {
		log.Printf("Invalid scan UUID for rescan: %s", scanUUID)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid scan ID format",
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

	// Get the existing scan to get the target URL
	scan, err := h.scannerService.GetScanByUUID(scanUUID, userID)
	if err != nil {
		log.Printf("Error getting scan for rescan: %v", err)
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Scan not found or access denied",
		})
		return
	}

	// Create ScanRequest struct with the original target URL
	scanReq := &scanner.ScanRequest{
		TargetURL: scan.TargetURL,
		MaxDepth:  req.MaxDepth,
		MaxPages:  req.MaxPages,
		Headers:   make(map[string]string), // Empty headers for rescan
	}

	log.Printf("Starting rescan for scan %s, user %d", scanUUID, userID)
	response, err := h.scannerService.RescanScanByUUID(scanUUID, userID, scanReq)
	if err != nil {
		log.Printf("Error starting rescan: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to start rescan",
		})
		return
	}

	log.Printf("Rescan started successfully for scan %s", scanUUID)
	c.JSON(http.StatusOK, response)
}


// GetScanParameters returns all unique parameters found in a scan
func (h *Handler) GetScanParameters(c *gin.Context) {
	userID := c.GetInt("user_id")
	scanUUID := c.Param("id")
	
	log.Printf("GetScanParameters called - UserID: %d, ScanUUID: %s", userID, scanUUID)
	
	// Validate UUID format
	if !isValidUUID(scanUUID) {
		log.Printf("Invalid scan UUID: %s", scanUUID)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid scan ID format",
		})
		return
	}

	// Verify scan ownership
	err := h.scannerService.VerifyScanOwnership(scanUUID, userID)
	if err != nil {
		log.Printf("Scan ownership verification failed: %v", err)
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Scan not found or access denied",
		})
		return
	}

	// Get scan results to extract parameters
	results, err := h.scannerService.GetScanResultsByUUID(scanUUID, userID)
	if err != nil {
		log.Printf("Error getting scan results: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get scan results",
		})
		return
	}
	
	log.Printf("Found %d results for parameter extraction", len(results))

	// Extract unique parameters
	paramSet := make(map[string]bool)
	paramCount := 0
	formDataCount := 0
	
	for _, result := range results {
		// Extract parameters from map (already unmarshaled by GetScanResultsByUUID)
		if result.Parameters != nil {
			for param := range result.Parameters {
				paramSet[param] = true
				paramCount++
			}
		}
		
		// Extract form data from map (already unmarshaled by GetScanResultsByUUID)
		if result.FormData != nil {
			for param := range result.FormData {
				paramSet[param] = true
				formDataCount++
			}
		}
	}

	// Convert to sorted slice
	var parameters []string
	for param := range paramSet {
		parameters = append(parameters, param)
	}
	sort.Strings(parameters)

	log.Printf("Parameter extraction complete - Total params: %d, Form data: %d, Unique params: %d", paramCount, formDataCount, len(parameters))
	
	c.JSON(http.StatusOK, gin.H{
		"scan_id": scanUUID,
		"parameters": parameters,
		"count": len(parameters),
	})
}

// GetScanURLs returns all GET URLs found in a scan
func (h *Handler) GetScanURLs(c *gin.Context) {
	userID := c.GetInt("user_id")
	scanUUID := c.Param("id")
	
	// Validate UUID format
	if !isValidUUID(scanUUID) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid scan ID format",
		})
		return
	}

	// Verify scan ownership
	err := h.scannerService.VerifyScanOwnership(scanUUID, userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Scan not found or access denied",
		})
		return
	}

	// Get scan results to extract GET URLs
	results, err := h.scannerService.GetScanResultsByUUID(scanUUID, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get scan results",
		})
		return
	}

	// Extract GET URLs
	var urls []string
	for _, result := range results {
		if result.EndpointType == "get" {
			urls = append(urls, result.URL)
		}
	}

	// Remove duplicates and sort
	urlSet := make(map[string]bool)
	for _, url := range urls {
		urlSet[url] = true
	}
	
	var uniqueURLs []string
	for url := range urlSet {
		uniqueURLs = append(uniqueURLs, url)
	}
	sort.Strings(uniqueURLs)

	c.JSON(http.StatusOK, gin.H{
		"scan_id": scanUUID,
		"urls": uniqueURLs,
		"count": len(uniqueURLs),
	})
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
