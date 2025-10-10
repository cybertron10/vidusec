package scanner

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"vidusec/web/internal/database"
	"vidusec/web/internal/crawler"
	"vidusec/web/internal/scanning"
)

type Service struct {
	db *database.DB
}

type ScanRequest struct {
	TargetURL  string            `json:"target_url" binding:"required,url"`
	MaxDepth   int               `json:"max_depth" binding:"min=1,max=50"`
	MaxPages   int               `json:"max_pages" binding:"min=1,max=100000"`
	Headers    map[string]string `json:"headers"`
}

type ScanResponse struct {
	ScanID int    `json:"scan_id"`
	Status string `json:"status"`
	Message string `json:"message"`
}

func NewService(db *database.DB) *Service {
	return &Service{db: db}
}

// StartScan initiates a new security scan
func (s *Service) StartScan(userID int, req *ScanRequest) (*ScanResponse, error) {
	// Create scan record
	result, err := s.db.Exec(`
		INSERT INTO scans (user_id, target_url, max_depth, max_pages, status) 
		VALUES (?, ?, ?, ?, 'pending')`,
		userID, req.TargetURL, req.MaxDepth, req.MaxPages)
	if err != nil {
		return nil, err
	}

	scanID, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	// Start scan in background
	go s.runScan(int(scanID), req)

	return &ScanResponse{
		ScanID:  int(scanID),
		Status:  "pending",
		Message: "Scan initiated successfully",
	}, nil
}

// runScan executes the actual scanning process
func (s *Service) runScan(scanID int, req *ScanRequest) {
	// Update status to running
	now := time.Now()
	_, err := s.db.Exec(`
		UPDATE scans SET status = 'running', started_at = ?, progress = 0 
		WHERE id = ?`,
		now, scanID)
	if err != nil {
		log.Printf("Error updating scan status: %v", err)
		return
	}

	// Create output directory for this scan
	scanDir := filepath.Join("data", "scans", strconv.Itoa(scanID))
	if err := os.MkdirAll(scanDir, 0755); err != nil {
		log.Printf("Error creating scan directory: %v", err)
		s.updateScanStatus(scanID, "failed", 0)
		return
	}

	// Update progress
	s.updateScanProgress(scanID, 10)

	// Run enhanced crawler
	log.Printf("Starting scan %d for URL: %s", scanID, req.TargetURL)
	
	crawlResult, err := crawler.EnhancedCrawl(
		req.TargetURL, 
		req.MaxDepth, 
		req.MaxPages, 
		req.Headers,
	)
	if err != nil {
		log.Printf("Error during crawling: %v", err)
		s.updateScanStatus(scanID, "failed", 0)
		return
	}

	// Update progress
	s.updateScanProgress(scanID, 50)

	// Create structured scanning data
	scanData := scanning.CreateScanningData(
		crawlResult.URLs,
		crawlResult.FormFields,
		crawlResult.JavaScriptAPIs,
		crawlResult.HiddenFields,
		crawlResult.POSTEndpoints,
	)

	// Update progress
	s.updateScanProgress(scanID, 70)

	// Save results to database
	log.Printf("Saving scan results for scan %d: %d GET, %d POST, %d JS endpoints", 
		scanID, len(scanData.GETEndpoints), len(scanData.POSTEndpoints), len(scanData.JSEndpoints))
	
	err = s.saveScanResults(scanID, scanData)
	if err != nil {
		log.Printf("Error saving scan results: %v", err)
		s.updateScanStatus(scanID, "failed", 0)
		return
	}
	
	log.Printf("Successfully saved scan results for scan %d", scanID)

	// Update progress
	s.updateScanProgress(scanID, 90)

	// Save files
	err = s.saveScanFiles(scanID, scanDir, scanData)
	if err != nil {
		log.Printf("Error saving scan files: %v", err)
		// Don't fail the scan for file save errors
	}

	// Update progress and status
	s.updateScanProgress(scanID, 100)
	s.updateScanStatus(scanID, "completed", 100)

	log.Printf("Scan %d completed successfully", scanID)
}

// saveScanResults saves discovered endpoints to database
func (s *Service) saveScanResults(scanID int, scanData *scanning.ScanningData) error {
	// Save GET endpoints
	for _, endpoint := range scanData.GETEndpoints {
		paramsJSON, _ := json.Marshal(endpoint.Parameters)
		headersJSON, _ := json.Marshal(endpoint.Headers)
		
		_, err := s.db.Exec(`
			INSERT INTO scan_results (scan_id, endpoint_type, url, method, parameters, headers, description)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			scanID, "get", endpoint.URL, endpoint.Method, string(paramsJSON), 
			string(headersJSON), endpoint.Description)
		if err != nil {
			return err
		}
	}

	// Save POST endpoints
	for _, endpoint := range scanData.POSTEndpoints {
		paramsJSON, _ := json.Marshal(endpoint.Parameters)
		formDataJSON, _ := json.Marshal(endpoint.FormData)
		headersJSON, _ := json.Marshal(endpoint.Headers)
		
		_, err := s.db.Exec(`
			INSERT INTO scan_results (scan_id, endpoint_type, url, method, parameters, form_data, headers, description)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			scanID, "post", endpoint.URL, endpoint.Method, string(paramsJSON), 
			string(formDataJSON), string(headersJSON), endpoint.Description)
		if err != nil {
			return err
		}
	}

	// Save JS endpoints
	for _, endpoint := range scanData.JSEndpoints {
		paramsJSON, _ := json.Marshal(endpoint.Parameters)
		headersJSON, _ := json.Marshal(endpoint.Headers)
		
		_, err := s.db.Exec(`
			INSERT INTO scan_results (scan_id, endpoint_type, url, method, parameters, headers, description)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			scanID, "js_api", endpoint.URL, endpoint.Method, string(paramsJSON), 
			string(headersJSON), endpoint.Description)
		if err != nil {
			return err
		}
	}

	// Save statistics
	_, err := s.db.Exec(`
		INSERT INTO scan_statistics (scan_id, total_endpoints, get_endpoints, post_endpoints, js_endpoints, total_parameters)
		VALUES (?, ?, ?, ?, ?, ?)`,
		scanID, scanData.Summary.TotalEndpoints, scanData.Summary.GETCount, 
		scanData.Summary.POSTCount, scanData.Summary.JSCount, scanData.Summary.TotalParams)
	
	return err
}

// saveScanFiles saves generated files
func (s *Service) saveScanFiles(scanID int, scanDir string, scanData *scanning.ScanningData) error {
	// Save JSON data
	jsonFile := filepath.Join(scanDir, "scan_results.json")
	err := scanData.SaveToFile(jsonFile)
	if err != nil {
		return err
	}

	// Save XSS endpoints
	xssFile := filepath.Join(scanDir, "xss_endpoints.txt")
	err = scanData.SaveEndpointsForXSS(xssFile)
	if err != nil {
		return err
	}

	// Record files in database
	files := []struct {
		fileType string
		filePath string
	}{
		{"json", jsonFile},
		{"txt", xssFile},
	}

	for _, file := range files {
		info, err := os.Stat(file.filePath)
		if err != nil {
			continue
		}

		_, err = s.db.Exec(`
			INSERT INTO scan_files (scan_id, file_type, file_path, file_size)
			VALUES (?, ?, ?, ?)`,
			scanID, file.fileType, file.filePath, info.Size())
		if err != nil {
			log.Printf("Error saving file record: %v", err)
		}
	}

	return nil
}

// updateScanStatus updates the scan status
func (s *Service) updateScanStatus(scanID int, status string, progress int) {
	now := time.Now()
	_, err := s.db.Exec(`
		UPDATE scans SET status = ?, progress = ?, completed_at = ? 
		WHERE id = ?`,
		status, progress, now, scanID)
	if err != nil {
		log.Printf("Error updating scan status: %v", err)
	}
}

// updateScanProgress updates the scan progress
func (s *Service) updateScanProgress(scanID int, progress int) {
	_, err := s.db.Exec(`UPDATE scans SET progress = ? WHERE id = ?`, progress, scanID)
	if err != nil {
		log.Printf("Error updating scan progress: %v", err)
	}
}

// GetScans retrieves scans for a user
func (s *Service) GetScans(userID int, limit, offset int) ([]database.Scan, error) {
	rows, err := s.db.Query(`
		SELECT id, user_id, target_url, max_depth, max_pages, status, progress, 
		       started_at, completed_at, created_at
		FROM scans 
		WHERE user_id = ? 
		ORDER BY created_at DESC 
		LIMIT ? OFFSET ?`,
		userID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []database.Scan
	for rows.Next() {
		var scan database.Scan
		err := rows.Scan(
			&scan.ID, &scan.UserID, &scan.TargetURL, &scan.MaxDepth, &scan.MaxPages,
			&scan.Status, &scan.Progress, &scan.StartedAt, &scan.CompletedAt, &scan.CreatedAt)
		if err != nil {
			return nil, err
		}
		scans = append(scans, scan)
	}

	return scans, nil
}

// GetScan retrieves a specific scan
func (s *Service) GetScan(scanID, userID int) (*database.Scan, error) {
	scan := &database.Scan{}
	err := s.db.QueryRow(`
		SELECT id, user_id, target_url, max_depth, max_pages, status, progress, 
		       started_at, completed_at, created_at
		FROM scans 
		WHERE id = ? AND user_id = ?`,
		scanID, userID).Scan(
		&scan.ID, &scan.UserID, &scan.TargetURL, &scan.MaxDepth, &scan.MaxPages,
		&scan.Status, &scan.Progress, &scan.StartedAt, &scan.CompletedAt, &scan.CreatedAt)
	if err != nil {
		return nil, err
	}
	return scan, nil
}

// GetScanResults retrieves results for a specific scan
func (s *Service) GetScanResults(scanID, userID int) ([]database.ScanResult, error) {
	// Verify scan belongs to user
	_, err := s.GetScan(scanID, userID)
	if err != nil {
		return nil, err
	}

	rows, err := s.db.Query(`
		SELECT id, scan_id, endpoint_type, url, method, parameters, form_data, headers, description, created_at
		FROM scan_results 
		WHERE scan_id = ? 
		ORDER BY created_at DESC`,
		scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []database.ScanResult
	for rows.Next() {
		var result database.ScanResult
		var paramsJSON, formDataJSON, headersJSON string
		
		err := rows.Scan(
			&result.ID, &result.ScanID, &result.EndpointType, &result.URL, &result.Method,
			&paramsJSON, &formDataJSON, &headersJSON, &result.Description, &result.CreatedAt)
		if err != nil {
			return nil, err
		}

		// Parse JSON fields
		json.Unmarshal([]byte(paramsJSON), &result.Parameters)
		json.Unmarshal([]byte(formDataJSON), &result.FormData)
		json.Unmarshal([]byte(headersJSON), &result.Headers)

		results = append(results, result)
	}

	return results, nil
}

// DeleteScan deletes a scan and its associated data
func (s *Service) DeleteScan(scanID, userID int) error {
	// Verify scan belongs to user
	_, err := s.GetScan(scanID, userID)
	if err != nil {
		return err
	}

	// Delete scan files
	scanDir := filepath.Join("data", "scans", strconv.Itoa(scanID))
	os.RemoveAll(scanDir)

	// Delete from database (cascade will handle related records)
	_, err = s.db.Exec(`DELETE FROM scans WHERE id = ? AND user_id = ?`, scanID, userID)
	return err
}

// GetDashboardStats retrieves dashboard statistics for a user
func (s *Service) GetDashboardStats(userID int) (*database.DashboardStats, error) {
	stats := &database.DashboardStats{}

	// Get scan counts
	err := s.db.QueryRow(`
		SELECT 
			COUNT(*) as total_scans,
			SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed_scans,
			SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) as running_scans
		FROM scans WHERE user_id = ?`,
		userID).Scan(&stats.TotalScans, &stats.CompletedScans, &stats.RunningScans)
	if err != nil {
		return nil, err
	}

	// Get total endpoints
	err = s.db.QueryRow(`
		SELECT COUNT(*) 
		FROM scan_results sr 
		JOIN scans s ON sr.scan_id = s.id 
		WHERE s.user_id = ?`,
		userID).Scan(&stats.TotalEndpoints)
	if err != nil {
		return nil, err
	}

	// Get recent scans
	recentScans, err := s.GetScans(userID, 5, 0)
	if err != nil {
		return nil, err
	}
	stats.RecentScans = recentScans

	return stats, nil
}
