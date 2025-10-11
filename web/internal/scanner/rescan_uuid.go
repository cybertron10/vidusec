package scanner

import "log"

// RescanScanByUUID restarts a scan by UUID with authorization check
func (s *Service) RescanScanByUUID(scanUUID string, userID int, req *ScanRequest) (*ScanResponse, error) {
	// Verify ownership first
	err := s.VerifyScanOwnership(scanUUID, userID)
	if err != nil {
		return nil, err
	}

	// Get the scan to get its ID
	scan, err := s.GetScanByUUID(scanUUID, userID)
	if err != nil {
		return nil, err
	}

	// Set the target URL in the request for the rescan
	req.TargetURL = scan.TargetURL
	log.Printf("Rescan request prepared - URL: %s, MaxDepth: %d, MaxPages: %d", req.TargetURL, req.MaxDepth, req.MaxPages)

	// Reset scan status and progress
	log.Printf("Resetting scan status for UUID %s", scanUUID)
	_, err = s.db.Exec(`
		UPDATE scans SET status = 'pending', progress = 0, started_at = NULL, completed_at = NULL 
		WHERE scan_uuid = ? AND user_id = ?`,
		scanUUID, userID)
	if err != nil {
		log.Printf("Failed to reset scan status: %v", err)
		return nil, err
	}

	// Delete old results
	log.Printf("Deleting old results for UUID %s", scanUUID)
	_, err = s.db.Exec(`DELETE FROM scan_results WHERE scan_uuid = ?`, scanUUID)
	if err != nil {
		log.Printf("Failed to delete old results: %v", err)
		return nil, err
	}

	// Delete old statistics
	log.Printf("Deleting old statistics for UUID %s", scanUUID)
	_, err = s.db.Exec(`DELETE FROM scan_statistics WHERE scan_uuid = ?`, scanUUID)
	if err != nil {
		log.Printf("Failed to delete old statistics: %v", err)
		return nil, err
	}

	// Delete old files
	log.Printf("Deleting old files for UUID %s", scanUUID)
	_, err = s.db.Exec(`DELETE FROM scan_files WHERE scan_uuid = ?`, scanUUID)
	if err != nil {
		log.Printf("Failed to delete old files: %v", err)
		return nil, err
	}

	// Start scan in background
	log.Printf("Starting background scan for ID %d, UUID %s", scan.ID, scanUUID)
	go s.runScan(scan.ID, scanUUID, req)

	log.Printf("Rescan initiated successfully for scan %d (UUID: %s)", scan.ID, scanUUID)
	return &ScanResponse{
		ScanID:  scan.ID,
		Status:  "pending",
		Message: "Rescan initiated successfully",
	}, nil
}
