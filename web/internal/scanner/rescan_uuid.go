package scanner

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

	// Reset scan status and progress
	_, err = s.db.Exec(`
		UPDATE scans SET status = 'pending', progress = 0, started_at = NULL, completed_at = NULL 
		WHERE scan_uuid = ? AND user_id = ?`,
		scanUUID, userID)
	if err != nil {
		return nil, err
	}

	// Delete old results
	_, err = s.db.Exec(`DELETE FROM scan_results WHERE scan_uuid = ?`, scanUUID)
	if err != nil {
		return nil, err
	}

	// Delete old statistics
	_, err = s.db.Exec(`DELETE FROM scan_statistics WHERE scan_uuid = ?`, scanUUID)
	if err != nil {
		return nil, err
	}

	// Delete old files
	_, err = s.db.Exec(`DELETE FROM scan_files WHERE scan_uuid = ?`, scanUUID)
	if err != nil {
		return nil, err
	}

	// Start scan in background
	go s.runScan(scan.ID, scanUUID, req)

	return &ScanResponse{
		ScanID:  scan.ID,
		Status:  "pending",
		Message: "Rescan initiated successfully",
	}, nil
}
