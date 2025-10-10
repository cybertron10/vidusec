package database

import (
	"database/sql"
	"log"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

type DB struct {
	*sql.DB
}

// Initialize creates and initializes the database
func Initialize() (*DB, error) {
	// Create data directory if it doesn't exist
	if err := os.MkdirAll("data", 0755); err != nil {
		return nil, err
	}

	// Open SQLite database
	db, err := sql.Open("sqlite3", "data/vidusec.db")
	if err != nil {
		return nil, err
	}

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, err
	}

	database := &DB{db}

	// Create tables
	if err := database.createTables(); err != nil {
		return nil, err
	}

	log.Println("✅ Database initialized successfully")
	return database, nil
}

// createTables creates all necessary tables
func (db *DB) createTables() error {
	queries := []string{
		// Users table
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			email TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// Scans table
		`CREATE TABLE IF NOT EXISTS scans (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			target_url TEXT NOT NULL,
			max_depth INTEGER DEFAULT 10,
			max_pages INTEGER DEFAULT 20000,
			status TEXT DEFAULT 'pending',
			progress INTEGER DEFAULT 0,
			started_at DATETIME,
			completed_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users (id)
		)`,

		// Scan results table
		`CREATE TABLE IF NOT EXISTS scan_results (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_id INTEGER NOT NULL,
			endpoint_type TEXT NOT NULL,
			url TEXT NOT NULL,
			method TEXT NOT NULL,
			parameters TEXT,
			form_data TEXT,
			headers TEXT,
			description TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (scan_id) REFERENCES scans (id)
		)`,

		// Scan statistics table
		`CREATE TABLE IF NOT EXISTS scan_statistics (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_id INTEGER NOT NULL,
			total_endpoints INTEGER DEFAULT 0,
			get_endpoints INTEGER DEFAULT 0,
			post_endpoints INTEGER DEFAULT 0,
			js_endpoints INTEGER DEFAULT 0,
			total_parameters INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (scan_id) REFERENCES scans (id)
		)`,

		// Scan files table (for storing generated files)
		`CREATE TABLE IF NOT EXISTS scan_files (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_id INTEGER NOT NULL,
			file_type TEXT NOT NULL,
			file_path TEXT NOT NULL,
			file_size INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (scan_id) REFERENCES scans (id)
		)`,
	}

	for _, query := range queries {
		if _, err := db.Exec(query); err != nil {
			return err
		}
	}

	// Create indexes for better performance
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id)",
		"CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)",
		"CREATE INDEX IF NOT EXISTS idx_scan_results_scan_id ON scan_results(scan_id)",
		"CREATE INDEX IF NOT EXISTS idx_scan_results_type ON scan_results(endpoint_type)",
		"CREATE INDEX IF NOT EXISTS idx_scan_files_scan_id ON scan_files(scan_id)",
	}

	for _, index := range indexes {
		if _, err := db.Exec(index); err != nil {
			return err
		}
	}

	return nil
}
