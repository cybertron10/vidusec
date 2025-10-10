package main

import (
	"log"
	"net/http"
	"os"
	"strconv"

	"vidusec/web/internal/api"
	"vidusec/web/internal/auth"
	"vidusec/web/internal/database"
	"vidusec/web/internal/middleware"
	"vidusec/web/internal/scanner"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	// Initialize database
	db, err := database.Initialize()
	if err != nil {
		log.Fatal("Failed to initialize database:", err)
	}
	defer db.Close()

	// Initialize scanner service
	scannerService := scanner.NewService(db)

	// Initialize auth service
	authService := auth.NewService(db)

	// Initialize API handlers
	apiHandler := api.NewHandler(scannerService, authService)

	// Setup Gin router
	r := gin.Default()

	// CORS configuration
	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"http://localhost:3000", "http://localhost:8080"}
	config.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	config.AllowHeaders = []string{"Origin", "Content-Type", "Accept", "Authorization"}
	config.AllowCredentials = true
	r.Use(cors.New(config))

	// Static files
	r.Static("/static", "./static")
	r.LoadHTMLGlob("templates/*")

	// Routes
	setupRoutes(r, apiHandler, authService)

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	host := os.Getenv("HOST")
	if host == "" {
		host = "0.0.0.0"
	}

	address := host + ":" + port
	log.Printf("🚀 ViduSec Web Server starting on %s", address)
	log.Fatal(http.ListenAndServe(address, r))
}

func setupRoutes(r *gin.Engine, apiHandler *api.Handler, authService *auth.Service) {
	// Public routes
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{
			"title": "ViduSec - Web Security Scanner",
		})
	})

	// Dashboard route
	r.GET("/dashboard", func(c *gin.Context) {
		c.HTML(http.StatusOK, "dashboard.html", gin.H{
			"title": "ViduSec Dashboard",
		})
	})

	// Scan Results route
	r.GET("/scan-results/:id", func(c *gin.Context) {
		c.HTML(http.StatusOK, "scan-results.html", gin.H{
			"title": "Scan Results",
		})
	})

	// API routes
	api := r.Group("/api")
	{
		// Authentication routes
		auth := api.Group("/auth")
		{
			auth.POST("/register", apiHandler.Register)
			auth.POST("/login", apiHandler.Login)
			auth.POST("/logout", middleware.AuthRequired(authService), apiHandler.Logout)
			auth.GET("/me", middleware.AuthRequired(authService), apiHandler.GetProfile)
		}

		// Scanner routes (protected)
		scanner := api.Group("/scanner")
		scanner.Use(middleware.AuthRequired(authService))
		{
			scanner.POST("/scan", apiHandler.StartScan)
			scanner.GET("/scans", apiHandler.GetScans)
			scanner.GET("/scans/:id", apiHandler.GetScan)
			scanner.DELETE("/scans/:id", apiHandler.DeleteScan)
			scanner.POST("/scans/:id/rescan", apiHandler.RescanScan)
			scanner.GET("/scans/:id/status", apiHandler.GetScanStatus)
			scanner.GET("/scans/:id/results", apiHandler.GetScanResults)
			scanner.GET("/scans/:id/export", apiHandler.ExportScanResults)
		}

		// Test route without authentication (temporary)
		api.GET("/test/results/:id", func(c *gin.Context) {
			scanIDStr := c.Param("id")
			c.JSON(http.StatusOK, gin.H{
				"message": "Test route working",
				"scan_id": scanIDStr,
			})
		})

		// Debug route to check scan results without authentication
		api.GET("/debug/scan/:id/results", func(c *gin.Context) {
			scanIDStr := c.Param("id")
			scanID, err := strconv.Atoi(scanIDStr)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid scan ID"})
				return
			}

			// Get results without user authentication for debugging
			results, err := apiHandler.GetScanResultsDebug(scanID, 1) // Use user ID 1 for debugging
			if err != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"scan_id": scanID,
				"results": results,
				"count":   len(results),
			})
		})

		// Debug route to check all scans in database
		api.GET("/debug/scans", func(c *gin.Context) {
			// Get all scans from database for debugging
			rows, err := db.Query("SELECT id, user_id, target_url, status, progress, created_at FROM scans ORDER BY created_at DESC LIMIT 10")
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			defer rows.Close()

			var scans []gin.H
			for rows.Next() {
				var id, userID, progress int
				var targetURL, status, createdAt string
				err := rows.Scan(&id, &userID, &targetURL, &status, &progress, &createdAt)
				if err != nil {
					continue
				}
				scans = append(scans, gin.H{
					"id":         id,
					"user_id":    userID,
					"target_url": targetURL,
					"status":     status,
					"progress":   progress,
					"created_at": createdAt,
				})
			}

			c.JSON(http.StatusOK, gin.H{
				"scans": scans,
				"count": len(scans),
			})
		})

		// Debug route to check scan results count
		api.GET("/debug/scan/:id/count", func(c *gin.Context) {
			scanIDStr := c.Param("id")
			scanID, err := strconv.Atoi(scanIDStr)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid scan ID"})
				return
			}

			// Count scan results in database
			var count int
			err = db.QueryRow("SELECT COUNT(*) FROM scan_results WHERE scan_id = ?", scanID).Scan(&count)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			// Get sample results
			rows, err := db.Query("SELECT id, endpoint_type, url, method FROM scan_results WHERE scan_id = ? LIMIT 5", scanID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			defer rows.Close()

			var sampleResults []gin.H
			for rows.Next() {
				var id int
				var endpointType, url, method string
				err := rows.Scan(&id, &endpointType, &url, &method)
				if err != nil {
					continue
				}
				sampleResults = append(sampleResults, gin.H{
					"id":            id,
					"endpoint_type": endpointType,
					"url":           url,
					"method":        method,
				})
			}

			c.JSON(http.StatusOK, gin.H{
				"scan_id":        scanID,
				"total_count":    count,
				"sample_results": sampleResults,
			})
		})

		// Dashboard routes (protected)
		dashboard := api.Group("/dashboard")
		dashboard.Use(middleware.AuthRequired(authService))
		{
			dashboard.GET("/stats", apiHandler.GetDashboardStats)
		}
	}
}
