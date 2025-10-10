package main

import (
	"log"
	"net/http"
	"os"

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
	r.Static("/static", "./web/static")
	r.LoadHTMLGlob("web/templates/*")

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
			scanner.GET("/scans/:id/status", apiHandler.GetScanStatus)
			scanner.GET("/scans/:id/results", apiHandler.GetScanResults)
			scanner.GET("/scans/:id/export", apiHandler.ExportScanResults)
		}

		// Dashboard routes (protected)
		dashboard := api.Group("/dashboard")
		dashboard.Use(middleware.AuthRequired(authService))
		{
			dashboard.GET("/stats", apiHandler.GetDashboardStats)
		}
	}
}
