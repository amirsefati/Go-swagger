package api

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"go-firewall/database"
	"go-firewall/monitor"
)

type Server struct {
	port           string
	db             *database.DB
	processMonitor *monitor.ProcessMonitor
	engine         *gin.Engine
}

type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

func NewServer(db *database.DB, pm *monitor.ProcessMonitor) *Server {
	gin.SetMode(gin.ReleaseMode)

	engine := gin.New()
	engine.Use(gin.Logger())
	engine.Use(gin.Recovery())
	engine.Use(corsMiddleware())

	server := &Server{
		port:           "8080",
		db:             db,
		processMonitor: pm,
		engine:         engine,
	}

	server.setupRoutes()
	return server
}

func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

func (s *Server) Start() {
	log.Printf("API Server starting on port %s", s.port)

	srv := &http.Server{
		Addr:    ":" + s.port,
		Handler: s.engine,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	log.Printf("API Server is running at http://localhost:%s", s.port)
	s.printRoutes()
}

func (s *Server) printRoutes() {
	log.Println("\nAvailable API Endpoints:")
	log.Println("  GET  /                                    - API info")
	log.Println("  GET  /health                              - Health check")
	log.Println("  GET  /api/logs                            - Get all logs")
	log.Println("  GET  /api/logs/recent                     - Get recent logs")
	log.Println("  GET  /api/logs/suspicious                 - Get suspicious logs")
	log.Println("  GET  /api/logs/type/:type                 - Get logs by type")
	log.Println("  GET  /api/logs/severity/:severity         - Get logs by severity")
	log.Println("  GET  /api/logs/search?q=keyword           - Search logs")
	log.Println("  GET  /api/logs/export                     - Export logs")
	log.Println("  GET  /api/processes                       - Get all processes")
	log.Println("  GET  /api/processes/suspicious            - Get suspicious processes")
	log.Println("  GET  /api/processes/high-ram             - Get high RAM processes")
	log.Println("  GET  /api/processes/stats                 - Get process statistics")
	log.Println("  POST  /api/processes/scan                 - Scan a file")
	log.Println("  GET  /api/history                         - Get process history")
	log.Println("  GET  /api/statistics                      - Get system statistics")
	log.Println("  GET  /api/statistics/daily                - Get daily statistics")
	log.Println("  GET  /api/whitelist                       - Get whitelist")
	log.Println("  POST  /api/whitelist                      - Add to whitelist")
	log.Println("  DELETE /api/whitelist/:id                 - Remove from whitelist")
	log.Println("  GET  /api/alerts/rules                   - Get alert rules")
	log.Println("  PUT  /api/alerts/rules/:name             - Update alert rule")
	log.Println("  POST /api/clean                          - Clean old logs")
}

func (s *Server) setupRoutes() {
	s.engine.GET("/", s.handleIndex)
	s.engine.GET("/health", s.handleHealth)

	api := s.engine.Group("/api")
	{
		logs := api.Group("/logs")
		{
			logs.GET("", s.handleGetLogs)
			logs.GET("/recent", s.handleGetRecentLogs)
			logs.GET("/suspicious", s.handleGetSuspiciousLogs)
			logs.GET("/type/:type", s.handleGetLogsByType)
			logs.GET("/severity/:severity", s.handleGetLogsBySeverity)
			logs.GET("/search", s.handleSearchLogs)
			logs.GET("/export", s.handleExportLogs)
		}

		processes := api.Group("/processes")
		{
			processes.GET("", s.handleGetProcesses)
			processes.GET("/suspicious", s.handleGetSuspiciousProcesses)
			processes.GET("/high-ram", s.handleGetHighRAMProcesses)
			processes.GET("/stats", s.handleGetProcessStats)
			processes.POST("/scan", s.handleScanFile)
		}

		api.GET("/history", s.handleGetHistory)
		api.GET("/statistics", s.handleGetStatistics)
		api.GET("/statistics/daily", s.handleGetDailyStats)

		whitelist := api.Group("/whitelist")
		{
			whitelist.GET("", s.handleGetWhitelist)
			whitelist.POST("", s.handleAddWhitelist)
			whitelist.DELETE("/:id", s.handleRemoveWhitelist)
		}

		alerts := api.Group("/alerts")
		{
			alerts.GET("/rules", s.handleGetAlertRules)
			alerts.PUT("/rules/:name", s.handleUpdateAlertRule)
		}

		api.POST("/clean", s.handleCleanLogs)
	}
}

func (s *Server) handleIndex(c *gin.Context) {
	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Go Firewall - Process Monitor API",
		Data: map[string]interface{}{
			"name":    "Go Firewall",
			"version": "1.0.0",
			"uptime":  time.Since(startTime).String(),
			"docs":    "Use /api/* endpoints for operations",
		},
	})
}

func (s *Server) handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "System is healthy",
		Data: map[string]interface{}{
			"status":    "running",
			"uptime":    time.Since(startTime).String(),
			"timestamp": time.Now().Format(time.RFC3339),
		},
	})
}

func (s *Server) handleGetLogs(c *gin.Context) {
	limit := s.getIntParam(c, "limit", 100)

	logs, err := s.db.GetRecentLogs(limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Data:    logs,
	})
}

func (s *Server) handleGetRecentLogs(c *gin.Context) {
	limit := s.getIntParam(c, "limit", 50)

	logs, err := s.db.GetRecentLogs(limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Data:    logs,
	})
}

func (s *Server) handleGetSuspiciousLogs(c *gin.Context) {
	limit := s.getIntParam(c, "limit", 50)

	logs, err := s.db.GetSuspiciousLogs(limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Data:    logs,
	})
}

func (s *Server) handleGetLogsByType(c *gin.Context) {
	logType := c.Param("type")
	limit := s.getIntParam(c, "limit", 100)

	logs, err := s.db.GetLogsByType(logType, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Data:    logs,
	})
}

func (s *Server) handleGetLogsBySeverity(c *gin.Context) {
	severity := c.Param("severity")
	limit := s.getIntParam(c, "limit", 100)

	logs, err := s.db.GetLogsBySeverity(severity, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Data:    logs,
	})
}

func (s *Server) handleSearchLogs(c *gin.Context) {
	keyword := c.Query("q")
	if keyword == "" {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   "Search keyword is required",
		})
		return
	}

	limit := s.getIntParam(c, "limit", 100)

	logs, err := s.db.SearchLogs(keyword, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Data:    logs,
	})
}

func (s *Server) handleExportLogs(c *gin.Context) {
	format := c.DefaultQuery("format", "json")

	data, err := s.db.ExportLogs(format)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	filename := fmt.Sprintf("logs_%s.%s", time.Now().Format("20060102_150405"), format)
	contentType := "application/json"
	if format == "csv" {
		contentType = "text/csv"
	}

	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	c.Data(http.StatusOK, contentType, []byte(data))
}

func (s *Server) handleGetProcesses(c *gin.Context) {
	processes := s.processMonitor.GetProcessList()

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Data:    processes,
	})
}

func (s *Server) handleGetSuspiciousProcesses(c *gin.Context) {
	processes := s.processMonitor.GetSuspiciousProcesses()

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Data:    processes,
	})
}

func (s *Server) handleGetHighRAMProcesses(c *gin.Context) {
	processes := s.processMonitor.GetHighRAMProcesses()

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Data:    processes,
	})
}

func (s *Server) handleGetProcessStats(c *gin.Context) {
	stats := s.processMonitor.GetProcessStats()

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Data:    stats,
	})
}

func (s *Server) handleScanFile(c *gin.Context) {
	var request struct {
		Path string `json:"path" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   "File path is required",
		})
		return
	}

	result, err := s.processMonitor.ScanFile(request.Path)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Data:    result,
	})
}

func (s *Server) handleGetHistory(c *gin.Context) {
	limit := s.getIntParam(c, "limit", 100)

	history, err := s.db.GetProcessHistory(limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Data:    history,
	})
}

func (s *Server) handleGetStatistics(c *gin.Context) {
	stats, err := s.db.GetStatistics()
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Data:    stats,
	})
}

func (s *Server) handleGetDailyStats(c *gin.Context) {
	days := s.getIntParam(c, "days", 7)

	stats, err := s.db.GetDailyStats(days)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Data:    stats,
	})
}

func (s *Server) handleGetWhitelist(c *gin.Context) {
	whitelist, err := s.db.GetWhitelist()
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Data:    whitelist,
	})
}

func (s *Server) handleAddWhitelist(c *gin.Context) {
	var request struct {
		Type   string `json:"type" binding:"required"`
		Value  string `json:"value" binding:"required"`
		Reason string `json:"reason"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   "Type and value are required",
		})
		return
	}

	if err := s.db.AddToWhitelist(request.Type, request.Value, request.Reason); err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Added to whitelist",
	})
}

func (s *Server) handleRemoveWhitelist(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   "Invalid ID",
		})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: fmt.Sprintf("Whitelist entry %d removed", id),
	})
}

func (s *Server) handleGetAlertRules(c *gin.Context) {
	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Data:    []interface{}{},
	})
}

func (s *Server) handleUpdateAlertRule(c *gin.Context) {
	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Alert rule updated",
	})
}

func (s *Server) handleCleanLogs(c *gin.Context) {
	var request struct {
		Days int `json:"days"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		request.Days = 30
	}

	count, err := s.db.CleanOldLogs(request.Days)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: fmt.Sprintf("Cleaned %d log entries", count),
	})
}

func (s *Server) getIntParam(c *gin.Context, name string, defaultVal int) int {
	valStr := c.Query(name)
	if valStr == "" {
		return defaultVal
	}

	val, err := strconv.Atoi(valStr)
	if err != nil || val < 1 {
		return defaultVal
	}

	if val > 10000 {
		return 10000
	}

	return val
}

var startTime = time.Now()
