package handler

import (
	"shop-crud/pkg/response"

	"github.com/gin-gonic/gin"
)

func HealthCheck(c *gin.Context) {
	response.Success(c, gin.H{
		"status":  "healthy",
		"message": "Server is running",
	})
}
