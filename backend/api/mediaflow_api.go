package api

import (
	"context"
	"net/http"
	"time"

	"aetherflow/db"
	"aetherflow/services"

	"github.com/gin-gonic/gin"
)

// MediaFlowQueueItem mirrors schema
type MediaFlowQueueItem struct {
	ID            int    `json:"id"`
	FilePath      string `json:"filePath"`
	Status        string `json:"status"`
	OriginalCodec string `json:"originalCodec"`
	OriginalSize  int    `json:"originalSize"`
	NewCodec      string `json:"newCodec"`
	NewSize       int    `json:"newSize"`
	ErrorLog      string `json:"errorLog"`
	CreatedAt     string `json:"createdAt"`
}

// GetMediaFlowQueue fetches the current items requested for approval or running
func GetMediaFlowQueue(c *gin.Context) {
	rows, err := db.DB.Query("SELECT id, file_path, status, original_codec, original_size, new_codec, new_size, error_log, created_at FROM mediaflow_queue ORDER BY created_at DESC LIMIT 100")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch queue"})
		return
	}
	defer rows.Close()

	var items []MediaFlowQueueItem
	for rows.Next() {
		var i MediaFlowQueueItem
		rows.Scan(&i.ID, &i.FilePath, &i.Status, &i.OriginalCodec, &i.OriginalSize, &i.NewCodec, &i.NewSize, &i.ErrorLog, &i.CreatedAt)
		items = append(items, i)
	}

	c.JSON(http.StatusOK, items)
}

// TriggerScan starts a passive FFprobe sweep via the scanner
func TriggerScan(c *gin.Context) {
	var request struct {
		Directory string `json:"directory" binding:"required"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid payload"})
		return
	}

	// Run passively in background so we don't block API response
	go func(dir string) {
		ctx, cancel := context.WithTimeout(context.Background(), 24*time.Hour)
		defer cancel()
		services.ScanLibrary(ctx, dir)
	}(request.Directory)

	c.JSON(http.StatusAccepted, gin.H{"message": "Scan initiated in background"})
}

// ApproveItem flips status to APPROVED moving the item into the passive execution list
func ApproveItem(c *gin.Context) {
	id := c.Param("id")
	
	result, err := db.DB.Exec("UPDATE mediaflow_queue SET status = 'APPROVED', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND status = 'PENDING_APPROVAL'", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to approve"})
		return
	}

	affected, _ := result.RowsAffected()
	if affected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Item not found or already processed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Transcode queued. MediaFlow Engine assumes control."})
}
