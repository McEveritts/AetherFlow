package api

import (
	"net/http"

	"aetherflow/cluster"

	"github.com/gin-gonic/gin"
)

// GetClusterNodes returns a list of all registered worker nodes with their status and metrics.
func GetClusterNodes(c *gin.Context) {
	if cluster.Manager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Cluster manager not initialized"})
		return
	}

	nodes := cluster.Manager.GetNodes()
	status := cluster.Manager.GetClusterStatus()

	c.JSON(http.StatusOK, gin.H{
		"nodes":   nodes,
		"summary": status,
	})
}

// EnrollWorker generates an enrollment token for a new worker node.
func EnrollWorker(c *gin.Context) {
	if cluster.Manager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Cluster manager not initialized"})
		return
	}

	token, err := cluster.Manager.GenerateEnrollmentToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate enrollment token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"enrollment_token": token,
		"instructions":     "Run on the worker node: aetherflow-api --cluster-mode=worker --master-addr=<this-server>:50051 --psk=" + token,
	})
}

// RemoveWorker removes a worker node from the cluster.
func RemoveWorker(c *gin.Context) {
	if cluster.Manager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Cluster manager not initialized"})
		return
	}

	nodeID := c.Param("id")
	if nodeID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Node ID is required"})
		return
	}

	node := cluster.Manager.GetNode(nodeID)
	if node == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Node not found"})
		return
	}

	if err := cluster.Manager.RemoveWorker(nodeID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove node: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Node removed successfully", "node_id": nodeID})
}

// GetWorkerMetrics returns detailed metrics for a specific worker node.
func GetWorkerMetrics(c *gin.Context) {
	if cluster.Manager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Cluster manager not initialized"})
		return
	}

	nodeID := c.Param("id")
	if nodeID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Node ID is required"})
		return
	}

	node := cluster.Manager.GetNode(nodeID)
	if node == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Node not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"node_id":  node.ID,
		"hostname": node.Hostname,
		"status":   node.Status,
		"metrics":  node.Metrics,
		"services": node.Services,
		"system_info": node.SystemInfo,
		"last_heartbeat": node.LastHeartbeat,
	})
}
