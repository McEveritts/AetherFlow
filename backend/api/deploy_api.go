package api

import (
	"fmt"
	"net/http"

	"aetherflow/services"

	"github.com/gin-gonic/gin"
)

// Global Orchestrator instance mimicking a fully spun-up environment engine singleton for brevity.
var globalOrchestrator = services.NewOrchestrator("http://unix%2Fvar%2Frun%2Fcaddy.sock")

// HandleDeployProcess is an asynchronous trigger that fires the master Atomic Swap Sequence.
// Responses are returned immediately with 202 Accepted.
func HandleDeployProcess(c *gin.Context) {
	appName := c.Param("appName")
	if appName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Application string param omitted"})
		return
	}

	appBlueprint := services.GetBlueprint(appName)
	if appBlueprint == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("Application blueprint missing or unsupported: %s", appName)})
		return
	}

	// 1. Establish the Event Stream Logging specific to this target
	statusChan := services.StreamHub.RegisterStream(appBlueprint.AppName)

	// In real environment, parameters like TargetCaddyPort and BinaryStaging are dynamically fetched locally.
	// We'll scaffold safe parameters here before sending down to the logic engine.
	deployConfig := services.DeployConfig{
		AppName:         appBlueprint.AppName,
		VersionStr:      "latest-update", 
		ActiveSymlink:   fmt.Sprintf("/opt/%s/active", appBlueprint.AppName),
		BinaryStaging:   fmt.Sprintf("/opt/%s/latest-update", appBlueprint.AppName),
		CentralDBPath:   appBlueprint.AppDataPath,
		TargetInternal:  fmt.Sprintf("%s.aether.local", appBlueprint.AppName),
		TargetCaddyPort: appBlueprint.DefaultPort + 10000, // Dummy green proxy logic
		StatusChan:      statusChan,
	}

	// 2. Fire the deployment routine asynchronously
	go func(cfg services.DeployConfig) {
		// Log start to trigger matching logic in SSE UI component
		cfg.StatusChan <- "[STEP 0] Deployment sequence queued asynchronously."

		if err := globalOrchestrator.ExecuteAtomicDeploy(cfg); err != nil {
			// Catch failure explicitly and push ROLLBACK standard string.
			cfg.StatusChan <- fmt.Sprintf("[ROLLBACK] Engine failure detected: %v", err)
		} else {
			// Match our defined exact String parameter so SSE react hook closes
			cfg.StatusChan <- "[SUCCESS] Atomic deployment verified and live."
		}

		// Sequence is totally terminal. Wait slightly to ensure buffers empty, then close natively.
		services.StreamHub.DeregisterStream(cfg.AppName)
	}(deployConfig)

	// 3. Inform the client that the background job fired.
	c.JSON(http.StatusAccepted, gin.H{
		"status":       "Initiated deployment cycle",
		"target":       deployConfig.TargetInternal,
		"streamTarget": fmt.Sprintf("/api/v1/deploy/stream?appName=%s", appBlueprint.AppName),
	})
}
