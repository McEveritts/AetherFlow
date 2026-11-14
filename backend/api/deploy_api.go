package api

import (
	"fmt"
	"net/http"

	"aetherflow/services"

	"github.com/gin-gonic/gin"
)

// Global Orchestrator instance mimicking a fully spun-up environment engine singleton for brevity.
var globalOrchestrator = services.NewOrchestrator()

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

	// 1. Atomically claim the deployment stream for this target; reject overlapping deploys.
	statusChan, registered := services.StreamHub.TryRegisterStream(appBlueprint.AppName)
	if !registered {
		RespondError(c, http.StatusConflict, "DEPLOYMENT_IN_PROGRESS", fmt.Sprintf("Deployment already in progress for %s", appBlueprint.AppName))
		return
	}

	targetPort := appBlueprint.DefaultPort
	if resolvedPort, _, err := services.ResolveDynamicAppPort(appBlueprint.AppName, false); err == nil && resolvedPort > 0 {
		targetPort = resolvedPort
	}

	internalDomain := appBlueprint.InternalDomain
	if internalDomain == "" {
		internalDomain = fmt.Sprintf("%s.aether.local", appBlueprint.AppName)
	}

	// In real environment, parameters like TargetPort and BinaryStaging are dynamically fetched locally.
	// We'll scaffold safe parameters here before sending down to the logic engine.
	deployConfig := services.DeployConfig{
		AppName:         appBlueprint.AppName,
		VersionStr:      "latest-update",
		ActiveSymlink:   fmt.Sprintf("/opt/%s/active", appBlueprint.AppName),
		BinaryStaging:   fmt.Sprintf("/opt/%s/latest-update", appBlueprint.AppName),
		CentralDBPath:   appBlueprint.AppDataPath,
		TargetInternal:  internalDomain,
		TargetPort:      targetPort,
		HealthCheckPath: appBlueprint.HealthCheckPath,
		StatusChan:      statusChan,
	}

	// 2. Fire the deployment routine asynchronously with panic-safe channel cleanup.
	go func(cfg services.DeployConfig) {
		defer func() {
			_ = recover()
			services.StreamHub.DeregisterStreamIfMatch(cfg.AppName, cfg.StatusChan)
		}()

		// Log start to trigger matching logic in SSE UI component
		services.SendStreamMessage(cfg.StatusChan, "[STEP 0] Deployment sequence queued asynchronously.")

		if err := globalOrchestrator.ExecuteAtomicDeploy(cfg); err != nil {
			// Catch failure explicitly and push ROLLBACK standard string.
			services.SendStreamMessage(cfg.StatusChan, fmt.Sprintf("[ROLLBACK] Engine failure detected: %v", err))
		} else {
			// Match our defined exact String parameter so SSE react hook closes
			services.SendStreamMessage(cfg.StatusChan, "[SUCCESS] Atomic deployment verified and live.")
		}
	}(deployConfig)

	// 3. Inform the client that the background job fired.
	c.JSON(http.StatusAccepted, gin.H{
		"status":       "Initiated deployment cycle",
		"target":       deployConfig.TargetInternal,
		"streamTarget": fmt.Sprintf("/api/v1/auth/deploy/stream?appName=%s", appBlueprint.AppName),
	})
}
