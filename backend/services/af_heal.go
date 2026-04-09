package services

import (
	"log"
	"os/exec"
	"time"

	"github.com/gin-gonic/gin"
)

var HealWorkerActive bool

// StartHealWorker starts the af-heal background orchestrator
// It performs process monitoring and automated recovery of crashed services
func StartHealWorker(interval time.Duration) {
	if HealWorkerActive {
		return
	}
	HealWorkerActive = true

	go func() {
		log.Println("[af-heal] Recovery orchestrator initialized")
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			performHealCheck()
		}
	}()
}

func performHealCheck() {
	servicesMap := GetActiveServices()

	for displayName, detailsObj := range servicesMap {
		details, ok := detailsObj.(gin.H)
		if !ok {
			continue
		}

		status, _ := details["status"].(string)
		managedBy, _ := details["managed_by"].(string)
		processName, _ := details["process"].(string)

		// Determine if the process requires healing
		needsHeal := false
		switch status {
		case "error", "failed", "errored", "crashed":
			needsHeal = true
		}

		if needsHeal {
			log.Printf("[af-heal] Detected ailing service: %s (%s). Attempting recovery...", displayName, processName)
			recoverService(displayName, processName, managedBy)
		}
	}
}

func recoverService(displayName, processName, managedBy string) {
	var err error
	var cmd *exec.Cmd

	switch managedBy {
	case "systemd":
		// Restart via systemctl
		cmd = exec.Command("systemctl", "restart", processName)
		err = cmd.Run()
	case "pm2":
		// Restart via pm2
		cmd = exec.Command("pm2", "restart", processName)
		err = cmd.Run()
	case "docker":
		// Restart via docker
		cmd = exec.Command("docker", "restart", processName)
		err = cmd.Run()
	default:
		log.Printf("[af-heal] Failure recovery skipped for %s: unknown manager %s", displayName, managedBy)
		return
	}

	if err != nil {
		log.Printf("[af-heal] CRITICAL: Failed to recover %s (manager: %s). Error: %v", displayName, managedBy, err)
		if Notifier != nil {
			Notifier.Dispatch(Notification{
				Level:   NotifyCritical,
				Title:   "af-heal Recovery Failed",
				Message: "Failed to automatically recover " + displayName + ".",
			})
		}
	} else {
		log.Printf("[af-heal] Successfully recovered service: %s", displayName)
		if Notifier != nil {
			Notifier.Dispatch(Notification{
				Level:   NotifyInfo,
				Title:   "af-heal Auto-Recovery",
				Message: "Successfully recovered crashed service: " + displayName + " (" + processName + ").",
			})
		}
	}
}
