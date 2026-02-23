package api

import (
	"database/sql"
	"log"
	"net/http"
	"strconv"

	"aetherflow/db"
	"aetherflow/models"

	"github.com/gin-gonic/gin"
)

func GetUsers(c *gin.Context) {
	rows, err := db.DB.Query("SELECT id, username, email, avatar_url, role FROM users")
	if err != nil {
		log.Printf("Error querying users: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query users"})
		return
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var u models.User
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.AvatarURL, &u.Role); err != nil {
			log.Printf("Error scanning user row: %v", err)
			continue
		}
		users = append(users, u)
	}

	c.JSON(http.StatusOK, users)
}

func UpdateUserRole(c *gin.Context) {
	idStr := c.Param("id")
	userId, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	var req struct {
		Role string `json:"role" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Role != "admin" && req.Role != "user" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid role specified. Must be 'admin' or 'user'."})
		return
	}

	// Prevent demoting the last admin
	if req.Role == "user" {
		var count int
		db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE role = 'admin'").Scan(&count)
		if count <= 1 {
			// Check if we're trying to demote the one remaining admin
			var currentRole string
			db.DB.QueryRow("SELECT role FROM users WHERE id = ?", userId).Scan(&currentRole)
			if currentRole == "admin" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot demote the last remaining admin."})
				return
			}
		}
	}

	_, err = db.DB.Exec("UPDATE users SET role = ? WHERE id = ?", req.Role, userId)
	if err != nil {
		log.Printf("Error updating user role: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update role"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Role updated successfully"})
}

func DeleteUser(c *gin.Context) {
	idStr := c.Param("id")
	userId, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	// Prevent deleting the last admin
	var currentRole string
	err = db.DB.QueryRow("SELECT role FROM users WHERE id = ?", userId).Scan(&currentRole)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	if currentRole == "admin" {
		var count int
		db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE role = 'admin'").Scan(&count)
		if count <= 1 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot delete the last remaining admin."})
			return
		}
	}

	_, err = db.DB.Exec("DELETE FROM users WHERE id = ?", userId)
	if err != nil {
		log.Printf("Error deleting user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}

// GetUserQuota is a mock endpoint showing storage quotas for an account
func GetUserQuota(c *gin.Context) {
	idStr := c.Param("id")
	userId, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	// In a real system, we'd query disk quotas (e.g. repquota or ZFS properties).
	// For AetherFlow, we return a deterministic mock based on user ID for presentation.
	totalQuotaGB := float64(50)
	if userId == 1 {
		totalQuotaGB = 250 // Give the primary admin more space
	}
	
	usedQuotaGB := float64(userId*5) + 3.4 // Just a deterministic fake number

	c.JSON(http.StatusOK, gin.H{
		"userId": userId,
		"usedGB": usedQuotaGB,
		"totalGB": totalQuotaGB,
		"percentage": (usedQuotaGB / totalQuotaGB) * 100,
	})
}
