package api

import (
	"database/sql"
	"log/slog"
	"net/http"
	"strconv"

	"aetherflow/db"
	"aetherflow/models"

	"github.com/gin-gonic/gin"
)

func GetUsers(c *gin.Context) {
	rows, err := db.DB.Query("SELECT id, username, email, avatar_url, role FROM users")
	if err != nil {
		slog.Error("querying users", "error", err)
		InternalError(c, "Failed to query users")
		return
	}
	defer rows.Close()

	users := make([]models.User, 0)
	for rows.Next() {
		var u models.User
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.AvatarURL, &u.Role); err != nil {
			slog.Error("scanning user row", "error", err)
			continue
		}
		users = append(users, u)
	}

	c.JSON(http.StatusOK, users)
}

func countOtherUsableHumanAdmins(execer oidcDBExecer, excludeUserID int) int {
	var count int
	err := execer.QueryRow(
		`SELECT COUNT(*) FROM users u
		 LEFT JOIN user_quotas uq ON uq.user_id = u.id
		 WHERE u.role = 'admin'
		   AND u.id != ?
		   AND LOWER(TRIM(u.username)) NOT LIKE 'plugin:%'
		   AND COALESCE(LOWER(TRIM(uq.status)), '') IN ('', 'active')`,
		excludeUserID,
	).Scan(&count)
	if err != nil {
		_ = execer.QueryRow(
			`SELECT COUNT(*) FROM users
			 WHERE role = 'admin' AND id != ? AND LOWER(TRIM(username)) NOT LIKE 'plugin:%'`,
			excludeUserID,
		).Scan(&count)
	}
	return count
}

func UpdateUserRole(c *gin.Context) {
	idStr := c.Param("id")
	userId, err := strconv.Atoi(idStr)
	if err != nil {
		BadRequest(c, "Invalid user ID")
		return
	}

	var req struct {
		Role string `json:"role" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	if req.Role != "admin" && req.Role != "user" {
		BadRequest(c, "Invalid role specified. Must be 'admin' or 'user'.")
		return
	}

	tx, txErr := db.DB.Begin()
	if txErr != nil {
		InternalError(c, "Database unavailable")
		return
	}
	defer func() {
		_ = tx.Rollback()
	}()

	var currentRole string
	if err := tx.QueryRow("SELECT role FROM users WHERE id = ?", userId).Scan(&currentRole); err != nil {
		if err == sql.ErrNoRows {
			NotFoundError(c, "User not found")
			return
		}
		InternalError(c, "Failed to query user")
		return
	}

	// Prevent demoting the last usable human admin
	if req.Role == "user" && currentRole == "admin" {
		if countOtherUsableHumanAdmins(tx, userId) < 1 {
			BadRequest(c, "Cannot demote the last remaining admin.")
			return
		}
	}

	if _, err := tx.Exec("UPDATE users SET role = ? WHERE id = ?", req.Role, userId); err != nil {
		slog.Error("updating user role", "error", err)
		InternalError(c, "Failed to update role")
		return
	}

	var revokedJTIs []string
	if req.Role == "user" && currentRole == "admin" {
		var revErr error
		_, revokedJTIs, revErr = revokeAllUserCredentialsInTx(tx, userId)
		if revErr != nil {
			InternalError(c, "Failed to revoke elevated credentials")
			return
		}
	}

	if err := tx.Commit(); err != nil {
		InternalError(c, "Failed to commit role update")
		return
	}

	if len(revokedJTIs) > 0 || (req.Role == "user" && currentRole == "admin") {
		finalizeUserCredentialRevocation(userId, revokedJTIs)
	}

	actorID, _ := c.Get("user_id")
	actorName, _ := c.Get("username")
	aid, _ := actorID.(int)
	aname, _ := actorName.(string)
	db.RecordAudit(aid, aname, "user_role_change", "user", idStr, "role="+req.Role, c.ClientIP(), c.Request.UserAgent())

	c.JSON(http.StatusOK, gin.H{"message": "Role updated successfully"})
}

func DeleteUser(c *gin.Context) {
	idStr := c.Param("id")
	userId, err := strconv.Atoi(idStr)
	if err != nil {
		BadRequest(c, "Invalid user ID")
		return
	}

	tx, txErr := db.DB.Begin()
	if txErr != nil {
		InternalError(c, "Database unavailable")
		return
	}
	defer func() {
		_ = tx.Rollback()
	}()

	var currentRole string
	err = tx.QueryRow("SELECT role FROM users WHERE id = ?", userId).Scan(&currentRole)
	if err == sql.ErrNoRows {
		NotFoundError(c, "User not found")
		return
	}
	if err != nil {
		InternalError(c, "Failed to query user")
		return
	}

	if currentRole == "admin" && countOtherUsableHumanAdmins(tx, userId) < 1 {
		BadRequest(c, "Cannot delete the last remaining admin.")
		return
	}

	_, revokedJTIs, revErr := revokeAllUserCredentialsInTx(tx, userId)
	if revErr != nil {
		InternalError(c, "Failed to revoke user sessions")
		return
	}

	_, _ = tx.Exec("DELETE FROM oidc_consents WHERE user_id = ?", userId)
	_, _ = tx.Exec("DELETE FROM oidc_refresh_tokens WHERE user_id = ?", userId)
	_, _ = tx.Exec("DELETE FROM oidc_auth_codes WHERE user_id = ?", userId)
	_, _ = tx.Exec("DELETE FROM oidc_device_codes WHERE user_id = ?", userId)
	_, _ = tx.Exec("DELETE FROM recovery_codes WHERE user_id = ?", userId)
	_, _ = tx.Exec("DELETE FROM user_quotas WHERE user_id = ?", userId)

	if _, err := tx.Exec("DELETE FROM users WHERE id = ?", userId); err != nil {
		slog.Error("deleting user", "error", err)
		InternalError(c, "Failed to delete user")
		return
	}

	if err := tx.Commit(); err != nil {
		InternalError(c, "Failed to commit user deletion")
		return
	}

	finalizeUserCredentialRevocation(userId, revokedJTIs)

	actorID, _ := c.Get("user_id")
	actorName, _ := c.Get("username")
	aid, _ := actorID.(int)
	aname, _ := actorName.(string)
	db.RecordAudit(aid, aname, "user_delete", "user", idStr, "", c.ClientIP(), c.Request.UserAgent())

	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}

// UpdatePassword godoc
// @Summary      Update user password
// @Description  Verifies current password with bcrypt and sets the new hashed password.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Security     ApiKeyAuth
// @Param        req body object true "Current and new password"
// @Success      200  {object}  map[string]interface{}
// @Failure      400  {object}  map[string]interface{}
// @Failure      401  {object}  map[string]interface{}
// @Failure      500  {object}  map[string]interface{}


