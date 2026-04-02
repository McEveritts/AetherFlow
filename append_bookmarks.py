import os

path = r'C:\Users\armyw\OneDrive\Documents\Antigravity\Projects\AetherFlow\backend\api\log_handlers.go'

handler = '''
// GetBookmarks retrieves log bookmarks for the current user.
func GetBookmarks(c *gin.Context) {
	userId, err := extractUserIDFromJWT(getCookieToken(c))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	rows, err := db.DB.Query(
		"SELECT id, log_source, log_line, timestamp, note, created_at FROM log_bookmarks WHERE user_id = ? ORDER BY created_at DESC",
		userId,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch bookmarks"})
		return
	}
	defer rows.Close()

	var bookmarks []map[string]interface{}
	for rows.Next() {
		var id int
		var logSource, logLine, timestamp, note, createdAt string
		if err := rows.Scan(&id, &logSource, &logLine, &timestamp, &note, &createdAt); err == nil {
			bookmarks = append(bookmarks, map[string]interface{}{
				"id": id,
				"log_source": logSource,
				"log_line": logLine,
				"timestamp": timestamp,
				"note": note,
				"created_at": createdAt,
			})
		}
	}

	if bookmarks == nil {
		bookmarks = make([]map[string]interface{}, 0)
	}

	c.JSON(http.StatusOK, gin.H{"bookmarks": bookmarks})
}
'''

with open(path, 'a', encoding='utf-8') as f:
    f.write('\n' + handler)

print('Appended GetBookmarks handler')
