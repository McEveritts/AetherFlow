import re

with open('auth.go', 'r') as f:
    content = f.read()

# Add imports
content = content.replace('\"crypto/rand\"', '\"context\"\n\t\"crypto/rand\"\n\t\"time\"')

# Update Logout
old_logout = '''func Logout(c *gin.Context) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(\"aetherflow_session\", \"\", -1, \"/\", \"\", secureCookie(), true)
	c.JSON(http.StatusOK, gin.H{\"message\": \"Logged out\"})
}'''

new_logout = '''func Logout(c *gin.Context) {
	// Attempt to revoke the token intelligently (Phase 10 integration)
	cookie, err := c.Cookie(\"aetherflow_session\")
	if err == nil && cookie != \"\" {
		token, _ := jwt.Parse(cookie, func(token *jwt.Token) (interface{}, error) {
			return getJWTSecret(), nil
		})
		if token != nil && token.Valid {
			if claims, ok := token.Claims.(jwt.MapClaims); ok {
				if jti, ok := claims[\"jti\"].(string); ok {
					if exp, ok := claims[\"exp\"].(float64); ok {
						remaining := time.Until(time.Unix(int64(exp), 0))
						if remaining > 0 {
							db.RevokeToken(jti, remaining)
						}
					}
				}
			}
		}
	}

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(\"aetherflow_session\", \"\", -1, \"/\", \"\", secureCookie(), true)
	c.JSON(http.StatusOK, gin.H{\"message\": \"Logged out\"})
}'''

content = content.replace(old_logout, new_logout)

# Update AuthMiddleware
old_auth = '''		userIdFloat, ok := claims[\"user_id\"].(float64)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{\"error\": \"Invalid token claims\"})
			return
		}
		userId := int(userIdFloat)'''

new_auth = '''		userIdFloat, ok := claims[\"user_id\"].(float64)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{\"error\": \"Invalid token claims\"})
			return
		}
		userId := int(userIdFloat)

		// Phase 11: Redis Fast Blacklist Lookup (O(1))
		jti, hasJti := claims[\"jti\"].(string)
		if hasJti && db.RedisClient != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			if db.RedisClient.Get(ctx, \"blacklist:\"+jti).Err() == nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{\"error\": \"Unauthorized: session revoked\"})
				return
			}
		}'''

content = content.replace(old_auth, new_auth)

with open('auth.go', 'w') as f:
    f.write(content)

print("auth.go successfully updated")
