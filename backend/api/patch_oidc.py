import re

with open('oidc.go', 'r') as f:
    content = f.read()

# Add \"github.com/google/uuid\"
content = content.replace('\"github.com/golang-jwt/jwt/v5\"', '\"github.com/golang-jwt/jwt/v5\"\n\t\"github.com/google/uuid\"')

# Update createStandardJWT
old_jwt = '''func createStandardJWT(userID int) (string, error) {
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return \"\", fmt.Errorf(\"failed to generate jti: %w\", err)
	}

	claims := jwt.MapClaims{
		\"user_id\": userID,
		\"sub\":     fmt.Sprintf(\"%d\", userID),
		\"iss\":     \"aetherflow\",
		\"iat\":     time.Now().Unix(),
		\"exp\":     time.Now().Add(15 * time.Minute).Unix(),
		\"jti\":     hex.EncodeToString(jti),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(getJWTSecret())
}'''

new_jwt = '''func createStandardJWT(userID int) (string, error) {
	jti := uuid.New().String()

	claims := jwt.MapClaims{
		\"user_id\": userID,
		\"sub\":     fmt.Sprintf(\"%d\", userID),
		\"iss\":     \"aetherflow\",
		\"iat\":     time.Now().Unix(),
		\"exp\":     time.Now().Add(15 * time.Minute).Unix(),
		\"jti\":     jti,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(getJWTSecret())
}'''

content = content.replace(old_jwt, new_jwt)

with open('oidc.go', 'w') as f:
    f.write(content)

print("oidc.go successfully updated")
