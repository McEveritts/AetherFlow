import sys

with open('backend/api/oidc.go', 'r') as f:
    content = f.read()

content = content.replace('''func lookupOIDCClient(clientID string) (name string, redirectURIs string, err error) {
	err = db.DB.QueryRow(
		"SELECT name, redirect_uris FROM oidc_clients WHERE id = ?",
		clientID,
	).Scan(&name, &redirectURIs)
	if err == sql.ErrNoRows {
		return "", "", fmt.Errorf("client not found")
	}
	return
}''', '''/* func lookupOIDCClient(clientID string) (name string, redirectURIs string, err error) {
	err = db.DB.QueryRow(
		"SELECT name, redirect_uris FROM oidc_clients WHERE id = ?",
		clientID,
	).Scan(&name, &redirectURIs)
	if err == sql.ErrNoRows {
		return "", "", fmt.Errorf("client not found")
	}
	return
} */''')

with open('backend/api/oidc.go', 'w') as f:
    f.write(content)
