package main

import (
	"bytes"
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/ssh"
)

func main() {
	config := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{
			ssh.Password("7338"),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", "192.168.1.164:4747", config)
	if err != nil {
		log.Fatalf("Failed to dial: %s", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		log.Fatalf("Failed to create session: %s", err)
	}
	defer session.Close()

	var b bytes.Buffer
	session.Stdout = &b
	session.Stderr = &os.Stderr
	
	err = session.Run("cd /opt/AetherFlow && git pull origin master && cd /opt/AetherFlow/backend && go build -o api-server main.go && sudo pm2 restart aetherflow-api && cd /opt/AetherFlow/frontend && npm install && npm run build && sudo pm2 restart aetherflow-web")
	if err != nil {
		log.Printf("Failed to run: %s", err)
	}

	fmt.Println(b.String())
}
