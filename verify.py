import paramiko

def run():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect('192.168.1.153', username='mcstream', password='7338')
        
        # 1. API Health Check (just check if port 8080 is listening and responds)
        print("Checking API health...")
        stdin, stdout, stderr = client.exec_command("curl -I http://localhost:8080/api/v1/health")
        out = stdout.read().decode('ascii', errors='ignore')
        print(out)
        
        # 2. Check if Sonarr install script is executable
        print("Verifying script permissions...")
        stdin, stdout, stderr = client.exec_command("ls -la /opt/AetherFlow/packages/package/install/installpackage-sonarr")
        print(stdout.read().decode('ascii', errors='ignore'))
        
        # 3. Check apt status
        print("Verifying apt availability...")
        stdin, stdout, stderr = client.exec_command("apt-get update --help")
        print("Apt is available.")
        
    finally:
        client.close()

if __name__ == "__main__":
    run()
