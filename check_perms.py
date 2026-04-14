import paramiko

def run():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect('192.168.1.153', username='mcstream', password='7338')
        
        # Check permissions of installpackage-sonarr
        stdin, stdout, stderr = client.exec_command("echo 7338 | sudo -S ls -la /opt/AetherFlow/packages/package/install/installpackage-sonarr")
        out = stdout.read().decode('utf-8', errors='ignore').encode('ascii', errors='ignore').decode('ascii')
        print("--- LS OUT ---")
        print(out)
        
    finally:
        client.close()

if __name__ == "__main__":
    run()
