import paramiko

def run():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect('192.168.1.153', username='mcstream', password='7338')
        
        # Check PM2 list
        stdin, stdout, stderr = client.exec_command("echo 7338 | sudo -S pm2 list")
        out = stdout.read().decode('ascii', errors='ignore')
        print("--- PM2 LIST ---")
        print(out)
        
        # If it's in there, delete it
        if "aetherflow-api" in out or "aetherflow" in out:
             stdin, stdout, stderr = client.exec_command("echo 7338 | sudo -S pm2 delete all") # Or be specific if there are others
             stdout.read()
             stdin, stdout, stderr = client.exec_command("echo 7338 | sudo -S pm2 save")
             stdout.read()
             print("PM2 apps deleted and saved.")
        
        # Also kill any remaining processes just in case
        stdin, stdout, stderr = client.exec_command("echo 7338 | sudo -S pkill -9 aetherflow-api")
        stdout.read()
        
        # Now restart systemd
        stdin, stdout, stderr = client.exec_command("echo 7338 | sudo -S systemctl restart aetherflow-api")
        stdout.read()
        
        # Check status
        stdin, stdout, stderr = client.exec_command("echo 7338 | sudo -S systemctl status aetherflow-api")
        print("--- STATUS ---")
        print(stdout.read().decode('ascii', errors='ignore'))
        
    finally:
        client.close()

if __name__ == "__main__":
    run()
