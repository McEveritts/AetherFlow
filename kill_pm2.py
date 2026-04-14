import paramiko

def run():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect('192.168.1.153', username='mcstream', password='7338')
        
        # Kill PM2 God Daemon
        stdin, stdout, stderr = client.exec_command("echo 7338 | sudo -S kill -9 168903")
        stdout.read()
        
        # Kill all aetherflow-api
        stdin, stdout, stderr = client.exec_command("echo 7338 | sudo -S pkill -9 aetherflow-api")
        stdout.read()
        
        # Restart service
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
