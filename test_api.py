import paramiko

def run():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect('192.168.1.153', username='mcstream', password='7338')
        
        # Check what is listening on 8080
        stdin, stdout, stderr = client.exec_command("echo 7338 | sudo -S netstat -tulpn | grep 8080")
        out = stdout.read().decode('ascii', errors='ignore')
        print("--- NETSTAT OUT ---")
        print(out)
        
        # Check if there is any hidden process or another user running it
        stdin, stdout, stderr = client.exec_command("echo 7338 | sudo -S lsof -i :8080")
        print("--- LSOF OUT ---")
        print(stdout.read().decode('ascii', errors='ignore'))
        
    finally:
        client.close()

if __name__ == "__main__":
    run()
