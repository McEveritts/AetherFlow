import paramiko

def run():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect('192.168.1.153', username='mcstream', password='7338')
        
        # Check backend logs
        stdin, stdout, stderr = client.exec_command("echo 7338 | sudo -S journalctl -eu aetherflow -n 50 --no-pager")
        print("--- AETHERFLOW LOGS ---")
        out = stdout.read().decode('utf-8', errors='ignore')
        print(out)
        
        # Check installer log
        stdin, stdout, stderr = client.exec_command("echo 7338 | sudo -S cat /opt/AetherFlow/logs/installer.log | tail -n 50")
        print("--- INSTALLER LOG ---")
        out_inst = stdout.read().decode('utf-8', errors='ignore').encode('ascii', errors='ignore').decode('ascii')
        print(out_inst)
        
    finally:
        client.close()

if __name__ == "__main__":
    run()
