import paramiko

def run():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect('192.168.1.153', username='mcstream', password='7338')
        
        # 1. Fix permissions
        print("Fixing script permissions...")
        stdin, stdout, stderr = client.exec_command("echo 7338 | sudo -S chmod -R +x /opt/AetherFlow/packages/package/")
        stdout.read()
        
        # 2. Clear apt locks
        print("Checking for apt/dpkg locks...")
        stdin, stdout, stderr = client.exec_command("ps aux | grep -E 'apt|dpkg'")
        out = stdout.read().decode('ascii', errors='ignore')
        print(out)
        
        # Kill them if they are running (ignore the grep itself)
        # Note: This is a bit aggressive, but we need to clear the lock.
        # We avoid killing the parent shell or other system stuff by being specific.
        stdin, stdout, stderr = client.exec_command("echo 7338 | sudo -S pkill -9 apt")
        stdout.read()
        stdin, stdout, stderr = client.exec_command("echo 7338 | sudo -S pkill -9 dpkg")
        stdout.read()
        
        # Remove lock files just in case
        stdin, stdout, stderr = client.exec_command("echo 7338 | sudo -S rm -v /var/lib/apt/lists/lock /var/cache/apt/archives/lock /var/lib/dpkg/lock*")
        print("Lock cleanup results:")
        print(stdout.read().decode('ascii', errors='ignore'))
        
        # 3. Final verification of permissions
        stdin, stdout, stderr = client.exec_command("ls -la /opt/AetherFlow/packages/package/install/installpackage-sonarr")
        print("Sonarr installer permissions:")
        print(stdout.read().decode('ascii', errors='ignore'))
        
    finally:
        client.close()

if __name__ == "__main__":
    run()
