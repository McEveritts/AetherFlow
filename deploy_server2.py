import paramiko

HOSTNAME = "192.168.1.153"
USERNAME = "mcstream"
PASSWORD = "7338"

def run():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        print("Connecting...")
        client.connect(HOSTNAME, username=USERNAME, password=PASSWORD, timeout=10)
        print("Connected! Executing update...")
        
        # Pull updates over git first so the deployer code is fresh
        # The blue/green deployer then builds it.
        commands = [
            f'echo "{PASSWORD}" | sudo -S -i bash -c "cd /opt/AetherFlow && git stash && git pull origin master"',
            f'echo "{PASSWORD}" | sudo -S -i bash -c "cd /opt/AetherFlow/backend && rm -f aetherflow-api && go build -o aetherflow-api ."',
            f'echo "{PASSWORD}" | sudo -S -i bash -c "cd /opt/AetherFlow/frontend && npm run build"',
            f'echo "{PASSWORD}" | sudo -S -i bash -c "systemctl restart aetherflow-api aetherflow-web"'
        ]
        
        for cmd in commands:
            stdin, stdout, stderr = client.exec_command(cmd)
            # The script might take some time to run
            print(f"--- Output of cmd ---")
            for line in iter(stdout.readline, ""):
                print(line.encode('ascii', 'ignore').decode('ascii'), end="")
            for line in iter(stderr.readline, ""):
                print("ERR:", line.encode('ascii', 'ignore').decode('ascii'), end="")
            stdout.channel.recv_exit_status() # Wait for command to complete
            print(f"--- End ---")
            
        print("Successfully deployed!")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    run()
