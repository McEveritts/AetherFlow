import paramiko
import time
import sys

HOSTNAME = "192.168.1.153"
USERNAME = "mcstream"
PASSWORD = "7338"

def run():
    print(f"Connecting to {HOSTNAME}...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        client.connect(HOSTNAME, username=USERNAME, password=PASSWORD, timeout=10)
        
        # We need a pseudo-terminal for sudo
        channel = client.invoke_shell()
        
        def execute(cmd, wait_for="# "):
            print(f"Executing: {cmd}")
            channel.send(cmd + "\n")
            output = ""
            while not output.endswith(wait_for):
                if channel.recv_ready():
                    chunk = channel.recv(4096).decode('utf-8', errors='ignore')
                    output += chunk
                    sys.stdout.write(chunk)
                    sys.stdout.flush()
                time.sleep(0.1)
            return output

        # Wait for initial prompt
        output = ""
        while not output.endswith("$ ") and not output.endswith("# ") and not output.endswith("~$ "):
            if channel.recv_ready():
                output += channel.recv(4096).decode('utf-8', errors='ignore')
            time.sleep(0.1)
        
        # Switch to root
        channel.send("sudo -i\n")
        time.sleep(0.5)
        if channel.recv_ready():
            prompt = channel.recv(4096).decode('utf-8', errors='ignore')
            if "password" in prompt.lower():
                channel.send(PASSWORD + "\n")
        
        # Wait for root prompt
        execute("echo ROOT_READY", "ROOT_READY")
        
        # Now trigger the deploy pipeline
        # Let's check where updateAetherFlow is
        execute("which updateAetherFlow || echo 'NOT FOUND'")
        
        # Execute the update manually or via script
        execute("cd /opt/AetherFlow && git pull origin master")
        
        # Let's build and restart
        execute("cd /opt/AetherFlow/backend && go build -o bin/aetherflow-api .")
        execute("cd /opt/AetherFlow/frontend && npm install && npm run build")
        execute("systemctl restart aetherflow-api aetherflow-web")
        
        # Check status
        execute("systemctl status aetherflow-api --no-pager")
        
        execute("exit")
        print("\n\nDone.")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    run()
