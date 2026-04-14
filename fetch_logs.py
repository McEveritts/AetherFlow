import paramiko

HOSTNAME = "192.168.1.153"
USERNAME = "mcstream"
PASSWORD = "7338"

def run():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(HOSTNAME, username=USERNAME, password=PASSWORD, timeout=10)
        
        commands = [
            f'echo "{PASSWORD}" | sudo -S journalctl -u aetherflow-api.service -n 100 --no-pager',
            f'echo "{PASSWORD}" | sudo -S systemctl status aetherflow-api.service --no-pager'
        ]
        
        for cmd in commands:
            stdin, stdout, stderr = client.exec_command(cmd)
            for line in iter(stdout.readline, ""):
                print(line.encode('ascii', 'ignore').decode('ascii'), end="")
            for line in iter(stderr.readline, ""):
                print("ERR:", line.encode('ascii', 'ignore').decode('ascii'), end="")
            stdout.channel.recv_exit_status()
            print("--- End ---")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    run()
