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
            f'echo "{PASSWORD}" | sudo -S -i bash -c "sed -i \\"/ALLOWED_HOSTS/d\\" /opt/AetherFlow/backend/.env; echo \\"ALLOWED_HOSTS=192.168.1.153,localhost,97.146.185.47,97.146.185.47:8080,192.168.1.153:8080\\" >> /opt/AetherFlow/backend/.env"',
            f'echo "{PASSWORD}" | sudo -S systemctl restart aetherflow-api.service'
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
