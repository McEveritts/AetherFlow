const { Client } = require('ssh2');

const conn = new Client();

function stripAnsi(str) {
    return str.replace(/\x1b\[[0-9;]*[a-zA-Z]|\x1b\([A-B]|\x1b\][^\x07]*\x07|\x1b\[[\?]?[0-9;]*[a-zA-Z]/g, '');
}

conn.on('ready', () => {
    console.log('=== Connected ===');
    conn.shell((err, stream) => {
        if (err) throw err;
        let step = 0;
        let buffer = '';

        stream.on('close', () => {
            console.log('\n=== Done ===');
            conn.end();
        }).on('data', (data) => {
            const output = data.toString();
            process.stdout.write(output);
            buffer += stripAnsi(output);

            if (step === 0 && buffer.includes('$')) {
                stream.write('su root\n');
                step = 1;
                buffer = '';
            } else if (step === 1 && buffer.toLowerCase().includes('password')) {
                stream.write('7338\n');
                step = 2;
                buffer = '';
            } else if (step === 2 && buffer.includes('#')) {
                setTimeout(() => {
                    console.log('\n---> Root shell ready, full deploy...');
                    const cmds = [
                        'export PATH=$PATH:/usr/local/go/bin:/root/go/bin',
                        'export GOPATH=/root/go',
                        'cd /opt/AetherFlow',
                        'git pull origin master',
                        'cd /opt/AetherFlow/backend',
                        'go mod tidy',
                        'go build -o api-server main.go',
                        'pm2 delete aetherflow-api 2>/dev/null; cd /opt/AetherFlow/backend && pm2 start ./api-server --name aetherflow-api',
                        'cd /opt/AetherFlow/frontend',
                        'npm install',
                        'npm run build',
                        'pm2 restart 0',
                        'sleep 3',
                        'curl -s http://localhost:8080/api/services | head -c 500',
                        'echo DEPLOY_OK'
                    ].join(' && ');
                    stream.write(cmds + '\n');
                    step = 3;
                    buffer = '';
                }, 3000);
            } else if (step === 3) {
                const clean = buffer.replace(/echo "?DEPLOY_OK"?/g, '');
                if (clean.includes('DEPLOY_OK')) {
                    console.log('\n=== Deployment complete! ===');
                    stream.write('exit\n');
                    setTimeout(() => {
                        stream.write('exit\n');
                        setTimeout(() => conn.end(), 1000);
                    }, 500);
                    step = 4;
                }
            }
        });
    });
}).connect({
    host: '192.168.1.164',
    port: 4747,
    username: 'mceveritts',
    password: '7338'
});

setTimeout(() => { conn.end(); process.exit(1); }, 300000);
