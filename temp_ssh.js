const { Client } = require('ssh2');
const conn = new Client();

const script = `
cd /opt/AetherFlow/backend && \
git pull origin master && \
go build -o api-server main.go && \
sudo pm2 restart aetherflow-api
`;

conn.on('ready', () => {
    conn.exec(script, (err, stream) => {
        if (err) throw err;
        stream.on('close', (code, signal) => {
            conn.end();
        }).on('data', (data) => {
            console.log('STDOUT: ' + data);
        }).stderr.on('data', (data) => {
            console.log('STDERR: ' + data);
        });
    });
}).connect({
    host: '192.168.0.100',
    port: 22,
    username: 'root',
    password: 'password'
});
