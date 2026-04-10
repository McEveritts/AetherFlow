const http = require('http');

function request(method, path, body = null, token = null) {
    return new Promise((resolve, reject) => {
        const options = {
            hostname: 'localhost',
            port: 8080,
            path: path,
            method: method,
            headers: {
                'Content-Type': 'application/json'
            }
        };

        if (token) {
            options.headers['Authorization'] = `Bearer ${token}`;
        }

        const req = http.request(options, (res) => {
            let data = '';
            // Capture cookies to test auth
            const cookies = res.headers['set-cookie'];
            let parsedCookieToken = null;
            if (cookies && cookies.length > 0) {
               const sessionCookie = cookies.find(c => c.startsWith('aetherflow_session='));
               if (sessionCookie) {
                   parsedCookieToken = sessionCookie.split('aetherflow_session=')[1].split(';')[0];
               }
            }

            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    const parsed = JSON.parse(data);
                    resolve({ status: res.statusCode, body: parsed, token: parsedCookieToken });
                } catch (e) {
                    resolve({ status: res.statusCode, body: data, token: parsedCookieToken });
                }
            });
        });

        req.on('error', reject);

        if (body) {
            req.write(JSON.stringify(body));
        }
        req.end();
    });
}

async function run() {
    console.log("== Phase 1: Authentication ==");
    const loginRes = await request('POST', '/api/v1/public/auth/login', { username: 'admin', password: 'password' });
    console.log(`[LOGIN] Status: ${loginRes.status}`);
    const token = loginRes.token;
    if (!token) {
        console.error("Failed to acquire token via login!");
        return;
    }
    
    console.log("\n== Phase 1 Loop: AI Proposal -> Inbox -> Approve -> Audit Visibility ==");
    const pendingRes = await request('GET', '/api/v1/admin/actions/pending?status=pending', null, token);
    console.log(`[GET PENDING ACTIONS] Status: ${pendingRes.status}`);
    console.log(`[ACTIONS COUNT] ${pendingRes.body.count}`);
    
    if (pendingRes.body.count > 0) {
        const actionId = pendingRes.body.actions[0].id;
        console.log(`Approving action ${actionId}...`);
        
        const approveRes = await request('POST', `/api/v1/admin/actions/${actionId}/approve`, null, token);
        console.log(`[APPROVE ACTION] Status: ${approveRes.status}`);
        console.log(`[APPROVE PAYLOAD] ${JSON.stringify(approveRes.body)}`);
    }

    const auditRes = await request('GET', '/api/v1/admin/audit-log?limit=5', null, token);
    console.log(`[GET AUDIT LOG] Status: ${auditRes.status}`);
    const logs = auditRes.body.audit_logs || auditRes.body.logs || [];
    const recentLoginAndApprove = logs.filter(l => l.action === 'action_approve');
    console.log(`[AUDIT FOUND APPROVAL] ${recentLoginAndApprove.length > 0}`);

    console.log("\n== Phase 2 Loop: OIDC and Session == ");
    const sessionRes = await request('GET', '/api/v1/auth/sessions', null, token);
    console.log(`[GET SESSIONS] Status: ${sessionRes.status}`);
    console.log(`[ACTIVE SESSIONS COUNT] ${sessionRes.body.count}`);

    if (sessionRes.body.count > 0) {
        const currentSession = sessionRes.body.sessions.find(s => s.is_current) || sessionRes.body.sessions[0];
        if (currentSession) {
             const jtiPrefix = currentSession.jti.replace('...', '');
             console.log(`Revoking session JTI prefix: ${jtiPrefix}...`);
             const revokeRes = await request('POST', `/api/v1/auth/sessions/${jtiPrefix}/revoke`, null, token);
             console.log(`[REVOKE SESSION] Status: ${revokeRes.status}`);
             console.log(`[REVOKE PAYLOAD] ${JSON.stringify(revokeRes.body)}`);

             const secureRes = await request('GET', '/api/v1/admin/actions/pending', null, token);
             console.log(`[POST-REVOKE GET] Status: ${secureRes.status} (Expected: 401)`);
        }
    }
}
run();
