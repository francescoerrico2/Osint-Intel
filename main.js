const { app, BrowserWindow, Menu, shell, ipcMain } = require('electron');
const path = require('path');
const http = require('http');
const https = require('https');
const url = require('url');

let mainWindow;

// Simple backend proxy for API calls
function createAPIServer() {
  const server = http.createServer(async (req, res) => {
    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    
    if (req.method === 'OPTIONS') {
      res.writeHead(200);
      res.end();
      return;
    }

    const parsedUrl = url.parse(req.url, true);
    
    // Health check
    if (parsedUrl.pathname === '/api/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'healthy', mode: 'electron' }));
      return;
    }

    // Root API
    if (parsedUrl.pathname === '/api/' || parsedUrl.pathname === '/api') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ message: 'OSINT Intelligence API', version: '1.0.0', mode: 'electron' }));
      return;
    }

    // IP Analysis
    if (parsedUrl.pathname === '/api/analyze/ip' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', async () => {
        try {
          const data = JSON.parse(body);
          const results = await analyzeIPs(data.ips, data.api_keys || {});
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(results));
        } catch (e) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: e.message }));
        }
      });
      return;
    }

    // Domain Analysis
    if (parsedUrl.pathname === '/api/analyze/domain' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', async () => {
        try {
          const data = JSON.parse(body);
          const result = await analyzeDomain(data.domain, data.api_keys || {});
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(result));
        } catch (e) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: e.message }));
        }
      });
      return;
    }

    // Hash Analysis
    if (parsedUrl.pathname === '/api/analyze/hash' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', async () => {
        try {
          const data = JSON.parse(body);
          const result = await analyzeHash(data.hash_value, data.api_keys || {});
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(result));
        } catch (e) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ detail: e.message }));
        }
      });
      return;
    }

    // History (empty for electron)
    if (parsedUrl.pathname === '/api/history') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify([]));
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not found' }));
  });

  server.listen(8001, '127.0.0.1', () => {
    console.log('API server running on http://127.0.0.1:8001');
  });

  return server;
}

// Helper: Check if IP is private
function isPrivateIP(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) return false;
  
  // Private ranges
  if (parts[0] === 10) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  if (parts[0] === 127) return true;
  if (parts[0] === 169 && parts[1] === 254) return true;
  return false;
}

// Helper: Validate IP
function isValidIP(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  return parts.every(p => {
    const num = parseInt(p, 10);
    return !isNaN(num) && num >= 0 && num <= 255 && String(num) === p;
  });
}

// Helper: Detect hash type
function detectHashType(hash) {
  if (hash.length === 32) return 'MD5';
  if (hash.length === 40) return 'SHA1';
  if (hash.length === 64) return 'SHA256';
  return 'unknown';
}

// Helper: Calculate threat level
function calculateThreatLevel(score) {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 40) return 'medium';
  if (score >= 20) return 'low';
  if (score > 0) return 'clean';
  return 'unknown';
}

// HTTP request helper
function httpRequest(options, postData = null) {
  return new Promise((resolve, reject) => {
    const protocol = options.protocol === 'https:' ? https : http;
    const req = protocol.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(data) });
        } catch {
          resolve({ status: res.statusCode, data: data });
        }
      });
    });
    req.on('error', reject);
    req.setTimeout(10000, () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });
    if (postData) req.write(postData);
    req.end();
  });
}

// Query AbuseIPDB
async function queryAbuseIPDB(ip, apiKey) {
  if (!apiKey) return { vendor: 'AbuseIPDB', error: 'API key not provided' };
  
  try {
    const result = await httpRequest({
      hostname: 'api.abuseipdb.com',
      path: `/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`,
      method: 'GET',
      protocol: 'https:',
      headers: { 'Key': apiKey, 'Accept': 'application/json' }
    });
    
    if (result.status === 200 && result.data.data) {
      const d = result.data.data;
      return {
        vendor: 'AbuseIPDB',
        score: d.abuseConfidenceScore || 0,
        is_malicious: (d.abuseConfidenceScore || 0) > 25,
        details: {
          total_reports: d.totalReports,
          last_reported: d.lastReportedAt,
          isp: d.isp,
          country_code: d.countryCode
        }
      };
    }
    return { vendor: 'AbuseIPDB', error: `API error: ${result.status}` };
  } catch (e) {
    return { vendor: 'AbuseIPDB', error: e.message };
  }
}

// Query VirusTotal IP
async function queryVirusTotalIP(ip, apiKey) {
  if (!apiKey) return { vendor: 'VirusTotal', error: 'API key not provided' };
  
  try {
    const result = await httpRequest({
      hostname: 'www.virustotal.com',
      path: `/api/v3/ip_addresses/${ip}`,
      method: 'GET',
      protocol: 'https:',
      headers: { 'x-apikey': apiKey }
    });
    
    if (result.status === 200 && result.data.data) {
      const attrs = result.data.data.attributes || {};
      const stats = attrs.last_analysis_stats || {};
      const malicious = stats.malicious || 0;
      const suspicious = stats.suspicious || 0;
      const total = Object.values(stats).reduce((a, b) => a + b, 0) || 1;
      const score = ((malicious + suspicious) / total * 100);
      
      return {
        vendor: 'VirusTotal',
        score: Math.round(score * 100) / 100,
        is_malicious: malicious > 0,
        details: {
          malicious, suspicious,
          harmless: stats.harmless || 0,
          undetected: stats.undetected || 0,
          as_owner: attrs.as_owner,
          country: attrs.country
        }
      };
    }
    return { vendor: 'VirusTotal', error: `API error: ${result.status}` };
  } catch (e) {
    return { vendor: 'VirusTotal', error: e.message };
  }
}

// Query IPinfo
async function queryIPinfo(ip, apiKey) {
  try {
    const path = apiKey ? `/${ip}/json?token=${apiKey}` : `/${ip}/json`;
    const result = await httpRequest({
      hostname: 'ipinfo.io',
      path: path,
      method: 'GET',
      protocol: 'https:'
    });
    
    if (result.status === 200) return result.data;
    return { error: `API error: ${result.status}` };
  } catch (e) {
    return { error: e.message };
  }
}

// Query VirusTotal Hash
async function queryVirusTotalHash(hash, apiKey) {
  if (!apiKey) return { vendor: 'VirusTotal', error: 'API key not provided' };
  
  try {
    const result = await httpRequest({
      hostname: 'www.virustotal.com',
      path: `/api/v3/files/${hash}`,
      method: 'GET',
      protocol: 'https:',
      headers: { 'x-apikey': apiKey }
    });
    
    if (result.status === 200 && result.data.data) {
      const attrs = result.data.data.attributes || {};
      const stats = attrs.last_analysis_stats || {};
      const malicious = stats.malicious || 0;
      const suspicious = stats.suspicious || 0;
      const total = Object.values(stats).reduce((a, b) => a + b, 0) || 1;
      const score = ((malicious + suspicious) / total * 100);
      
      return {
        vendor: 'VirusTotal',
        score: Math.round(score * 100) / 100,
        is_malicious: malicious > 0,
        details: {
          malicious, suspicious,
          file_type: attrs.type_description,
          file_size: attrs.size,
          names: (attrs.names || []).slice(0, 5)
        }
      };
    }
    if (result.status === 404) {
      return { vendor: 'VirusTotal', score: 0, is_malicious: false, details: { message: 'Hash not found' } };
    }
    return { vendor: 'VirusTotal', error: `API error: ${result.status}` };
  } catch (e) {
    return { vendor: 'VirusTotal', error: e.message };
  }
}

// Query VirusTotal Domain
async function queryVirusTotalDomain(domain, apiKey) {
  if (!apiKey) return { vendor: 'VirusTotal', error: 'API key not provided' };
  
  try {
    const result = await httpRequest({
      hostname: 'www.virustotal.com',
      path: `/api/v3/domains/${domain}`,
      method: 'GET',
      protocol: 'https:',
      headers: { 'x-apikey': apiKey }
    });
    
    if (result.status === 200 && result.data.data) {
      const attrs = result.data.data.attributes || {};
      const stats = attrs.last_analysis_stats || {};
      const malicious = stats.malicious || 0;
      const suspicious = stats.suspicious || 0;
      const total = Object.values(stats).reduce((a, b) => a + b, 0) || 1;
      const score = ((malicious + suspicious) / total * 100);
      
      return {
        vendor: 'VirusTotal',
        score: Math.round(score * 100) / 100,
        is_malicious: malicious > 0,
        details: { malicious, suspicious, registrar: attrs.registrar }
      };
    }
    return { vendor: 'VirusTotal', error: `API error: ${result.status}` };
  } catch (e) {
    return { vendor: 'VirusTotal', error: e.message };
  }
}

// DNS resolve
function resolveDomain(domain) {
  return new Promise((resolve) => {
    const dns = require('dns');
    dns.resolve4(domain, (err, addresses) => {
      resolve(err ? [] : addresses);
    });
  });
}

// Analyze IPs
async function analyzeIPs(ips, apiKeys) {
  const results = [];
  
  for (const ip of ips) {
    const trimmedIP = ip.trim();
    
    if (!isValidIP(trimmedIP)) {
      results.push({ ip: trimmedIP, is_private: false, is_valid: false, threat_level: 'unknown', threat_score: 0, vendor_results: [] });
      continue;
    }
    
    if (isPrivateIP(trimmedIP)) {
      results.push({ ip: trimmedIP, is_private: true, is_valid: true, threat_level: 'clean', threat_score: 0, vendor_results: [] });
      continue;
    }
    
    const [abuseResult, vtResult, ipinfoData] = await Promise.all([
      queryAbuseIPDB(trimmedIP, apiKeys.abuseipdb),
      queryVirusTotalIP(trimmedIP, apiKeys.virustotal),
      queryIPinfo(trimmedIP, apiKeys.ipinfo)
    ]);
    
    const vendorResults = [abuseResult, vtResult];
    const scores = vendorResults.filter(v => v.score != null).map(v => v.score);
    const avgScore = scores.length ? scores.reduce((a, b) => a + b, 0) / scores.length : 0;
    
    let geolocation = null;
    if (ipinfoData.loc) {
      const [lat, lon] = ipinfoData.loc.split(',').map(Number);
      geolocation = {
        latitude: lat, longitude: lon,
        country: ipinfoData.country,
        city: ipinfoData.city,
        region: ipinfoData.region
      };
    }
    
    results.push({
      ip: trimmedIP,
      is_private: false,
      is_valid: true,
      threat_score: Math.round(avgScore * 100) / 100,
      threat_level: calculateThreatLevel(avgScore),
      geolocation,
      isp: ipinfoData.org,
      org: ipinfoData.org,
      asn: ipinfoData.asn,
      vendor_results: vendorResults
    });
  }
  
  return results;
}

// Analyze Domain
async function analyzeDomain(domain, apiKeys) {
  domain = domain.replace(/^https?:\/\//, '').split('/')[0].toLowerCase();
  
  const [resolvedIPs, vtResult] = await Promise.all([
    resolveDomain(domain),
    queryVirusTotalDomain(domain, apiKeys.virustotal)
  ]);
  
  let ipResults = [];
  if (resolvedIPs.length) {
    ipResults = await analyzeIPs(resolvedIPs, apiKeys);
  }
  
  const vendorResults = [vtResult];
  const scores = vendorResults.filter(v => v.score != null).map(v => v.score);
  if (ipResults.length) {
    scores.push(...ipResults.filter(r => r.threat_score > 0).map(r => r.threat_score));
  }
  const avgScore = scores.length ? scores.reduce((a, b) => a + b, 0) / scores.length : 0;
  
  return {
    domain,
    resolved_ips: resolvedIPs,
    is_malicious: vendorResults.some(v => v.is_malicious),
    threat_score: Math.round(avgScore * 100) / 100,
    threat_level: calculateThreatLevel(avgScore),
    dns_records: { A: resolvedIPs },
    vendor_results: vendorResults,
    ip_results: ipResults
  };
}

// Analyze Hash
async function analyzeHash(hashValue, apiKeys) {
  hashValue = hashValue.trim().toLowerCase();
  const hashType = detectHashType(hashValue);
  
  if (hashType === 'unknown') {
    throw new Error('Invalid hash format. Supported: MD5 (32), SHA1 (40), SHA256 (64)');
  }
  
  if (!/^[a-f0-9]+$/.test(hashValue)) {
    throw new Error('Hash must contain only hexadecimal characters');
  }
  
  const vtResult = await queryVirusTotalHash(hashValue, apiKeys.virustotal);
  const vendorResults = [vtResult];
  const scores = vendorResults.filter(v => v.score != null).map(v => v.score);
  const avgScore = scores.length ? scores.reduce((a, b) => a + b, 0) / scores.length : 0;
  
  return {
    hash_value: hashValue,
    hash_type: hashType,
    is_malicious: vendorResults.some(v => v.is_malicious),
    threat_score: Math.round(avgScore * 100) / 100,
    threat_level: calculateThreatLevel(avgScore),
    vendor_results: vendorResults,
    file_info: vtResult.details || {}
  };
}

// Create window
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1024,
    minHeight: 700,
    backgroundColor: '#0A0A0A',
    icon: path.join(__dirname, 'build', 'icon.png'),
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js')
    },
    show: false
  });

  mainWindow.loadFile(path.join(__dirname, 'build', 'index.html'));

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: 'deny' };
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// Menu
const menuTemplate = [
  {
    label: 'File',
    submenu: [
      { label: 'Clear Data', accelerator: 'CmdOrCtrl+Shift+Delete', click: () => mainWindow?.webContents.executeJavaScript('localStorage.clear(); location.reload();') },
      { type: 'separator' },
      { label: 'Exit', accelerator: 'Alt+F4', click: () => app.quit() }
    ]
  },
  {
    label: 'View',
    submenu: [
      { role: 'reload' }, { role: 'forceReload' }, { type: 'separator' },
      { role: 'resetZoom' }, { role: 'zoomIn' }, { role: 'zoomOut' }, { type: 'separator' },
      { role: 'togglefullscreen' }
    ]
  },
  {
    label: 'Tools',
    submenu: [
      { label: 'Developer Tools', accelerator: 'F12', click: () => mainWindow?.webContents.toggleDevTools() }
    ]
  },
  {
    label: 'Help',
    submenu: [
      { label: 'Get AbuseIPDB Key', click: () => shell.openExternal('https://www.abuseipdb.com/account/api') },
      { label: 'Get VirusTotal Key', click: () => shell.openExternal('https://www.virustotal.com/gui/my-apikey') },
      { label: 'Get IPinfo Token', click: () => shell.openExternal('https://ipinfo.io/account/token') },
      { type: 'separator' },
      { label: 'About', click: () => require('electron').dialog.showMessageBox(mainWindow, { type: 'info', title: 'OSINT Intel', message: 'OSINT Intel v1.0.0', detail: 'Threat Intelligence Dashboard\n\nAnalyze IPs, Domains, and Hashes.' }) }
    ]
  }
];

let apiServer;

app.whenReady().then(() => {
  apiServer = createAPIServer();
  Menu.setApplicationMenu(Menu.buildFromTemplate(menuTemplate));
  createWindow();
});

app.on('window-all-closed', () => {
  if (apiServer) apiServer.close();
  if (process.platform !== 'darwin') app.quit();
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});
