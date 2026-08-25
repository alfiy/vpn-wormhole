/**
 * VPN-Wormhole - Signaling + optional relay server
 * HTTPS by default (self-signed cert auto-generated) so crypto.subtle works
 * when clients access via LAN IP: https://服务器IP:3080
 *
 * Only external dependency: ws
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3080;
const ROOM_TTL_MS = 30 * 60 * 1000;
const PUBLIC_DIR = path.join(__dirname, 'public');
const CERT_DIR = path.join(__dirname, 'certs');
const KEY_FILE = path.join(CERT_DIR, 'key.pem');
const CERT_FILE = path.join(CERT_DIR, 'cert.pem');

const rooms = new Map(); // code -> { clients: Map, createdAt }

function generateCode() {
  const words = [
    'apple','brave','cloud','delta','eagle','flame','grape','harbor',
    'ivory','jade','kite','lemon','maple','noble','ocean','pearl',
    'quartz','river','stone','tiger','umbra','vivid','whale','xenon',
    'yellow','zebra','amber','blaze','coral','dawn','ember','frost',
    'glow','haven','iris','jewel','karma','lunar','mist','nova',
    'orbit','prism','quest','raven','solar','thunder','ultra','vortex'
  ];
  const n = Math.floor(Math.random() * 16) + 1;
  const w1 = words[Math.floor(Math.random() * words.length)];
  const w2 = words[Math.floor(Math.random() * words.length)];
  return `${n}-${w1}-${w2}`;
}

function cleanRooms() {
  const now = Date.now();
  for (const [code, room] of rooms) {
    if (now - room.createdAt > ROOM_TTL_MS) {
      for (const ws of room.clients.keys()) {
        try {
          ws.send(JSON.stringify({ type: 'room-expired' }));
          ws.close();
        } catch (_) {}
      }
      rooms.delete(code);
      console.log('[room] expired', code);
    }
  }
}
setInterval(cleanRooms, 60000);

/** Ensure self-signed certificate exists (valid for LAN / VPN use) */
function ensureCerts() {
  if (fs.existsSync(KEY_FILE) && fs.existsSync(CERT_FILE)) {
    return {
      key: fs.readFileSync(KEY_FILE),
      cert: fs.readFileSync(CERT_FILE)
    };
  }

  console.log('[cert] 未找到证书，正在自动生成自签名证书…');
  fs.mkdirSync(CERT_DIR, { recursive: true });

  // Subject Alternative Name covers typical LAN usage; browsers still warn once
  const conf = `
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
x509_extensions = v3_req

[dn]
CN = vpn-wormhole
O = VPN-Wormhole Local
C = CN

[v3_req]
subjectAltName = @alt_names
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = localhost
DNS.2 = *.local
IP.1 = 127.0.0.1
IP.2 = ::1
`;
  const confPath = path.join(CERT_DIR, 'openssl.cnf');
  fs.writeFileSync(confPath, conf);

  try {
    execSync(
      `openssl req -x509 -nodes -newkey rsa:2048 -keyout "${KEY_FILE}" -out "${CERT_FILE}" -days 825 -config "${confPath}"`,
      { stdio: 'pipe' }
    );
    console.log('[cert] 自签名证书已生成 → certs/key.pem + certs/cert.pem');
  } catch (e) {
    console.error('[cert] openssl 生成失败，请确认已安装 openssl');
    console.error(e.message);
    process.exit(1);
  }

  return {
    key: fs.readFileSync(KEY_FILE),
    cert: fs.readFileSync(CERT_FILE)
  };
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json',
  '.ico': 'image/x-icon',
  '.png': 'image/png',
  '.svg': 'image/svg+xml'
};

function serveStatic(req, res) {
  let urlPath = req.url.split('?')[0];
  if (urlPath === '/') urlPath = '/index.html';
  const safe = path.normalize(urlPath).replace(/^(\.\.[\/\\])+/, '');
  const filePath = path.join(PUBLIC_DIR, safe);
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    res.end('Forbidden');
    return;
  }
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404);
      res.end('Not Found');
      return;
    }
    const ext = path.extname(filePath);
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(data);
  });
}

function createAppHandler() {
  return (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    if (req.url.startsWith('/api/health')) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        status: 'ok',
        secure: req.socket.encrypted === true,
        rooms: rooms.size,
        uptime: Math.floor(process.uptime())
      }));
      return;
    }

    if (req.url.startsWith('/api/rooms')) {
      const list = [];
      for (const [code, room] of rooms) {
        list.push({
          code,
          members: room.clients.size,
          ageSec: Math.floor((Date.now() - room.createdAt) / 1000)
        });
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(list));
      return;
    }

    serveStatic(req, res);
  };
}

function attachWebSocket(server) {
  const wss = new WebSocketServer({ server });

  wss.on('connection', (ws) => {
    ws.isAlive = true;
    ws.roomCode = null;

    ws.on('pong', () => { ws.isAlive = true; });

    ws.on('message', (raw) => {
      let msg;
      try {
        msg = JSON.parse(raw.toString());
      } catch {
        return;
      }

      switch (msg.type) {
        case 'create-room': {
          let code;
          do {
            code = generateCode();
          } while (rooms.has(code));
          const room = { clients: new Map(), createdAt: Date.now() };
          room.clients.set(ws, { role: 'creator', joinedAt: Date.now() });
          rooms.set(code, room);
          ws.roomCode = code;
          ws.send(JSON.stringify({ type: 'room-created', code }));
          console.log('[room] created', code);
          break;
        }

        case 'join-room': {
          const code = (msg.code || '').trim().toLowerCase();
          const room = rooms.get(code);
          if (!room) {
            ws.send(JSON.stringify({ type: 'error', error: '房间不存在或已过期' }));
            return;
          }
          if (room.clients.size >= 2) {
            ws.send(JSON.stringify({ type: 'error', error: '房间已满（仅支持两人）' }));
            return;
          }
          room.clients.set(ws, { role: 'joiner', joinedAt: Date.now() });
          ws.roomCode = code;
          ws.send(JSON.stringify({ type: 'room-joined', code }));

          for (const [client] of room.clients) {
            if (client.readyState === 1) {
              client.send(JSON.stringify({ type: 'peer-joined' }));
            }
          }
          console.log('[room] joined', code);
          break;
        }

        case 'signal':
        case 'relay-data': {
          const code = ws.roomCode;
          if (!code) return;
          const room = rooms.get(code);
          if (!room) return;
          for (const [client] of room.clients) {
            if (client !== ws && client.readyState === 1) {
              client.send(JSON.stringify({
                type: msg.type,
                data: msg.data
              }));
            }
          }
          break;
        }

        case 'leave': {
          leaveRoom(ws);
          break;
        }
      }
    });

    ws.on('close', () => leaveRoom(ws));
  });

  setInterval(() => {
    wss.clients.forEach((ws) => {
      if (!ws.isAlive) return ws.terminate();
      ws.isAlive = false;
      ws.ping();
    });
  }, 30000);

  return wss;
}

function leaveRoom(ws) {
  const code = ws.roomCode;
  if (!code) return;
  const room = rooms.get(code);
  if (!room) return;
  room.clients.delete(ws);
  for (const [client] of room.clients) {
    if (client.readyState === 1) {
      client.send(JSON.stringify({ type: 'peer-left' }));
    }
  }
  if (room.clients.size === 0) {
    rooms.delete(code);
    console.log('[room] destroyed', code);
  }
  ws.roomCode = null;
}

// ---------- Start ----------
const tls = ensureCerts();
const handler = createAppHandler();

// Primary: HTTPS (required for crypto.subtle on LAN IP)
const httpsServer = https.createServer(tls, handler);
attachWebSocket(httpsServer);

httpsServer.listen(PORT, '0.0.0.0', () => {
  console.log('');
  console.log('🚀 VPN-Wormhole 已启动（HTTPS）');
  console.log('────────────────────────────────────────');
  console.log(`  本机访问:     https://127.0.0.1:${PORT}`);
  console.log(`  局域网访问:   https://<服务器IP>:${PORT}`);
  console.log('');
  console.log('  首次用 IP 访问时浏览器会提示「证书不受信任」：');
  console.log('  点击「高级」→「继续访问」即可（自签名证书，仅内网使用）。');
  console.log('────────────────────────────────────────');
  console.log(`  健康检查: https://127.0.0.1:${PORT}/api/health`);
  console.log('');
});

// Optional plain HTTP on PORT+1 just to show a friendly redirect hint
const httpPort = Number(PORT) + 1;
const httpServer = http.createServer((req, res) => {
  const host = (req.headers.host || 'localhost').split(':')[0];
  const httpsUrl = `https://${host}:${PORT}/`;
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>请使用 HTTPS</title></head>
<body style="font-family:system-ui;padding:2rem;max-width:560px;margin:auto">
<h2>请使用 HTTPS 访问</h2>
<p>加密功能需要安全上下文。请打开：</p>
<p><a href="${httpsUrl}">${httpsUrl}</a></p>
<p style="color:#666">浏览器会提示证书不受信任，选择「高级 → 继续访问」即可。</p>
</body></html>`);
});
httpServer.listen(httpPort, '0.0.0.0', () => {
  console.log(`  (可选) HTTP 提示页: http://0.0.0.0:${httpPort} → 引导到 HTTPS`);
});
