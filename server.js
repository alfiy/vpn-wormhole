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
// 房间过期时间（分钟）。部署时设置，例如：ROOM_TTL_MINUTES=5 npm start
const ROOM_TTL_MINUTES = Math.max(1, parseInt(process.env.ROOM_TTL_MINUTES || '30', 10) || 30);
const ROOM_TTL_MS = ROOM_TTL_MINUTES * 60 * 1000;
// 限速：VPN 出口常为同一源 IP（SNAT），失败次数按 nameplate 计，IP 只做宽松防洪
const JOIN_RATE_WINDOW_MS = Math.max(10, parseInt(process.env.JOIN_RATE_WINDOW_SEC || '60', 10) || 60) * 1000;
const JOIN_MAX_FAILS_PER_NAMEPLATE = Math.max(3, parseInt(process.env.JOIN_MAX_FAILS || '8', 10) || 8);
const JOIN_MAX_ATTEMPTS_PER_IP = Math.max(20, parseInt(process.env.JOIN_MAX_ATTEMPTS || '200', 10) || 200);
const CREATE_MAX_PER_WINDOW = Math.max(5, parseInt(process.env.CREATE_MAX_PER_WINDOW || '80', 10) || 80);
// TURN（部署在 OpenVPN 服务器上，默认只监听 VPN 地址）
const TURN_HOST = (process.env.TURN_HOST || '10.8.0.1').trim();
const TURN_PORT = parseInt(process.env.TURN_PORT || '3478', 10) || 3478;
const TURN_USER = (process.env.TURN_USER || 'wormhole').trim();
const TURN_PASS = (process.env.TURN_PASS || '').trim();
const PUBLIC_DIR = path.join(__dirname, 'public');
const CERT_DIR = path.join(__dirname, 'certs');
const KEY_FILE = path.join(CERT_DIR, 'key.pem');
const CERT_FILE = path.join(CERT_DIR, 'cert.pem');

const rooms = new Map(); // nameplate -> { clients: Map, createdAt }
// 服务端只分配 nameplate（路由 ID），从不生成/存储 SPAKE2 口令

/** @type {Map<string, { attempts: number, creates: number, resetAt: number, blockedUntil: number }>} */
const ipLimits = new Map();
/** @type {Map<string, { fails: number, resetAt: number, blockedUntil: number }>} */
const nameplateLimits = new Map();

function clientIpFromReq(req) {
  const xf = (req && req.headers && req.headers['x-forwarded-for']) || '';
  if (xf) return String(xf).split(',')[0].trim();
  const addr = (req && req.socket && req.socket.remoteAddress) || 'unknown';
  return addr.replace(/^::ffff:/, '');
}

function getWindowed(map, key, extra) {
  const now = Date.now();
  let e = map.get(key);
  if (!e || now > e.resetAt) {
    e = Object.assign({ resetAt: now + JOIN_RATE_WINDOW_MS, blockedUntil: 0 }, extra);
    map.set(key, e);
  }
  return e;
}

function getIpLimit(ip) {
  return getWindowed(ipLimits, ip, { attempts: 0, creates: 0 });
}

function getNameplateLimit(np) {
  return getWindowed(nameplateLimits, np, { fails: 0 });
}

function assertIpNotFlooding(ip) {
  const e = getIpLimit(ip);
  if (e.blockedUntil && Date.now() < e.blockedUntil) {
    const sec = Math.ceil((e.blockedUntil - Date.now()) / 1000);
    return { ok: false, error: `请求过于频繁，请 ${sec} 秒后再试` };
  }
  return { ok: true, entry: e };
}

function assertNameplateJoinAllowed(np) {
  const e = getNameplateLimit(np);
  if (e.blockedUntil && Date.now() < e.blockedUntil) {
    const sec = Math.ceil((e.blockedUntil - Date.now()) / 1000);
    return { ok: false, error: `该房间尝试次数过多，请 ${sec} 秒后再试` };
  }
  return { ok: true, entry: e };
}

function noteJoinFail(ip, np) {
  const ipE = getIpLimit(ip);
  ipE.attempts += 1;
  if (ipE.attempts >= JOIN_MAX_ATTEMPTS_PER_IP) {
    ipE.blockedUntil = Date.now() + JOIN_RATE_WINDOW_MS;
    console.log('[rate] flood-block ip=', ip, 'attempts=', ipE.attempts);
  }
  if (np) {
    const npE = getNameplateLimit(np);
    npE.fails += 1;
    if (npE.fails >= JOIN_MAX_FAILS_PER_NAMEPLATE) {
      npE.blockedUntil = Date.now() + JOIN_RATE_WINDOW_MS;
      console.log('[rate] block nameplate=', np, 'fails=', npE.fails);
    }
  }
}

function noteJoinSuccess(ip) {
  const e = getIpLimit(ip);
  e.attempts += 1;
}

function noteCreate(ip) {
  const e = getIpLimit(ip);
  e.creates += 1;
  if (e.creates > CREATE_MAX_PER_WINDOW) {
    e.blockedUntil = Date.now() + JOIN_RATE_WINDOW_MS;
    return { ok: false, error: '创建过于频繁，请稍后再试' };
  }
  return { ok: true };
}

function generateNameplate() {
  // 短数字名牌，便于人口头传递；唯一性由 rooms Map 保证
  let n;
  do {
    n = String(Math.floor(Math.random() * 9000) + 1000); // 1000-9999
  } while (rooms.has(n));
  return n;
}

/** 下发给浏览器的 ICE 配置：无公网 STUN，仅 VPN 内 TURN */
function getIceServers() {
  if (!TURN_PASS) return [];
  const host = `${TURN_HOST}:${TURN_PORT}`;
  return [
    { urls: `turn:${host}?transport=udp`, username: TURN_USER, credential: TURN_PASS },
    { urls: `turn:${host}?transport=tcp`, username: TURN_USER, credential: TURN_PASS }
  ];
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

    if (req.url.startsWith('/api/health') || req.url.startsWith('/api/config')) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        status: 'ok',
        secure: req.socket.encrypted === true,
        rooms: rooms.size,
        uptime: Math.floor(process.uptime()),
        roomTtlMinutes: ROOM_TTL_MINUTES,
        roomTtlMs: ROOM_TTL_MS,
        joinMaxFailsPerNameplate: JOIN_MAX_FAILS_PER_NAMEPLATE,
        joinMaxAttemptsPerIp: JOIN_MAX_ATTEMPTS_PER_IP,
        joinRateWindowSec: Math.floor(JOIN_RATE_WINDOW_MS / 1000),
        createMaxPerWindow: CREATE_MAX_PER_WINDOW,
        turnHost: TURN_HOST,
        turnPort: TURN_PORT,
        turnEnabled: Boolean(TURN_PASS),
        iceServers: getIceServers()
      }));
      return;
    }

    if (req.url.startsWith('/api/rooms')) {
      const list = [];
      const now = Date.now();
      for (const [code, room] of rooms) {
        const ageSec = Math.floor((now - room.createdAt) / 1000);
        list.push({
          nameplate: code,
          members: room.clients.size,
          ageSec,
          remainSec: Math.max(0, Math.floor((ROOM_TTL_MS - (now - room.createdAt)) / 1000))
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

  wss.on('connection', (ws, req) => {
    ws.isAlive = true;
    ws.roomCode = null;
    ws.clientIp = clientIpFromReq(req);

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
          const blocked = assertIpNotFlooding(ws.clientIp);
          if (!blocked.ok) {
            ws.send(JSON.stringify({ type: 'error', error: blocked.error }));
            return;
          }
          const created = noteCreate(ws.clientIp);
          if (!created.ok) {
            ws.send(JSON.stringify({ type: 'error', error: created.error }));
            return;
          }
          // 只返回 nameplate；口令由客户端本地生成，服务端永不接收
          const nameplate = generateNameplate();
          const room = { clients: new Map(), createdAt: Date.now() };
          room.clients.set(ws, { role: 'creator', joinedAt: Date.now() });
          rooms.set(nameplate, room);
          ws.roomCode = nameplate; // 内部仅存 nameplate
          ws.send(JSON.stringify({ type: 'room-created', nameplate }));
          console.log('[room] created nameplate=', nameplate, 'ip=', ws.clientIp);
          break;
        }

        case 'join-room': {
          const blocked = assertIpNotFlooding(ws.clientIp);
          if (!blocked.ok) {
            ws.send(JSON.stringify({ type: 'error', error: blocked.error }));
            return;
          }
          // 客户端只提交 nameplate，不得提交完整口令
          const nameplate = String(msg.nameplate || msg.code || '').trim().toLowerCase();
          const np = nameplate.split('-')[0];
          const room = rooms.get(np);
          const npLimit = assertNameplateJoinAllowed(np);
          if (!npLimit.ok) {
            ws.send(JSON.stringify({ type: 'error', error: npLimit.error }));
            return;
          }
          if (!room) {
            noteJoinFail(ws.clientIp, np);
            ws.send(JSON.stringify({ type: 'error', error: '房间不存在或已过期' }));
            return;
          }
          if (room.clients.size >= 2) {
            noteJoinFail(ws.clientIp, np);
            ws.send(JSON.stringify({ type: 'error', error: '房间已满（仅支持两人）' }));
            return;
          }
          noteJoinSuccess(ws.clientIp);
          room.clients.set(ws, { role: 'joiner', joinedAt: Date.now() });
          ws.roomCode = np;
          ws.send(JSON.stringify({ type: 'room-joined', nameplate: np }));

          for (const [client] of room.clients) {
            if (client.readyState === 1) {
              client.send(JSON.stringify({ type: 'peer-joined' }));
            }
          }
          console.log('[room] joined nameplate=', np, 'ip=', ws.clientIp);
          break;
        }

        case 'signal':
        case 'relay-data':
        case 'pake': {
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
  console.log(`  房间过期:     ${ROOM_TTL_MINUTES} 分钟  (环境变量 ROOM_TTL_MINUTES)`);
  if (TURN_PASS) {
    console.log(`  TURN:         turn:${TURN_HOST}:${TURN_PORT}  user=${TURN_USER}`);
  } else {
    console.log('  TURN:         未启用（请设置 TURN_PASS，并在本机运行 coturn）');
  }
  console.log(`  加入限速:     每名牌 ${JOIN_MAX_FAILS_PER_NAMEPLATE} 次失败 · 每出口IP ${JOIN_MAX_ATTEMPTS_PER_IP} 次尝试 / ${JOIN_RATE_WINDOW_MS/1000}s（适配 VPN SNAT）`);
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
