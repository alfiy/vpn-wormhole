/**
 * VPN-Wormhole Client
 * - Short-code room pairing
 * - PBKDF2 + AES-256-GCM end-to-end encryption
 * - WebRTC DataChannel preferred, encrypted WebSocket relay fallback
 * - Chat + chunked file transfer with integrity check
 */
(() => {
  const $ = (sel) => document.querySelector(sel);
  const lobby = $('#lobby');
  const session = $('#session');
  const createPanel = $('#create-panel');
  const joinPanel = $('#join-panel');
  const codeDisplay = $('#code-display');
  const roomCodeEl = $('#room-code');
  const createStatus = $('#create-status');
  const joinStatus = $('#join-status');
  const createTtl = $('#create-ttl');
  const createTtlCustom = $('#create-ttl-custom');
  const ttlHint = $('#ttl-hint');
  const roomExpireEl = $('#room-expire');
  const transferBanner = $('#transfer-banner');
  const roomTtlText = $('#room-ttl-text');
  const joinCodeInput = $('#join-code');
  const sessionCode = $('#session-code');
  const connStatus = $('#conn-status');
  const chatLog = $('#chat-log');
  const chatInput = $('#chat-input');
  const btnSend = $('#btn-send');
  const fileInput = $('#file-input');
  const fileProgress = $('#file-progress');
  const receivedFiles = $('#received-files');
  const channelType = $('#channel-type');
  const webrtcState = $('#webrtc-state');

  // Web Crypto API 只在安全上下文可用（https:// 或 localhost）
  function ensureCrypto() {
    if (window.crypto && window.crypto.subtle) return true;
    const msg =
      '加密功能需要 HTTPS 安全上下文。\n\n' +
      '请使用 https://服务器IP:3080 访问本服务。\n' +
      '浏览器会提示「证书不受信任」，点击「高级」→「继续访问」即可。\n\n' +
      '当前地址：' + location.href;
    alert(msg);
    return false;
  }

  if (!window.crypto || !window.crypto.subtle) {
    console.warn('[crypto] crypto.subtle 不可用（需要 HTTPS）：', location.href);
  }

  let ws = null;
  let roomCode = null;       // 展示给用户的完整码 = nameplate-password（仅 UI / 复制）
  let nameplate = null;      // 服务端路由 ID（可被服务器知道）
  let pakePassword = null;   // SPAKE2 口令（仅本地，不发送给服务器）
  let idleMinutes = 30;
  let idleUntil = null;
  let expireTimer = null;
  let idleArmed = false; // 双方入房后才开始闲置计时
  let transferBusy = 0;  // >0 表示正在传文件，禁止闲置退出
  let maxTtlMinutes = 1440;
  let defaultTtlMinutes = 30;
  let isCreator = false;
  let cryptoKey = null;
  let pc = null;
  let dataChannel = null;
  let useRelay = false;
  let pendingFiles = new Map();
  // Pending resolvers for create/join responses (avoids race with temporary listeners)
  let pendingCreate = null; // { resolve, reject }
  let pendingJoin = null;

  const CHUNK_SIZE = 64 * 1024; // 64KB 分块，中继/TURN 更稳
  const MAX_FILE_SIZE = 1024 * 1024 * 1024; // 1GB
  // 不再使用公网 STUN。ICE 服务器由 /api/config 下发（VPN 内 TURN）
  let ICE_SERVERS = [];
  let relayReady = false;

  // 口令词表（仅客户端使用，服务端无此逻辑）
  const PAKE_WORDS = [
    '青山','流水','白云','明月','清风','星河','秋水','春山',
    '竹林','松涛','梅花','兰草','菊花','莲叶','梧桐','杨柳',
    '石桥','渔舟','江雪','塞北','江南','雁门','天山','东海',
    '赤壁','玉门','长安','洛阳','钱塘','洞庭','昆仑','太行',
    '晨光','暮色','霜叶','雪原','谷雨','惊蛰','白露','小满',
    '琥珀','青瓷','锦书','玉盘','金风','银汉','丹霞','翠峰'
  ];

  /** 客户端本地生成高熵口令（不经过服务器） */
  function generateLocalPassword() {
    const w1 = PAKE_WORDS[Math.floor(Math.random() * PAKE_WORDS.length)];
    const w2 = PAKE_WORDS[Math.floor(Math.random() * PAKE_WORDS.length)];
    const rnd = new Uint8Array(3);
    crypto.getRandomValues(rnd);
    const hex = Array.from(rnd).map(b => b.toString(16).padStart(2, '0')).join('');
    return `${w1}-${w2}-${hex}`;
  }

  /**
   * 解析用户输入的完整房间码
   * 格式: {nameplate}-{password...}  例如 4821-青山-流水-a1b2c3
   */
  function parseDisplayCode(full) {
    const raw = (full || '').trim().toLowerCase();
    const parts = raw.split('-').filter(Boolean);
    if (parts.length < 2) {
      return { ok: false, error: '房间码格式无效，应为：名牌-口令词-…' };
    }
    const np = parts[0];
    const password = parts.slice(1).join('-');
    if (!/^[a-z0-9]+$/i.test(np) || password.length < 3) {
      return { ok: false, error: '房间码格式无效' };
    }
    return { ok: true, nameplate: np, password, display: `${np}-${password}` };
  }

  // ---------- SPAKE2 PAKE ----------
  // 真正的口令认证密钥交换：短码仅用于 PAKE，会话密钥由协商产生（抗离线字典）
  let keyReadyResolve = null;
  let keyReady = new Promise((resolve) => { keyReadyResolve = resolve; });
  let pakeDone = false;
  let pendingPakeMsg = null; // 若 peer 的 pake 消息先到，先缓存
  let spakeInstance = null;

  let keyConfirmed = false;
  let pendingConfirmMsg = null;

  function markKeyReady() {
    pakeDone = true;
    if (keyReadyResolve) {
      keyReadyResolve();
      keyReadyResolve = null;
    }
  }
  async function waitForKey() {
    if (cryptoKey) return;
    await keyReady;
  }

  function resetKeyReady() {
    pakeDone = false;
    keyConfirmed = false;
    cryptoKey = null;
    pendingPakeMsg = null;
    pendingConfirmMsg = null;
    spakeInstance = null;
    window.__pakeWait = null;
    window.__confirmWait = null;
    keyReady = new Promise((resolve) => { keyReadyResolve = resolve; });
  }

  function randomNonceHex(bytes = 16) {
    const buf = new Uint8Array(bytes);
    crypto.getRandomValues(buf);
    return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * SPAKE2 之后的密钥确认：双方用新密钥加密交换 nonce。
   * 能成功解密对端 confirm = 证明双方持有同一 AES 密钥。
   */
  async function runKeyConfirm() {
    setConnStatus('正在进行密钥确认…');
    const myNonce = randomNonceHex(16);
    console.log('[confirm] sending key-confirm');

    // 通过加密中继发送（此时尚无 DataChannel）
    const sealed = await encrypt({ type: 'key-confirm', nonce: myNonce, side: isCreator ? 'A' : 'B' });
    if (ws && ws.readyState === 1) {
      ws.send(JSON.stringify({ type: 'relay-data', data: sealed }));
    }

    const peerMsg = await new Promise((resolve, reject) => {
      if (pendingConfirmMsg) {
        const m = pendingConfirmMsg;
        pendingConfirmMsg = null;
        resolve(m);
        return;
      }
      const timer = setTimeout(() => reject(new Error('密钥确认超时：双方密钥可能不一致或网络异常')), 12000);
      window.__confirmWait = (msg) => {
        clearTimeout(timer);
        window.__confirmWait = null;
        resolve(msg);
      };
    });

    if (!peerMsg || peerMsg.type !== 'key-confirm' || !peerMsg.nonce) {
      throw new Error('密钥确认失败：无效的对端确认消息');
    }
    if (peerMsg.nonce === myNonce) {
      throw new Error('密钥确认失败：异常的 nonce');
    }

    // 回传 ack（同样加密），便于对端日志与双向确认
    const ackSealed = await encrypt({
      type: 'key-confirm-ack',
      nonce: myNonce,
      peerNonce: peerMsg.nonce
    });
    if (ws && ws.readyState === 1) {
      ws.send(JSON.stringify({ type: 'relay-data', data: ackSealed }));
    }

    keyConfirmed = true;
    console.log('[confirm] key confirmation OK');
  }

  function onKeyConfirmMessage(msg) {
    if (msg.type === 'key-confirm') {
      if (window.__confirmWait) {
        window.__confirmWait(msg);
      } else {
        pendingConfirmMsg = msg;
      }
    }
    // key-confirm-ack 仅作日志
    if (msg.type === 'key-confirm-ack') {
      console.log('[confirm] received ack from peer');
    }
  }

  async function runPAKE() {
    if (cryptoKey && keyConfirmed) return;
    if (typeof SPAKE2 === 'undefined') {
      throw new Error('SPAKE2 库未加载');
    }
    const side = isCreator ? 'A' : 'B';
    console.log('[pake] start SPAKE2 side=', side);
    setConnStatus('正在进行 SPAKE2 密钥协商…');
    if (!pakePassword) throw new Error('缺少本地口令，无法进行 SPAKE2');
    spakeInstance = SPAKE2.create(pakePassword, side);
    const myMsg = await spakeInstance.start();
    const b64 = SPAKE2.bytesToBase64(myMsg);
    if (ws && ws.readyState === 1) {
      ws.send(JSON.stringify({ type: 'pake', data: b64 }));
    }

    // 等待对端 pake 消息
    const peerB64 = await new Promise((resolve, reject) => {
      if (pendingPakeMsg) {
        const m = pendingPakeMsg;
        pendingPakeMsg = null;
        resolve(m);
        return;
      }
      const timer = setTimeout(() => reject(new Error('SPAKE2 协商超时')), 15000);
      window.__pakeWait = (data) => {
        clearTimeout(timer);
        window.__pakeWait = null;
        resolve(data);
      };
    });

    const peerMsg = SPAKE2.base64ToBytes(peerB64);
    const keyMaterial = await spakeInstance.finish(peerMsg);
    cryptoKey = await SPAKE2.keyMaterialToAesGcm(keyMaterial);
    markKeyReady(); // 允许 encrypt/decrypt，供密钥确认使用
    console.log('[pake] SPAKE2 complete, AES key ready');

    await runKeyConfirm();

    setConnStatus('密钥确认完成，正在建立通道…');
    addChat('✅ SPAKE2 协商与密钥确认成功，通信已端到端加密。', false);
  }

  async function onPakeMessage(data) {
    if (window.__pakeWait) {
      window.__pakeWait(data);
    } else {
      pendingPakeMsg = data;
    }
  }

  // 大块二进制安全转 base64（避免 String.fromCharCode(...大数组) 爆栈）
  function u8ToBase64(u8) {
    let s = '';
    const chunk = 0x8000;
    for (let i = 0; i < u8.length; i += chunk) {
      s += String.fromCharCode.apply(null, u8.subarray(i, i + chunk));
    }
    return btoa(s);
  }
  function base64ToU8(b64) {
    const s = atob(b64);
    const u8 = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) u8[i] = s.charCodeAt(i);
    return u8;
  }

  async function encrypt(obj) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plaintext = new TextEncoder().encode(JSON.stringify(obj));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, plaintext);
    return {
      iv: u8ToBase64(iv),
      ct: u8ToBase64(new Uint8Array(ciphertext))
    };
  }

  async function decrypt(payload) {
    const iv = base64ToU8(payload.iv);
    const ct = base64ToU8(payload.ct);
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, cryptoKey, ct);
    return JSON.parse(new TextDecoder().decode(plaintext));
  }

  async function encryptBinary(buffer) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, buffer);
    const out = new Uint8Array(12 + ciphertext.byteLength);
    out.set(iv, 0);
    out.set(new Uint8Array(ciphertext), 12);
    return out;
  }

  async function decryptBinary(data) {
    const iv = data.slice(0, 12);
    const ct = data.slice(12);
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv }, cryptoKey, ct);
  }

  async function sha256(buffer) {
    const hash = await crypto.subtle.digest('SHA-256', buffer);
    return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
  }


  function readCreateTtlMinutes() {
    const sel = createTtl ? createTtl.value : '30';
    let n;
    if (sel === 'custom') {
      n = parseInt(createTtlCustom && createTtlCustom.value, 10);
    } else {
      n = parseInt(sel, 10);
    }
    if (!Number.isFinite(n) || n < 1) n = defaultTtlMinutes;
    if (n > maxTtlMinutes) n = maxTtlMinutes;
    return n;
  }

  function formatRemain(ms) {
    if (ms <= 0) return '即将退出';
    const s = Math.ceil(ms / 1000);
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    if (h > 0) return `无操作 ${h}小时${m}分后退出`;
    if (m > 0) return `无操作 ${m}分${sec}秒后退出`;
    return `无操作 ${sec}秒后退出`;
  }

  function formatTtlLabel(minutes) {
    const n = Number(minutes) || defaultTtlMinutes;
    if (n >= 60 && n % 60 === 0) return n / 60 + ' 小时';
    return n + ' 分钟';
  }

  function updateFooterTtl(minutes) {
    if (roomTtlText) roomTtlText.textContent = formatTtlLabel(minutes);
  }

  function setIdleHint(text) {
    if (roomExpireEl) roomExpireEl.textContent = text || '';
  }

  function formatEta(sec) {
    if (!Number.isFinite(sec) || sec < 0) return '估算中…';
    if (sec < 5) return '即将完成';
    if (sec < 60) return '约 ' + Math.ceil(sec) + ' 秒';
    const m = Math.floor(sec / 60);
    const s = Math.ceil(sec % 60);
    return '约 ' + m + ' 分 ' + s + ' 秒';
  }

  function setTransferBusy(on, detail) {
    transferBusy += on ? 1 : (transferBusy > 0 ? -1 : 0);
    if (transferBusy < 0) transferBusy = 0;
    if (transferBanner) {
      if (transferBusy > 0) {
        transferBanner.textContent = detail || '正在传输文件，请勿刷新或关闭页面。传完前房间不会因闲置退出。';
        transferBanner.classList.remove('hidden');
      } else {
        transferBanner.classList.add('hidden');
      }
    }
    if (transferBusy > 0) bumpIdle(true);
  }

  function bumpIdle(notifyServer) {
    if (!idleArmed || !idleMinutes) return;
    idleUntil = Date.now() + idleMinutes * 60 * 1000;
    if (notifyServer !== false && ws && ws.readyState === 1) {
      try { ws.send(JSON.stringify({ type: 'activity' })); } catch (_) {}
    }
  }

  function armIdleTimer(minutes) {
    if (minutes) idleMinutes = minutes;
    idleArmed = true;
    bumpIdle(true);
    if (expireTimer) clearInterval(expireTimer);
    expireTimer = setInterval(() => {
      if (!idleArmed || !idleUntil) return;
      if (transferBusy > 0) {
        bumpIdle(true);
        setIdleHint('正在传文件，闲置倒计时已暂停');
        return;
      }
      const left = idleUntil - Date.now();
      setIdleHint(formatRemain(left));
      if (left <= 0) {
        clearInterval(expireTimer);
        expireTimer = null;
        idleArmed = false;
        addChat('长时间无聊天或传文件，已自动退出房间。', false);
        if (ws && ws.readyState === 1) {
          try { ws.send(JSON.stringify({ type: 'leave' })); } catch (_) {}
        }
        setTimeout(() => location.reload(), 800);
      }
    }, 1000);
    setIdleHint(formatRemain(idleMinutes * 60 * 1000));
  }

  function showSession(code) {
    lobby.classList.add('hidden');
    session.classList.remove('hidden');
    sessionCode.textContent = code;
    chatInput.disabled = false;
    btnSend.disabled = false;
    // 确保文件选择也可用
    if (fileInput) fileInput.disabled = false;
  }

  function addChat(text, mine = false) {
    const div = document.createElement('div');
    div.className = `chat-msg ${mine ? 'mine' : 'theirs'}`;
    const time = new Date().toLocaleTimeString();
    div.innerHTML = `${escapeHtml(text)}<div class="time">${time}</div>`;
    chatLog.appendChild(div);
    chatLog.scrollTop = chatLog.scrollHeight;
  }

  function escapeHtml(str) {
    return String(str).replace(/[&<>"']/g, m =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m])
    );
  }

  function setConnStatus(text, type = '') {
    connStatus.textContent = text;
    connStatus.className = 'badge ' + type;
  }

  function updateChannelInfo() {
    channelType.textContent = useRelay ? '服务器中继 (加密)' : 'WebRTC P2P';
    webrtcState.textContent = pc ? pc.connectionState : '—';
  }

  function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
  }

  function connectWS() {
    // Reuse existing open connection if available
    if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
      if (ws.readyState === WebSocket.OPEN) return Promise.resolve();
      return new Promise((resolve, reject) => {
        const onOpen = () => { cleanup(); resolve(); };
        const onErr = (e) => { cleanup(); reject(e); };
        const cleanup = () => {
          ws.removeEventListener('open', onOpen);
          ws.removeEventListener('error', onErr);
        };
        ws.addEventListener('open', onOpen);
        ws.addEventListener('error', onErr);
      });
    }

    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = `${proto}//${location.host}`;
    console.log('[ws] connecting to', url);
    ws = new WebSocket(url);

    return new Promise((resolve, reject) => {
      const onOpen = () => {
        cleanup();
        console.log('[ws] connected');
        resolve();
      };
      const onErr = (e) => {
        cleanup();
        console.error('[ws] error', e);
        reject(e || new Error('WebSocket connection failed'));
      };
      const cleanup = () => {
        ws.removeEventListener('open', onOpen);
        ws.removeEventListener('error', onErr);
      };
      ws.addEventListener('open', onOpen);
      ws.addEventListener('error', onErr);

      ws.onclose = () => {
        setConnStatus('连接断开', 'failed');
        console.log('[ws] closed');
      };

      // Single permanent message handler
      ws.onmessage = async (ev) => {
        let msg;
        try {
          msg = JSON.parse(ev.data);
        } catch (e) {
          console.warn('[ws] invalid json', ev.data);
          return;
        }
        console.log('[ws] recv', msg.type, msg.nameplate || msg.code || '');
        await handleServerMessage(msg);
      };
    });
  }

  async function handleServerMessage(msg) {
    switch (msg.type) {
      case 'room-created':
        if (pendingCreate) {
          pendingCreate.resolve(msg);
          pendingCreate = null;
        }
        break;
      case 'room-joined':
        if (pendingJoin) {
          pendingJoin.resolve(msg);
          pendingJoin = null;
        }
        break;
      case 'error':
        if (pendingCreate) {
          pendingCreate.reject(new Error(msg.error || '创建失败'));
          pendingCreate = null;
        }
        if (pendingJoin) {
          pendingJoin.reject(new Error(msg.error || '加入失败'));
          pendingJoin = null;
        }
        createStatus.textContent = msg.error || '';
        createStatus.className = 'status error';
        joinStatus.textContent = msg.error || '';
        joinStatus.className = 'status error';
        break;
      case 'peer-joined':
        setConnStatus('对端已加入，正在协商密钥…');
        addChat('对方已进入房间，开始 SPAKE2 密钥协商…', false);
        armIdleTimer(idleMinutes);
        try {
          await runPAKE();
          await startWebRTC();
        } catch (e) {
          console.error('[pake] failed', e);
          setConnStatus('密钥协商失败', 'failed');
          addChat('密钥协商失败：' + (e.message || e), false);
        }
        break;
      case 'pake':
        // 对端 SPAKE2 消息（明文经服务器转发，不含最终密钥）
        if (msg.data) await onPakeMessage(msg.data);
        break;
      case 'peer-left':
        setConnStatus('对方已离开', 'failed');
        addChat('对方离开了房间。', false);
        cleanupPeer();
        break;
      case 'room-expired':
        alert('房间已过期');
        location.reload();
        break;
      case 'signal':
        try {
          await waitForKey();
          const plain = await decrypt(msg.data);
          await handleSignal(plain);
        } catch (e) {
          console.error('signal decrypt failed', e);
        }
        break;
      case 'relay-data':
        try {
          await waitForKey();
          const plain = await decrypt(msg.data);
          handleIncomingMessage(plain);
        } catch (e) {
          console.error('relay decrypt failed', e);
        }
        break;
      default:
        console.log('[ws] unhandled', msg.type);
    }
  }

  function enableRelay(reason) {
    if (relayReady) return;
    relayReady = true;
    useRelay = true;
    setConnStatus('已连接 (中继)', 'connected');
    updateChannelInfo();
    addChat('✅ ' + (reason || '已启用加密中继通道，可以开始聊天和传文件。'), false);
    chatInput.disabled = false;
    btnSend.disabled = false;
    try { chatInput.focus(); } catch (_) {}
    console.log('[relay] enabled:', reason || 'fallback');
    // 主动发一个中继 hello，确认双向通畅
    sendAppMessage({ type: 'hello', text: 'relay-ready' }).catch(() => {});
  }

  async function startWebRTC() {
    if (pc) return;
    await waitForKey();
    console.log('[webrtc] start, isCreator=', isCreator);

    pc = new RTCPeerConnection({
      iceServers: ICE_SERVERS,
      iceCandidatePoolSize: 4
    });

    pc.onicecandidate = async (ev) => {
      if (ev.candidate) {
        try {
          await sendSignal({
            type: 'candidate',
            candidate: {
              candidate: ev.candidate.candidate,
              sdpMid: ev.candidate.sdpMid,
              sdpMLineIndex: ev.candidate.sdpMLineIndex,
              usernameFragment: ev.candidate.usernameFragment
            }
          });
        } catch (e) {
          console.warn('[webrtc] send candidate failed', e);
        }
      }
    };

    pc.onconnectionstatechange = () => {
      console.log('[webrtc] state=', pc.connectionState);
      updateChannelInfo();
      if (pc.connectionState === 'connected') {
        setConnStatus('已连接 (P2P)', 'connected');
        useRelay = false;
        relayReady = true;
        updateChannelInfo();
      } else if (pc.connectionState === 'failed') {
        enableRelay('P2P 直连失败，已切换到加密中继模式。');
      }
    };

    pc.ondatachannel = (ev) => setupDataChannel(ev.channel);

    // 3 秒内未建立 P2P 则启用中继（局域网 ICE 失败很常见，中继保证可用）
    setTimeout(() => {
      if (!(dataChannel && dataChannel.readyState === 'open')) {
        enableRelay('已启用加密中继通道，可以开始聊天和传文件。');
      }
    }, 3000);

    if (isCreator) {
      dataChannel = pc.createDataChannel('vpn-wormhole', { ordered: true });
      setupDataChannel(dataChannel);
      try {
        const offer = await pc.createOffer();
        await pc.setLocalDescription(offer);
        await sendSignal({
          type: 'offer',
          sdp: { type: pc.localDescription.type, sdp: pc.localDescription.sdp }
        });
        console.log('[webrtc] offer sent');
      } catch (e) {
        console.error('[webrtc] offer failed', e);
        enableRelay('WebRTC 协商失败，已切换到加密中继。');
      }
    }
  }

  function setupDataChannel(channel) {
    dataChannel = channel;
    channel.binaryType = 'arraybuffer';
    channel.onopen = () => {
      useRelay = false;
      relayReady = true;
      setConnStatus('已连接 (P2P)', 'connected');
      updateChannelInfo();
      addChat('安全通道已建立（P2P），可以开始聊天和传文件。', false);
      sendAppMessage({ type: 'hello', text: '通道就绪' });
    };
    channel.onmessage = async (ev) => {
      if (typeof ev.data === 'string') {
        try {
          const sealed = JSON.parse(ev.data);
          const plain = await decrypt(sealed);
          handleIncomingMessage(plain);
        } catch (e) { console.error('DC text error', e); }
      } else {
        try {
          const decrypted = await decryptBinary(new Uint8Array(ev.data));
          handleBinaryChunk(new Uint8Array(decrypted));
        } catch (e) { console.error('DC binary error', e); }
      }
    };
  }

  async function sendSignal(obj) {
    if (!ws || ws.readyState !== 1) return;
    await waitForKey();
    if (!cryptoKey) return;
    const sealed = await encrypt(obj);
    ws.send(JSON.stringify({ type: 'signal', data: sealed }));
  }

  async function handleSignal(msg) {
    if (!pc) await startWebRTC();
    try {
      if (msg.type === 'offer') {
        // JSON 往返后必须重新构造 RTCSessionDescription
        await pc.setRemoteDescription(new RTCSessionDescription(msg.sdp));
        const answer = await pc.createAnswer();
        await pc.setLocalDescription(answer);
        await sendSignal({
          type: 'answer',
          sdp: { type: pc.localDescription.type, sdp: pc.localDescription.sdp }
        });
        console.log('[webrtc] answer sent');
      } else if (msg.type === 'answer') {
        await pc.setRemoteDescription(new RTCSessionDescription(msg.sdp));
        console.log('[webrtc] answer applied');
      } else if (msg.type === 'candidate' && msg.candidate) {
        try {
          await pc.addIceCandidate(new RTCIceCandidate(msg.candidate));
        } catch (e) {
          console.warn('[webrtc] addIceCandidate', e.message || e);
        }
      }
    } catch (e) {
      console.error('[webrtc] handleSignal error', e);
      enableRelay('WebRTC 信令处理失败，已切换到加密中继。');
    }
  }

  async function sendAppMessage(obj) {
    await waitForKey();
    if (!cryptoKey) return;

    const canUseDc = dataChannel && dataChannel.readyState === 'open' && !useRelay;
    if (canUseDc) {
      const sealed = await encrypt(obj);
      dataChannel.send(JSON.stringify(sealed));
      return;
    }

    // 中继路径
    useRelay = true;
    updateChannelInfo();
    const sealed = await encrypt(obj);
    if (ws && ws.readyState === 1) {
      ws.send(JSON.stringify({ type: 'relay-data', data: sealed }));
    }
  }

  function handleIncomingMessage(msg) {
    switch (msg.type) {
      case 'key-confirm':
      case 'key-confirm-ack':
        onKeyConfirmMessage(msg);
        break;
      case 'hello':
        // 对端中继/通道就绪确认
        if (!relayReady) {
          relayReady = true;
          useRelay = true;
          setConnStatus('已连接 (中继)', 'connected');
          updateChannelInfo();
          addChat('✅ 与对方的加密通道已确认，可以发送消息和文件。', false);
          chatInput.disabled = false;
          btnSend.disabled = false;
        }
        break;
      case 'chat':
        addChat(msg.text, false);
        bumpIdle(false);
        break;
      case 'file-meta':
        bumpIdle(false);
        onFileMeta(msg);
        break;
      case 'file-chunk':
        decryptBinary(base64ToU8(msg.data))
          .then(dec => handleBinaryChunk(new Uint8Array(dec)))
          .catch(console.error);
        break;
      case 'file-done':
        bumpIdle(false);
        assembleFile(msg.transferId, msg.hash);
        break;
      default:
        console.log('unknown', msg);
    }
  }

  function sendChat() {
    if (!keyConfirmed) {
      addChat('密钥尚未确认，请稍候…', false);
      return;
    }
    const text = chatInput.value.trim();
    if (!text) return;
    addChat(text, true);
    sendAppMessage({ type: 'chat', text });
    bumpIdle(true);
    chatInput.value = '';
  }

  async function sendFiles(fileList) {
    if (!keyConfirmed) {
      addChat('密钥尚未确认，无法发送文件。', false);
      return;
    }
    bumpIdle(true);
    for (const file of fileList) {
      try {
        if (file.size > MAX_FILE_SIZE) {
          addChat(`文件「${file.name}」超过 1GB 上限（当前 ${formatSize(file.size)}），已跳过。`, false);
          continue;
        }
        if (file.size <= 0) {
          addChat(`文件「${file.name}」为空，已跳过。`, false);
          continue;
        }
        const transferId = crypto.randomUUID();
        const total = Math.max(1, Math.ceil(file.size / CHUNK_SIZE));
        const chunkHashes = [];
        const progressEl = document.createElement('div');
        progressEl.className = 'progress-item';
        progressEl.innerHTML =
          '<div>发送: ' + escapeHtml(file.name) + ' (' + formatSize(file.size) + ')</div>' +
          '<div class="progress-bar"><div style="width:0%"></div></div>' +
          '<div class="eta-text">正在估算剩余时间… 请勿刷新页面</div>';
        fileProgress.appendChild(progressEl);
        const bar = progressEl.querySelector('.progress-bar > div');
        const etaEl = progressEl.querySelector('.eta-text');
        setTransferBusy(true, '正在发送「' + file.name + '」，请勿刷新页面。');
        const t0 = Date.now();

        await sendAppMessage({
          type: 'file-meta',
          transferId,
          name: file.name,
          size: file.size,
          chunks: total,
          hashMode: 'chunk-sha256'
        });

        for (let i = 0; i < total; i++) {
          const start = i * CHUNK_SIZE;
          const end = Math.min(start + CHUNK_SIZE, file.size);
          const chunk = new Uint8Array(await file.slice(start, end).arrayBuffer());
          chunkHashes.push(await sha256(chunk));
          const header = new TextEncoder().encode(JSON.stringify({ transferId, index: i, total }));
          const packed = new Uint8Array(2 + header.length + chunk.byteLength);
          new DataView(packed.buffer).setUint16(0, header.length);
          packed.set(header, 2);
          packed.set(chunk, 2 + header.length);
          const encrypted = await encryptBinary(packed);
          if (dataChannel && dataChannel.readyState === 'open' && !useRelay) {
            while (dataChannel.bufferedAmount > 1024 * 1024) {
              await new Promise(r => setTimeout(r, 30));
            }
            dataChannel.send(encrypted);
          } else {
            await sendAppMessage({
              type: 'file-chunk',
              transferId,
              index: i,
              total,
              data: u8ToBase64(encrypted)
            });
          }
          const pct = Math.round(((i + 1) / total) * 100);
          bar.style.width = pct + '%';
          const elapsed = (Date.now() - t0) / 1000;
          const speed = elapsed > 0.2 ? ((i + 1) * CHUNK_SIZE) / elapsed : 0;
          const remainBytes = file.size - (i + 1) * CHUNK_SIZE;
          const etaSec = speed > 0 ? Math.max(0, remainBytes) / speed : 0;
          if (etaEl) {
            etaEl.textContent = pct >= 100
              ? '发送完成，请勿刷新直至对方收完'
              : ('已用 ' + formatEta(elapsed).replace('约 ', '') + ' · 剩余 ' + formatEta(etaSec) + ' · 请勿刷新页面');
          }
          bumpIdle(true);
        }

        const hash = await sha256(new TextEncoder().encode(chunkHashes.join('')));
        await sendAppMessage({ type: 'file-done', transferId, hash });
        progressEl.querySelector('div').textContent += ' ✓';
        if (etaEl) etaEl.textContent = '已发送完成';
      } catch (e) {
        console.error('send file failed', e);
        addChat('发送失败: ' + (e.message || e), false);
      } finally {
        setTransferBusy(false);
      }
    }
  }

  function onFileMeta(msg) {
    if (msg.size > MAX_FILE_SIZE) {
      addChat('对方发送的文件「' + (msg.name || '') + '」超过 1GB 上限，已拒绝。', false);
      return;
    }
    pendingFiles.set(msg.transferId, {
      name: msg.name,
      size: msg.size,
      hash: msg.hash || '',
      total: msg.chunks || 1,
      parts: new Array(msg.chunks || 1),
      hashes: new Array(msg.chunks || 1),
      received: 0,
      assembling: false
    });
    const el = document.createElement('div');
    el.className = 'progress-item';
    el.id = 'recv-' + msg.transferId;
    el.innerHTML =
      '<div>接收: ' + escapeHtml(msg.name) + ' (' + formatSize(msg.size) + ')</div>' +
      '<div class="progress-bar"><div style="width:0%"></div></div>' +
      '<div class="eta-text">正在接收，请勿刷新页面…</div>';
    fileProgress.appendChild(el);
    const rec = pendingFiles.get(msg.transferId);
    if (rec) rec.startedAt = Date.now();
    setTransferBusy(true, '正在接收「' + msg.name + '」，请勿刷新页面。');
  }

  function handleBinaryChunk(data) {
    if (!(data instanceof Uint8Array)) data = new Uint8Array(data);
    const headerLen = new DataView(data.buffer, data.byteOffset, 2).getUint16(0);
    const header = JSON.parse(new TextDecoder().decode(data.subarray(2, 2 + headerLen)));
    const chunkData = data.slice(2 + headerLen); // copy，避免共享 buffer
    const info = pendingFiles.get(header.transferId);
    if (!info) {
      console.warn('[file] chunk before meta', header.transferId);
      return;
    }
    if (info.parts[header.index]) return;
    info.parts[header.index] = new Blob([chunkData]);
    info.received++;
    const el = document.getElementById('recv-' + header.transferId);
    if (el) {
      const pct = Math.round((info.received / info.total) * 100);
      el.querySelector('.progress-bar > div').style.width = pct + '%';
      const etaEl = el.querySelector('.eta-text');
      if (etaEl && info.startedAt) {
        const elapsed = (Date.now() - info.startedAt) / 1000;
        const speed = elapsed > 0.2 ? (info.received * CHUNK_SIZE) / elapsed : 0;
        const remain = Math.max(0, info.total - info.received) * CHUNK_SIZE;
        const etaSec = speed > 0 ? remain / speed : 0;
        etaEl.textContent = pct >= 100
          ? '接收完成，正在校验…'
          : ('剩余 ' + formatEta(etaSec) + ' · 请勿刷新页面');
      }
    }
    bumpIdle(true);
    sha256(chunkData).then((h) => {
      const cur = pendingFiles.get(header.transferId);
      if (!cur) return;
      cur.hashes[header.index] = h;
    }).catch(console.error);
  }

  async function assembleFile(transferId, expectedHash) {
    const info = pendingFiles.get(transferId);
    if (!info || info.assembling) return;
    info.assembling = true;
    try {
      if (info.received !== info.total) {
        throw new Error('分块不完整 ' + info.received + '/' + info.total);
      }
      for (let i = 0; i < 50 && info.hashes.filter(Boolean).length < info.total; i++) {
        await new Promise(r => setTimeout(r, 20));
      }
      const hash = await sha256(new TextEncoder().encode(info.hashes.join('')));
      if (expectedHash && hash !== expectedHash) {
        addChat('文件 ' + info.name + ' 校验失败！', false);
        pendingFiles.delete(transferId);
        return;
      }
      const blob = new Blob(info.parts);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = info.name;
      a.textContent = '下载 ' + info.name;
      a.className = 'btn secondary small';
      a.style.marginTop = '0.5rem';
      a.onclick = () => setTimeout(() => URL.revokeObjectURL(url), 60000);
      const item = document.createElement('div');
      item.className = 'received-item';
      item.appendChild(a);
      receivedFiles.appendChild(item);
      const el = document.getElementById('recv-' + transferId);
      if (el) el.querySelector('div').textContent += ' ✓ 校验通过';
      addChat('收到文件: ' + info.name, false);
      const etaEl = document.querySelector('#recv-' + transferId + ' .eta-text');
      if (etaEl) etaEl.textContent = '已完成，可以下载';
    } catch (e) {
      console.error('assemble failed', e);
      addChat('文件 ' + (info && info.name) + ' 组装失败', false);
    }
    pendingFiles.delete(transferId);
    setTransferBusy(false);
  }

  function cleanupPeer() {
    if (dataChannel) { try { dataChannel.close(); } catch (_) {} dataChannel = null; }
    if (pc) { try { pc.close(); } catch (_) {} pc = null; }
    updateChannelInfo();
  }

  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      (tab.dataset.tab === 'create' ? createPanel : joinPanel).classList.add('active');
    });
  });

  function refreshLobbyTtlFooter() {
    updateFooterTtl(readCreateTtlMinutes());
  }
  if (createTtl) {
    createTtl.addEventListener('change', () => {
      if (createTtlCustom) {
        if (createTtl.value === 'custom') {
          createTtlCustom.classList.remove('hidden');
          createTtlCustom.focus();
        } else {
          createTtlCustom.classList.add('hidden');
        }
      }
      refreshLobbyTtlFooter();
    });
  }
  if (createTtlCustom) {
    createTtlCustom.addEventListener('input', refreshLobbyTtlFooter);
  }

  $('#btn-create').addEventListener('click', async () => {
    if (!ensureCrypto()) {
      createStatus.textContent = '当前环境不支持加密（请用 HTTPS 访问）';
      createStatus.className = 'status error';
      return;
    }
    createStatus.textContent = '正在创建…';
    createStatus.className = 'status';
    try {
      await connectWS();
      const msg = await new Promise((resolve, reject) => {
        pendingCreate = { resolve, reject };
        setTimeout(() => {
          if (pendingCreate) {
            pendingCreate.reject(new Error('创建超时，请检查网络或刷新页面重试'));
            pendingCreate = null;
          }
        }, 8000);
        const ttlMinutes = readCreateTtlMinutes();
        ws.send(JSON.stringify({ type: 'create-room', ttlMinutes }));
      });

      // 服务端只给 nameplate；口令本地生成，永不上传
      nameplate = msg.nameplate || msg.code;
      if (!nameplate) throw new Error('服务器未返回 nameplate');
      pakePassword = generateLocalPassword();
      roomCode = `${nameplate}-${pakePassword}`;
      isCreator = true;
      resetKeyReady();

      roomCodeEl.textContent = roomCode;
      codeDisplay.classList.remove('hidden');
      createStatus.textContent = '房间已创建。请把完整房间码私下发给对方（服务器看不到口令部分）。';
      createStatus.className = 'status ok';
      showSession(roomCode);
      idleMinutes = msg.idleMinutes || msg.ttlMinutes || defaultTtlMinutes;
      updateFooterTtl(idleMinutes);
      setIdleHint('等待对方加入；加入后无操作 ' + idleMinutes + ' 分钟将退出');
      setConnStatus('等待对方加入…');
      console.log('[room] nameplate=', nameplate, '(password kept local)');
    } catch (e) {
      console.error('create failed', e);
      createStatus.textContent = e.message || '连接服务器失败';
      createStatus.className = 'status error';
    }
  });

  $('#btn-copy').addEventListener('click', () => {
    if (!roomCode) return;
    navigator.clipboard.writeText(roomCode).then(() => {
      $('#btn-copy').textContent = '已复制';
      setTimeout(() => { $('#btn-copy').textContent = '复制'; }, 1500);
    }).catch(() => {
      // fallback
      const ta = document.createElement('textarea');
      ta.value = roomCode;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      $('#btn-copy').textContent = '已复制';
      setTimeout(() => { $('#btn-copy').textContent = '复制'; }, 1500);
    });
  });

  $('#btn-join').addEventListener('click', async () => {
    if (!ensureCrypto()) {
      joinStatus.textContent = '当前环境不支持加密（请用 HTTPS 访问）';
      joinStatus.className = 'status error';
      return;
    }
    const raw = joinCodeInput.value.trim().toLowerCase();
    if (!raw) {
      joinStatus.textContent = '请输入完整房间码';
      joinStatus.className = 'status error';
      return;
    }
    const parsed = parseDisplayCode(raw);
    if (!parsed.ok) {
      joinStatus.textContent = parsed.error;
      joinStatus.className = 'status error';
      return;
    }
    joinStatus.textContent = '正在加入…';
    joinStatus.className = 'status';
    try {
      isCreator = false;
      nameplate = parsed.nameplate;
      pakePassword = parsed.password; // 只留在本地
      roomCode = parsed.display;
      resetKeyReady();

      await connectWS();
      const msg = await new Promise((resolve, reject) => {
        pendingJoin = { resolve, reject };
        setTimeout(() => {
          if (pendingJoin) {
            pendingJoin.reject(new Error('加入超时，请检查房间码或网络'));
            pendingJoin = null;
          }
        }, 8000);
        // 只向服务器提交 nameplate，不提交口令
        ws.send(JSON.stringify({ type: 'join-room', nameplate }));
      });

      if (msg.nameplate) nameplate = msg.nameplate;
      idleMinutes = msg.idleMinutes || msg.ttlMinutes || defaultTtlMinutes;
      updateFooterTtl(idleMinutes);
      joinStatus.textContent = '加入成功';
      joinStatus.className = 'status ok';
      showSession(roomCode);
      if (!pc) {
        setConnStatus('等待通道建立…');
      }
      console.log('[room] joined nameplate=', nameplate, '(password kept local)');
    } catch (e) {
      console.error('join failed', e);
      joinStatus.textContent = e.message || '连接服务器失败';
      joinStatus.className = 'status error';
    }
  });

  joinCodeInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') $('#btn-join').click();
  });
  btnSend.addEventListener('click', sendChat);
  chatInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') sendChat();
  });
  window.addEventListener('beforeunload', (e) => {
    if (transferBusy > 0) {
      e.preventDefault();
      e.returnValue = '文件尚未传完，离开页面会中断传输。';
      return e.returnValue;
    }
  });

  fileInput.addEventListener('change', (e) => {
    if (e.target.files.length) {
      sendFiles(Array.from(e.target.files));
      e.target.value = '';
    }
  });
  $('#btn-leave').addEventListener('click', () => {
    if (ws && ws.readyState === 1) ws.send(JSON.stringify({ type: 'leave' }));
    cleanupPeer();
    location.reload();
  });

  // 从服务端读取房间 TTL + TURN/ICE
  (async () => {
    const el = document.getElementById('room-ttl-text');
    try {
      const res = await fetch('/api/config');
      const cfg = await res.json();
      defaultTtlMinutes = cfg.roomTtlMinutes || 30;
      maxTtlMinutes = cfg.roomTtlMaxMinutes || 1440;
      updateFooterTtl(defaultTtlMinutes);
      if (ttlHint) {
        ttlHint.textContent = `双方加入后，若没有聊天或传文件达到该时长将自动退出（默认 ${defaultTtlMinutes} 分钟，最长 ${maxTtlMinutes} 分钟）。有操作会重新计时。`;
      }
      if (createTtl) {
        const opt = Array.from(createTtl.options).find(o => o.value === String(defaultTtlMinutes));
        if (opt) createTtl.value = String(defaultTtlMinutes);
      }
      if (createTtlCustom) createTtlCustom.max = String(maxTtlMinutes);
      if (Array.isArray(cfg.iceServers) && cfg.iceServers.length) {
        ICE_SERVERS = cfg.iceServers;
        console.log('[ice] TURN enabled', cfg.turnHost + ':' + cfg.turnPort);
      } else {
        ICE_SERVERS = [];
        console.warn('[ice] 未配置 TURN（服务端未设置 TURN_PASS），将仅尝试 host / 加密中继');
      }
    } catch (_) {
      if (el) el.textContent = '30 分钟';
    }
  })();
})();
