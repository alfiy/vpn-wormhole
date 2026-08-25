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
  let roomCode = null;
  let isCreator = false;
  let cryptoKey = null;
  let pc = null;
  let dataChannel = null;
  let useRelay = false;
  let pendingFiles = new Map();
  // Pending resolvers for create/join responses (avoids race with temporary listeners)
  let pendingCreate = null; // { resolve, reject }
  let pendingJoin = null;

  const CHUNK_SIZE = 32 * 1024;
  // 局域网/VPN 下 host 候选通常最可靠；公网 STUN 作为补充
  const ICE_SERVERS = [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' },
    { urls: 'stun:stun.cloudflare.com:3478' }
  ];
  let relayReady = false;

  async function deriveKey(code) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw', enc.encode(code), 'PBKDF2', false, ['deriveKey']
    );
    // 10 万次迭代：在普通设备上约 100–300ms，安全强度足够短码场景
    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: enc.encode('vpn-wormhole-v1-salt'),
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  // 等待密钥就绪（避免 peer-joined / signal 在密钥派生完成前到达）
  let keyReadyResolve = null;
  const keyReady = new Promise((resolve) => { keyReadyResolve = resolve; });
  function markKeyReady() {
    if (keyReadyResolve) {
      keyReadyResolve();
      keyReadyResolve = null;
    }
  }
  async function waitForKey() {
    if (cryptoKey) return;
    await keyReady;
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
        console.log('[ws] recv', msg.type, msg.code || '');
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
        // 必须等密钥就绪，否则后续加密信令会失败
        await waitForKey();
        setConnStatus('对端已加入，正在建立安全通道…');
        addChat('对方已进入房间，正在协商加密通道…', false);
        await startWebRTC();
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
        break;
      case 'file-meta':
        onFileMeta(msg);
        break;
      case 'file-chunk':
        decryptBinary(base64ToU8(msg.data))
          .then(dec => handleBinaryChunk(new Uint8Array(dec)))
          .catch(console.error);
        break;
      case 'file-done':
        break;
      default:
        console.log('unknown', msg);
    }
  }

  function sendChat() {
    const text = chatInput.value.trim();
    if (!text) return;
    addChat(text, true);
    sendAppMessage({ type: 'chat', text });
    chatInput.value = '';
  }

  async function sendFiles(fileList) {
    for (const file of fileList) {
      const transferId = crypto.randomUUID();
      const arrayBuffer = await file.arrayBuffer();
      const hash = await sha256(arrayBuffer);
      const progressEl = document.createElement('div');
      progressEl.className = 'progress-item';
      progressEl.innerHTML = `
        <div>发送: ${escapeHtml(file.name)} (${formatSize(file.size)})</div>
        <div class="progress-bar"><div style="width:0%"></div></div>`;
      fileProgress.appendChild(progressEl);
      const bar = progressEl.querySelector('.progress-bar > div');
      await sendAppMessage({
        type: 'file-meta', transferId, name: file.name, size: file.size, hash,
        chunks: Math.ceil(file.size / CHUNK_SIZE)
      });
      const total = Math.ceil(file.size / CHUNK_SIZE);
      for (let i = 0; i < total; i++) {
        const start = i * CHUNK_SIZE;
        const end = Math.min(start + CHUNK_SIZE, file.size);
        const chunk = arrayBuffer.slice(start, end);
        const header = new TextEncoder().encode(JSON.stringify({ transferId, index: i, total }));
        const headerLen = new Uint8Array(2);
        new DataView(headerLen.buffer).setUint16(0, header.length);
        const payload = new Uint8Array(2 + header.length + chunk.byteLength);
        payload.set(headerLen, 0);
        payload.set(header, 2);
        payload.set(new Uint8Array(chunk), 2 + header.length);
        const encrypted = await encryptBinary(payload);
        if (dataChannel && dataChannel.readyState === 'open' && !useRelay) {
          while (dataChannel.bufferedAmount > 2 * 1024 * 1024) {
            await new Promise(r => setTimeout(r, 40));
          }
          dataChannel.send(encrypted);
        } else {
          const b64 = u8ToBase64(encrypted);
          await sendAppMessage({ type: 'file-chunk', transferId, index: i, total, data: b64 });
        }
        bar.style.width = Math.round(((i + 1) / total) * 100) + '%';
      }
      await sendAppMessage({ type: 'file-done', transferId, hash });
      progressEl.querySelector('div').textContent += ' ✓';
    }
  }

  function onFileMeta(msg) {
    pendingFiles.set(msg.transferId, {
      name: msg.name, size: msg.size, hash: msg.hash,
      total: msg.chunks, chunks: new Array(msg.chunks), received: 0
    });
    const el = document.createElement('div');
    el.className = 'progress-item';
    el.id = `recv-${msg.transferId}`;
    el.innerHTML = `
      <div>接收: ${escapeHtml(msg.name)} (${formatSize(msg.size)})</div>
      <div class="progress-bar"><div style="width:0%"></div></div>`;
    fileProgress.appendChild(el);
  }

  function handleBinaryChunk(data) {
    const headerLen = new DataView(data.buffer, data.byteOffset, 2).getUint16(0);
    const headerBytes = data.slice(2, 2 + headerLen);
    const header = JSON.parse(new TextDecoder().decode(headerBytes));
    const chunkData = data.slice(2 + headerLen);
    const info = pendingFiles.get(header.transferId);
    if (!info) return;
    info.chunks[header.index] = chunkData;
    info.received++;
    const el = document.getElementById(`recv-${header.transferId}`);
    if (el) {
      el.querySelector('.progress-bar > div').style.width =
        Math.round((info.received / info.total) * 100) + '%';
    }
    if (info.received === info.total) assembleFile(header.transferId);
  }

  async function assembleFile(transferId) {
    const info = pendingFiles.get(transferId);
    if (!info) return;
    let totalLen = 0;
    for (const c of info.chunks) totalLen += c.byteLength;
    const full = new Uint8Array(totalLen);
    let offset = 0;
    for (const c of info.chunks) {
      full.set(c, offset);
      offset += c.byteLength;
    }
    const hash = await sha256(full.buffer);
    if (hash !== info.hash) {
      addChat(`文件 ${info.name} 校验失败！`, false);
      return;
    }
    const blob = new Blob([full]);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = info.name;
    a.textContent = `下载 ${info.name}`;
    a.className = 'btn secondary small';
    a.style.marginTop = '0.5rem';
    a.onclick = () => setTimeout(() => URL.revokeObjectURL(url), 15000);
    const item = document.createElement('div');
    item.className = 'received-item';
    item.appendChild(a);
    receivedFiles.appendChild(item);
    const el = document.getElementById(`recv-${transferId}`);
    if (el) el.querySelector('div').textContent += ' ✓ 校验通过';
    pendingFiles.delete(transferId);
    addChat(`收到文件: ${info.name}`, false);
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
        ws.send(JSON.stringify({ type: 'create-room' }));
      });

      roomCode = msg.code;
      isCreator = true;
      createStatus.textContent = '正在派生加密密钥…';
      cryptoKey = await deriveKey(roomCode);
      markKeyReady();

      roomCodeEl.textContent = roomCode;
      codeDisplay.classList.remove('hidden');
      createStatus.textContent = '房间已创建，等待对方加入…';
      createStatus.className = 'status ok';
      showSession(roomCode);
      setConnStatus('等待对方加入…');
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
    const code = joinCodeInput.value.trim().toLowerCase();
    if (!code) {
      joinStatus.textContent = '请输入房间码';
      joinStatus.className = 'status error';
      return;
    }
    joinStatus.textContent = '正在派生加密密钥…';
    joinStatus.className = 'status';
    try {
      // 加入方在发 join 之前就知道房间码，先派生密钥，避免 peer-joined / signal 抢跑
      isCreator = false;
      roomCode = code;
      cryptoKey = await deriveKey(code);
      markKeyReady();

      joinStatus.textContent = '正在加入…';
      await connectWS();
      const msg = await new Promise((resolve, reject) => {
        pendingJoin = { resolve, reject };
        setTimeout(() => {
          if (pendingJoin) {
            pendingJoin.reject(new Error('加入超时，请检查房间码或网络'));
            pendingJoin = null;
          }
        }, 8000);
        ws.send(JSON.stringify({ type: 'join-room', code }));
      });

      roomCode = msg.code || code;
      joinStatus.textContent = '加入成功';
      joinStatus.className = 'status ok';
      showSession(roomCode);
      // 不在这里写死「等待通道建立」，由 peer-joined / WebRTC 状态更新
      // 若 peer-joined 已在密钥就绪后处理过，状态会是「正在建立安全通道」
      if (!pc) {
        setConnStatus('等待通道建立…');
      }
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
})();
