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
  const ICE_SERVERS = [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' }
  ];

  async function deriveKey(code) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw', enc.encode(code), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: enc.encode('vpn-wormhole-v1-salt'),
        iterations: 210000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function encrypt(obj) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plaintext = new TextEncoder().encode(JSON.stringify(obj));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, plaintext);
    return {
      iv: btoa(String.fromCharCode(...iv)),
      ct: btoa(String.fromCharCode(...new Uint8Array(ciphertext)))
    };
  }

  async function decrypt(payload) {
    const iv = Uint8Array.from(atob(payload.iv), c => c.charCodeAt(0));
    const ct = Uint8Array.from(atob(payload.ct), c => c.charCodeAt(0));
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
          const plain = await decrypt(msg.data);
          await handleSignal(plain);
        } catch (e) {
          console.error('signal decrypt failed', e);
        }
        break;
      case 'relay-data':
        try {
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

  async function startWebRTC() {
    if (pc) return;
    pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });
    pc.onicecandidate = async (ev) => {
      if (ev.candidate) await sendSignal({ type: 'candidate', candidate: ev.candidate });
    };
    pc.onconnectionstatechange = () => {
      updateChannelInfo();
      if (pc.connectionState === 'connected') {
        setConnStatus('已连接 (P2P)', 'connected');
        useRelay = false;
        updateChannelInfo();
      } else if (pc.connectionState === 'failed' || pc.connectionState === 'disconnected') {
        setTimeout(() => {
          if (pc && (pc.connectionState === 'failed' || pc.connectionState === 'disconnected')) {
            useRelay = true;
            setConnStatus('已连接 (中继)', 'connected');
            updateChannelInfo();
            addChat('P2P 直连失败，已切换到加密中继模式。', false);
          }
        }, 4000);
      }
    };
    pc.ondatachannel = (ev) => setupDataChannel(ev.channel);
    if (isCreator) {
      dataChannel = pc.createDataChannel('vpn-wormhole', { ordered: true });
      setupDataChannel(dataChannel);
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      await sendSignal({ type: 'offer', sdp: pc.localDescription });
    }
  }

  function setupDataChannel(channel) {
    dataChannel = channel;
    channel.binaryType = 'arraybuffer';
    channel.onopen = () => {
      useRelay = false;
      setConnStatus('已连接 (P2P)', 'connected');
      updateChannelInfo();
      addChat('安全通道已建立，可以开始聊天和传文件。', false);
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
    if (!cryptoKey || !ws || ws.readyState !== 1) return;
    const sealed = await encrypt(obj);
    ws.send(JSON.stringify({ type: 'signal', data: sealed }));
  }

  async function handleSignal(msg) {
    if (!pc) await startWebRTC();
    if (msg.type === 'offer') {
      await pc.setRemoteDescription(msg.sdp);
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      await sendSignal({ type: 'answer', sdp: pc.localDescription });
    } else if (msg.type === 'answer') {
      await pc.setRemoteDescription(msg.sdp);
    } else if (msg.type === 'candidate') {
      try { await pc.addIceCandidate(msg.candidate); } catch (e) { console.warn(e); }
    }
  }

  async function sendAppMessage(obj) {
    if (!cryptoKey) return;
    if (dataChannel && dataChannel.readyState === 'open' && !useRelay) {
      const sealed = await encrypt(obj);
      dataChannel.send(JSON.stringify(sealed));
    } else {
      useRelay = true;
      updateChannelInfo();
      const sealed = await encrypt(obj);
      if (ws && ws.readyState === 1) {
        ws.send(JSON.stringify({ type: 'relay-data', data: sealed }));
      }
    }
  }

  function handleIncomingMessage(msg) {
    switch (msg.type) {
      case 'hello': break;
      case 'chat': addChat(msg.text, false); break;
      case 'file-meta': onFileMeta(msg); break;
      case 'file-chunk':
        decryptBinary(Uint8Array.from(atob(msg.data), c => c.charCodeAt(0)))
          .then(dec => handleBinaryChunk(new Uint8Array(dec)))
          .catch(console.error);
        break;
      case 'file-done': break;
      default: console.log('unknown', msg);
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
          const b64 = btoa(String.fromCharCode(...encrypted));
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
      createStatus.textContent = '当前环境不支持加密（请用 localhost 或 HTTPS 访问）';
      createStatus.className = 'status error';
      return;
    }
    createStatus.textContent = '正在创建…';
    createStatus.className = 'status';
    try {
      await connectWS();
      // Wait for room-created (or error) via the permanent handler
      const msg = await new Promise((resolve, reject) => {
        pendingCreate = { resolve, reject };
        // Safety timeout
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
      cryptoKey = await deriveKey(roomCode);
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
      joinStatus.textContent = '当前环境不支持加密（请用 localhost 或 HTTPS 访问）';
      joinStatus.className = 'status error';
      return;
    }
    const code = joinCodeInput.value.trim().toLowerCase();
    if (!code) {
      joinStatus.textContent = '请输入房间码';
      joinStatus.className = 'status error';
      return;
    }
    joinStatus.textContent = '正在加入…';
    joinStatus.className = 'status';
    try {
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

      roomCode = msg.code;
      isCreator = false;
      cryptoKey = await deriveKey(roomCode);
      joinStatus.textContent = '加入成功';
      joinStatus.className = 'status ok';
      showSession(roomCode);
      setConnStatus('等待通道建立…');
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
