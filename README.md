# VPN-Wormhole

类似 Magic-Wormhole 的 **B/S 端到端加密** 文件传输 + 实时对话模块，面向 OpenVPN / 局域网场景。

一台服务器部署本服务，其他终端浏览器打开 `https://服务器IP:3080` 即可创建/加入房间，完成加密聊天与文件传输。

## 为什么必须是 HTTPS？

浏览器规定：只有 **HTTPS**（或 localhost）下才能使用 Web Crypto API（`crypto.subtle`）。  
因此本服务**默认启用 HTTPS**，并在首次启动时自动生成自签名证书。

## 快速开始

```bash
cd vpn-wormhole
npm install          # 仅依赖 ws
npm start            # 默认 https://0.0.0.0:3080 ，房间 30 分钟过期
```

自定义房间过期时间（单位：分钟）：

```bash
ROOM_TTL_MINUTES=5 npm start     # 5 分钟
ROOM_TTL_MINUTES=10 npm start    # 10 分钟
ROOM_TTL_MINUTES=60 npm start    # 60 分钟
```

也可在 systemd / Docker 里用环境变量 `ROOM_TTL_MINUTES` 配置。  
启动后终端会打印当前过期时间与访问地址。

### 客户端怎么用

1. 在任意一台能访问服务器的机器上，浏览器打开：  
   **`https://服务器IP:3080`**
2. 浏览器提示「证书不受信任 / 连接不是私密连接」：  
   - Chrome：点击「高级」→「继续前往 xxx（不安全）」  
   - Firefox：点「高级」→「接受风险并继续」
3. 之后即可正常「生成房间码 / 加入房间」，端到端加密可用。

> 同一台机器也可以用 `https://127.0.0.1:3080`。

可选：`http://服务器IP:3081` 会显示一个提示页，引导你改用 HTTPS。

## 功能

- 无账号短码配对（如 `7-apple-river`）
- **SPAKE2 PAKE** + AES-256-GCM 端到端加密（短码用于口令认证密钥交换，抗离线字典攻击）
- 优先 WebRTC P2P，失败自动切加密中继
- 实时聊天 + 分块文件传输 + SHA-256 校验
- 房间自动过期（默认 30 分钟，可用环境变量 `ROOM_TTL_MINUTES` 配置），仅支持两人

## 证书说明

首次启动会在 `certs/` 目录生成：

- `key.pem`
- `cert.pem`

自签名证书仅用于内网/VPN，有效期约 2 年。  
如需重新生成，删除 `certs/` 目录后重启服务即可。

## 目录结构

```
vpn-wormhole/
├── package.json
├── server.js          # HTTPS 信令服务器（自动生成证书）
├── certs/             # 自签名证书（自动生成）
├── public/
│   ├── index.html
│   ├── style.css
│   └── app.js
├── test/
│   └── crypto-test.js
└── README.md
```

## 测试

```bash
npm test
```

## License

MIT


## 安全模型（SPAKE2）

两端共享房间短码后，通过 **SPAKE2**（RFC 9382 风格，2048-bit MODP 群）协商会话密钥：

1. 创建方为 SPAKE2 角色 A，加入方为角色 B  
2. 各生成一轮 PAKE 消息，经服务器**明文转发**（服务器无法从中算出会话密钥）  
3. 双方得到相同的高熵密钥材料，再经 HKDF 得到 AES-256-GCM 密钥  
4. 之后聊天 / 文件 / WebRTC 信令均使用该密钥加密  

相比「短码 → PBKDF2 → 密钥」，被动窃听者无法对密文做高效离线穷举短码；主动攻击者每次只能在线尝试一次。

实现见 `public/spake2.js`（纯 JS/BigInt，无额外 npm 依赖）。