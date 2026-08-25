# VPN-Wormhole

类似 Magic-Wormhole 的 **B/S 架构** 端到端加密文件传输 + 实时对话模块，专为 **OpenVPN 等私有网络** 场景优化。

两个用户先通过 OpenVPN 客户端接入同一 VPN，然后在浏览器中打开本服务，用短码配对后即可安全聊天和传文件。

## 特性

- **无账号**：短码（如 `7-apple-river`）配对
- **端到端加密**：AES-256-GCM，密钥由短码通过 PBKDF2（21 万次迭代）派生，服务器看不到明文
- **优先 WebRTC P2P**：VPN 内网直连成功率高；失败时自动 fallback 到服务器加密中继
- **实时聊天 + 分块文件传输**：多文件、进度条、SHA-256 完整性校验
- **房间自动过期**：默认 30 分钟
- **依赖极简**：仅需一个轻量 `ws` 包

## 快速开始

```bash
cd vpn-wormhole
npm install          # 仅安装 ws
npm start            # 默认监听 0.0.0.0:3080
```

访问：
- 本机：http://localhost:3080
- VPN 内网：http://你的VPN内网IP:3080

### 使用流程

1. 用户 A 点击「生成房间码」，得到类似 `7-apple-river` 的短码
2. **通过电话 / 短信 / 当面等安全渠道**把短码告诉用户 B
3. 用户 B 输入短码加入
4. 双方建立加密通道后即可聊天或选择文件发送
5. 文件在接收端自动校验并提供下载链接

## 安全说明

| 项目 | 说明 |
|------|------|
| 密钥派生 | PBKDF2-SHA256，固定盐 + 21 万次迭代 |
| 传输加密 | 聊天与文件均使用 AES-GCM（随机 IV） |
| 服务器角色 | 仅做信令转发与可选中继，无法解密内容 |
| 短码保护 | 短码是唯一共享秘密，务必安全传递；房间短时有效 |

当前使用强 PBKDF2 而非完整 SPAKE2/CPace。后续可替换为真正的 PAKE。

## 目录结构

```
vpn-wormhole/
├── package.json
├── server.js          # 纯 Node + ws 信令服务器
├── public/
│   ├── index.html
│   ├── style.css
│   └── app.js         # 前端（WebRTC + 加密 + UI）
├── test/
│   └── crypto-test.js
└── README.md
```

## 测试

```bash
npm test   # 密钥派生与加解密单元测试
```

手动测试：两个浏览器标签页（或两台已连同一 VPN 的设备）分别创建/加入同一房间码。

## 部署建议（OpenVPN）

1. 将服务运行在 VPN 服务器或同一网段机器上
2. 可选用 systemd / Docker 守护
3. VPN 内网可用 HTTP；若暴露公网请加 HTTPS
4. 防火墙最好只允许 VPN 网段访问 3080

## License

MIT
