# Cloudflare Worker 传输实现（CloudflareTransport）—— 海外/进阶选项

> 定位：v1 方案的完整保留。体验最好（WSS 实时 + 服务端信箱），但受 workers.dev 大陆不可达限制，降级为海外市场主干、大陆用户的进阶选项。

## 1. 组件

- **Worker `twinperch-relay`**（单 TS 脚本）：`GET /ws`（WebSocket 升级）+ 健康检查
- **Durable Object `Room`**（SQLite 后端，免费层必需 `new_sqlite_classes` migration）：

```sql
CREATE TABLE pending (
  id         TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  envelope   BLOB NOT NULL
);
CREATE TABLE room_meta (k TEXT PRIMARY KEY, v TEXT);   -- k_room（房间鉴权用，加密协议 §8）
```

- Hibernation API：无连接时休眠零计费；入站消息唤醒计一次请求。情侣量级（~2000 消息/天 ≈ 2000 请求）远低于免费层 10 万/天。

## 2. WS 协议

```
C→S  {t:"hello",    room: "<room_id_hex>"}
S→C  {t:"challenge", n: "<base64 32B>"}
C→S  {t:"auth",     mac: "<base64 HMAC-SHA256(k_room, n)>"}
S→C  {t:"ok",       backlog: N}
S→C  {t:"msg",      id, env: "<base64 Envelope>"}   // 先重放 backlog，再实时转发
C→S  {t:"ack",      ids: [...]}                      // 删除对应 pending 行
```

- 双方互斥：第二个连接到来时踢掉旧连接（DO 内单活跃连接）
- 离线消息：对端不在线时 insert pending；TTL 14 天，DO alarm 每 6h 清扫

## 3. Worker 只做三件事

1. 校验房间鉴权（HMAC challenge）
2. 转发或暂存 Envelope 字节（Base64 字符串，不解析内容）
3. TTL 清扫 + 调用推送代理（opt-in 用户，见推送代理文档）

## 4. 部署流程（App 内封装，v1 第 4 节的落地版）

已核实：Cloudflare 于 2025 上线自管理 OAuth client（`fundamentals/oauth`），App 内完成授权可行。

1. `ASWebAuthenticationSession` 发起 OAuth（所需 scope：Account:Read、Workers Scripts:Edit）
2. 拿到短效 token 后立即部署：
   - `GET /client/v4/accounts` → account_id
   - `PUT /accounts/{a}/workers/scripts/twinperch-relay`（multipart：main module + metadata，含 `migrations: [new_sqlite_classes]`、DO binding `Room`、vars `PUSH_PROXY_URL` / `PUSH_PROXY_KEY`）
   - `POST /accounts/{a}/workers/scripts/twinperch-relay/subdomain` → 启用 workers.dev 子域
3. 返回 `https://twinperch-relay.<用户子域>.workers.dev`，与 room_id / k_room 一并存入 Vault
4. **OAuth token 用后即焚**：短效（~1h）且无 refresh token，部署完成后不保留——反而成了隐私优点。App 更新需要更新 Worker 脚本时重新走一次授权（UI 文案："升级你的中转站"）
5. 每步失败都有明确文案 + **"改用邮箱连接"降级按钮**（大陆用户在此被自然引导回主干传输）

## 5. Phase 0 必验项

- [ ] 免费账户经 API 部署含 DO migration 的 Worker 全流程
- [ ] OAuth scope 覆盖上述 API（Account:Read + Workers Scripts:Edit 是否足够）
- [ ] 免费层 DO + Hibernation WS 的实际计费行为（入站消息计请求数）

## 6. 后台存活

iOS 后台 WS 会被挂起：回前台立即重连 + `fetchPending` 补账；后台到达依赖推送代理。与邮箱传输一致，无特殊处理。
