/**
 * twinperch-relay：情侣专属的密文中转站（docs/04-传输-Cloudflare.md）。
 *
 * 设计红线：
 * - 只搬运 Envelope 字节（Base64 字符串），不解析、不解密、不持久化任何明文
 * - 房间鉴权：HMAC-SHA256 挑战应答（k_room 由握手派生，Worker 仅能用于鉴权，无法解密内容）
 * - 离线信箱：SQLite 暂存，ACK 后删除，TTL 14 天由 alarm 清扫
 * - Hibernation：无消息时休眠零计费（见 room.ts）
 *
 * 部署：App 通过 Cloudflare API 完成（docs/04 §4），OAuth token 用后即焚。
 * room_meta 表由客户端在首次连接后经 API 写入 k_room / device_id——
 * 更简单的方案见 README 的"部署后配置"：部署脚本把 k_room 一并写入 DO 存储。
 */

import { Room, type Env } from "./room";

export { Room };

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return new Response("ok", { status: 200 });
    }

    // 部署后一次性写入房间元数据（k_room / device_id），x-tp-deploy-key 防护。
    // 泄露影响面 = 该情侣自己的中转站可被重置（DoS），不涉及任何内容解密。
    if (url.pathname === "/bootstrap" && request.method === "POST") {
      if (!env.DEPLOY_KEY || request.headers.get("x-tp-deploy-key") !== env.DEPLOY_KEY) {
        return new Response("forbidden", { status: 403 });
      }
      const body = (await request.json()) as { room: string; k_room: string; device_id?: string };
      if (!body.room || !body.k_room) {
        return new Response("bad request", { status: 400 });
      }
      const id = env.ROOM.idFromName(body.room);
      const stub = env.ROOM.get(id);
      return stub.fetch(new Request("https://internal/bootstrap", {
        method: "POST",
        body: JSON.stringify(body),
      }));
    }

    if (url.pathname === "/ws") {
      const roomID = url.searchParams.get("room");
      if (!roomID || roomID.length < 16) {
        return new Response("bad room", { status: 400 });
      }
      const id = env.ROOM.idFromName(roomID);
      const stub = env.ROOM.get(id);
      return stub.fetch(request);
    }

    return new Response("not found", { status: 404 });
  },
};
