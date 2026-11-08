/**
 * Room：每对情侣一个 Durable Object（SQLite 后端 + WebSocket Hibernation）。
 *
 * 使用 Hibernation API 是成本模型的前提（docs/00 §1、docs/04 §1）：
 * 无消息时 DO 休眠不计费，每条入站消息唤醒一次计一次请求。
 * 因此连接状态不驻内存：challenge/鉴权进度走 serializeAttachment，
 * 在线连接列表走 state.getWebSockets()。
 *
 * WS 协议（docs/04 §2）：
 *   S→C {t:"challenge", n}           —— accept 后立即下发
 *   C→S {t:"auth", mac}              —— HMAC-SHA256(k_room, n)，Base64
 *   S→C {t:"ok", backlog}
 *   C→S {t:"send", id, env}          —— 发送（id 为客户端生成的 UUID）
 *   S→C {t:"msg", id, env}           —— 对端在线实时转发；不在线入信箱
 *   C→S {t:"ack", ids}               —— 确认，删除信箱行
 */

const TTL_MS = 14 * 24 * 3600 * 1000; // 离线信箱保留 14 天
const SWEEP_INTERVAL_MS = 6 * 3600 * 1000;
const MAX_WEBSOCKETS = 2; // 双方各一条；超出说明有僵尸

interface ConnAttachment {
  authenticated: boolean;
  challenge: string | null;
}

type ServerFrame =
  | { t: "challenge"; n: string }
  | { t: "ok"; backlog: number }
  | { t: "msg"; id: string; env: string }
  | { t: "bye"; why: string };

type ClientFrame =
  | { t: "hello"; room: string }
  | { t: "auth"; mac: string }
  | { t: "send"; id: string; env: string }
  | { t: "ack"; ids: string[] };

export interface Env {
  ROOM: DurableObjectNamespace;
  PUSH_PROXY_URL: string;
  PUSH_PROXY_KEY: string;
  DEPLOY_KEY: string;
}

export class Room {
  private readonly state: DurableObjectState;
  private readonly sql: SqlStorage;
  private readonly env: Env;

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
    this.sql = state.storage.sql;
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS pending (
        id TEXT PRIMARY KEY,
        created_at INTEGER NOT NULL,
        envelope TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS room_meta (k TEXT PRIMARY KEY, v TEXT);
    `);
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/bootstrap") {
      const body = (await request.json()) as { k_room: string; device_id?: string };
      this.sql.exec("INSERT OR REPLACE INTO room_meta (k, v) VALUES ('k_room', ?)", body.k_room);
      if (body.device_id) {
        this.sql.exec("INSERT OR REPLACE INTO room_meta (k, v) VALUES ('device_id', ?)", body.device_id);
      }
      return new Response("ok", { status: 200 });
    }
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("websocket required", { status: 426 });
    }
    const pair = new WebSocketPair();
    const server = pair[1];

    // 防僵尸：超过上限时挤掉最早的一条
    const existing = this.state.getWebSockets();
    if (existing.length >= MAX_WEBSOCKETS) {
      const zombie = existing[0];
      try {
        zombie.send(JSON.stringify({ t: "bye", why: "superseded" } satisfies ServerFrame));
        zombie.close(4001, "superseded");
      } catch {
        // 已死连接忽略
      }
    }

    server.accept();
    const challenge = bytesToB64(crypto.getRandomValues(new Uint8Array(32)));
    const attachment: ConnAttachment = { authenticated: false, challenge };
    server.serializeAttachment(attachment);
    this.state.acceptWebSocket(server);
    server.send(JSON.stringify({ t: "challenge", n: challenge } satisfies ServerFrame));

    void this.sweepExpired();
    const alarm = await this.state.storage.getAlarm();
    if (alarm === null) {
      await this.state.storage.setAlarm(Date.now() + SWEEP_INTERVAL_MS);
    }
    return new Response(null, { status: 101, webSocket: pair[0] });
  }

  // ---------- Hibernation 回调 ----------

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    if (typeof message !== "string") {
      ws.close(4002, "text only");
      return;
    }
    let frame: ClientFrame;
    try {
      frame = JSON.parse(message) as ClientFrame;
    } catch {
      ws.close(4002, "bad json");
      return;
    }

    const attachment = (ws.deserializeAttachment() as ConnAttachment | null) ?? {
      authenticated: false,
      challenge: null,
    };

    switch (frame.t) {
      case "hello":
        return; // 挑战已在 accept 时下发

      case "auth": {
        const ok = await this.verifyAuth(frame.mac, attachment.challenge ?? "");
        attachment.challenge = null;
        if (!ok) {
          ws.close(4003, "auth failed");
          return;
        }
        attachment.authenticated = true;
        ws.serializeAttachment(attachment);
        const count = Number(
          (this.sql.exec("SELECT COUNT(*) AS c FROM pending").one() as { c: number }).c,
        );
        ws.send(JSON.stringify({ t: "ok", backlog: count } satisfies ServerFrame));
        await this.replayBacklog(ws);
        return;
      }

      case "send": {
        if (!attachment.authenticated) {
          ws.close(4003, "not authenticated");
          return;
        }
        await this.route(ws, frame.id, frame.env);
        return;
      }

      case "ack": {
        if (!attachment.authenticated) {
          ws.close(4003, "not authenticated");
          return;
        }
        for (const id of frame.ids) {
          this.sql.exec("DELETE FROM pending WHERE id = ?", id);
        }
        return;
      }
    }
  }

  async webSocketClose(_ws: WebSocket, _code: number, _reason: string): Promise<void> {
    // Hibernation API 自动清理；无需显式处理
  }

  // ---------- 消息路由 ----------

  private async route(sender: WebSocket, id: string, envelope: string): Promise<void> {
    let delivered = false;
    for (const peer of this.state.getWebSockets()) {
      if (peer === sender) continue;
      const attachment = peer.deserializeAttachment() as ConnAttachment | null;
      if (attachment?.authenticated) {
        peer.send(JSON.stringify({ t: "msg", id, env: envelope } satisfies ServerFrame));
        delivered = true;
      }
    }
    if (!delivered) {
      // 离线信箱：ACK 后删除，TTL 14 天
      this.sql.exec("INSERT OR REPLACE INTO pending (id, created_at, envelope) VALUES (?, ?, ?)",
        id, Date.now(), envelope);
      await this.notifyPushProxy();
    }
  }

  private async replayBacklog(ws: WebSocket): Promise<void> {
    const rows = this.sql
      .exec("SELECT id, envelope FROM pending ORDER BY created_at ASC")
      .toArray() as { id: string; envelope: string }[];
    for (const row of rows) {
      ws.send(JSON.stringify({ t: "msg", id: row.id, env: row.envelope } satisfies ServerFrame));
    }
  }

  // ---------- 定时清扫 ----------

  async alarm(): Promise<void> {
    await this.sweepExpired();
    await this.state.storage.setAlarm(Date.now() + SWEEP_INTERVAL_MS);
  }

  private async sweepExpired(): Promise<void> {
    this.sql.exec("DELETE FROM pending WHERE created_at < ?", Date.now() - TTL_MS);
  }

  // ---------- 鉴权与辅助 ----------

  private async verifyAuth(mac: string, challengeB64: string): Promise<boolean> {
    if (!challengeB64) return false;
    const keyB64 = this.getMeta("k_room");
    if (!keyB64) return false;
    let got: Uint8Array;
    try {
      got = b64ToBytes(mac);
    } catch {
      return false;
    }
    const cryptoKey = await crypto.subtle.importKey("raw", b64ToBytes(keyB64) as BufferSource,
      { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const expected = new Uint8Array(
      await crypto.subtle.sign("HMAC", cryptoKey, b64ToBytes(challengeB64) as BufferSource),
    );
    if (got.length !== expected.length) return false;
    let diff = 0;
    for (let i = 0; i < got.length; i++) diff |= got[i]! ^ expected[i]!;
    return diff === 0;
  }

  private getMeta(k: string): string | null {
    const row = this.sql.exec("SELECT v FROM room_meta WHERE k = ?", k).one() as { v: string } | null;
    return row?.v ?? null;
  }

  /** opt-in 推送：仅上报"有新消息"（随机 device_id + 计数），无任何内容。 */
  private async notifyPushProxy(): Promise<void> {
    if (!this.env.PUSH_PROXY_URL || !this.env.PUSH_PROXY_KEY) return;
    const deviceID = this.getMeta("device_id");
    if (!deviceID) return;
    try {
      await fetch(`${this.env.PUSH_PROXY_URL}/notify`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-tp-key": this.env.PUSH_PROXY_KEY },
        body: JSON.stringify({ device_id: deviceID, count: 1 }),
      });
    } catch {
      // 推送失败不影响投递
    }
  }
}

function bytesToB64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function b64ToBytes(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}
