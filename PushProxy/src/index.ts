/**
 * twinperch-push-proxy（docs/05-推送代理.md）
 *
 * 开发者运营的唯一组件；opt-in，内容零知识：
 * - 知道：device_id（128-bit 随机数）→ APNs token 映射 + 消息计数
 * - 不知道：消息内容、发送方身份、房间、IP
 *
 * API：
 *   POST /register   {device_id, apns_token, kind}    // App 注册/更新
 *   POST /unregister {device_id}
 *   POST /notify     {device_id, count}               // 仅 relay（x-tp-key）
 *
 * 存储：Workers KV（免费层足够；device_id 是随机数，无隐私聚合价值）。
 */

export interface Env {
  REGISTRATIONS: KVNamespace;
  APNS_KEY_ID: string;
  APNS_TEAM_ID: string;
  APNS_TOKEN_BUNDLE: string; // .p8 私钥 Base64
  APNS_HOST: string;
  PROXY_NOTIFY_KEY: string;
}

interface Registration {
  apns_token: string;
  registered_at: number;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (request.method !== "POST") {
      return new Response("post only", { status: 405 });
    }

    let body: Record<string, unknown>;
    try {
      body = (await request.json()) as Record<string, unknown>;
    } catch {
      return json({ error: "bad json" }, 400);
    }

    const deviceID = typeof body.device_id === "string" ? body.device_id : "";
    if (!/^[a-f0-9]{32}$/.test(deviceID)) {
      return json({ error: "bad device_id" }, 400);
    }

    switch (url.pathname) {
      case "/register": {
        const token = typeof body.apns_token === "string" ? body.apns_token : "";
        if (token.length < 16 || token.length > 256) {
          return json({ error: "bad apns_token" }, 400);
        }
        const reg: Registration = { apns_token: token, registered_at: Date.now() };
        await env.REGISTRATIONS.put(deviceID, JSON.stringify(reg));
        return json({ ok: true });
      }

      case "/unregister": {
        await env.REGISTRATIONS.delete(deviceID);
        return json({ ok: true });
      }

      case "/notify": {
        if (request.headers.get("x-tp-key") !== env.PROXY_NOTIFY_KEY) {
          return json({ error: "forbidden" }, 403);
        }
        const reg = await env.REGISTRATIONS.get(deviceID);
        if (!reg) return json({ ok: true, unknown: true }); // 未注册即忽略
        const token = (JSON.parse(reg) as Registration).apns_token;
        const sent = await sendAPNs(env, token, typeof body.count === "number" ? body.count : 1);
        return json({ ok: sent });
      }

      default:
        return json({ error: "not found" }, 404);
    }
  },
};

/** 固定文案 APNs 推送：不携带任何内容与身份信息。 */
async function sendAPNs(env: Env, token: string, count: number): Promise<boolean> {
  const jwt = await apnsJWT(env);
  const payload = JSON.stringify({
    aps: {
      alert: { title: "双栖", body: "收到新消息" },
      sound: "default",
    },
    n: Math.min(count, 99),
  });
  const resp = await fetch(`${env.APNS_HOST}/3/device/${encodeURIComponent(token)}`, {
    method: "POST",
    headers: {
      authorization: `bearer ${jwt}`,
      "apns-topic": "app.twinperch", // 与 App bundle id 一致
      "apns-push-type": "alert",
      "apns-priority": "10",
      "content-type": "application/json",
    },
    body: payload,
  });
  return resp.status === 200;
}

/** ES256 JWT（APNs token-based auth），缓存到全局减少 .p8 解析与签名次数。 */
let cachedJWT: { value: string; exp: number } | null = null;

async function apnsJWT(env: Env): Promise<string> {
  if (cachedJWT && cachedJWT.exp > Date.now() + 60_000) {
    return cachedJWT.value;
  }
  const header = { alg: "ES256", kid: env.APNS_KEY_ID };
  const claims = { iss: env.APNS_TEAM_ID, iat: Math.floor(Date.now() / 1000) };
  const b64u = (obj: unknown) =>
    btoa(JSON.stringify(obj)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const signingInput = `${b64u(header)}.${b64u(claims)}`;

  const keyB64 = env.APNS_TOKEN_BUNDLE;
  const pem = atob(keyB64);
  const key = await crypto.subtle.importKey(
    "pkcs8",
    pemToPKCS8(pem),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key,
    new TextEncoder().encode(signingInput));
  // JOSE 要求 r‖s 各 32 字节（Web Crypto 返回 ASN.1 DER，需转换）
  const rs = derToRS(new Uint8Array(sig));
  const jwt = `${signingInput}.${bytesB64url(rs)}`;

  cachedJWT = { value: jwt, exp: Date.now() + 30 * 60 * 1000 };
  return jwt;
}

function pemToPKCS8(pem: string): Uint8Array {
  const body = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\s+/g, "");
  return b64ToBytes(body);
}

function bytesB64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** DER ECDSA 签名 → 64 字节 r‖s */
function derToRS(der: Uint8Array): Uint8Array {
  // SEQ { INTEGER r, INTEGER s }
  let idx = 2; // 跳过 0x30 len
  const readInt = (): Uint8Array => {
    const len = der[idx + 1]!;
    let v = der.slice(idx + 2, idx + 2 + len);
    idx += 2 + len;
    if (v.length > 32) v = v.slice(v.length - 32); // 去符号填充
    while (v.length < 32) {
      const padded = new Uint8Array(32);
      padded.set(v, 32 - v.length);
      v = padded;
    }
    return v;
  };
  const r = readInt();
  const s = readInt();
  const out = new Uint8Array(64);
  out.set(r, 0);
  out.set(s, 32);
  return out;
}

function b64ToBytes(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

function json(obj: unknown, status = 200): Response {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json" },
  });
}
