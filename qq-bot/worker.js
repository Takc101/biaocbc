/**
 * ============================================================
 *  QQ 一键注册 · 绑定服务（Cloudflare Worker）
 * ============================================================
 *
 * 作用：把 QQ 群机器人变成表白墙网站的「一键注册」通道。
 *
 *   网站(浏览器)                    Worker(本文件)                 QQ 开放平台
 *   ───────────                   ──────────────                 ───────────
 *   点「QQ 一键注册」      →   POST /api/bind/start   →   生成 6 位验证码
 *   展示验证码 + 添加机器人入口                                          │
 *                                  ← 返回 {code, shareUrl, botName}  ←┘
 *                                        │
 *   用户在 QQ 里 @机器人 发验证码 ──→ WebHook /qq/callback（ed25519 验签）
 *                                        │ 匹配验证码 → 记录 openid
 *   轮询 GET /api/bind/status   ←   返回 {status:"bound", openid}
 *                                        │
 *   用 openid 注册/登录（写入 data.json）
 *
 * 安全设计：
 *   - 所有来自 QQ 的事件都做 ed25519 签名校验，伪造事件无法绑定
 *   - AppSecret 只存在于 Worker 的 secrets，不出现在浏览器和 data.json
 *   - 验证码 6 位（约 8.8 亿组合），10 分钟有效，一次性消费
 *   - 被动回复（msg_id/event_id），不消耗 QQ 的主动消息配额
 *
 * 部署步骤见同目录 README.md。
 */

/* ---------------- 常量 ---------------- */
const QQ_API_BASES = ["https://api.bot.qq.com", "https://api.sgroup.qq.com"];
const CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // 去掉易混淆的 0/O/1/I
const CODE_LEN = 6;
const CODE_RE = /^[A-HJ-NP-Z2-9]{6}$/;
const CODE_EXTRACT_RE = /[A-HJ-NP-Z2-9]{6}/;
const CODE_TTL = 600;        // 验证码有效期（秒）——用户需在此时间内发给机器人
const BOUND_TTL = 1800;      // 绑定记录保留时间（秒）——等网站来消费
const MAX_PENDING = 500;     // 待绑定验证码上限（保护 KV 写入配额）
const TS_WINDOW = 600;       // 事件时间戳允许偏差（秒）
const PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20
]);

/* ---------------- 小工具 ---------------- */
function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json;charset=UTF-8", ...extraHeaders }
  });
}
function hexOf(buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}
function genCode() {
  const a = new Uint8Array(CODE_LEN);
  crypto.getRandomValues(a);
  let s = "";
  for (let i = 0; i < CODE_LEN; i++) s += CODE_ALPHABET[a[i] % CODE_ALPHABET.length];
  return s;
}

/* ---------------- ed25519 签名（Web Crypto，Workers / Node 均可用） ---------------- */
function seedFromSecret(secret) {
  let seed = String(secret || "");
  while (seed.length < 32) seed += seed;
  return new TextEncoder().encode(seed.slice(0, 32));
}
async function qqSign(secret, message) {
  const pkcs8 = new Uint8Array(48);
  pkcs8.set(PKCS8_PREFIX, 0);
  pkcs8.set(seedFromSecret(secret), 16);
  const key = await crypto.subtle.importKey("pkcs8", pkcs8, "Ed25519", false, ["sign"]);
  const sig = await crypto.subtle.sign("Ed25519", key, new TextEncoder().encode(message));
  return hexOf(sig);
}

/* ---------------- CORS ---------------- */
function corsHeaders(env, request) {
  const origin = request.headers.get("Origin") || "";
  const allowed = String(env.SITE_ORIGIN || "").split(",").map(s => s.trim()).filter(Boolean);
  const isLocal = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin);
  let allow = "*";
  if (isLocal) allow = origin; // 本地开发始终放行
  else if (allowed.length) allow = allowed.includes(origin) ? origin : allowed[0];
  else if (origin) allow = origin; // 未配置 SITE_ORIGIN 时宽松放行（部署后请配置）
  return {
    "Access-Control-Allow-Origin": allow,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin"
  };
}

/* ---------------- QQ 开放平台 API ---------------- */
async function getAccessToken(env) {
  const cached = await env.QQ_BINDINGS.get("cache:token", "json").catch(() => null);
  if (cached && cached.token && cached.expiresAt > Date.now() + 60000) return cached.token;
  const res = await fetch(QQ_API_BASES[0] + "/app/getAppAccessToken", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ appId: env.QQ_APP_ID, clientSecret: env.QQ_APP_SECRET })
  });
  const j = await res.json().catch(() => ({}));
  if (!j.access_token) throw new Error("获取 access_token 失败: " + JSON.stringify(j));
  const ttl = Math.max(60, Math.min(7000, (j.expires_in || 7200) - 120));
  try {
    await env.QQ_BINDINGS.put("cache:token",
      JSON.stringify({ token: j.access_token, expiresAt: Date.now() + ttl * 1000 }),
      { expirationTtl: ttl });
  } catch (e) { /* 缓存失败不影响主流程 */ }
  return j.access_token;
}

/**
 * 调用 QQ API；网络错误时自动切换到备用域名。
 * 返回 { ok, status, data }，不抛异常。
 */
async function qqApi(env, path, options = {}) {
  let lastErr = null;
  for (const base of QQ_API_BASES) {
    try {
      const token = await getAccessToken(env);
      const res = await fetch(base + path, {
        method: options.method || "GET",
        headers: {
          "Authorization": "QQBot " + token,
          "Content-Type": "application/json",
          ...(options.headers || {})
        },
        body: options.body ? JSON.stringify(options.body) : undefined
      });
      const text = await res.text();
      let data = null;
      try { data = JSON.parse(text); } catch (e) { /* 保持 null */ }
      return { ok: res.ok, status: res.status, data };
    } catch (e) {
      lastErr = e;
    }
  }
  return { ok: false, status: 0, data: { message: String(lastErr && lastErr.message || lastErr) } };
}

/** 机器人信息（名字 / 头像 / 分享链接），KV 缓存 24 小时 */
async function getBotInfo(env) {
  const cached = await env.QQ_BINDINGS.get("cache:botinfo", "json").catch(() => null);
  if (cached && cached.name) return cached;
  const r = await qqApi(env, "/users/@me");
  if (!r.ok || !r.data || !r.data.id) return { name: "", avatar: "", shareUrl: "" };
  const info = {
    name: r.data.username || "",
    avatar: r.data.avatar || "",
    shareUrl: r.data.share_url || ""
  };
  try { await env.QQ_BINDINGS.put("cache:botinfo", JSON.stringify(info), { expirationTtl: 86400 }); } catch (e) {}
  return info;
}

/** 发送群消息（被动回复，消耗被动配额） */
async function sendGroupMessage(env, groupOpenid, content, msgId, eventId) {
  const body = { content, msg_type: 0, msg_seq: 1 };
  if (msgId) body.msg_id = msgId;
  else if (eventId) body.event_id = eventId;
  const r = await qqApi(env, "/v2/groups/" + encodeURIComponent(groupOpenid) + "/messages", { method: "POST", body });
  if (!r.ok) console.log("发送群消息失败:", r.status, JSON.stringify(r.data));
  return r;
}

/** 发送 C2C 单聊消息（被动回复） */
async function sendC2CMessage(env, openid, content, msgId, eventId) {
  const body = { content, msg_type: 0, msg_seq: 1 };
  if (msgId) body.msg_id = msgId;
  else if (eventId) body.event_id = eventId;
  const r = await qqApi(env, "/v2/users/" + encodeURIComponent(openid) + "/messages", { method: "POST", body });
  if (!r.ok) console.log("发送 C2C 消息失败:", r.status, JSON.stringify(r.data));
  return r;
}

/* ---------------- QQ 昵称清洗 ---------------- */
/**
 * 群聊事件 author.username 是 QQ 昵称（单聊为空串）。
 * 这里做长度截断 + 去控制字符，防止异常值污染网站数据。
 */
function cleanQQName(raw) {
  let s = String(raw || "").replace(/[\u0000-\u001f\u007f]/g, "").trim();
  if (s.length > 24) s = s.slice(0, 24);
  return s;
}

/* ---------------- QQ WebHook 回调 ---------------- */
async function handleQQCallback(request, env) {
  const raw = await request.text();
  let payload = null;
  try { payload = JSON.parse(raw); } catch (e) { return new Response("bad json", { status: 400 }); }

  // 1) 回调地址校验（在 QQ 后台保存回调地址时触发，op=13）
  if (payload.op === 13) {
    const d = payload.d || {};
    const s = String(env.QQ_APP_SECRET || "");
    console.log("[op13] 收到:", JSON.stringify(d),
      "| secretLen:", s.length,
      "| head:", s.slice(0, 4), "| tail:", s.slice(-4),
      "| hasSpace:", /\s/.test(s));
    const signature = await qqSign(env.QQ_APP_SECRET, String(d.event_ts || "") + String(d.plain_token || ""));
    console.log("[op13] 回复 signature:", signature);
    return json({ plain_token: d.plain_token || "", signature });
  }

  // 2) 事件验签：X-Signature-Timestamp + 原始 body
  const ts = request.headers.get("X-Signature-Timestamp") || "";
  const sig = (request.headers.get("X-Signature-Ed25519") || "").toLowerCase();
  if (!ts || !sig) return new Response("missing signature", { status: 401 });
  if (Math.abs(Math.floor(Date.now() / 1000) - Number(ts)) > TS_WINDOW) {
    return new Response("stale timestamp", { status: 403 });
  }
  const expect = await qqSign(env.QQ_APP_SECRET, ts + raw);
  if (expect !== sig) return new Response("bad signature", { status: 403 });

  // 3) 派发事件（QQ 要求 3 秒内返回 200/204）
  if (payload.op === 0 && typeof payload.t === "string") {
    try {
      await handleEvent(env, payload.t, payload.d || {}, payload.id || "");
    } catch (e) {
      console.log("事件处理异常:", e && e.message);
    }
  }
  return new Response(null, { status: 204 });
}

async function handleEvent(env, type, d, eventId) {
  const isGroup = type === "GROUP_AT_MESSAGE_CREATE" || type === "GROUP_MESSAGE_CREATE";
  const isC2C = type === "C2C_MESSAGE_CREATE";
  if (!isGroup && !isC2C) return;

  const author = d.author || {};
  // union_openid 跨场景稳定，优先；群聊场景回退 member_openid，单聊回退 user_openid
  const openid = author.union_openid || author.member_openid || author.user_openid || "";
  if (!openid || author.bot) return;

  // 群聊事件带 QQ 昵称（author.username），单聊为空串——拿不到就留空，网站用占位昵称
  const qqName = cleanQQName(author.username);

  const content = String(d.content || "").trim();
  const upper = content.toUpperCase();
  const match = upper.match(CODE_EXTRACT_RE);

  const reply = (text) => isGroup
    ? sendGroupMessage(env, d.group_openid, text, d.id, eventId)
    : sendC2CMessage(env, openid, text, d.id, eventId);

  if (!match) {
    // 不含验证码：识别「帮助」类意图，回复使用说明；否则静默忽略
    if (/注册|绑定|开通|怎么|如何|help/i.test(content)) {
      await reply("使用方法：在表白墙网站点「QQ 一键注册」获取 6 位验证码，然后在这里把验证码发给我，即可完成注册。");
    }
    return;
  }

  const code = match[0];
  const key = "bind:" + code;
  const rec = await env.QQ_BINDINGS.get(key, "json").catch(() => null);

  if (!rec) {
    await reply("验证码不存在或已过期，请在表白墙网站重新获取。");
    return;
  }
  if (rec.status === "bound") {
    // QQ 可能重复推送同一 msg_id：同一条消息只回复一次
    if (rec.boundMsgId === d.id) {
      if (!rec.replied) {
        rec.replied = true;
        await env.QQ_BINDINGS.put(key, JSON.stringify(rec), { expirationTtl: BOUND_TTL }).catch(() => {});
        await reply("✅ 绑定成功！请返回表白墙网站，页面会自动完成注册。");
      }
      return;
    }
    await reply("这个验证码已经用过了，请回到网站重新获取一个新的。");
    return;
  }

  // 命中：记录绑定（顺带把 QQ 昵称透传给网站）
  const bound = {
    status: "bound",
    openid,
    nickname: qqName,
    groupOpenid: d.group_openid || "",
    createdAt: rec.createdAt || Date.now(),
    boundAt: Date.now(),
    boundMsgId: d.id || "",
    replied: false
  };
  await env.QQ_BINDINGS.put(key, JSON.stringify(bound), { expirationTtl: BOUND_TTL });
  const r = await reply("✅ 绑定成功！请返回表白墙网站，页面会自动完成注册。");
  if (r && r.ok) {
    bound.replied = true;
    await env.QQ_BINDINGS.put(key, JSON.stringify(bound), { expirationTtl: BOUND_TTL }).catch(() => {});
  }
}

/* ---------------- 网站侧 API ---------------- */
async function handleBindStart(env, cors) {
  if (!env.QQ_APP_ID || !env.QQ_APP_SECRET) {
    return json({ ok: false, error: "Worker 未配置 QQ_APP_ID / QQ_APP_SECRET" }, 500, cors);
  }
  // 保护 KV 写入配额：待绑定验证码过多时拒绝
  try {
    const listed = await env.QQ_BINDINGS.list({ prefix: "bind:", limit: MAX_PENDING + 1 });
    if (listed && listed.keys && listed.keys.length > MAX_PENDING) {
      return json({ ok: false, error: "当前绑定请求过多，请稍后再试" }, 429, cors);
    }
  } catch (e) { /* list 失败不阻塞主流程 */ }

  const code = genCode();
  await env.QQ_BINDINGS.put("bind:" + code,
    JSON.stringify({ status: "pending", createdAt: Date.now() }),
    { expirationTtl: CODE_TTL });

  const bot = await getBotInfo(env).catch(() => ({ name: "", avatar: "", shareUrl: "" }));
  return json({
    ok: true,
    code,
    botName: bot.name || "",
    botAvatar: bot.avatar || "",
    shareUrl: bot.shareUrl || "",
    expiresIn: CODE_TTL
  }, 200, cors);
}

async function handleBindStatus(url, env, cors) {
  const code = (url.searchParams.get("code") || "").toUpperCase().trim();
  if (!CODE_RE.test(code)) return json({ status: "invalid" }, 200, cors);
  const rec = await env.QQ_BINDINGS.get("bind:" + code, "json").catch(() => null);
  if (!rec) return json({ status: "expired" }, 200, cors);
  if (rec.status === "bound" && rec.openid) {
    return json({ status: "bound", openid: rec.openid, nickname: rec.nickname || "" }, 200, cors);
  }
  return json({ status: "pending" }, 200, cors);
}

async function handleHealth(env, cors) {
  const configured = !!(env.QQ_APP_ID && env.QQ_APP_SECRET);
  const bot = configured ? await getBotInfo(env).catch(() => null) : null;
  return json({
    ok: configured && !!(bot && bot.name),
    configured,
    botName: bot ? bot.name || "" : "",
    shareUrl: bot ? bot.shareUrl || "" : ""
  }, 200, cors);
}

/* ---------------- 入口 ---------------- */
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(env, request) });
    }
    const cors = corsHeaders(env, request);
    try {
      if (url.pathname === "/qq/callback" && request.method === "POST") {
        return await handleQQCallback(request, env);
      }
      if (url.pathname === "/api/bind/start" && request.method === "POST") {
        return await handleBindStart(env, cors);
      }
      if (url.pathname === "/api/bind/status" && request.method === "GET") {
        return await handleBindStatus(url, env, cors);
      }
      if (url.pathname === "/api/health" && request.method === "GET") {
        return await handleHealth(env, cors);
      }
      // 临时调试端点：查看 Worker 运行时实际读到的配置（验证完可删）
      if (url.pathname === "/api/debug" && request.method === "GET") {
        const s = String(env.QQ_APP_SECRET || "");
        const a = String(env.QQ_APP_ID || "");
        return json({
          appId: a,
          appIdLen: a.length,
          hasSecret: !!s,
          secretLen: s.length,
          secretHead: s.slice(0, 4),
          secretTail: s.slice(-4),
          secretHasSpace: /\s/.test(s),
          kvBound: !!env.QQ_BINDINGS,
        }, 200, cors);
      }
      return json({ error: "not found" }, 404, cors);
    } catch (e) {
      console.log("Worker 异常:", e && e.stack || e);
      return json({ ok: false, error: String(e && e.message || e) }, 500, cors);
    }
  }
};
