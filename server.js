const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const crypto = require("crypto");
const https = require("https");
const { Pool } = require("pg");

const app = express();

const SERVER_BUILD_ID = "digit-attack-drag-flow-v4-20260827";
console.log(`SERVER_BUILD_ID=${SERVER_BUILD_ID}`);

// Render reverse proxy arkasında gerçek istemci IP'sini req.ip üzerinden alabilmek için tek proxy hop'una güven.
// Farklı bir topoloji kullanıyorsan TRUST_PROXY_HOPS ortam değişkenini buna göre ayarla.
const TRUST_PROXY_HOPS = Math.max(0, Math.min(5, Number(process.env.TRUST_PROXY_HOPS || 1) || 1));
if (TRUST_PROXY_HOPS > 0) app.set("trust proxy", TRUST_PROXY_HOPS);

// Harici Redis gerektirmeyen hafif, instance-bazlı rate limiter.
// Birden fazla Render instance varsa limitler instance başınadır; yine de kaba kuvvet / spam maliyetini ciddi düşürür.
const securityRateBuckets = new Map();
const SECURITY_RATE_BUCKET_MAX_KEYS = Math.max(
  5_000,
  Math.min(200_000, Number(process.env.SECURITY_RATE_BUCKET_MAX_KEYS || 50_000) || 50_000)
);

function cleanRateLimitKey(value) {
  return String(value || "unknown").trim().slice(0, 180) || "unknown";
}

function forwardedClientIp(req) {
  const forwarded = String(req?.headers?.["x-forwarded-for"] || "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  if (TRUST_PROXY_HOPS > 0 && forwarded.length > 0) {
    // Sağdan say: istemcinin sahte bir X-Forwarded-For öneki eklemesi limiti aşmak için kullanılamaz.
    const trustedIndex = Math.max(0, forwarded.length - TRUST_PROXY_HOPS);
    return cleanRateLimitKey(forwarded[trustedIndex]);
  }
  return cleanRateLimitKey(req?.socket?.remoteAddress || req?.connection?.remoteAddress || "unknown");
}

function consumeSecurityRateLimit(scope, key, maxRequests, windowMs) {
  const now = Date.now();
  const bucketKey = `${scope}:${cleanRateLimitKey(key)}`;
  let bucket = securityRateBuckets.get(bucketKey);
  if (!bucket || now >= bucket.resetAt) {
    bucket = { count: 0, resetAt: now + windowMs };
    securityRateBuckets.set(bucketKey, bucket);
  }
  if (bucket.count >= maxRequests) {
    return { allowed: false, retryAfterMs: Math.max(1, bucket.resetAt - now) };
  }
  bucket.count += 1;
  return { allowed: true, retryAfterMs: 0 };
}

function createHttpRateLimiter({ scope, maxRequests, windowMs, key }) {
  return (req, res, next) => {
    const keyValue = key ? key(req) : (req.ip || forwardedClientIp(req));
    const result = consumeSecurityRateLimit(scope, keyValue, maxRequests, windowMs);
    if (!result.allowed) {
      res.set("Retry-After", String(Math.max(1, Math.ceil(result.retryAfterMs / 1000))));
      res.status(429).json({
        ok: false,
        code: "RATE_LIMITED",
        message: "Çok fazla istek gönderildi. Lütfen kısa süre sonra tekrar deneyin.",
      });
      return;
    }
    next();
  };
}

const generalHttpRateLimit = createHttpRateLimiter({
  scope: "http-general",
  maxRequests: Math.max(120, Math.min(5_000, Number(process.env.HTTP_RATE_LIMIT_PER_MINUTE || 900) || 900)),
  windowMs: 60_000,
});
const guestAuthRateLimit = createHttpRateLimiter({
  scope: "auth-guest",
  maxRequests: Math.max(5, Math.min(100, Number(process.env.GUEST_AUTH_RATE_LIMIT_10M || 30) || 30)),
  windowMs: 10 * 60_000,
});
const playGamesAuthRateLimit = createHttpRateLimiter({
  scope: "auth-play-games",
  maxRequests: Math.max(5, Math.min(120, Number(process.env.PLAY_GAMES_AUTH_RATE_LIMIT_10M || 40) || 40)),
  windowMs: 10 * 60_000,
});
const gameplayAcquireRateLimit = createHttpRateLimiter({
  scope: "game-session-acquire",
  maxRequests: Math.max(10, Math.min(240, Number(process.env.GAME_SESSION_ACQUIRE_RATE_LIMIT_PER_MINUTE || 60) || 60)),
  windowMs: 60_000,
  key: (req) => req.auth?.sub || req.ip || forwardedClientIp(req),
});
const challengeMutationRateLimit = createHttpRateLimiter({
  scope: "challenge-mutation",
  maxRequests: Math.max(30, Math.min(600, Number(process.env.CHALLENGE_RATE_LIMIT_PER_MINUTE || 180) || 180)),
  windowMs: 60_000,
  key: (req) => req.auth?.sub || req.ip || forwardedClientIp(req),
});

const rateCleanupTimer = setInterval(() => {
  const now = Date.now();
  for (const [key, bucket] of securityRateBuckets.entries()) {
    if (now >= bucket.resetAt) securityRateBuckets.delete(key);
  }
  while (securityRateBuckets.size > SECURITY_RATE_BUCKET_MAX_KEYS) {
    const oldestKey = securityRateBuckets.keys().next().value;
    if (oldestKey === undefined) break;
    securityRateBuckets.delete(oldestKey);
  }
}, 5 * 60_000);
rateCleanupTimer.unref?.();

app.use(generalHttpRateLimit);

const ENABLE_REALTIME_LOGS = process.env.ENABLE_REALTIME_LOGS === "true";
function realtimeLog(...args) {
  if (ENABLE_REALTIME_LOGS) console.log(...args);
}

if (process.env.ENABLE_HTTP_REQUEST_LOGS === "true") {
  app.use((req, res, next) => {
    console.log(
      "HTTP request:",
      req.method,
      req.url,
      "ua:",
      req.headers["user-agent"] || "-"
    );
    next();
  });
}

app.use(express.json({ limit: "64kb" }));

const server = http.createServer(app);

const SOCKET_PATH = "/socket.io/";
const DATABASE_URL = process.env.DATABASE_URL;

const GOOGLE_WEB_CLIENT_ID = process.env.GOOGLE_WEB_CLIENT_ID || "";
const GOOGLE_WEB_CLIENT_SECRET = process.env.GOOGLE_WEB_CLIENT_SECRET || "";
const PLAY_GAMES_APP_ID = process.env.PLAY_GAMES_APP_ID || "";
const SESSION_SECRET = process.env.SESSION_SECRET || "";
const SESSION_TTL_SECONDS = Number(process.env.SESSION_TTL_SECONDS || 24 * 60 * 60);
// Gameplay heartbeat yoktur. Aktif oyun kilidi yalnız oyun başlangıcı/bitimi ve zaten var olan
// authoritative HTTP/Socket trafiğiyle yönetilir. Aynı cihaz yeni sessionId alırsa newest-wins;
// farklı cihazdaki süresi dolmamış aktif oyun ise yeni acquire isteğini engeller.
const GAMEPLAY_SESSION_ACTIVE_TTL_SECONDS = Math.max(10 * 60, Math.min(6 * 60 * 60,
  Number(process.env.GAMEPLAY_SESSION_ACTIVE_TTL_SECONDS || 30 * 60) || 30 * 60));
const GAMEPLAY_SESSION_RENEW_BEFORE_SECONDS = Math.max(60, Math.min(10 * 60,
  Number(process.env.GAMEPLAY_SESSION_RENEW_BEFORE_SECONDS || 10 * 60) || 10 * 60,
  Math.floor(GAMEPLAY_SESSION_ACTIVE_TTL_SECONDS / 2)));

function assertSecurityEnvironment() {
  const missing = [];
  if (!DATABASE_URL) missing.push("DATABASE_URL");
  if (!GOOGLE_WEB_CLIENT_ID) missing.push("GOOGLE_WEB_CLIENT_ID");
  if (!GOOGLE_WEB_CLIENT_SECRET) missing.push("GOOGLE_WEB_CLIENT_SECRET");
  if (!PLAY_GAMES_APP_ID) missing.push("PLAY_GAMES_APP_ID");
  if (!SESSION_SECRET || SESSION_SECRET.length < 32) missing.push("SESSION_SECRET (en az 32 karakter)");
  if (missing.length > 0) {
    throw new Error(`Güvenli oturum için eksik değişkenler: ${missing.join(", ")}`);
  }
}

function base64UrlEncode(value) {
  return Buffer.from(value).toString("base64url");
}

function base64UrlDecode(value) {
  return Buffer.from(value, "base64url").toString("utf8");
}

function signSessionPayload(encodedPayload) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(encodedPayload).digest("base64url");
}

function createSessionToken(playerId) {
  if (!SESSION_SECRET) throw new Error("SESSION_SECRET tanımlı değil.");
  const nowSeconds = Math.floor(Date.now() / 1000);
  const encodedPayload = base64UrlEncode(JSON.stringify({
    sub: String(playerId),
    iat: nowSeconds,
    exp: nowSeconds + SESSION_TTL_SECONDS,
    aud: "target-number-api",
    nonce: crypto.randomBytes(12).toString("hex"),
  }));
  return `${encodedPayload}.${signSessionPayload(encodedPayload)}`;
}

function verifySessionToken(token) {
  if (!SESSION_SECRET || !token) return null;
  const parts = String(token).split(".");
  if (parts.length !== 2) return null;
  const [encodedPayload, signature] = parts;
  const expected = signSessionPayload(encodedPayload);
  const actualBuffer = Buffer.from(signature);
  const expectedBuffer = Buffer.from(expected);
  if (actualBuffer.length !== expectedBuffer.length || !crypto.timingSafeEqual(actualBuffer, expectedBuffer)) return null;
  try {
    const payload = JSON.parse(base64UrlDecode(encodedPayload));
    const nowSeconds = Math.floor(Date.now() / 1000);
    if (!payload.sub || payload.aud !== "target-number-api" || Number(payload.exp || 0) <= nowSeconds) return null;
    return payload;
  } catch (_) {
    return null;
  }
}

function bearerToken(req) {
  const header = String(req.headers.authorization || "");
  return header.startsWith("Bearer ") ? header.slice(7).trim() : "";
}

function requireAuth(req, res, next) {
  const session = verifySessionToken(bearerToken(req));
  if (!session) {
    res.status(401).json({ ok: false, code: "AUTH_REQUIRED", message: "Güvenli oyuncu oturumu gerekli." });
    return;
  }
  req.auth = session;
  next();
}

function postFormJson(urlString, form) {
  return new Promise((resolve, reject) => {
    const body = new URLSearchParams(form).toString();
    const url = new URL(urlString);
    const request = https.request({
      hostname: url.hostname,
      port: 443,
      path: `${url.pathname}${url.search}`,
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": Buffer.byteLength(body),
        Accept: "application/json",
      },
      timeout: 15_000,
    }, (response) => {
      let text = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => { text += chunk; });
      response.on("end", () => {
        let json;
        try { json = JSON.parse(text || "{}"); } catch (_) { json = {}; }
        if ((response.statusCode || 500) < 200 || (response.statusCode || 500) >= 300) {
          reject(new Error(json.error_description || json.error || `Google OAuth HTTP ${response.statusCode}`));
          return;
        }
        resolve(json);
      });
    });
    request.on("timeout", () => request.destroy(new Error("Google OAuth zaman aşımı.")));
    request.on("error", reject);
    request.end(body);
  });
}

function getJsonWithBearer(urlString, accessToken) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlString);
    const request = https.request({
      hostname: url.hostname,
      port: 443,
      path: `${url.pathname}${url.search}`,
      method: "GET",
      headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" },
      timeout: 15_000,
    }, (response) => {
      let text = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => { text += chunk; });
      response.on("end", () => {
        let json;
        try { json = JSON.parse(text || "{}"); } catch (_) { json = {}; }
        if ((response.statusCode || 500) < 200 || (response.statusCode || 500) >= 300) {
          reject(new Error(json.error?.message || json.message || `Google Games HTTP ${response.statusCode}`));
          return;
        }
        resolve(json);
      });
    });
    request.on("timeout", () => request.destroy(new Error("Google Games doğrulaması zaman aşımına uğradı.")));
    request.on("error", reject);
    request.end();
  });
}

async function exchangePlayGamesAuthCode(authCode) {
  if (!GOOGLE_WEB_CLIENT_ID || !GOOGLE_WEB_CLIENT_SECRET || !PLAY_GAMES_APP_ID) {
    const error = new Error("Sunucu Google Play Games değişkenleri eksik.");
    error.statusCode = 503;
    throw error;
  }
  const tokenJson = await postFormJson("https://oauth2.googleapis.com/token", {
    code: String(authCode || ""),
    client_id: GOOGLE_WEB_CLIENT_ID,
    client_secret: GOOGLE_WEB_CLIENT_SECRET,
    redirect_uri: "",
    grant_type: "authorization_code",
  });
  const accessToken = String(tokenJson.access_token || "");
  if (!accessToken) throw new Error("Google erişim jetonu alınamadı.");
  const verifyJson = await getJsonWithBearer(
    `https://www.googleapis.com/games/v1/applications/${encodeURIComponent(PLAY_GAMES_APP_ID)}/verify`,
    accessToken
  );
  const verifiedPlayerId = safeLeaderboardPlayerId(verifyJson.player_id);
  if (!verifiedPlayerId) throw new Error("Play Games oyuncu kimliği doğrulanamadı.");
  // Eski Android sürümleri ve mevcut leaderboard satırları Play Games
  // kimliğini pg_ önekiyle saklıyor. Aynı biçimi koruyarak hesapların
  // güncelleme sonrasında iki ayrı oyuncuya bölünmesini engelle.
  return verifiedPlayerId.startsWith("pg_")
    ? verifiedPlayerId
    : `pg_${verifiedPlayerId}`.slice(0, 96);
}


const pool = DATABASE_URL
  ? new Pool({
      connectionString: DATABASE_URL,
      ssl:
        DATABASE_URL.includes("localhost") ||
        DATABASE_URL.includes("127.0.0.1")
          ? false
          : { rejectUnauthorized: false },
      max: Number(process.env.PG_POOL_MAX || 10),
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 10_000,
    })
  : null;

async function initDatabase() {
  if (!pool) {
    console.warn(
      "DATABASE_URL tanımlı değil. Skor tablosu endpointleri veritabanı olmadan çalışmaz."
    );
    return;
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS players (
      player_id TEXT PRIMARY KEY,
      username TEXT NOT NULL,
      country TEXT NOT NULL DEFAULT 'TR',
      username_user_set BOOLEAN NOT NULL DEFAULT FALSE,
      username_change_count INTEGER NOT NULL DEFAULT 0 CHECK (username_change_count >= 0),
      username_last_changed_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS schema_migrations (
      migration_id TEXT PRIMARY KEY,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    -- Ağır cleanup'ların her Render restartında / her instance'ta tekrar çalışmasını önleyen
    -- çok küçük bakım kilidi. Her iş için yalnız son başarılı claim zamanı tutulur.
    CREATE TABLE IF NOT EXISTS maintenance_state (
      task_key TEXT PRIMARY KEY,
      last_run_at TIMESTAMPTZ NOT NULL DEFAULT TO_TIMESTAMP(0)
    );

    CREATE TABLE IF NOT EXISTS player_game_sessions (
      player_id TEXT PRIMARY KEY REFERENCES players(player_id) ON DELETE CASCADE,
      session_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      game_key TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ NOT NULL,
      protocol_version INTEGER NOT NULL DEFAULT 4
    );

    -- Eski heartbeat/lease tablosu kalıcı oyuncu verisi değildir. V3'e geçişte yalnızca
    -- legacy lease kolonları gerçekten varsa bir kez düşürülüp yeni sessionId şeması kurulur.
    DO $game_session_v3$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE migration_id = 'game_session_v3_newest_wins'
      ) THEN
        IF EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_schema = 'public' AND table_name = 'player_game_sessions' AND column_name = 'lease_id'
        ) THEN
          DROP TABLE player_game_sessions;
          CREATE TABLE player_game_sessions (
            player_id TEXT PRIMARY KEY REFERENCES players(player_id) ON DELETE CASCADE,
            session_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            game_key TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            protocol_version INTEGER NOT NULL DEFAULT 4
          );
        END IF;
        INSERT INTO schema_migrations (migration_id)
        VALUES ('game_session_v3_newest_wins')
        ON CONFLICT (migration_id) DO NOTHING;
      END IF;
    END
    $game_session_v3$;

    -- V4: heartbeat olmadan iki cihazda eşzamanlı oyunu engellemek için aktif oyun son kullanma
    -- zamanı eklenir. V3'ten kalan satırlar deploy anında bilerek expired yapılır; böylece eski
    -- sürümden kalmış bir session başka cihazı gereksiz yere kilitlemez. Bu migration yalnız 1 kez çalışır.
    DO $game_session_v4$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE migration_id = 'game_session_v4_cross_device_active_lock'
      ) THEN
        IF NOT EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_schema = 'public' AND table_name = 'player_game_sessions' AND column_name = 'expires_at'
        ) THEN
          ALTER TABLE player_game_sessions ADD COLUMN expires_at TIMESTAMPTZ;
        END IF;
        UPDATE player_game_sessions
        SET expires_at = NOW()
        WHERE expires_at IS NULL;
        ALTER TABLE player_game_sessions ALTER COLUMN expires_at SET NOT NULL;
        ALTER TABLE player_game_sessions ALTER COLUMN protocol_version SET DEFAULT 4;
        INSERT INTO schema_migrations (migration_id)
        VALUES ('game_session_v4_cross_device_active_lock')
        ON CONFLICT (migration_id) DO NOTHING;
      END IF;
    END
    $game_session_v4$;

    CREATE UNIQUE INDEX IF NOT EXISTS idx_player_game_sessions_session_id
      ON player_game_sessions (session_id);

    CREATE TABLE IF NOT EXISTS player_scores (
      player_id TEXT PRIMARY KEY REFERENCES players(player_id) ON DELETE CASCADE,
      general_score INTEGER NOT NULL DEFAULT 0 CHECK (general_score >= 0),
      infinite_score INTEGER NOT NULL DEFAULT 0 CHECK (infinite_score >= 0),
      monthly_key TEXT NOT NULL DEFAULT '',
      monthly_general_score INTEGER NOT NULL DEFAULT 0 CHECK (monthly_general_score >= 0),
      monthly_infinite_score INTEGER NOT NULL DEFAULT 0 CHECK (monthly_infinite_score >= 0),
      monthly_updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    ALTER TABLE player_scores
      ADD COLUMN IF NOT EXISTS monthly_key TEXT NOT NULL DEFAULT '';
    ALTER TABLE player_scores
      ADD COLUMN IF NOT EXISTS monthly_general_score INTEGER NOT NULL DEFAULT 0 CHECK (monthly_general_score >= 0);
    ALTER TABLE player_scores
      ADD COLUMN IF NOT EXISTS monthly_infinite_score INTEGER NOT NULL DEFAULT 0 CHECK (monthly_infinite_score >= 0);
    ALTER TABLE player_scores
      ADD COLUMN IF NOT EXISTS monthly_updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

    -- Eski ayrı aylık leaderboard tablosunu yalnızca bir kez yeni player_scores
    -- kolonlarına taşı. Sonrasında aylık ve genel skor aynı satırda tutulur.
    DO $monthly_migration$
    BEGIN
      IF to_regclass('public.player_monthly_scores') IS NOT NULL THEN
        EXECUTE $monthly_sql$
          UPDATE player_scores AS target
          SET monthly_key = legacy.month_key,
              monthly_general_score = legacy.general_score,
              monthly_infinite_score = legacy.infinite_score,
              monthly_updated_at = legacy.updated_at
          FROM player_monthly_scores AS legacy
          WHERE legacy.player_id = target.player_id
            AND legacy.month_key = TO_CHAR(NOW() AT TIME ZONE 'UTC', 'YYYY-MM')
        $monthly_sql$;
        EXECUTE 'DROP TABLE player_monthly_scores';
      END IF;
    END
    $monthly_migration$;

    CREATE TABLE IF NOT EXISTS player_progress (
      player_id TEXT PRIMARY KEY REFERENCES players(player_id) ON DELETE CASCADE,
      total_xp INTEGER NOT NULL DEFAULT 0 CHECK (total_xp >= 0),
      infinite_run_score INTEGER NOT NULL DEFAULT 0 CHECK (infinite_run_score >= 0),
      infinite_next_stage INTEGER NOT NULL DEFAULT 1 CHECK (infinite_next_stage >= 1),
      tournament_stage INTEGER NOT NULL DEFAULT 1 CHECK (tournament_stage BETWEEN 1 AND 8),
      tournament_rights INTEGER NOT NULL DEFAULT 3 CHECK (tournament_rights BETWEEN 0 AND 3),
      tournament_bank INTEGER NOT NULL DEFAULT 0 CHECK (tournament_bank >= 0),
      tournament_completed BOOLEAN NOT NULL DEFAULT FALSE,
      tournament_tickets INTEGER NOT NULL DEFAULT 0 CHECK (tournament_tickets >= 0),
      tournament_entry_active BOOLEAN NOT NULL DEFAULT FALSE,
      hundred_active BOOLEAN NOT NULL DEFAULT FALSE,
      hundred_stage INTEGER NOT NULL DEFAULT 0 CHECK (hundred_stage BETWEEN 0 AND 12),
      hundred_daily_key TEXT NOT NULL DEFAULT '',
      hundred_daily_base_used BOOLEAN NOT NULL DEFAULT FALSE,
      hundred_daily_ad_used BOOLEAN NOT NULL DEFAULT FALSE,
      hundred_rewarded_rights INTEGER NOT NULL DEFAULT 0 CHECK (hundred_rewarded_rights BETWEEN 0 AND 2),
      game_rights INTEGER NOT NULL DEFAULT 10 CHECK (game_rights BETWEEN 0 AND 10),
      game_rights_refill_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      diamond_balance INTEGER NOT NULL DEFAULT 0 CHECK (diamond_balance >= 0),
      level_reward_claimed_through INTEGER NOT NULL DEFAULT 0
        CHECK (level_reward_claimed_through BETWEEN 0 AND 1000),
      two_player_finish_count INTEGER NOT NULL DEFAULT 0
        CHECK (two_player_finish_count >= 0),
      two_player_finish_total_ms BIGINT NOT NULL DEFAULT 0
        CHECK (two_player_finish_total_ms >= 0),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    ALTER TABLE player_progress
      ADD COLUMN IF NOT EXISTS infinite_run_score INTEGER NOT NULL DEFAULT 0;

    ALTER TABLE player_progress
      ADD COLUMN IF NOT EXISTS infinite_next_stage INTEGER NOT NULL DEFAULT 1;

    ALTER TABLE player_progress
      ADD COLUMN IF NOT EXISTS tournament_stage INTEGER NOT NULL DEFAULT 1;
    ALTER TABLE player_progress
      ADD COLUMN IF NOT EXISTS tournament_rights INTEGER NOT NULL DEFAULT 3;
    ALTER TABLE player_progress
      ADD COLUMN IF NOT EXISTS tournament_bank INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE player_progress
      ADD COLUMN IF NOT EXISTS tournament_completed BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE player_progress
      ADD COLUMN IF NOT EXISTS tournament_tickets INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE player_progress
      ADD COLUMN IF NOT EXISTS tournament_entry_active BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE player_progress
      ADD COLUMN IF NOT EXISTS hundred_active BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE player_progress
      ADD COLUMN IF NOT EXISTS hundred_stage INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE player_progress
      ADD COLUMN IF NOT EXISTS hundred_daily_key TEXT NOT NULL DEFAULT '';
    ALTER TABLE player_progress
      ADD COLUMN IF NOT EXISTS hundred_daily_base_used BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE player_progress
      ADD COLUMN IF NOT EXISTS hundred_daily_ad_used BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE player_progress
      ADD COLUMN IF NOT EXISTS hundred_rewarded_rights INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE player_progress
      ADD COLUMN IF NOT EXISTS hundred_daily_base_used_count INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE player_progress
      ADD COLUMN IF NOT EXISTS tournament_reward_day_key TEXT NOT NULL DEFAULT '';
    ALTER TABLE player_progress
      ADD COLUMN IF NOT EXISTS tournament_rewarded_tickets_today INTEGER NOT NULL DEFAULT 0;

    -- Büyük UPDATE/constraint normalizasyonları her Render restartında değil yalnızca bir kez çalışır.
    DO $progress_normalization_v3$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE migration_id = 'progress_normalization_v3_20260813'
      ) THEN
        UPDATE player_progress
          SET tournament_entry_active = TRUE
          WHERE tournament_entry_active = FALSE
            AND tournament_completed = FALSE
            AND (tournament_stage > 1 OR tournament_bank > 0 OR tournament_rights < 3);

        UPDATE player_progress
          SET tournament_entry_active = FALSE
          WHERE tournament_completed = TRUE;

        UPDATE player_progress
          SET tournament_tickets = LEAST(GREATEST(tournament_tickets, 0), 9999)
          WHERE tournament_tickets < 0 OR tournament_tickets > 9999;
        ALTER TABLE player_progress
          DROP CONSTRAINT IF EXISTS player_progress_tournament_tickets_check_v1;
        BEGIN
          ALTER TABLE player_progress
            ADD CONSTRAINT player_progress_tournament_tickets_check_v1
            CHECK (tournament_tickets BETWEEN 0 AND 9999);
        EXCEPTION WHEN duplicate_object THEN
          NULL;
        END;

        UPDATE player_progress
          SET tournament_stage = LEAST(GREATEST(tournament_stage, 1), 8)
          WHERE tournament_stage < 1 OR tournament_stage > 8;
        ALTER TABLE player_progress
          DROP CONSTRAINT IF EXISTS player_progress_tournament_stage_check;
        ALTER TABLE player_progress
          DROP CONSTRAINT IF EXISTS player_progress_tournament_stage_check_v2;
        BEGIN
          ALTER TABLE player_progress
            ADD CONSTRAINT player_progress_tournament_stage_check_v2
            CHECK (tournament_stage BETWEEN 1 AND 8);
        EXCEPTION WHEN duplicate_object THEN
          NULL;
        END;

        UPDATE player_progress
          SET hundred_rewarded_rights = LEAST(GREATEST(hundred_rewarded_rights, 0), 2)
          WHERE hundred_rewarded_rights < 0 OR hundred_rewarded_rights > 1;
        ALTER TABLE player_progress
          DROP CONSTRAINT IF EXISTS player_progress_hundred_rewarded_rights_check_v1;
        BEGIN
          ALTER TABLE player_progress
            ADD CONSTRAINT player_progress_hundred_rewarded_rights_check_v1
            CHECK (hundred_rewarded_rights BETWEEN 0 AND 2);
        EXCEPTION WHEN duplicate_object THEN
          NULL;
        END;

        INSERT INTO schema_migrations (migration_id)
        VALUES ('progress_normalization_v3_20260813')
        ON CONFLICT (migration_id) DO NOTHING;
      END IF;
    END
    $progress_normalization_v3$;

    UPDATE player_progress
      SET hundred_daily_base_used_count = CASE
        WHEN hundred_daily_base_used_count > 0 THEN LEAST(hundred_daily_base_used_count, 2)
        WHEN hundred_daily_base_used THEN 1
        ELSE 0
      END;

    -- Bu constraint'ler her Render restartında silinip yeniden oluşturulmaz.
    -- Var olan doğru constraint korunur; yalnız eksikse eklenir. Böylece eski/yeni
    -- instance'ların kısa süre aynı anda initDatabase() çalıştırması duplicate_object
    -- (PostgreSQL 42710) hatasına yol açmaz.
    DO $shared_progress_constraints_v5$
    BEGIN
      -- Eski adlar artık kullanılmıyor; varsa kaldırmak güvenlidir.
      ALTER TABLE player_progress
        DROP CONSTRAINT IF EXISTS player_progress_hundred_rewarded_rights_check;
      ALTER TABLE player_progress
        DROP CONSTRAINT IF EXISTS player_progress_hundred_rewarded_rights_check_v1;

      IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'player_progress_hundred_daily_base_used_count_check'
          AND conrelid = 'player_progress'::regclass
      ) THEN
        BEGIN
          ALTER TABLE player_progress
            ADD CONSTRAINT player_progress_hundred_daily_base_used_count_check
            CHECK (hundred_daily_base_used_count BETWEEN 0 AND 2);
        EXCEPTION WHEN duplicate_object THEN
          NULL;
        END;
      END IF;

      IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'player_progress_tournament_rewarded_tickets_today_check'
          AND conrelid = 'player_progress'::regclass
      ) THEN
        BEGIN
          ALTER TABLE player_progress
            ADD CONSTRAINT player_progress_tournament_rewarded_tickets_today_check
            CHECK (tournament_rewarded_tickets_today BETWEEN 0 AND 15);
        EXCEPTION WHEN duplicate_object THEN
          NULL;
        END;
      END IF;

      IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'player_progress_hundred_rewarded_rights_check_v2'
          AND conrelid = 'player_progress'::regclass
      ) THEN
        BEGIN
          ALTER TABLE player_progress
            ADD CONSTRAINT player_progress_hundred_rewarded_rights_check_v2
            CHECK (hundred_rewarded_rights BETWEEN 0 AND 2);
        EXCEPTION WHEN duplicate_object THEN
          NULL;
        END;
      END IF;
    END
    $shared_progress_constraints_v5$;

    ALTER TABLE player_progress
      ADD COLUMN IF NOT EXISTS game_rights INTEGER NOT NULL DEFAULT 10;
    ALTER TABLE player_progress
      ADD COLUMN IF NOT EXISTS game_rights_refill_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
    ALTER TABLE player_progress
      ADD COLUMN IF NOT EXISTS diamond_balance INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE player_progress
      ADD COLUMN IF NOT EXISTS level_reward_claimed_through INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE player_progress
      ADD COLUMN IF NOT EXISTS two_player_finish_count INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE player_progress
      ADD COLUMN IF NOT EXISTS two_player_finish_total_ms BIGINT NOT NULL DEFAULT 0;

    ALTER TABLE players
      ADD COLUMN IF NOT EXISTS username_user_set BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE players
      ADD COLUMN IF NOT EXISTS username_change_count INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE players
      ADD COLUMN IF NOT EXISTS username_last_changed_at TIMESTAMPTZ;

    CREATE TABLE IF NOT EXISTS guest_credentials (
      guest_id TEXT PRIMARY KEY,
      secret_hash TEXT NOT NULL,
      linked_player_id TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      linked_at TIMESTAMPTZ
    );

    CREATE INDEX IF NOT EXISTS idx_guest_credentials_linked_player
      ON guest_credentials (linked_player_id);

    -- Bir Play Games hesabına yalnızca tek bir guest geçmişinin aktarılmasına izin verir.
    -- target_player_id PRIMARY KEY ve guest_id UNIQUE birlikte hem hedef hem kaynak tarafında
    -- tekrar/yarış durumlarını transaction seviyesinde engeller.
    CREATE TABLE IF NOT EXISTS play_games_guest_migrations (
      target_player_id TEXT PRIMARY KEY REFERENCES players(player_id) ON DELETE CASCADE,
      guest_id TEXT NOT NULL UNIQUE,
      migrated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    -- Daha önce guest -> PGS aktarımı yapılmış hesapları da korumaya al. Aynı PGS'ye geçmişte
    -- birden fazla guest bağlanmışsa en eski bağlantı seçilir ve hedef hesap bundan sonra yeni
    -- guest aktarımı kabul etmez. Tarama yalnızca bu migration ilk kez deploy edildiğinde çalışır.
    DO $guest_migration_guard_backfill$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE migration_id = 'guest_migration_guard_v1_20260814'
      ) THEN
        INSERT INTO play_games_guest_migrations (target_player_id, guest_id, migrated_at)
        SELECT DISTINCT ON (gc.linked_player_id)
          gc.linked_player_id,
          gc.guest_id,
          COALESCE(gc.linked_at, gc.updated_at, NOW())
        FROM guest_credentials gc
        JOIN players p ON p.player_id = gc.linked_player_id
        WHERE gc.linked_player_id IS NOT NULL
        ORDER BY gc.linked_player_id, COALESCE(gc.linked_at, gc.updated_at, NOW()) ASC, gc.guest_id ASC
        ON CONFLICT DO NOTHING;

        INSERT INTO schema_migrations (migration_id)
        VALUES ('guest_migration_guard_v1_20260814')
        ON CONFLICT (migration_id) DO NOTHING;
      END IF;
    END
    $guest_migration_guard_backfill$;

    -- 90 günlük pasif guest temizliğinde bütün tabloyu taramak yerine önce unlinked + eski
    -- credential adaylarını ucuz biçimde daralt. Aktif guest timestamp'i en fazla haftada bir dokunulur.
    CREATE INDEX IF NOT EXISTS idx_guest_credentials_unlinked_activity
      ON guest_credentials (updated_at, guest_id)
      WHERE linked_player_id IS NULL;

    -- Oyunların kendileri dışında bütün sistem ortaktır; yalnızca oyun bazlı ilerleme
    -- bu tabloda game_key ile ayrılır. Genel puan, 10 oyun hakkı, günlük 100 kişilik
    -- hakları ve turnuva biletleri player_progress içinde ortak kalır.
    CREATE TABLE IF NOT EXISTS player_game_progress (
      player_id TEXT NOT NULL REFERENCES players(player_id) ON DELETE CASCADE,
      game_key TEXT NOT NULL,
      infinite_score INTEGER NOT NULL DEFAULT 0 CHECK (infinite_score >= 0),
      infinite_run_score INTEGER NOT NULL DEFAULT 0 CHECK (infinite_run_score >= 0),
      infinite_next_stage INTEGER NOT NULL DEFAULT 1 CHECK (infinite_next_stage >= 1),
      tournament_stage INTEGER NOT NULL DEFAULT 1 CHECK (tournament_stage BETWEEN 1 AND 8),
      tournament_rights INTEGER NOT NULL DEFAULT 3 CHECK (tournament_rights BETWEEN 0 AND 3),
      tournament_bank INTEGER NOT NULL DEFAULT 0 CHECK (tournament_bank >= 0),
      tournament_completed BOOLEAN NOT NULL DEFAULT FALSE,
      tournament_entry_active BOOLEAN NOT NULL DEFAULT FALSE,
      hundred_active BOOLEAN NOT NULL DEFAULT FALSE,
      hundred_stage INTEGER NOT NULL DEFAULT 0 CHECK (hundred_stage BETWEEN 0 AND 12),
      two_player_finish_count INTEGER NOT NULL DEFAULT 0 CHECK (two_player_finish_count >= 0),
      two_player_finish_total_ms BIGINT NOT NULL DEFAULT 0 CHECK (two_player_finish_total_ms >= 0),
      stats JSONB NOT NULL DEFAULT '{}'::jsonb,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (player_id, game_key)
    );
    -- CREATE TABLE IF NOT EXISTS mevcut tabloyu değiştirmez. Eski/yarım migration ile
    -- player_game_progress daha önce oluşmuşsa eksik kolonların tamamını burada tamamla.
    -- Bu blok tekrar çalıştırılabilir; mevcut kolonlara dokunmaz.
    ALTER TABLE player_game_progress
      ADD COLUMN IF NOT EXISTS infinite_score INTEGER NOT NULL DEFAULT 0 CHECK (infinite_score >= 0);
    ALTER TABLE player_game_progress
      ADD COLUMN IF NOT EXISTS infinite_run_score INTEGER NOT NULL DEFAULT 0 CHECK (infinite_run_score >= 0);
    ALTER TABLE player_game_progress
      ADD COLUMN IF NOT EXISTS infinite_next_stage INTEGER NOT NULL DEFAULT 1 CHECK (infinite_next_stage >= 1);
    ALTER TABLE player_game_progress
      ADD COLUMN IF NOT EXISTS tournament_stage INTEGER NOT NULL DEFAULT 1 CHECK (tournament_stage BETWEEN 1 AND 8);
    ALTER TABLE player_game_progress
      ADD COLUMN IF NOT EXISTS tournament_rights INTEGER NOT NULL DEFAULT 3 CHECK (tournament_rights BETWEEN 0 AND 3);
    ALTER TABLE player_game_progress
      ADD COLUMN IF NOT EXISTS tournament_bank INTEGER NOT NULL DEFAULT 0 CHECK (tournament_bank >= 0);
    ALTER TABLE player_game_progress
      ADD COLUMN IF NOT EXISTS tournament_completed BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE player_game_progress
      ADD COLUMN IF NOT EXISTS tournament_entry_active BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE player_game_progress
      ADD COLUMN IF NOT EXISTS hundred_active BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE player_game_progress
      ADD COLUMN IF NOT EXISTS hundred_stage INTEGER NOT NULL DEFAULT 0 CHECK (hundred_stage BETWEEN 0 AND 12);
    ALTER TABLE player_game_progress
      ADD COLUMN IF NOT EXISTS two_player_finish_count INTEGER NOT NULL DEFAULT 0 CHECK (two_player_finish_count >= 0);
    ALTER TABLE player_game_progress
      ADD COLUMN IF NOT EXISTS two_player_finish_total_ms BIGINT NOT NULL DEFAULT 0 CHECK (two_player_finish_total_ms >= 0);
    ALTER TABLE player_game_progress
      ADD COLUMN IF NOT EXISTS stats JSONB NOT NULL DEFAULT '{}'::jsonb;
    ALTER TABLE player_game_progress
      ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

    CREATE INDEX IF NOT EXISTS idx_player_game_progress_game
      ON player_game_progress (game_key, player_id);

    -- Eski tek oyun sürümündeki Hedef Sayıyı Bul ilerlemesini ilk geçişte koru.
    INSERT INTO player_game_progress (
      player_id, game_key, infinite_score, infinite_run_score, infinite_next_stage,
      tournament_stage, tournament_rights, tournament_bank, tournament_completed,
      tournament_entry_active, hundred_active, hundred_stage,
      two_player_finish_count, two_player_finish_total_ms, updated_at
    )
    SELECT p.player_id, 'target_number', s.infinite_score, p.infinite_run_score, p.infinite_next_stage,
           p.tournament_stage, p.tournament_rights, p.tournament_bank, p.tournament_completed,
           p.tournament_entry_active, p.hundred_active, p.hundred_stage,
           p.two_player_finish_count, p.two_player_finish_total_ms, NOW()
    FROM player_progress p
    JOIN player_scores s ON s.player_id = p.player_id
    ON CONFLICT (player_id, game_key) DO NOTHING;

    CREATE TABLE IF NOT EXISTS secure_game_challenges (
      challenge_id TEXT PRIMARY KEY,
      player_id TEXT NOT NULL REFERENCES players(player_id) ON DELETE CASCADE,
      mode TEXT NOT NULL,
      difficulty TEXT NOT NULL,
      stage INTEGER NOT NULL DEFAULT 1,
      puzzle JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ NOT NULL,
      completed_at TIMESTAMPTZ,
      result JSONB
    );

    ALTER TABLE secure_game_challenges
      ADD COLUMN IF NOT EXISTS wager_points INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE secure_game_challenges
      ADD COLUMN IF NOT EXISTS game_key TEXT NOT NULL DEFAULT 'target_number';

    -- Yeni görev mimarisi: geçmiş event taramak yerine oyuncu başına tek aggregate satır.
    CREATE TABLE IF NOT EXISTS player_task_state (
      player_id TEXT PRIMARY KEY REFERENCES players(player_id) ON DELETE CASCADE,
      daily_key TEXT NOT NULL DEFAULT '',
      daily_state JSONB NOT NULL DEFAULT '{}'::jsonb,
      weekly_key TEXT NOT NULL DEFAULT '',
      weekly_state JSONB NOT NULL DEFAULT '{}'::jsonb,
      monthly_key TEXT NOT NULL DEFAULT '',
      monthly_state JSONB NOT NULL DEFAULT '{}'::jsonb,
      game_totals JSONB NOT NULL DEFAULT '{}'::jsonb,
      recent_sources JSONB NOT NULL DEFAULT '[]'::jsonb,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    ALTER TABLE player_task_state
      ADD COLUMN IF NOT EXISTS recent_sources JSONB NOT NULL DEFAULT '[]'::jsonb;

    CREATE INDEX IF NOT EXISTS idx_secure_challenges_player_active
      ON secure_game_challenges (player_id, mode, completed_at, expires_at);
    CREATE INDEX IF NOT EXISTS idx_secure_challenges_cleanup
      ON secure_game_challenges (completed_at, expires_at);

    -- Leaderboard eşitlik sırası artık ortak updated_at alanlarına bağlı değildir.
    -- Böylece bir skor türündeki hareket, başka bir skor tablosundaki eşitlik sırasını
    -- değiştirmez ve indeksler daha küçük / daha ucuz tutulur.
    DO $leaderboard_index_cleanup_v4$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE migration_id = 'leaderboard_index_cleanup_v4'
      ) THEN
        DROP INDEX IF EXISTS idx_player_scores_general;
        DROP INDEX IF EXISTS idx_player_scores_infinite;
        DROP INDEX IF EXISTS idx_monthly_scores_month_general;
        DROP INDEX IF EXISTS idx_monthly_scores_month_infinite;
        DROP INDEX IF EXISTS idx_player_scores_general_v2;
        DROP INDEX IF EXISTS idx_player_scores_infinite_v2;
        DROP INDEX IF EXISTS idx_player_scores_month_general_v3;
        DROP INDEX IF EXISTS idx_player_scores_month_infinite_v3;
        DROP INDEX IF EXISTS idx_players_country;
        INSERT INTO schema_migrations (migration_id)
        VALUES ('leaderboard_index_cleanup_v4')
        ON CONFLICT (migration_id) DO NOTHING;
      END IF;
    END
    $leaderboard_index_cleanup_v4$;

    CREATE INDEX IF NOT EXISTS idx_player_scores_general_v3
      ON player_scores (general_score DESC, player_id ASC)
      WHERE general_score > 0;

    CREATE INDEX IF NOT EXISTS idx_player_scores_infinite_v3
      ON player_scores (infinite_score DESC, player_id ASC)
      WHERE infinite_score > 0;

    CREATE INDEX IF NOT EXISTS idx_player_scores_month_general_v4
      ON player_scores (monthly_key, monthly_general_score DESC, player_id ASC)
      WHERE monthly_general_score > 0;

    CREATE INDEX IF NOT EXISTS idx_player_scores_month_infinite_v4
      ON player_scores (monthly_key, monthly_infinite_score DESC, player_id ASC)
      WHERE monthly_infinite_score > 0;

    CREATE INDEX IF NOT EXISTS idx_players_country_player_v2
      ON players (country, player_id);

    CREATE INDEX IF NOT EXISTS idx_players_username_lower
      ON players (LOWER(username));
  `);

  console.log("PostgreSQL leaderboard tabloları hazır.");
}

function currentMonthKey() {
  return new Date().toISOString().slice(0, 7);
}

/**
 * Genel ve mevcut-ay skorlarını tek player_scores UPDATE'i ile değiştirir.
 * Ay değişmişse aylık sayaçlar önce sıfır kabul edilir; böylece ayrı aylık tablo
 * ve günlük eski-ay temizleme işi gerekmez.
 */
async function applyLeaderboardScoreDeltaInTransaction(
  client,
  playerId,
  generalDelta = 0,
  infiniteDelta = 0
) {
  const monthKey = currentMonthKey();
  return client.query(
    `UPDATE player_scores
     SET general_score = GREATEST(0, LEAST(general_score::bigint + $2::bigint, 2000000000))::integer,
         infinite_score = GREATEST(0, LEAST(infinite_score::bigint + $3::bigint, 2000000000))::integer,
         monthly_general_score = CASE
           WHEN monthly_key = $4 THEN
             GREATEST(0, LEAST(monthly_general_score::bigint + $2::bigint, 2000000000))::integer
           ELSE GREATEST(0, LEAST($2::bigint, 2000000000))::integer
         END,
         monthly_infinite_score = CASE
           WHEN monthly_key = $4 THEN
             GREATEST(0, LEAST(monthly_infinite_score::bigint + $3::bigint, 2000000000))::integer
           ELSE GREATEST(0, LEAST($3::bigint, 2000000000))::integer
         END,
         monthly_key = $4,
         monthly_updated_at = NOW(),
         updated_at = NOW()
     WHERE player_id = $1`,
    [playerId, generalDelta, infiniteDelta, monthKey]
  );
}

/**
 * Sonsuz modda toplam sonsuz skor bir yüksek-skor değeridir; artış değildir.
 * Genel puanı eklerken hem tüm-zamanlar hem mevcut-ay sonsuz yüksek skorunu
 * tek player_scores UPDATE'i içinde GREATEST ile korur.
 */
async function applyLeaderboardGeneralDeltaAndInfiniteHighScoreInTransaction(
  client,
  playerId,
  generalDelta,
  infiniteHighScore
) {
  const monthKey = currentMonthKey();
  return client.query(
    `UPDATE player_scores
     SET general_score = GREATEST(0, LEAST(general_score::bigint + $2::bigint, 2000000000))::integer,
         infinite_score = GREATEST(infinite_score, GREATEST(0, LEAST($3::bigint, 2000000000))::integer),
         monthly_general_score = CASE
           WHEN monthly_key = $4 THEN
             GREATEST(0, LEAST(monthly_general_score::bigint + $2::bigint, 2000000000))::integer
           ELSE GREATEST(0, LEAST($2::bigint, 2000000000))::integer
         END,
         monthly_infinite_score = CASE
           WHEN monthly_key = $4 THEN
             GREATEST(monthly_infinite_score, GREATEST(0, LEAST($3::bigint, 2000000000))::integer)
           ELSE GREATEST(0, LEAST($3::bigint, 2000000000))::integer
         END,
         monthly_key = $4,
         monthly_updated_at = NOW(),
         updated_at = NOW()
     WHERE player_id = $1`,
    [playerId, generalDelta, infiniteHighScore, monthKey]
  );
}


const TASK_DEFINITIONS = [
  { code: "login", title: "Oyuna giriş yap", baseTarget: 1, baseReward: 10 },
  { code: "multiplayer_play", title: "Çok oyunculu oyun oyna", baseTarget: 3, baseReward: 20 },
  { code: "multiplayer_win", title: "Çok oyunculu oyunu kazan", baseTarget: 1, baseReward: 20 },
  { code: "different_games", title: "Farklı oyunlar oyna", baseTarget: 2, baseReward: 10 },
  { code: "different_multiplayer_games", title: "Farklı çok oyunculu oyunlar oyna", baseTarget: 2, baseReward: 20 },
];
const TASK_PERIOD_CONFIG = {
  daily: { multiplier: 1, diamondReward: 2 },
  weekly: { multiplier: 7, diamondReward: 15 },
  monthly: { multiplier: 30, diamondReward: 60 },
};

function taskDisplayTitle(code, target, periodType) {
  switch (code) {
    case "login":
      return target === 1 ? "Oyuna giriş yap" : `${target} gün oyuna giriş yap`;
    case "multiplayer_play":
      return `${target} çok oyunculu oyun oyna`;
    case "multiplayer_win":
      return `${target} çok oyunculu oyun kazan`;
    case "different_games":
      return periodType === "daily"
        ? `${target} farklı oyun oyna`
        : `${target} oyun oyna`;
    case "different_multiplayer_games":
      return periodType === "daily"
        ? `${target} farklı çok oyunculu oyun oyna`
        : `${target} çok oyunculu oyun oyna`;
    default:
      return `${target} görev ilerlemesi`;
  }
}

function taskPeriodInfo(type, now = new Date()) {
  const current = new Date(now.getTime());
  let start;
  let end;
  let key;
  if (type === "weekly") {
    start = new Date(Date.UTC(current.getUTCFullYear(), current.getUTCMonth(), current.getUTCDate()));
    const day = start.getUTCDay() || 7;
    start.setUTCDate(start.getUTCDate() - day + 1);
    end = new Date(start.getTime());
    end.setUTCDate(end.getUTCDate() + 7);
    key = start.toISOString().slice(0, 10);
  } else if (type === "monthly") {
    start = new Date(Date.UTC(current.getUTCFullYear(), current.getUTCMonth(), 1));
    end = new Date(Date.UTC(current.getUTCFullYear(), current.getUTCMonth() + 1, 1));
    key = start.toISOString().slice(0, 7);
  } else {
    start = new Date(Date.UTC(current.getUTCFullYear(), current.getUTCMonth(), current.getUTCDate()));
    end = new Date(start.getTime());
    end.setUTCDate(end.getUTCDate() + 1);
    key = start.toISOString().slice(0, 10);
  }
  return { type, key, start, end };
}

function emptyTaskAggregatePeriod() {
  return {
    login: 0,
    games: 0,
    multiplayer: 0,
    wins: 0,
    gameCounts: {},
    multiplayerGameCounts: {},
    claimed: {},
  };
}

function safeTaskCountMap(value) {
  const source = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const out = {};
  for (const [key, raw] of Object.entries(source)) {
    const gameKey = safeText(key, "", 64);
    if (!gameKey) continue;
    const count = Math.max(0, Math.min(Number(raw || 0), 2_000_000_000));
    if (count > 0) out[gameKey] = count;
  }
  return out;
}

function safeTaskClaimMap(value) {
  const source = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const out = {};
  const allowedCodes = new Set([...TASK_DEFINITIONS.map((item) => item.code), "all_complete"]);
  for (const [rawCode, rawClaimed] of Object.entries(source)) {
    const code = safeText(rawCode, "", 64).toLowerCase();
    if (!code || !allowedCodes.has(code) || rawClaimed !== true) continue;
    out[code] = true;
  }
  return out;
}

function normalizeTaskAggregatePeriod(value) {
  const source = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  return {
    login: Math.max(0, Number(source.login || 0)),
    games: Math.max(0, Number(source.games || 0)),
    multiplayer: Math.max(0, Number(source.multiplayer || 0)),
    wins: Math.max(0, Number(source.wins || 0)),
    gameCounts: safeTaskCountMap(source.gameCounts),
    multiplayerGameCounts: safeTaskCountMap(source.multiplayerGameCounts),
    claimed: safeTaskClaimMap(source.claimed),
  };
}

function incrementTaskMap(map, key) {
  if (!key) return;
  map[key] = Math.min(2_000_000_000, Math.max(0, Number(map[key] || 0)) + 1);
}

function taskSourceHash(value) {
  return crypto.createHash("sha256").update(String(value || "")).digest("hex").slice(0, 32);
}

const TASK_RECENT_SOURCE_LIMIT = 64;

function taskAggregateSkeleton(now = new Date()) {
  const daily = taskPeriodInfo("daily", now);
  const weekly = taskPeriodInfo("weekly", now);
  const monthly = taskPeriodInfo("monthly", now);
  return {
    dailyKey: daily.key,
    dailyState: emptyTaskAggregatePeriod(),
    weeklyKey: weekly.key,
    weeklyState: emptyTaskAggregatePeriod(),
    monthlyKey: monthly.key,
    monthlyState: emptyTaskAggregatePeriod(),
    gameTotals: {},
    recentSources: [],
  };
}

function normalizeTaskAggregateRow(row, now = new Date()) {
  const base = taskAggregateSkeleton(now);
  if (!row) return base;
  return {
    dailyKey: row.daily_key === base.dailyKey ? base.dailyKey : base.dailyKey,
    dailyState: row.daily_key === base.dailyKey
      ? normalizeTaskAggregatePeriod(row.daily_state)
      : emptyTaskAggregatePeriod(),
    weeklyKey: row.weekly_key === base.weeklyKey ? base.weeklyKey : base.weeklyKey,
    weeklyState: row.weekly_key === base.weeklyKey
      ? normalizeTaskAggregatePeriod(row.weekly_state)
      : emptyTaskAggregatePeriod(),
    monthlyKey: row.monthly_key === base.monthlyKey ? base.monthlyKey : base.monthlyKey,
    monthlyState: row.monthly_key === base.monthlyKey
      ? normalizeTaskAggregatePeriod(row.monthly_state)
      : emptyTaskAggregatePeriod(),
    gameTotals: safeTaskCountMap(row.game_totals),
    recentSources: Array.isArray(row.recent_sources)
      ? row.recent_sources
          .map((item) => String(item || "").toLowerCase())
          .filter((item) => /^[a-f0-9]{32}$/.test(item))
          .slice(-TASK_RECENT_SOURCE_LIMIT)
      : [],
  };
}

function applyTaskEventToAggregatePeriod(periodState, event) {
  if (event.eventType === "login") {
    periodState.login = 1;
    return;
  }
  if (event.eventType !== "game") return;
  periodState.games = Math.min(2_000_000_000, periodState.games + 1);
  if (event.gameKey) incrementTaskMap(periodState.gameCounts, event.gameKey);
  if (event.multiplayer) {
    periodState.multiplayer = Math.min(2_000_000_000, periodState.multiplayer + 1);
    if (event.gameKey) incrementTaskMap(periodState.multiplayerGameCounts, event.gameKey);
    if (event.won) periodState.wins = Math.min(2_000_000_000, periodState.wins + 1);
  }
}

function applyTaskEventToAggregate(aggregate, event) {
  applyTaskEventToAggregatePeriod(aggregate.dailyState, event);
  applyTaskEventToAggregatePeriod(aggregate.weeklyState, event);
  applyTaskEventToAggregatePeriod(aggregate.monthlyState, event);
  if (event.eventType === "game" && event.gameKey) {
    incrementTaskMap(aggregate.gameTotals, event.gameKey);
  }
}

function aggregateLegacyTaskEvents(rows, now = new Date()) {
  const aggregate = taskAggregateSkeleton(now);
  const periods = {
    daily: taskPeriodInfo("daily", now),
    weekly: taskPeriodInfo("weekly", now),
    monthly: taskPeriodInfo("monthly", now),
  };
  for (const row of rows) {
    const sourceKey = String(row.source_key || "").slice(0, 180);
    if (sourceKey) aggregate.recentSources.push(taskSourceHash(sourceKey));
    const occurredAt = new Date(row.occurred_at).getTime();
    const event = {
      eventType: row.event_type,
      gameKey: row.game_key || null,
      multiplayer: row.multiplayer === true,
      won: row.won === true,
    };
    if (event.eventType === "game" && event.gameKey) {
      incrementTaskMap(aggregate.gameTotals, event.gameKey);
    }
    for (const [type, period] of Object.entries(periods)) {
      if (occurredAt < period.start.getTime() || occurredAt >= period.end.getTime()) continue;
      const target = type === "daily"
        ? aggregate.dailyState
        : type === "weekly" ? aggregate.weeklyState : aggregate.monthlyState;
      applyTaskEventToAggregatePeriod(target, event);
    }
  }
  aggregate.recentSources = [...new Set(aggregate.recentSources)].slice(-TASK_RECENT_SOURCE_LIMIT);
  return aggregate;
}

async function persistTaskAggregateState(
  client,
  playerId,
  aggregate,
  { writeGameTotals = true } = {}
) {
  const commonValues = [
    playerId,
    aggregate.dailyKey,
    JSON.stringify(aggregate.dailyState),
    aggregate.weeklyKey,
    JSON.stringify(aggregate.weeklyState),
    aggregate.monthlyKey,
    JSON.stringify(aggregate.monthlyState),
  ];

  if (!writeGameTotals) {
    // Login gibi game_totals'ı değiştirmeyen eventlerde büyük/uzun ömürlü JSONB alanını tekrar yazma.
    await client.query(
      `INSERT INTO player_task_state
         (player_id, daily_key, daily_state, weekly_key, weekly_state,
          monthly_key, monthly_state, game_totals, recent_sources, updated_at)
       VALUES ($1, $2, $3::jsonb, $4, $5::jsonb, $6, $7::jsonb, '{}'::jsonb, $8::jsonb, NOW())
       ON CONFLICT (player_id) DO UPDATE SET
         daily_key = EXCLUDED.daily_key,
         daily_state = EXCLUDED.daily_state,
         weekly_key = EXCLUDED.weekly_key,
         weekly_state = EXCLUDED.weekly_state,
         monthly_key = EXCLUDED.monthly_key,
         monthly_state = EXCLUDED.monthly_state,
         recent_sources = EXCLUDED.recent_sources,
         updated_at = NOW()`,
      [
        ...commonValues,
        JSON.stringify((aggregate.recentSources || []).slice(-TASK_RECENT_SOURCE_LIMIT)),
      ]
    );
    return;
  }

  await client.query(
    `INSERT INTO player_task_state
       (player_id, daily_key, daily_state, weekly_key, weekly_state,
        monthly_key, monthly_state, game_totals, recent_sources, updated_at)
     VALUES ($1, $2, $3::jsonb, $4, $5::jsonb, $6, $7::jsonb, $8::jsonb, $9::jsonb, NOW())
     ON CONFLICT (player_id) DO UPDATE SET
       daily_key = EXCLUDED.daily_key,
       daily_state = EXCLUDED.daily_state,
       weekly_key = EXCLUDED.weekly_key,
       weekly_state = EXCLUDED.weekly_state,
       monthly_key = EXCLUDED.monthly_key,
       monthly_state = EXCLUDED.monthly_state,
       game_totals = EXCLUDED.game_totals,
       recent_sources = EXCLUDED.recent_sources,
       updated_at = NOW()`,
    [
      ...commonValues,
      JSON.stringify(aggregate.gameTotals),
      JSON.stringify((aggregate.recentSources || []).slice(-TASK_RECENT_SOURCE_LIMIT)),
    ]
  );
}

async function readTaskAggregateState(client, playerId, now = new Date()) {
  const current = await client.query(
    `SELECT daily_key, daily_state, weekly_key, weekly_state,
            monthly_key, monthly_state, game_totals, recent_sources
     FROM player_task_state
     WHERE player_id = $1`,
    [playerId]
  );
  if (current.rowCount > 0) return normalizeTaskAggregateRow(current.rows[0], now);
  // Yalnız ilk kullanım/migration durumunda kilitli oluşturma yoluna geç.
  return loadTaskAggregateStateForUpdate(client, playerId, now);
}

async function loadTaskAggregateStateForUpdate(
  client,
  playerId,
  now = new Date(),
  playerAlreadyEnsured = false
) {
  // requireAuth / socket kimlik doğrulaması oyuncu ana satırlarının varlığını garanti eder.
  // Burada her görev eventinde ayrıca ensure JOIN/SELECT gönderme.
  void playerAlreadyEnsured;
  let current = await client.query(
    `SELECT daily_key, daily_state, weekly_key, weekly_state,
            monthly_key, monthly_state, game_totals, recent_sources
     FROM player_task_state
     WHERE player_id = $1
     FOR UPDATE`,
    [playerId]
  );
  if (current.rowCount > 0) {
    return normalizeTaskAggregateRow(current.rows[0], now);
  }

  // İlk aggregate satırı oluşturulurken aynı oyuncuya ait iki paralel istek veri kaybetmesin.
  await client.query(`SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, [`task:${playerId}`]);
  current = await client.query(
    `SELECT daily_key, daily_state, weekly_key, weekly_state,
            monthly_key, monthly_state, game_totals, recent_sources
     FROM player_task_state
     WHERE player_id = $1
     FOR UPDATE`,
    [playerId]
  );
  if (current.rowCount > 0) {
    return normalizeTaskAggregateRow(current.rows[0], now);
  }

  // Legacy ham event tablosu startup migrasyonunda tek seferlik taşınıp kaldırılır.
  // Yeni oyuncuda doğrudan boş aggregate state oluştur.
  const aggregate = taskAggregateSkeleton(now);
  await persistTaskAggregateState(client, playerId, aggregate);
  return aggregate;
}

function taskPeriodTargetedMutationSql(baseExpression) {
  const base = `(${baseExpression})`;
  const gameCounts = `COALESCE(${base}->'gameCounts', '{}'::jsonb)`;
  const multiplayerGameCounts = `COALESCE(${base}->'multiplayerGameCounts', '{}'::jsonb)`;
  const claimed = `COALESCE(${base}->'claimed', '{}'::jsonb)`;
  return `jsonb_build_object(
    'login', CASE WHEN $6 = 'login' THEN 1 ELSE COALESCE((${base}->>'login')::bigint, 0) END,
    'games', LEAST(2000000000::bigint,
      COALESCE((${base}->>'games')::bigint, 0) + CASE WHEN $6 = 'game' THEN 1 ELSE 0 END),
    'multiplayer', LEAST(2000000000::bigint,
      COALESCE((${base}->>'multiplayer')::bigint, 0) + CASE WHEN $6 = 'game' AND $8 THEN 1 ELSE 0 END),
    'wins', LEAST(2000000000::bigint,
      COALESCE((${base}->>'wins')::bigint, 0) + CASE WHEN $6 = 'game' AND $8 AND $9 THEN 1 ELSE 0 END),
    'gameCounts', CASE
      WHEN $6 = 'game' AND $7 <> '' THEN jsonb_set(
        ${gameCounts}, ARRAY[$7],
        to_jsonb(LEAST(2000000000::bigint, COALESCE((${gameCounts}->>$7)::bigint, 0) + 1)), true)
      ELSE ${gameCounts}
    END,
    'multiplayerGameCounts', CASE
      WHEN $6 = 'game' AND $8 AND $7 <> '' THEN jsonb_set(
        ${multiplayerGameCounts}, ARRAY[$7],
        to_jsonb(LEAST(2000000000::bigint, COALESCE((${multiplayerGameCounts}->>$7)::bigint, 0) + 1)), true)
      ELSE ${multiplayerGameCounts}
    END,
    'claimed', ${claimed}
  )`;
}

async function recordTaskEventInTransaction(client, {
  playerId, sourceKey, eventType, gameKey = null, multiplayer = false, won = false,
  playerAlreadyEnsured = false,
}) {
  if (!playerId || !sourceKey) return false;
  // requireAuth / socket load oyuncu satırlarını zaten garanti ediyor. playerAlreadyEnsured
  // parametresi geriye dönük uyumluluk için tutuluyor; hot path'te ek ensure sorgusu yok.
  void playerAlreadyEnsured;

  const safeSourceKey = String(sourceKey).slice(0, 180);
  const sourceHash = taskSourceHash(safeSourceKey);
  const now = new Date();
  const normalizedGameKey = gameKey ? safeText(gameKey, '', 64) : '';
  const event = {
    eventType,
    gameKey: normalizedGameKey || null,
    multiplayer: multiplayer === true,
    won: won === true,
  };

  // İlk görev event'i için gereken başlangıç JSON'ları yalnız bir kez gönderilir. Mevcut oyuncuda
  // ON CONFLICT kolu tam JSONB payload'larını tekrar yazmak yerine yalnız değişen sayaç/path'leri
  // PostgreSQL içinde jsonb_set ile günceller. Böylece her oyun event'inde SELECT + büyük UPSERT yerine
  // tek SQL round-trip ve daha küçük istemci->PostgreSQL payload'ı kullanılır.
  const initial = taskAggregateSkeleton(now);
  applyTaskEventToAggregate(initial, event);
  initial.recentSources = [sourceHash];

  const dailyBase = `CASE WHEN player_task_state.daily_key = EXCLUDED.daily_key
    THEN player_task_state.daily_state ELSE '{}'::jsonb END`;
  const weeklyBase = `CASE WHEN player_task_state.weekly_key = EXCLUDED.weekly_key
    THEN player_task_state.weekly_state ELSE '{}'::jsonb END`;
  const monthlyBase = `CASE WHEN player_task_state.monthly_key = EXCLUDED.monthly_key
    THEN player_task_state.monthly_state ELSE '{}'::jsonb END`;

  const result = await client.query(
    `INSERT INTO player_task_state
       (player_id, daily_key, daily_state, weekly_key, weekly_state,
        monthly_key, monthly_state, game_totals, recent_sources, updated_at)
     VALUES ($1, $2, $10::jsonb, $3, $11::jsonb, $4, $12::jsonb, $13::jsonb, $14::jsonb, NOW())
     ON CONFLICT (player_id) DO UPDATE SET
       daily_key = EXCLUDED.daily_key,
       daily_state = ${taskPeriodTargetedMutationSql(dailyBase)},
       weekly_key = EXCLUDED.weekly_key,
       weekly_state = ${taskPeriodTargetedMutationSql(weeklyBase)},
       monthly_key = EXCLUDED.monthly_key,
       monthly_state = ${taskPeriodTargetedMutationSql(monthlyBase)},
       game_totals = CASE
         WHEN $6 = 'game' AND $7 <> '' THEN jsonb_set(
           COALESCE(player_task_state.game_totals, '{}'::jsonb), ARRAY[$7],
           to_jsonb(LEAST(
             2000000000::bigint,
             COALESCE((player_task_state.game_totals->>$7)::bigint, 0) + 1
           )), true
         )
         ELSE player_task_state.game_totals
       END,
       recent_sources = (
         CASE
           WHEN jsonb_array_length(COALESCE(player_task_state.recent_sources, '[]'::jsonb)) >= ${TASK_RECENT_SOURCE_LIMIT}
             THEN COALESCE(player_task_state.recent_sources, '[]'::jsonb) #- '{0}'
           ELSE COALESCE(player_task_state.recent_sources, '[]'::jsonb)
         END
       ) || jsonb_build_array($5::text),
       updated_at = NOW()
     WHERE NOT (COALESCE(player_task_state.recent_sources, '[]'::jsonb) ? $5)
     RETURNING daily_key, daily_state, weekly_key, weekly_state,
               monthly_key, monthly_state, game_totals, recent_sources`,
    [
      playerId,
      initial.dailyKey,
      initial.weeklyKey,
      initial.monthlyKey,
      sourceHash,
      event.eventType,
      normalizedGameKey,
      event.multiplayer,
      event.won,
      JSON.stringify(initial.dailyState),
      JSON.stringify(initial.weeklyState),
      JSON.stringify(initial.monthlyState),
      JSON.stringify(initial.gameTotals),
      JSON.stringify(initial.recentSources),
    ]
  );

  if (result.rowCount > 0) {
    return normalizeTaskAggregateRow(result.rows[0], now);
  }
  // Aynı sourceKey ikinci kez geldiyse UPDATE bilinçli olarak yapılmaz. Bu nadir idempotency
  // yolunda mevcut aggregate yalnız bir kez okunur.
  return readTaskAggregateState(client, playerId, now);
}

async function recordTaskGameEvent(playerId, sourceKey, gameKey, multiplayer, won) {
  if (!pool || !playerId) return;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await recordTaskEventInTransaction(client, {
      playerId, sourceKey, eventType: "game", gameKey, multiplayer, won,
    });
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

function favoriteTaskGameKey(gameTotals) {
  return Object.entries(safeTaskCountMap(gameTotals))
    .sort((a, b) => Number(b[1]) - Number(a[1]) || String(a[0]).localeCompare(String(b[0])))[0]?.[0] || null;
}

async function buildTaskCenterStateFromAggregate(_client, _playerId, aggregate, now = new Date()) {
  const favoriteGameKey = favoriteTaskGameKey(aggregate.gameTotals);
  const periods = ["daily", "weekly", "monthly"].map((type) => taskPeriodInfo(type, now));

  const periodStates = periods.map((period) => {
    const config = TASK_PERIOD_CONFIG[period.type];
    const state = period.type === "daily"
      ? aggregate.dailyState
      : period.type === "weekly" ? aggregate.weeklyState : aggregate.monthlyState;
    const distinctGames = Object.keys(state.gameCounts).length;
    const distinctMultiplayerGames = Object.keys(state.multiplayerGameCounts).length;
    const favoritePlays = favoriteGameKey ? Number(state.gameCounts[favoriteGameKey] || 0) : 0;
    const favoriteMultiplayerPlays = favoriteGameKey
      ? Number(state.multiplayerGameCounts[favoriteGameKey] || 0) : 0;
    const nonFavoriteGames = Math.max(0, state.games - favoritePlays);
    const nonFavoriteMultiplayerGames = Math.max(0, state.multiplayer - favoriteMultiplayerPlays);
    const counts = {
      login: state.login,
      multiplayer_play: state.multiplayer,
      multiplayer_win: state.wins,
      different_games: period.type === "daily" ? distinctGames : state.games,
      different_multiplayer_games: period.type === "daily" ? distinctMultiplayerGames : state.multiplayer,
    };

    const tasks = TASK_DEFINITIONS.map((definition) => {
      const target = definition.baseTarget * config.multiplier;
      const isDiversity = definition.code === "different_games" || definition.code === "different_multiplayer_games";
      const secondaryTarget = isDiversity && period.type !== "daily" ? target / 2 : null;
      const secondaryProgress = definition.code === "different_games"
        ? nonFavoriteGames
        : definition.code === "different_multiplayer_games" ? nonFavoriteMultiplayerGames : null;
      const progress = counts[definition.code] || 0;
      const completed = progress >= target && (secondaryTarget === null || secondaryProgress >= secondaryTarget);
      return {
        code: definition.code,
        title: taskDisplayTitle(definition.code, target, period.type),
        rewardScore: definition.baseReward * config.multiplier,
        progress,
        target,
        secondaryProgress,
        secondaryTarget,
        secondaryLabel: secondaryTarget === null ? null : "Favori dışı",
        completed,
        claimed: state.claimed?.[definition.code] === true,
      };
    });
    const allComplete = tasks.every((task) => task.completed);
    return {
      type: period.type,
      periodKey: period.key,
      endsAtMillis: period.end.getTime(),
      favoriteGameKey,
      tasks,
      allComplete,
      masterRewardDiamonds: config.diamondReward,
      masterClaimed: state.claimed?.all_complete === true,
    };
  });

  return { serverNowMillis: now.getTime(), periods: periodStates };
}

async function readTaskCenterState(client, playerId, forUpdate = false) {
  const now = new Date();
  const aggregate = forUpdate
    ? await loadTaskAggregateStateForUpdate(client, playerId, now)
    : await readTaskAggregateState(client, playerId, now);
  return buildTaskCenterStateFromAggregate(client, playerId, aggregate, now);
}

async function readTaskCenterStateReadMostly(playerId) {
  const now = new Date();
  const current = await pool.query(
    `SELECT daily_key, daily_state, weekly_key, weekly_state,
            monthly_key, monthly_state, game_totals, recent_sources
     FROM player_task_state
     WHERE player_id = $1`,
    [playerId]
  );
  if (current.rowCount > 0) {
    return buildTaskCenterStateFromAggregate(
      pool,
      playerId,
      normalizeTaskAggregateRow(current.rows[0], now),
      now
    );
  }

  // İlk kez görev merkezi açan oyuncuda yalnız bir kere kilitli aggregate satırı oluştur.
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const aggregate = await loadTaskAggregateStateForUpdate(client, playerId, now);
    const state = await buildTaskCenterStateFromAggregate(client, playerId, aggregate, now);
    await client.query('COMMIT');
    return state;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

function mergeTaskCountMaps(a, b) {
  const out = safeTaskCountMap(a);
  for (const [key, count] of Object.entries(safeTaskCountMap(b))) {
    out[key] = Math.min(2_000_000_000, Number(out[key] || 0) + Number(count || 0));
  }
  return out;
}

function mergeTaskAggregatePeriod(a, b) {
  const left = normalizeTaskAggregatePeriod(a);
  const right = normalizeTaskAggregatePeriod(b);
  return {
    login: Math.min(2_000_000_000, left.login + right.login),
    games: Math.min(2_000_000_000, left.games + right.games),
    multiplayer: Math.min(2_000_000_000, left.multiplayer + right.multiplayer),
    wins: Math.min(2_000_000_000, left.wins + right.wins),
    gameCounts: mergeTaskCountMaps(left.gameCounts, right.gameCounts),
    multiplayerGameCounts: mergeTaskCountMaps(left.multiplayerGameCounts, right.multiplayerGameCounts),
    claimed: { ...safeTaskClaimMap(left.claimed), ...safeTaskClaimMap(right.claimed) },
  };
}

async function mergeTaskAggregateStateForGuest(client, guestId, targetPlayerId) {
  const now = new Date();
  const guest = await loadTaskAggregateStateForUpdate(client, guestId, now);
  const target = await loadTaskAggregateStateForUpdate(client, targetPlayerId, now);
  const merged = {
    dailyKey: target.dailyKey,
    dailyState: mergeTaskAggregatePeriod(target.dailyState, guest.dailyState),
    weeklyKey: target.weeklyKey,
    weeklyState: mergeTaskAggregatePeriod(target.weeklyState, guest.weeklyState),
    monthlyKey: target.monthlyKey,
    monthlyState: mergeTaskAggregatePeriod(target.monthlyState, guest.monthlyState),
    gameTotals: mergeTaskCountMaps(target.gameTotals, guest.gameTotals),
    recentSources: [...new Set([...(target.recentSources || []), ...(guest.recentSources || [])])].slice(-TASK_RECENT_SOURCE_LIMIT),
  };
  await persistTaskAggregateState(client, targetPlayerId, merged);
}

async function claimTaskRewardInTransaction(client, playerId, periodType, taskCode) {
  const type = TASK_PERIOD_CONFIG[periodType] ? periodType : "daily";
  const period = taskPeriodInfo(type);
  const taskCenter = await readTaskCenterState(client, playerId, true);
  const periodState = taskCenter.periods.find((item) => item.type === type);
  const isMaster = taskCode === "all_complete";
  const task = periodState?.tasks.find((item) => item.code === taskCode);
  if ((!isMaster && (!task || !task.completed)) || (isMaster && !periodState?.allComplete)) {
    const error = new Error("Bu görev henüz tamamlanmadı.");
    error.statusCode = 409;
    error.publicCode = "TASK_NOT_COMPLETE";
    throw error;
  }

  const alreadyClaimed = isMaster ? periodState?.masterClaimed === true : task?.claimed === true;
  if (alreadyClaimed) return taskCenter;

  const rewardScore = isMaster ? 0 : task.rewardScore;
  const rewardDiamonds = isMaster ? periodState.masterRewardDiamonds : 0;
  const stateColumn = type === "daily" ? "daily_state" : type === "weekly" ? "weekly_state" : "monthly_state";
  const keyColumn = type === "daily" ? "daily_key" : type === "weekly" ? "weekly_key" : "monthly_key";

  // player_task_state satırı yukarıdaki FOR UPDATE ile zaten kilitli. Claim idempotency'sini ayrı bir
  // tarihsel tablo/INSERT yerine aynı aggregate JSON içinde tut; böylece claim SELECT/INSERT/cleanup yoktur.
  const marked = await client.query(
    `UPDATE player_task_state
     SET ${stateColumn} = jsonb_set(
           COALESCE(${stateColumn}, '{}'::jsonb),
           '{claimed}',
           COALESCE(${stateColumn}->'claimed', '{}'::jsonb) || jsonb_build_object($3::text, TRUE),
           true
         ),
         updated_at = NOW()
     WHERE player_id = $1
       AND ${keyColumn} = $2
       AND NOT (COALESCE(${stateColumn}->'claimed', '{}'::jsonb) ? $3)
     RETURNING player_id`,
    [playerId, period.key, taskCode]
  );

  if (marked.rowCount === 0) return taskCenter;

  if (rewardScore > 0) await addPositiveGeneralAndXpInTransaction(client, playerId, rewardScore, 0);
  if (rewardDiamonds > 0) {
    await client.query(
      `UPDATE player_progress SET diamond_balance = LEAST(diamond_balance + $2, 2000000000), updated_at = NOW()
       WHERE player_id = $1`,
      [playerId, rewardDiamonds]
    );
  }

  return {
    ...taskCenter,
    periods: taskCenter.periods.map((item) => {
      if (item.type !== type) return item;
      if (isMaster) return { ...item, masterClaimed: true };
      return {
        ...item,
        tasks: item.tasks.map((entry) =>
          entry.code === taskCode ? { ...entry, claimed: true } : entry
        ),
      };
    }),
  };
}

function timestampMillis(value) {
  if (!value) return 0;
  const millis = new Date(value).getTime();
  return Number.isFinite(millis) ? millis : 0;
}

function safeText(value, fallback, maxLength) {
  const text = String(value || fallback || "").trim();
  return (text || fallback || "").slice(0, maxLength);
}

function safeLeaderboardPlayerId(value) {
  return safeText(value, "", 96)
    .replace(/[^a-zA-Z0-9_.:-]/g, "")
    .slice(0, 96);
}

function safeUsername(value) {
  const username = safeText(value, "Oyuncu", 20).replace(/\s+/g, "");
  return username || "Oyuncu";
}

function validateRequestedUsername(value) {
  const raw = String(value ?? "");
  if (raw !== raw.trim() || raw.length < 3 || raw.length > 20) {
    return "Kullanıcı adı 3-20 karakter olmalı ve başında/sonunda boşluk bulunmamalı.";
  }
  if (!/^[\p{L}\p{N}][\p{L}\p{N}._-]*$/u.test(raw)) {
    return "Kullanıcı adı harf veya rakamla başlamalı; yalnızca harf, rakam, ., _ ve - içerebilir.";
  }
  return null;
}

function safeCountry(value) {
  return (
    safeText(value, "TR", 3)
      .toUpperCase()
      .replace(/[^A-Z]/g, "")
      .slice(0, 3) || "TR"
  );
}

function safeScore(value) {
  const number = Number(value || 0);

  if (!Number.isFinite(number)) return 0;

  return Math.max(
    0,
    Math.min(Math.floor(number), 2_000_000_000)
  );
}

function safeDelta(value) {
  const number = Number(value || 0);

  if (!Number.isFinite(number)) return 0;

  return Math.max(
    0,
    Math.min(
      Math.floor(number),
      Number(process.env.MAX_SCORE_DELTA || 100_000)
    )
  );
}

function safeSignedDelta(value) {
  const number = Number(value || 0);
  const maxDelta = Number(
    process.env.MAX_SCORE_DELTA || 100_000
  );

  if (!Number.isFinite(number)) return 0;

  return Math.max(
    -maxDelta,
    Math.min(Math.trunc(number), maxDelta)
  );
}

function requireDatabase(res) {
  if (!pool) {
    res.status(503).json({
      ok: false,
      message: "DATABASE_URL tanımlı değil.",
    });

    return false;
  }

  return true;
}

function usernameTakenError() {
  const error = new Error("Bu kullanıcı adı zaten alınmış.");
  error.statusCode = 409;
  error.publicCode = "USERNAME_TAKEN";
  return error;
}

function sendLeaderboardError(
  res,
  error,
  fallbackMessage,
  logLabel
) {
  const statusCode = Number(error.statusCode || 500);
  const isPublicError =
    statusCode >= 400 && statusCode < 500;

  if (!isPublicError) {
    console.error(logLabel, {
      message: error.message,
      code: error.code,
      detail: error.detail,
      stack: error.stack,
    });
  }

  res.status(isPublicError ? statusCode : 500).json({
    ok: false,
    code: error.publicCode,
    message: isPublicError
      ? error.message
      : fallbackMessage,
  });
}

async function ensurePlayerScoreRow(client, playerId) {
  await client.query(
    `INSERT INTO player_scores (player_id)
     VALUES ($1)
     ON CONFLICT (player_id) DO NOTHING`,
    [playerId]
  );
}

/**
 * Kullanıcı adı yalnızca kullanıcı adı kaydetme/değiştirme sırasında sahiplenilir.
 *
 * Güvenlik: kullanıcı adı hesap sahipliğinin kanıtı değildir. Bu nedenle eski local_ satırlar
 * artık yalnız aynı kullanıcı adına sahip diye otomatik olarak pg_ hesabına taşınmaz.
 */
async function claimOrCreatePlayer(
  client,
  playerId,
  username,
  country
) {
  await client.query(
    "SELECT pg_advisory_xact_lock(hashtext(LOWER($1::text)))",
    [username]
  );

  const ownersResult = await client.query(
    `SELECT player_id
     FROM players
     WHERE LOWER(username) = LOWER($1)
       AND player_id <> $2
     ORDER BY created_at ASC
     FOR UPDATE`,
    [username, playerId]
  );

  // local_ dahil başka bir oyuncunun aynı adı kullanması halinde migration yapılmaz.
  // Eski hesap aktarımı gerekiyorsa ayrıca sahiplik kanıtlı, tek kullanımlık migration akışı kurulmalıdır.
  if (ownersResult.rowCount > 0) {
    throw usernameTakenError();
  }

  await client.query(
    `INSERT INTO players (
       player_id,
       username,
       country,
       updated_at
     )
     VALUES ($1, $2, $3, NOW())
     ON CONFLICT (player_id)
     DO UPDATE SET
       username = EXCLUDED.username,
       country = EXCLUDED.country,
       updated_at = NOW()`,
    [playerId, username, country]
  );

  await ensurePlayerScoreRow(client, playerId);
}

/**
 * Skor isteği mevcut oyuncunun kullanıcı adını tekrar sahiplenmez.
 *
 * Böylece geçici/eski kullanıcı adı verisi skor güncellemesini
 * 409 hatasıyla durduramaz.
 *
 * Oyuncu kimliği henüz sunucuda yoksa normal ilk kayıt yapılır.
 * Kullanıcı adına bakarak legacy hesap birleştirmesi yapılmaz.
 */
async function ensurePlayerForScore(
  client,
  playerId,
  username,
  country
) {
  const existingResult = await client.query(
    `SELECT player_id
     FROM players
     WHERE player_id = $1
     FOR UPDATE`,
    [playerId]
  );

  if (existingResult.rowCount > 0) {
    await client.query(
      `UPDATE players
       SET
         country = $2,
         updated_at = NOW()
       WHERE player_id = $1`,
      [playerId, country]
    );

    await ensurePlayerScoreRow(client, playerId);
    return;
  }

  await claimOrCreatePlayer(
    client,
    playerId,
    username,
    country
  );
}


function secureDifficulty(_value) {
  // İstemciden eski Medium/Hard değeri gelse bile bütün yeni oyunlar tek seviyededir.
  return "Standard";
}

function shuffled(values) {
  const result = [...values];
  for (let i = result.length - 1; i > 0; i -= 1) {
    const j = crypto.randomInt(0, i + 1);
    [result[i], result[j]] = [result[j], result[i]];
  }
  return result;
}

function permutations(values) {
  if (values.length <= 1) return [values];
  const out = [];
  values.forEach((value, index) => {
    const rest = values.slice(0, index).concat(values.slice(index + 1));
    permutations(rest).forEach((tail) => out.push([value, ...tail]));
  });
  const seen = new Set();
  return out.filter((item) => {
    const key = item.join(",");
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function operatorOrders(operators, count) {
  if (count <= 0) return [[]];
  const out = [];
  operators.forEach((operator) => {
    operatorOrders(operators, count - 1).forEach((tail) => out.push([operator, ...tail]));
  });
  return out;
}

function evaluateExpression(orderedNumbers, operators) {
  if (!Array.isArray(orderedNumbers) || orderedNumbers.length === 0 || operators.length !== orderedNumbers.length - 1) return null;
  const additiveNumbers = [Number(orderedNumbers[0])];
  const additiveOperators = [];
  for (let index = 0; index < operators.length; index += 1) {
    const operator = operators[index];
    const nextNumber = Number(orderedNumbers[index + 1]);
    if (!Number.isFinite(nextNumber)) return null;
    if (operator === "×") additiveNumbers[additiveNumbers.length - 1] *= nextNumber;
    else if (operator === "÷") {
      if (Math.abs(nextNumber) < 0.0001) return null;
      additiveNumbers[additiveNumbers.length - 1] /= nextNumber;
    } else if (operator === "+" || operator === "−") {
      additiveOperators.push(operator);
      additiveNumbers.push(nextNumber);
    } else return null;
  }
  let result = additiveNumbers[0];
  additiveOperators.forEach((operator, index) => {
    result = operator === "+" ? result + additiveNumbers[index + 1] : result - additiveNumbers[index + 1];
  });
  return Number.isFinite(result) ? result : null;
}

function buildAddSubtractOnlyTargets(numbers) {
  const targets = new Set();
  permutations(numbers).forEach((order) => {
    operatorOrders(["+", "−"], numbers.length - 1).forEach((ops) => {
      const value = evaluateExpression(order, ops);
      if (value !== null && Math.abs(value - Math.round(value)) < 0.0001) targets.add(Math.round(value));
    });
  });
  return targets;
}

function buildSolvableTarget(numbers, minTarget, maxTarget, requireMultiplyOrDivide) {
  const allOperators = ["+", "−", "×", "÷"];
  const forbidden = requireMultiplyOrDivide ? buildAddSubtractOnlyTargets(numbers) : new Set();
  const numberOrders = shuffled(permutations(numbers));
  const opOrders = shuffled(operatorOrders(allOperators, numbers.length - 1));
  for (const order of numberOrders) {
    for (const ops of opOrders) {
      if (requireMultiplyOrDivide && !ops.some((op) => op === "×" || op === "÷")) continue;
      const result = evaluateExpression(order, ops);
      if (result === null) continue;
      const rounded = Math.round(result);
      if (Math.abs(result - rounded) < 0.0001 && rounded >= minTarget && rounded <= maxTarget && !forbidden.has(rounded)) return rounded;
    }
  }
  return null;
}

const GAME_DEFINITIONS = Object.freeze({
  target_number: Object.freeze({
    key: "target_number",
    displayName: "HEDEF SAYIYI BUL",
    roundDurationMs: 2 * 60 * 1000,
    hundredStageDurationMs: 90 * 1000,
    // Bot algoritması ortaktır; yalnız bu değerler oyuna özeldir.
    botFinishMinMs: 24 * 1000,
    botFinishMaxMs: 105 * 1000,
    botCalibrationMinMs: 90 * 1000,
    botCalibrationMaxMs: 119 * 1000,
    botAverageVarianceMs: 4 * 1000,
    infiniteDifficultyForStage: (stage) => Number(stage || 1) <= 5 ? "Medium" : "Hard",
  }),
  equal_sum: Object.freeze({
    key: "equal_sum",
    displayName: "EŞİT TOPLAM",
    // Normal / sonsuz / ikili / turnuva tur süresi 5 dakika.
    roundDurationMs: 5 * 60 * 1000,
    hundredStageDurationMs: 90 * 1000,
    // İlk 5 kalibrasyon: Hedef Sayıyı Bul'un 90-119 sn temel aralığının tam 2.5 katı.
    botFinishMinMs: 1 * 1000,
    botFinishMaxMs: 299 * 1000,
    botCalibrationMinMs: 225 * 1000,
    botCalibrationMaxMs: 297_500,
    // 6. oyundan itibaren oyuncunun o oyundaki ortalaması ±7 sn.
    botAverageVarianceMs: 7 * 1000,
    infiniteDifficultyForStage: () => "Standard",
  }),
  total_equals: Object.freeze({
    key: "total_equals",
    displayName: "TOPLAM EŞİTTİR",
    roundDurationMs: 5 * 60 * 1000,
    hundredStageDurationMs: 90 * 1000,
    botFinishMinMs: 1 * 1000,
    botFinishMaxMs: 299 * 1000,
    // Toplam Eşittir ilk 5 bot kalibrasyonu 4-5 dakika. Gerçek bitiş süresi
    // createTwoPlayerBotFinishMs içinde tur sonundan 1 sn önce güvenli biçimde sınırlandırılır.
    botCalibrationMinMs: 4 * 60 * 1000,
    botCalibrationMaxMs: 5 * 60 * 1000,
    botAverageVarianceMs: 7 * 1000,
    infiniteDifficultyForStage: () => "Standard",
  }),
  next_number: Object.freeze({
    key: "next_number",
    displayName: "SONRAKİ SAYI",
    // Normal / sonsuz / ikili / turnuva tur süresi 2 dakika.
    roundDurationMs: 2 * 60 * 1000,
    hundredStageDurationMs: 90 * 1000,
    // Bot profili Hedef Sayıyı Bul ile birebir aynıdır: ilk 5 tur 90-119 sn, sonrasında oyuncu ortalamasının ±4 sn çevresi.
    botFinishMinMs: 24 * 1000,
    botFinishMaxMs: 105 * 1000,
    botCalibrationMinMs: 90 * 1000,
    botCalibrationMaxMs: 119 * 1000,
    botAverageVarianceMs: 4 * 1000,
    infiniteDifficultyForStage: () => "Standard",
  }),
  equation_hunt: Object.freeze({
    key: "equation_hunt",
    displayName: "DENKLEM AVI",
    // Denklem Avı da ortak 2 dakikalık rekabet temposunu kullanır.
    roundDurationMs: 2 * 60 * 1000,
    hundredStageDurationMs: 90 * 1000,
    // Ortak bot motorunda Hedef Sayıyı Bul / Sonraki Sayı profili kullanılır.
    botFinishMinMs: 24 * 1000,
    botFinishMaxMs: 105 * 1000,
    botCalibrationMinMs: 90 * 1000,
    botCalibrationMaxMs: 119 * 1000,
    botAverageVarianceMs: 4 * 1000,
    infiniteDifficultyForStage: () => "Standard",
  }),
  shortest_path: Object.freeze({
    key: "shortest_path",
    displayName: "EN KISA YOL",
    // Beş şehirli rota oyunu ortak 2 dakikalık rekabet temposunu kullanır.
    roundDurationMs: 2 * 60 * 1000,
    hundredStageDurationMs: 90 * 1000,
    // Botun bitirme zamanı ortak Hedef Sayıyı Bul / Sonraki Sayı profiliyle aynıdır.
    // Yalnızca bu oyuna özel %21 yanlış rota davranışı aşağıdaki ortak bot planına eklenir.
    botFinishMinMs: 24 * 1000,
    botFinishMaxMs: 105 * 1000,
    botCalibrationMinMs: 90 * 1000,
    botCalibrationMaxMs: 119 * 1000,
    botAverageVarianceMs: 4 * 1000,
    infiniteDifficultyForStage: () => "Standard",
  }),
  digit_attack: Object.freeze({
    key: "digit_attack",
    displayName: "RAKAM SALDIRISI",
    roundDurationMs: 2 * 60 * 1000,
    hundredStageDurationMs: 2 * 60 * 1000,
    // İlk 5: 90-119 sn. Sonrasında oyuncunun Rakam Saldırısı ortalaması ±4 sn;
    // eski 80 sn alt sınırı bu ortak davranışı bozduğu için kaldırıldı.
    botFinishMinMs: 1 * 1000,
    botFinishMaxMs: 119 * 1000,
    botCalibrationMinMs: 90 * 1000,
    botCalibrationMaxMs: 119 * 1000,
    botAverageVarianceMs: 4 * 1000,
    infiniteDifficultyForStage: () => "Standard",
  }),
  consecutive: Object.freeze({
    key: "consecutive",
    displayName: "ARDIŞIK",
    // 15 taşlı 5x5 tahta için ortak rekabet süresi 5 dakika.
    roundDurationMs: 5 * 60 * 1000,
    hundredStageDurationMs: 90 * 1000,
    // Ortak bot motoru; Toplam Eşittir ile aynı 4-5 dk kalibrasyon + oyuncu ortalamasının ±7 sn çevresi.
    botFinishMinMs: 1 * 1000,
    botFinishMaxMs: 299 * 1000,
    botCalibrationMinMs: 4 * 60 * 1000,
    botCalibrationMaxMs: 5 * 60 * 1000,
    botAverageVarianceMs: 7 * 1000,
    infiniteDifficultyForStage: () => "Standard",
  }),
});

function unsupportedGameError(value) {
  const raw = String(value ?? "").trim().slice(0, 96);
  const error = new Error(`Desteklenmeyen oyun anahtarı: ${raw || "(boş)"}`);
  error.statusCode = 400;
  error.publicCode = "UNSUPPORTED_GAME";
  return error;
}

function normalizeBaseGameKey(value) {
  // Eski istemciler gameKey göndermiyorsa Hedef Sayıyı Bul geriye dönük varsayılan olmaya devam eder.
  // Fakat açıkça gönderilmiş bilinmeyen bir anahtar ASLA target_number'a sessizce çevrilmez.
  const raw = String(value ?? "").trim();
  const cleaned = (raw || "target_number").toLowerCase().slice(0, 96);
  const withoutStage = cleaned.replace(/_stage_\d+$/, "");
  const base = withoutStage.replace(/_(?:tournament|hundred)$/, "");
  if (!GAME_DEFINITIONS[base]) throw unsupportedGameError(raw || base);
  return base;
}

function gameDefinition(value) {
  return GAME_DEFINITIONS[normalizeBaseGameKey(value)];
}

function gameModeKey(value, mode) {
  const base = normalizeBaseGameKey(value);
  if (mode === "tournament") return `${base}_tournament`;
  if (mode === "hundred") return `${base}_hundred`;
  return base;
}

// HTTP tarafında gameKey taşıyan bütün oyun isteklerini handler'a girmeden önce doğrula.
// Böylece yeni Android oyunu Render'a eklenmeyi unutursa yanlışlıkla Hedef Sayıyı Bul verisine yazılmaz.
app.use((req, res, next) => {
  if (!String(req.path || "").startsWith("/game")) return next();
  const candidates = [req.body?.gameKey, req.query?.gameKey];
  for (const candidate of candidates) {
    if (candidate === undefined || candidate === null || String(candidate).trim() === "") continue;
    try {
      normalizeBaseGameKey(candidate);
    } catch (error) {
      res.status(error.statusCode || 400).json({
        ok: false,
        code: error.publicCode || "UNSUPPORTED_GAME",
        message: error.message || "Desteklenmeyen oyun.",
      });
      return;
    }
  }
  next();
});

function lineHasFourDistinctValues(values) {
  return Array.isArray(values) && values.length === 4 && new Set(values.map(Number)).size === 4;
}

function generateEqualSumSolution(target) {
  const maxCell = Math.max(6, target - 3);
  for (let attempt = 0; attempt < 30000; attempt += 1) {
    const grid = Array.from({ length: 4 }, () => Array(4).fill(0));
    let firstNineSum = 0;
    let failed = false;
    for (let row = 0; row < 3 && !failed; row += 1) {
      for (let col = 0; col < 3; col += 1) {
        // Merkez hücreleri hedefin yaklaşık dörtte biri çevresinde tutmak,
        // türetilen son satır/sütunda pozitif sayı bulma olasılığını yükseltir.
        const upper = Math.max(2, Math.min(maxCell, Math.floor(target * 0.55)));
        grid[row][col] = secureRandomInt(1, upper + 1);
        firstNineSum += grid[row][col];
      }
      const last = target - grid[row][0] - grid[row][1] - grid[row][2];
      if (last <= 0 || last > maxCell) failed = true;
      else grid[row][3] = last;
    }
    if (failed) continue;
    for (let col = 0; col < 3; col += 1) {
      const last = target - grid[0][col] - grid[1][col] - grid[2][col];
      if (last <= 0 || last > maxCell) { failed = true; break; }
      grid[3][col] = last;
    }
    if (failed) continue;
    grid[3][3] = target - grid[3][0] - grid[3][1] - grid[3][2];
    if (grid[3][3] <= 0 || grid[3][3] > maxCell) continue;
    if (grid[0][3] + grid[1][3] + grid[2][3] + grid[3][3] !== target) continue;

    const lines = [];
    for (let row = 0; row < 4; row += 1) lines.push([...grid[row]]);
    for (let col = 0; col < 4; col += 1) lines.push(grid.map((row) => row[col]));
    if (!lines.every((line) => line.reduce((a, b) => a + b, 0) === target && lineHasFourDistinctValues(line))) continue;
    // Kullanıcının istediği gibi iki satır/sütun tamamen aynı sıralı dörtlü olmasın.
    const signatures = lines.map((line) => line.join(","));
    if (new Set(signatures).size !== signatures.length) continue;
    return grid.flat();
  }
  return null;
}

function chooseEqualSumInitialIndices() {
  for (let attempt = 0; attempt < 2000; attempt += 1) {
    const selected = shuffled(Array.from({ length: 16 }, (_, index) => index)).slice(0, 8);
    const rowCounts = [0, 0, 0, 0];
    const colCounts = [0, 0, 0, 0];
    for (const index of selected) {
      rowCounts[Math.floor(index / 4)] += 1;
      colCounts[index % 4] += 1;
    }
    if (rowCounts.every((count) => count <= 3) && colCounts.every((count) => count <= 3)) return selected;
  }
  return [0, 1, 4, 6, 9, 11, 14, 15];
}

function generateEqualSumPuzzle() {
  for (let targetAttempt = 0; targetAttempt < 120; targetAttempt += 1) {
    const target = secureRandomInt(12, 51);
    const solution = generateEqualSumSolution(target);
    if (!solution) continue;
    const fixedIndices = new Set(chooseEqualSumInitialIndices());
    const initialGrid = solution.map((value, index) => fixedIndices.has(index) ? value : null);
    const numbers = shuffled(solution.filter((_, index) => !fixedIndices.has(index)));
    if (numbers.length !== 8 || initialGrid.filter((value) => value !== null).length !== 8) continue;
    return {
      gameKey: "equal_sum",
      difficulty: "Standard",
      target,
      numbers,
      initialGrid,
    };
  }
  // Çok düşük hedeflerde rastgele üretim olağan dışı biçimde başarısız olursa
  // güvenli aralıkta yeniden üret; hard-coded çözüm göndermek yerine üretimi tekrar deneriz.
  const target = 34;
  const base = [
    16, 2, 3, 13,
    5, 11, 10, 8,
    9, 7, 6, 12,
    4, 14, 15, 1,
  ];
  const fixedIndices = new Set(chooseEqualSumInitialIndices());
  return {
    gameKey: "equal_sum",
    difficulty: "Standard",
    target,
    numbers: shuffled(base.filter((_, index) => !fixedIndices.has(index))),
    initialGrid: base.map((value, index) => fixedIndices.has(index) ? value : null),
  };
}

const TOTAL_EQUALS_PAIR_COUNT = 15;
const TOTAL_EQUALS_NUMBER_COUNT = TOTAL_EQUALS_PAIR_COUNT * 2;
const TOTAL_EQUALS_TARGET_MIN = 21;
const TOTAL_EQUALS_TARGET_MAX = 40;

function totalEqualsSplitPuzzle(puzzle) {
  const target = Number(puzzle?.target);
  const numbers = Array.isArray(puzzle?.numbers) ? puzzle.numbers.map(Number) : [];
  if (!Number.isInteger(target) || target < TOTAL_EQUALS_TARGET_MIN || target > TOTAL_EQUALS_TARGET_MAX) return null;
  if (numbers.length !== TOTAL_EQUALS_NUMBER_COUNT || numbers.some((value) => !Number.isInteger(value))) return null;
  const left = numbers.slice(0, TOTAL_EQUALS_PAIR_COUNT);
  const right = numbers.slice(TOTAL_EQUALS_PAIR_COUNT);
  if (left.some((value) => value <= 0 || value >= target)) return null;
  if (right.some((value) => value <= 0 || value >= target)) return null;
  if (new Set(left).size !== TOTAL_EQUALS_PAIR_COUNT) return null;
  if (new Set(right).size !== TOTAL_EQUALS_PAIR_COUNT) return null;

  const expectedRight = left.map((value) => target - value).sort((a, b) => a - b);
  const actualRight = [...right].sort((a, b) => a - b);
  if (!expectedRight.every((value, index) => value === actualRight[index])) return null;

  // İki taraf bağımsız karışık görünür; doğru çift başlangıçta aynı satıra denk gelmez.
  if (left.some((value, index) => value + right[index] === target)) return null;
  return { target, left, right };
}

function derangeTotalEqualsRight(left, target) {
  const complements = left.map((value) => target - value);
  for (let attempt = 0; attempt < 40; attempt += 1) {
    const candidate = shuffled(complements);
    if (candidate.every((value, index) => left[index] + value !== target)) return candidate;
  }

  // Benzersiz complementler için bir hücrelik döndürme her satırdaki doğru eşleşmeyi kesin bozar.
  return complements.slice(1).concat(complements[0]);
}

function generateTotalEqualsPuzzle() {
  const target = secureRandomInt(TOTAL_EQUALS_TARGET_MIN, TOTAL_EQUALS_TARGET_MAX + 1);
  const candidates = shuffled(Array.from({ length: target - 1 }, (_, index) => index + 1));
  const left = shuffled(candidates.slice(0, TOTAL_EQUALS_PAIR_COUNT));
  const right = derangeTotalEqualsRight(left, target);
  return {
    gameKey: "total_equals",
    difficulty: "Standard",
    target,
    numbers: [...left, ...right],
    initialGrid: [],
  };
}

function normalizeTotalEqualsMatches(answer = {}) {
  if (Array.isArray(answer.matches)) {
    return answer.matches.map((match) => ({
      leftIndex: Number(match?.leftIndex),
      rightIndex: Number(match?.rightIndex),
    }));
  }

  // Yeni istemcide kullanılmaz; generic state'in numberSlots biçimini eski istemci/server
  // geçişlerinde okuyabilmek için yalnız uyumluluk yolu olarak tutulur.
  if (Array.isArray(answer.numberSlots) && answer.numberSlots.length === TOTAL_EQUALS_PAIR_COUNT) {
    return answer.numberSlots.map((rightIndex, leftIndex) => ({
      leftIndex,
      rightIndex: Number(rightIndex),
    }));
  }
  return [];
}

function validateTotalEqualsChallengeAnswer(puzzle, answer = {}) {
  const parsed = totalEqualsSplitPuzzle(puzzle);
  if (!parsed) return false;
  const matches = normalizeTotalEqualsMatches(answer);
  if (matches.length !== TOTAL_EQUALS_PAIR_COUNT) return false;

  const usedLeft = new Set();
  const usedRight = new Set();
  for (const match of matches) {
    const leftIndex = Number(match.leftIndex);
    const rightIndex = Number(match.rightIndex);
    if (!Number.isInteger(leftIndex) || !Number.isInteger(rightIndex)) return false;
    if (leftIndex < 0 || leftIndex >= TOTAL_EQUALS_PAIR_COUNT) return false;
    if (rightIndex < 0 || rightIndex >= TOTAL_EQUALS_PAIR_COUNT) return false;
    if (usedLeft.has(leftIndex) || usedRight.has(rightIndex)) return false;
    if (parsed.left[leftIndex] + parsed.right[rightIndex] !== parsed.target) return false;
    usedLeft.add(leftIndex);
    usedRight.add(rightIndex);
  }

  return usedLeft.size === TOTAL_EQUALS_PAIR_COUNT && usedRight.size === TOTAL_EQUALS_PAIR_COUNT;
}

const NEXT_NUMBER_MIN_VALUE = 0;
const NEXT_NUMBER_MAX_VALUE = 99;
const NEXT_NUMBER_MIN_FIXED_OFFSET = 1;
const NEXT_NUMBER_MAX_FIXED_OFFSET = 5;

// Sabit olmayan y yalnızca bu altı desen olabilir ve yalnızca "sayı × x ± y"
// kurallarında kullanılır. Böylece 1-4-7, 2-5-8, 7-5-3 gibi başka
// aritmetik diziler üretilemez. "(sayı ± y) × x" kurallarında ise y her
// üç geçişte de sabittir. Sabit y değeri bütün kural türlerinde 1..5'tir.
const NEXT_NUMBER_VARIABLE_OFFSET_SERIES = Object.freeze([
  Object.freeze([1, 2, 3]),
  Object.freeze([3, 2, 1]),
  Object.freeze([2, 4, 6]),
  Object.freeze([6, 4, 2]),
  Object.freeze([3, 6, 9]),
  Object.freeze([9, 6, 3]),
]);

function nextNumberStep(value, multiplier, offset, ruleType) {
  switch (ruleType) {
    case "multiply_plus": return value * multiplier + offset;
    case "multiply_minus": return value * multiplier - offset;
    case "plus_then_multiply": return (value + offset) * multiplier;
    case "minus_then_multiply": return (value - offset) * multiplier;
    default: return Number.NaN;
  }
}

function generateNextNumberOffsetSeries(ruleType) {
  // Önce y eklenip/çıkarılıp sonra çarpılan kurallarda değişken y YOKTUR.
  // Örn. (sayı + 3) × 2 ise sonraki iki geçiş de yine +3 kullanır.
  const mustUseFixedOffset =
    ruleType === "plus_then_multiply" || ruleType === "minus_then_multiply";

  const useFixedOffset = mustUseFixedOffset || secureRandomInt(0, 2) === 0;
  if (useFixedOffset) {
    const offset = secureRandomInt(
      NEXT_NUMBER_MIN_FIXED_OFFSET,
      NEXT_NUMBER_MAX_FIXED_OFFSET + 1
    );
    return [offset, offset, offset];
  }

  // Değişken y yalnızca sayı × x + y / sayı × x - y kurallarında kullanılır.
  const pattern = NEXT_NUMBER_VARIABLE_OFFSET_SERIES[
    secureRandomInt(0, NEXT_NUMBER_VARIABLE_OFFSET_SERIES.length)
  ];
  return [...pattern];
}

function generateNextNumberPuzzle() {
  const ruleTypes = ["multiply_plus", "multiply_minus", "plus_then_multiply", "minus_then_multiply"];

  for (let attempt = 0; attempt < 7000; attempt += 1) {
    const multiplier = secureRandomInt(2, 13); // x = 2..12; x her zaman en az 2.
    const ruleType = ruleTypes[secureRandomInt(0, ruleTypes.length)];
    const offsets = generateNextNumberOffsetSeries(ruleType);
    const first = secureRandomInt(0, 21);
    const sequence = [first];

    for (let index = 0; index < 3; index += 1) {
      const next = nextNumberStep(sequence[sequence.length - 1], multiplier, offsets[index], ruleType);
      if (!Number.isInteger(next) || next < NEXT_NUMBER_MIN_VALUE || next > NEXT_NUMBER_MAX_VALUE) break;
      sequence.push(next);
    }

    if (sequence.length !== 4) continue;
    if (new Set(sequence).size !== 4) continue;

    return {
      gameKey: "next_number",
      difficulty: "Standard",
      target: sequence[3],
      numbers: sequence.slice(0, 3),
      initialGrid: [],
    };
  }

  // RNG'nin olağan dışı biçimde geçerli dizi üretememesi durumunda da izin verilen sabit kurala uyan fallback.
  // 3 -> 8 -> 18 -> 38 : her adım 2x+2.
  return {
    gameKey: "next_number",
    difficulty: "Standard",
    target: 38,
    numbers: [3, 8, 18],
    initialGrid: [],
  };
}

function validateNextNumberChallengeAnswer(puzzle, answer = {}) {
  const numbers = Array.isArray(puzzle?.numbers) ? puzzle.numbers.map(Number) : [];
  const target = Number(puzzle?.target);
  const submitted = Number(answer?.nextNumber);
  if (numbers.length !== 3 || numbers.some((value) => !Number.isInteger(value))) return false;
  if (!Number.isInteger(target) || target < NEXT_NUMBER_MIN_VALUE || target > NEXT_NUMBER_MAX_VALUE) return false;
  if (numbers.some((value) => value < NEXT_NUMBER_MIN_VALUE || value > NEXT_NUMBER_MAX_VALUE)) return false;
  if (new Set([...numbers, target]).size !== 4) return false;
  return Number.isInteger(submitted) && submitted === target;
}



const CONSECUTIVE_GRID_SIZE = 5;
const CONSECUTIVE_CELL_COUNT = 25;
const CONSECUTIVE_FIXED_COUNT = 10;
const CONSECUTIVE_POOL_COUNT = 15;

function consecutiveLineInfo(values) {
  if (!Array.isArray(values) || values.length !== CONSECUTIVE_GRID_SIZE) return { valid: false, step: null };
  const line = values.map(Number);
  if (!line.every(Number.isInteger)) return { valid: false, step: null };
  if (line[0] < 1 || line[0] >= 11) return { valid: false, step: null };
  const step = line[1] - line[0];
  if (!Number.isInteger(step) || step < 1 || step > 10) return { valid: false, step: null };
  for (let index = 2; index < line.length; index += 1) {
    if (line[index] - line[index - 1] !== step) return { valid: false, step: null };
  }
  return { valid: true, step };
}

function consecutiveGridSolved(gridRaw) {
  if (!Array.isArray(gridRaw) || gridRaw.length !== CONSECUTIVE_CELL_COUNT) return false;
  const grid = gridRaw.map(Number);
  if (!grid.every((value) => Number.isInteger(value) && value > 0 && value <= 200)) return false;

  const rowInfos = [];
  const colInfos = [];
  for (let row = 0; row < CONSECUTIVE_GRID_SIZE; row += 1) {
    rowInfos.push(consecutiveLineInfo(grid.slice(row * CONSECUTIVE_GRID_SIZE, row * CONSECUTIVE_GRID_SIZE + CONSECUTIVE_GRID_SIZE)));
  }
  for (let col = 0; col < CONSECUTIVE_GRID_SIZE; col += 1) {
    colInfos.push(consecutiveLineInfo(Array.from({ length: CONSECUTIVE_GRID_SIZE }, (_, row) => grid[row * CONSECUTIVE_GRID_SIZE + col])));
  }
  if (!rowInfos.every((item) => item.valid) || !colInfos.every((item) => item.valid)) return false;

  // Her satırın kendi artış miktarı diğer satırlardan, her sütununki de diğer sütunlardan farklıdır.
  if (new Set(rowInfos.map((item) => item.step)).size !== CONSECUTIVE_GRID_SIZE) return false;
  if (new Set(colInfos.map((item) => item.step)).size !== CONSECUTIVE_GRID_SIZE) return false;
  return true;
}

function consecutiveChooseInitialIndices() {
  const first = shuffled([0, 1, 2, 3, 4]);
  let second = null;
  for (let attempt = 0; attempt < 50; attempt += 1) {
    const candidate = shuffled([0, 1, 2, 3, 4]);
    if (candidate.every((col, row) => col !== first[row])) {
      second = candidate;
      break;
    }
  }
  if (!second) second = first.map((col) => (col + 1) % CONSECUTIVE_GRID_SIZE);

  const selected = [];
  for (let row = 0; row < CONSECUTIVE_GRID_SIZE; row += 1) {
    selected.push(row * CONSECUTIVE_GRID_SIZE + first[row]);
    selected.push(row * CONSECUTIVE_GRID_SIZE + second[row]);
  }
  return selected;
}

function generateConsecutivePuzzle() {
  for (let attempt = 0; attempt < 500; attempt += 1) {
    // a(r,c) = start + verticalBase*r + horizontalBase*c + delta*r*c
    // => satır adımı horizontalBase + delta*r, sütun adımı verticalBase + delta*c.
    // Böylece her satır/sütun kendi içinde tam aritmetik dizi olur.
    const delta = secureRandomInt(1, 3); // 1 veya 2
    const horizontalBase = secureRandomInt(1, 3); // 1 veya 2
    const verticalBase = secureRandomInt(1, 3);   // 1 veya 2
    const maxStartByHorizontal = 10 - 4 * horizontalBase;
    const maxStartByVertical = 10 - 4 * verticalBase;
    const maxStart = Math.min(maxStartByHorizontal, maxStartByVertical, 6);
    if (maxStart < 1) continue;
    if (horizontalBase + 4 * delta > 10 || verticalBase + 4 * delta > 10) continue;
    const start = secureRandomInt(1, maxStart + 1);

    const solution = Array.from({ length: CONSECUTIVE_CELL_COUNT }, (_, index) => {
      const row = Math.floor(index / CONSECUTIVE_GRID_SIZE);
      const col = index % CONSECUTIVE_GRID_SIZE;
      return start + verticalBase * row + horizontalBase * col + delta * row * col;
    });
    if (!consecutiveGridSolved(solution)) continue;

    const fixedIndices = new Set(consecutiveChooseInitialIndices());
    const initialGrid = solution.map((value, index) => fixedIndices.has(index) ? value : null);
    const numbers = shuffled(solution.filter((_, index) => !fixedIndices.has(index)));
    if (initialGrid.filter((value) => value !== null).length !== CONSECUTIVE_FIXED_COUNT) continue;
    if (numbers.length !== CONSECUTIVE_POOL_COUNT) continue;

    return {
      gameKey: "consecutive",
      difficulty: "Standard",
      target: CONSECUTIVE_GRID_SIZE,
      numbers: solution,
      initialGrid,
    };
  }

  const solution = Array.from({ length: CONSECUTIVE_CELL_COUNT }, (_, index) => {
    const row = Math.floor(index / CONSECUTIVE_GRID_SIZE);
    const col = index % CONSECUTIVE_GRID_SIZE;
    return 1 + 2 * row + col + row * col;
  });
  const fallbackIndices = new Set([0, 1, 6, 7, 12, 13, 18, 19, 20, 24]);
  return {
    gameKey: "consecutive",
    difficulty: "Standard",
    target: CONSECUTIVE_GRID_SIZE,
    numbers: solution,
    initialGrid: solution.map((value, index) => fallbackIndices.has(index) ? value : null),
  };
}

function isConsecutivePuzzleEncodingValid(puzzle) {
  const target = Number(puzzle?.target);
  const numbers = Array.isArray(puzzle?.numbers) ? puzzle.numbers.map(Number) : [];
  const initialGrid = Array.isArray(puzzle?.initialGrid) ? puzzle.initialGrid : [];
  if (target !== CONSECUTIVE_GRID_SIZE || numbers.length !== CONSECUTIVE_CELL_COUNT || initialGrid.length !== CONSECUTIVE_CELL_COUNT) return false;
  if (!numbers.every((value) => Number.isInteger(value) && value > 0 && value <= 200)) return false;
  if (!consecutiveGridSolved(numbers)) return false;

  let fixedCount = 0;
  const rowCounts = Array(CONSECUTIVE_GRID_SIZE).fill(0);
  const colCounts = Array(CONSECUTIVE_GRID_SIZE).fill(0);
  for (let index = 0; index < initialGrid.length; index += 1) {
    const raw = initialGrid[index];
    if (raw === null || raw === undefined) continue;
    const value = Number(raw);
    if (!Number.isInteger(value) || value <= 0 || value > 200) return false;
    if (value !== numbers[index]) return false;
    fixedCount += 1;
    rowCounts[Math.floor(index / CONSECUTIVE_GRID_SIZE)] += 1;
    colCounts[index % CONSECUTIVE_GRID_SIZE] += 1;
  }
  if (fixedCount !== CONSECUTIVE_FIXED_COUNT) return false;
  if (!rowCounts.every((count) => count >= 1 && count <= 3)) return false;
  if (!colCounts.every((count) => count >= 1 && count <= 3)) return false;
  return true;
}

function validateConsecutiveChallengeAnswer(puzzle, answer = {}) {
  if (!isConsecutivePuzzleEncodingValid(puzzle)) return false;
  const grid = Array.isArray(answer?.grid) ? answer.grid.map(Number) : [];
  if (grid.length !== CONSECUTIVE_CELL_COUNT || !grid.every(Number.isInteger)) return false;

  const initialGrid = puzzle.initialGrid;
  for (let index = 0; index < CONSECUTIVE_CELL_COUNT; index += 1) {
    const fixed = initialGrid[index];
    if (fixed !== null && fixed !== undefined && grid[index] !== Number(fixed)) return false;
  }

  if (!grid.every((value, index) => value === Number(puzzle.numbers[index]))) return false;
  return consecutiveGridSolved(grid);
}

const EQUATION_HUNT_MAX_LINEAR_SOLUTION = 20;
const EQUATION_HUNT_MAX_QUADRATIC_SOLUTION = 10;

function equationHuntRandomSign() {
  return secureRandomInt(0, 2) === 0 ? -1 : 1;
}

function equationHuntRandomSignedNonZero(maxAbs) {
  return equationHuntRandomSign() * secureRandomInt(1, maxAbs + 1);
}

function equationHuntQuadraticParams(solution) {
  const direct = secureRandomInt(0, 2) === 0;
  if (direct) {
    for (let attempt = 0; attempt < 30; attempt += 1) {
      const coefficient = secureRandomInt(1, 4); // 1..3
      const constant = equationHuntRandomSignedNonZero(12);
      if (coefficient * solution * solution + constant > 0) {
        return [0, coefficient, constant];
      }
    }
  }

  // (v ± k)². +k her zaman tek pozitif kök verir.
  // -k yalnız seçilen çözüm >= 2k ise kullanılır; böylece ikinci kök pozitif olamaz.
  const canUseMinus = solution >= 2;
  if (canUseMinus && secureRandomInt(0, 2) === 0) {
    const maxK = Math.min(5, Math.floor(solution / 2));
    if (maxK >= 1) {
      const k = secureRandomInt(1, maxK + 1);
      return [1, -k, 0];
    }
  }
  const k = secureRandomInt(1, 6);
  return [1, k, 0];
}

function generateEquationHuntPuzzle() {
  // Önce aileyi seçip o aile içinde geçerli parametre bulunana kadar tekrar dene.
  // Böylece üretimi daha kolay olan bir denklem tipi diğer tipleri istatistiksel olarak ezmez;
  // yedi aile uzun vadede yaklaşık eşit olasılıkla gelir.
  const family = secureRandomInt(1, 8);
  const pairIndex = secureRandomInt(0, 3);
  const maxSolution = family === 7
    ? EQUATION_HUNT_MAX_QUADRATIC_SOLUTION
    : EQUATION_HUNT_MAX_LINEAR_SOLUTION;

  for (let attempt = 0; attempt < 8000; attempt += 1) {
    const firstSolution = secureRandomInt(1, maxSolution + 1);
    const secondSolution = secureRandomInt(1, maxSolution + 1);
    let params = null;

    if (family === 1) {
      // ax ± by = r
      // cx ± dy = s
      const a = secureRandomInt(1, 6);
      const b = secureRandomInt(1, 6);
      const c = secureRandomInt(1, 6);
      const d = secureRandomInt(1, 6);
      const signB = equationHuntRandomSign();
      const signD = equationHuntRandomSign();
      const signedB = signB * b;
      const signedD = signD * d;
      const determinant = a * signedD - c * signedB;
      const rhs1 = a * firstSolution + signedB * secondSolution;
      const rhs2 = c * firstSolution + signedD * secondSolution;
      if (determinant === 0 || rhs1 <= 0 || rhs2 <= 0) continue;
      params = [a, signB, b, c, signD, d];
    } else if (family === 2) {
      // ax ± b = r
      // cy ± d = s
      const a = secureRandomInt(1, 6);
      const c = secureRandomInt(1, 6);
      const signB = equationHuntRandomSign();
      const signD = equationHuntRandomSign();
      const b = secureRandomInt(1, 21);
      const d = secureRandomInt(1, 21);
      if (a * firstSolution + signB * b <= 0) continue;
      if (c * secondSolution + signD * d <= 0) continue;
      params = [a, signB, b, c, signD, d];
    } else if (family === 3) {
      // ax + b = cx + d
      // ey + f = gy + h
      const a = secureRandomInt(1, 6);
      const c = secureRandomInt(1, 6);
      const e = secureRandomInt(1, 6);
      const g = secureRandomInt(1, 6);
      if (a === c || e === g) continue;
      const b = equationHuntRandomSignedNonZero(12);
      const f = equationHuntRandomSignedNonZero(12);
      const d = (a - c) * firstSolution + b;
      const h = (e - g) * secondSolution + f;
      if (d === 0 || h === 0 || Math.abs(d) > 40 || Math.abs(h) > 40) continue;
      if (a * firstSolution + b <= 0 || c * firstSolution + d <= 0) continue;
      if (e * secondSolution + f <= 0 || g * secondSolution + h <= 0) continue;
      params = [a, b, c, d, e, f, g, h];
    } else if (family === 4) {
      // ax + p = by + q
      // cx + r = dy + s
      const a = secureRandomInt(1, 6);
      const b = secureRandomInt(1, 6);
      const c = secureRandomInt(1, 6);
      const d = secureRandomInt(1, 6);
      if (a * d - b * c === 0) continue;
      const p = equationHuntRandomSignedNonZero(12);
      const r = equationHuntRandomSignedNonZero(12);
      const q = a * firstSolution + p - b * secondSolution;
      const s = c * firstSolution + r - d * secondSolution;
      if (q === 0 || s === 0 || Math.abs(q) > 50 || Math.abs(s) > 50) continue;
      if (a * firstSolution + p <= 0 || c * firstSolution + r <= 0) continue;
      if (b * secondSolution + q <= 0 || d * secondSolution + s <= 0) continue;
      params = [a, p, b, q, c, r, d, s];
    } else if (family === 5) {
      // a(x ± p) = r
      // b(y ± q) = s
      const a = secureRandomInt(1, 6);
      const b = secureRandomInt(1, 6);
      const p = equationHuntRandomSignedNonZero(8);
      const q = equationHuntRandomSignedNonZero(8);
      if (firstSolution + p <= 0 || secondSolution + q <= 0) continue;
      params = [a, p, b, q];
    } else if (family === 6) {
      // a(x ± p) + b(x ± q) = r
      // c(y ± r) + d(y ± s) = t
      const a = secureRandomInt(1, 6);
      const b = secureRandomInt(1, 6);
      const c = secureRandomInt(1, 6);
      const d = secureRandomInt(1, 6);
      const p = equationHuntRandomSignedNonZero(6);
      const q = equationHuntRandomSignedNonZero(6);
      const r = equationHuntRandomSignedNonZero(6);
      const s = equationHuntRandomSignedNonZero(6);
      if (firstSolution + p <= 0 || firstSolution + q <= 0) continue;
      if (secondSolution + r <= 0 || secondSolution + s <= 0) continue;
      if (a * (firstSolution + p) + b * (firstSolution + q) <= 0) continue;
      if (c * (secondSolution + r) + d * (secondSolution + s) <= 0) continue;
      params = [a, p, b, q, c, r, d, s];
    } else if (family === 7) {
      params = [
        ...equationHuntQuadraticParams(firstSolution),
        ...equationHuntQuadraticParams(secondSolution),
      ];
    }

    if (!params) continue;

    const puzzle = {
      gameKey: "equation_hunt",
      difficulty: "Standard",
      target: firstSolution,
      // [aile, değişkenÇifti, ikinciÇözüm, ...denklemParametreleri]
      numbers: [family, pairIndex, secondSolution, ...params],
      initialGrid: [],
    };
    if (isEquationHuntPuzzleEncodingValid(puzzle)) return puzzle;
  }

  // Güvenli fallback: 2x + 5 = 11, 3y - 4 = 8 => x=3, y=4.
  return {
    gameKey: "equation_hunt",
    difficulty: "Standard",
    target: 3,
    numbers: [2, 0, 4, 2, 1, 5, 3, -1, 4],
    initialGrid: [],
  };
}

function isEquationHuntPuzzleEncodingValid(puzzle) {
  const numbers = Array.isArray(puzzle?.numbers) ? puzzle.numbers.map(Number) : [];
  const firstSolution = Number(puzzle?.target);
  if (numbers.length < 3 || !numbers.every(Number.isInteger) || !Number.isInteger(firstSolution)) return false;

  const family = numbers[0];
  const pairIndex = numbers[1];
  const secondSolution = numbers[2];
  if (family < 1 || family > 7 || pairIndex < 0 || pairIndex > 2) return false;

  const maxSolution = family === 7
    ? EQUATION_HUNT_MAX_QUADRATIC_SOLUTION
    : EQUATION_HUNT_MAX_LINEAR_SOLUTION;
  if (firstSolution < 1 || firstSolution > maxSolution) return false;
  if (secondSolution < 1 || secondSolution > maxSolution) return false;

  const coefficient = (value, max = 5) => Number.isInteger(value) && value >= 1 && value <= max;
  const sign = (value) => value === -1 || value === 1;
  const nonZeroRange = (value, maxAbs) =>
    Number.isInteger(value) && value !== 0 && Math.abs(value) <= maxAbs;

  if (family === 1) {
    if (numbers.length !== 9) return false;
    const [a, signB, b, c, signD, d] = numbers.slice(3);
    const signedB = signB * b;
    const signedD = signD * d;
    return coefficient(a) && sign(signB) && coefficient(b) &&
      coefficient(c) && sign(signD) && coefficient(d) &&
      a * signedD - c * signedB !== 0 &&
      a * firstSolution + signedB * secondSolution > 0 &&
      c * firstSolution + signedD * secondSolution > 0;
  }

  if (family === 2) {
    if (numbers.length !== 9) return false;
    const [a, signB, b, c, signD, d] = numbers.slice(3);
    return coefficient(a) && sign(signB) && b >= 1 && b <= 20 &&
      coefficient(c) && sign(signD) && d >= 1 && d <= 20 &&
      a * firstSolution + signB * b > 0 &&
      c * secondSolution + signD * d > 0;
  }

  if (family === 3) {
    if (numbers.length !== 11) return false;
    const [a, b, c, d, e, f, g, h] = numbers.slice(3);
    return coefficient(a) && coefficient(c) && a !== c &&
      coefficient(e) && coefficient(g) && e !== g &&
      nonZeroRange(b, 40) && nonZeroRange(d, 40) &&
      nonZeroRange(f, 40) && nonZeroRange(h, 40) &&
      a * firstSolution + b === c * firstSolution + d &&
      e * secondSolution + f === g * secondSolution + h;
  }

  if (family === 4) {
    if (numbers.length !== 11) return false;
    const [a, p, b, q, c, r, d, s] = numbers.slice(3);
    return coefficient(a) && coefficient(b) && coefficient(c) && coefficient(d) &&
      a * d - b * c !== 0 &&
      nonZeroRange(p, 50) && nonZeroRange(q, 50) &&
      nonZeroRange(r, 50) && nonZeroRange(s, 50) &&
      a * firstSolution + p === b * secondSolution + q &&
      c * firstSolution + r === d * secondSolution + s &&
      a * firstSolution + p > 0 &&
      c * firstSolution + r > 0;
  }

  if (family === 5) {
    if (numbers.length !== 7) return false;
    const [a, p, b, q] = numbers.slice(3);
    return coefficient(a) && coefficient(b) &&
      nonZeroRange(p, 8) && nonZeroRange(q, 8) &&
      firstSolution + p > 0 &&
      secondSolution + q > 0;
  }

  if (family === 6) {
    if (numbers.length !== 11) return false;
    const [a, p, b, q, c, r, d, s] = numbers.slice(3);
    return coefficient(a) && coefficient(b) && coefficient(c) && coefficient(d) &&
      nonZeroRange(p, 6) && nonZeroRange(q, 6) &&
      nonZeroRange(r, 6) && nonZeroRange(s, 6) &&
      firstSolution + p > 0 && firstSolution + q > 0 &&
      secondSolution + r > 0 && secondSolution + s > 0 &&
      a * (firstSolution + p) + b * (firstSolution + q) > 0 &&
      c * (secondSolution + r) + d * (secondSolution + s) > 0;
  }

  if (family === 7) {
    if (numbers.length !== 9) return false;

    const validQuadratic = (solution, kind, firstParam, secondParam) => {
      if (kind === 0) {
        return coefficient(firstParam, 3) &&
          nonZeroRange(secondParam, 12) &&
          firstParam * solution * solution + secondParam > 0;
      }
      if (kind === 1) {
        return nonZeroRange(firstParam, 5) &&
          secondParam === 0 &&
          solution + firstParam > 0 &&
          (firstParam > 0 || solution >= 2 * Math.abs(firstParam));
      }
      return false;
    };

    return validQuadratic(firstSolution, numbers[3], numbers[4], numbers[5]) &&
      validQuadratic(secondSolution, numbers[6], numbers[7], numbers[8]);
  }

  return false;
}

function validateEquationHuntChallengeAnswer(puzzle, answer = {}) {
  if (!isEquationHuntPuzzleEncodingValid(puzzle)) return false;
  const firstValue = Number(answer?.firstValue);
  const secondValue = Number(answer?.secondValue);
  if (!Number.isInteger(firstValue) || !Number.isInteger(secondValue)) return false;
  return firstValue === Number(puzzle.target) &&
    secondValue === Number(puzzle.numbers[2]);
}

function generatePuzzleForGame(gameKey, difficultyValue) {
  return gameHandler(gameKey).createPuzzle(difficultyValue);
}

function generateSecurePuzzle(difficultyValue) {
  const difficulty = secureDifficulty(difficultyValue);
  const count = secureRandomInt(3, 5); // 3 veya 4 sayı

  for (let attempt = 0; attempt < 1000; attempt += 1) {
    const numbers = Array.from({ length: count }, () => secureRandomInt(2, 10));
    const operatorCount = count - 1;
    const operators = [];

    // Her bulmacada en az bir ×/÷ ve en az bir +/− bulunur.
    operators.push(["×", "÷"][secureRandomInt(0, 2)]);
    operators.push(["+", "−"][secureRandomInt(0, 2)]);
    while (operators.length < operatorCount) {
      operators.push(["+", "−", "×", "÷"][secureRandomInt(0, 4)]);
    }

    const shuffledNumbers = shuffled(numbers);
    const shuffledOperators = shuffled(operators);
    const result = evaluateExpression(shuffledNumbers, shuffledOperators);
    if (result === null) continue;
    const rounded = Math.round(result);
    if (Math.abs(result - rounded) < 0.0001 && rounded >= 1 && rounded < 100) {
      return { difficulty, target: rounded, numbers: shuffledNumbers };
    }
  }

  return { difficulty, target: 20, numbers: shuffled([2, 4, 5]) };
}
function challengeRewards(mode, stage) {
  const safeStage = Math.max(1, Math.min(Number(stage || 1), 1000));
  if (mode === "infinite") {
    const points = Math.min(2_000_000_000, safeStage * 5);
    const stageSum = safeStage * (safeStage + 1) / 2;
    // Sonsuz mod puanı ayrı tutulur; normal/genel puanı artırmaz.
    return { generalDelta: 0, infiniteDelta: points, xpDelta: Math.min(2_000_000_000, stageSum * 5) };
  }
  return { generalDelta: 0, infiniteDelta: 0, xpDelta: 0 };
}

const TOURNAMENT_STAGE_REWARDS = [50, 150, 350, 1000, 2500, 7000, 18000, 50000];
const TOURNAMENT_ENTRY_TICKET_COST = 0;
const TOURNAMENT_TICKET_MAX = 9999;
const TOURNAMENT_REWARDED_TICKETS_PER_AD = 5;
const TOURNAMENT_REWARDED_DAILY_MAX = 15;
const HUNDRED_DAILY_BASE_RIGHTS = 2;
const HUNDRED_DAILY_REWARDED_RIGHTS_MAX = 2;

function currentUtcDayKey() {
  return new Date().toISOString().slice(0, 10);
}

function nextUtcDayStartMillis() {
  const now = new Date();
  return Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1, 0, 0, 0, 0);
}

function tournamentStageReward(stageValue) {
  const stage = Math.max(1, Math.min(Number(stageValue || 1), TOURNAMENT_STAGE_REWARDS.length));
  return TOURNAMENT_STAGE_REWARDS[stage - 1];
}

const GAME_RIGHT_MAX = 10;
const GAME_RIGHT_REFILL_MS = 10 * 60 * 1000;
const BOT_FALLBACK_MIN_WAIT_MS = 20 * 1000;
const USERNAME_CHANGE_COOLDOWN_MS = 30 * 24 * 60 * 60 * 1000;
const MULTI_ROUND_MIN_SCORE_EXCLUSIVE = 2_000;

function normalizeRoundCount(value) {
  return Math.max(1, Math.min(Math.floor(Number(value || 1)), 3));
}

function assertRoundCountEligibility(roundCountValue, generalScore, stakePoints = 0) {
  const roundCount = normalizeRoundCount(roundCountValue);
  const score = Math.max(0, Number(generalScore || 0));
  if (roundCount > 1 && score <= MULTI_ROUND_MIN_SCORE_EXCLUSIVE) {
    const error = new Error("2 veya 3 ellik masa açmak/oynamak için 2.000 puandan fazla puan gerekir.");
    error.statusCode = 409;
    error.publicCode = "MULTI_ROUND_SCORE_REQUIRED";
    throw error;
  }
  return roundCount;
}

async function normalizeGameRightsInTransaction(client, playerId, playerAlreadyEnsured = false) {
  if (!playerAlreadyEnsured) {
    await ensureAuthenticatedPlayer(client, playerId);
  }
  const result = await client.query(
    `SELECT game_rights, game_rights_refill_at
     FROM player_progress WHERE player_id = $1 FOR UPDATE`,
    [playerId]
  );
  const row = result.rows[0] || {};
  const now = Date.now();
  const stored = Math.max(0, Math.min(Number(row.game_rights ?? GAME_RIGHT_MAX), GAME_RIGHT_MAX));
  const anchor = new Date(row.game_rights_refill_at || now).getTime();
  const elapsed = Math.max(0, now - anchor);
  const refillCount = stored >= GAME_RIGHT_MAX ? 0 : Math.floor(elapsed / GAME_RIGHT_REFILL_MS);
  const remaining = Math.min(GAME_RIGHT_MAX, stored + refillCount);
  const nextAnchor = remaining >= GAME_RIGHT_MAX
    ? now
    : anchor + refillCount * GAME_RIGHT_REFILL_MS;

  // Tasarruf: hak gerçekten değişmediyse PostgreSQL'e UPDATE gönderme.
  if (remaining !== stored) {
    await client.query(
      `UPDATE player_progress SET game_rights = $2,
         game_rights_refill_at = TO_TIMESTAMP($3 / 1000.0), updated_at = NOW()
       WHERE player_id = $1`,
      [playerId, remaining, nextAnchor]
    );
  }

  return {
    remainingRights: remaining,
    maxRights: GAME_RIGHT_MAX,
    lastRefillTimeMillis: nextAnchor,
    millisUntilNextRight: remaining >= GAME_RIGHT_MAX
      ? 0
      : Math.max(0, GAME_RIGHT_REFILL_MS - (now - nextAnchor)),
  };
}

function minimumTwoPlayerStake(difficulty) {
  return secureDifficulty(difficulty) === "Hard" ? 15 : 10;
}

function quickStakeRange(availableScore, difficulty) {
  const score = Math.max(0, Math.min(Number(availableScore || 0), 2_000_000_000));
  const minimum = minimumTwoPlayerStake(difficulty);
  const minStake = Math.max(minimum, Math.floor(score / 10));
  const maxStake = Math.max(minStake, Math.floor(score / 2));
  return { minStake, maxStake };
}

function randomStakeEndingWith50Or100(minimumValue, maximumValue) {
  const minimum = Math.max(0, Math.floor(Number(minimumValue || 0)));
  const maximum = Math.max(minimum, Math.floor(Number(maximumValue || minimum)));
  const endings = [];

  const fiftyMinMultiplier = Math.ceil((minimum - 50) / 100);
  const fiftyMaxMultiplier = Math.floor((maximum - 50) / 100);
  if (fiftyMinMultiplier <= fiftyMaxMultiplier) {
    endings.push({ offset: 50, minMultiplier: fiftyMinMultiplier, maxMultiplier: fiftyMaxMultiplier });
  }

  const hundredMinMultiplier = Math.ceil(minimum / 100);
  const hundredMaxMultiplier = Math.floor(maximum / 100);
  if (hundredMinMultiplier <= hundredMaxMultiplier) {
    endings.push({ offset: 0, minMultiplier: hundredMinMultiplier, maxMultiplier: hundredMaxMultiplier });
  }

  if (endings.length === 0) return null;
  const selected = endings[secureRandomInt(0, endings.length)];
  const multiplier = secureRandomInt(selected.minMultiplier, selected.maxMultiplier + 1);
  return multiplier * 100 + selected.offset;
}

function randomStakeWithNaturalEnding(minimumValue, maximumValue) {
  const minimum = Math.max(0, Math.floor(Number(minimumValue || 0)));
  const maximum = Math.max(minimum, Math.floor(Number(maximumValue || minimum)));
  if (maximum <= minimum) return minimum;

  if (secureRandomInt(0, 100) < 40) {
    const friendlyStake = randomStakeEndingWith50Or100(minimum, maximum);
    if (friendlyStake != null) return friendlyStake;
  }

  return secureRandomInt(minimum, maximum + 1);
}

function minimumOpenTableStake(availableScore, difficulty) {
  const score = Math.max(0, Math.min(Number(availableScore || 0), 2_000_000_000));
  const lowestEligibleGroup = TWO_PLAYER_ROOM_GROUPS.find((group) =>
    score >= group.minScore && (group.maxScore == null || score <= group.maxScore)
  );
  return Math.max(
    minimumTwoPlayerStake(difficulty),
    Number(lowestEligibleGroup?.minScore || minimumTwoPlayerStake(difficulty))
  );
}

function assertOpenTableStake(stakePoints, availableScore, difficulty) {
  const minimum = minimumOpenTableStake(availableScore, difficulty);
  const requested = Math.floor(Number(stakePoints || 0));
  if (!Number.isFinite(requested) || requested < minimum) {
    const error = new Error(`Masa puanı, girebildiğiniz en düşük salon için en az ${minimum} olmalıdır.`);
    error.statusCode = 409;
    error.publicCode = "INVALID_WAGER";
    throw error;
  }
  if (requested > Number(availableScore || 0)) {
    const error = new Error("Masa puanı mevcut genel puanınızı aşamaz.");
    error.statusCode = 409;
    error.publicCode = "INSUFFICIENT_SCORE";
    throw error;
  }
  return requested;
}

function normalizeRequestedStake(value, difficulty, availableScore, allowAutomatic = false) {
  const minimum = minimumTwoPlayerStake(difficulty);
  const score = Math.max(0, Math.min(Number(availableScore || 0), 2_000_000_000));
  const requested = Math.floor(Number(value || 0));
  if (allowAutomatic && requested <= 0) {
    const { minStake: lower, maxStake: upper } = quickStakeRange(score, difficulty);
    return randomStakeWithNaturalEnding(lower, upper);
  }
  if (!Number.isFinite(requested) || requested < minimum) {
    const error = new Error(`Bu zorluk için oyun puanı en az ${minimum} olmalıdır.`);
    error.statusCode = 409;
    error.publicCode = "INVALID_WAGER";
    throw error;
  }
  if (requested > score) {
    const error = new Error("Seçilen oyun puanı mevcut genel puanınızı aşamaz.");
    error.statusCode = 409;
    error.publicCode = "INSUFFICIENT_SCORE";
    throw error;
  }
  return requested;
}

async function assertTwoPlayerEntryScoreInTransaction(client, playerId, difficulty, wagerPoints = 0, allowAutomatic = false) {
  const result = await client.query(
    `SELECT general_score FROM player_scores WHERE player_id = $1 FOR UPDATE`,
    [playerId]
  );
  const generalScore = Number(result.rows[0]?.general_score || 0);
  const requiredScore = minimumTwoPlayerStake(difficulty);
  if (generalScore < requiredScore) {
    const error = new Error(`Bu zorluk için en az ${requiredScore} genel puan gerekli.`);
    error.statusCode = 409;
    error.publicCode = 'INSUFFICIENT_SCORE';
    throw error;
  }
  const stakePoints = normalizeRequestedStake(wagerPoints, difficulty, generalScore, allowAutomatic);
  return { generalScore, stakePoints };
}

function normalizedGameRightConsumption(row, difficulty, wagerPoints, allowAutomatic = false) {
  const generalScore = Math.max(0, Number(row?.general_score || 0));
  const requiredScore = minimumTwoPlayerStake(difficulty);
  if (generalScore < requiredScore) {
    const error = new Error(`Bu zorluk için en az ${requiredScore} genel puan gerekli.`);
    error.statusCode = 409;
    error.publicCode = 'INSUFFICIENT_SCORE';
    throw error;
  }

  const stakePoints = normalizeRequestedStake(wagerPoints, difficulty, generalScore, allowAutomatic);
  const now = Date.now();
  const stored = Math.max(0, Math.min(Number(row?.game_rights ?? GAME_RIGHT_MAX), GAME_RIGHT_MAX));
  const anchor = new Date(row?.game_rights_refill_at || now).getTime();
  const elapsed = Math.max(0, now - anchor);
  const refillCount = stored >= GAME_RIGHT_MAX ? 0 : Math.floor(elapsed / GAME_RIGHT_REFILL_MS);
  const normalizedRemaining = Math.min(GAME_RIGHT_MAX, stored + refillCount);
  const normalizedAnchor = normalizedRemaining >= GAME_RIGHT_MAX
    ? now
    : anchor + refillCount * GAME_RIGHT_REFILL_MS;

  if (normalizedRemaining <= 0) {
    const error = new Error('İki oyunculu oyun hakkın kalmadı.');
    error.statusCode = 409;
    error.publicCode = 'NO_GAME_RIGHT';
    throw error;
  }

  const wasFull = normalizedRemaining >= GAME_RIGHT_MAX;
  const remaining = normalizedRemaining - 1;
  const consumedAnchor = wasFull ? now : normalizedAnchor;
  return {
    generalScore,
    stakePoints,
    remainingRights: remaining,
    maxRights: GAME_RIGHT_MAX,
    lastRefillTimeMillis: consumedAnchor,
    millisUntilNextRight: GAME_RIGHT_REFILL_MS,
  };
}

async function consumeGameRightInTransaction(client, playerId, difficulty, wagerPoints = minimumTwoPlayerStake(difficulty), allowAutomatic = false, gameKey = "target_number") {
  // Genel skor ve 10 oyun hakkı oyuncuya ortaktır; bot hız profili ve turnuva ilerlemesi oyuna özeldir.
  const normalizedGameKey = normalizeBaseGameKey(gameKey);
  await ensurePlayerGameProgress(client, playerId, normalizedGameKey);
  const result = await client.query(
    `SELECT s.general_score, p.game_rights, p.game_rights_refill_at,
            gp.two_player_finish_count, gp.two_player_finish_total_ms,
            gp.tournament_stage, gp.tournament_rights, gp.tournament_bank,
            gp.tournament_completed, p.tournament_tickets, gp.tournament_entry_active
     FROM player_scores s
     JOIN player_progress p ON p.player_id = s.player_id
     JOIN player_game_progress gp ON gp.player_id = s.player_id AND gp.game_key = $2
     WHERE s.player_id = $1
     FOR UPDATE OF s, p, gp`,
    [playerId, normalizedGameKey]
  );
  const lockedRow = result.rows[0] || {};
  const state = normalizedGameRightConsumption(
    lockedRow, difficulty, wagerPoints, allowAutomatic
  );
  state.finishProfile = normalizeTwoPlayerFinishProfile({
    finishCount: lockedRow.two_player_finish_count,
    finishTotalMs: lockedRow.two_player_finish_total_ms,
  });
  state.tournamentResponse = {
    currentStage: Math.max(1, Math.min(Number(lockedRow.tournament_stage || 1), 8)),
    remainingRights: Math.max(0, Math.min(Number(lockedRow.tournament_rights ?? 3), 3)),
    totalScore: Math.max(0, Number(lockedRow.tournament_bank || 0)),
    completed: lockedRow.tournament_completed === true,
    tickets: Math.max(0, Number(lockedRow.tournament_tickets || 0)),
    ticketCost: TOURNAMENT_ENTRY_TICKET_COST,
    entryActive: lockedRow.tournament_entry_active === true,
  };
  await client.query(
    `UPDATE player_progress SET game_rights = $2,
       game_rights_refill_at = TO_TIMESTAMP($3 / 1000.0), updated_at = NOW()
     WHERE player_id = $1`,
    [playerId, state.remainingRights, state.lastRefillTimeMillis]
  );
  return state;
}

async function consumeGameRightsForPlayers(playerIds, difficulty, wagerPoints = minimumTwoPlayerStake(difficulty)) {
  const uniqueIds = [...new Set((playerIds || []).filter(Boolean).map(String))].sort();
  if (uniqueIds.length === 0) return true;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // İki gerçek oyuncuyu tek seferde ve deterministik player_id sırasıyla kilitle.
    // Böylece oyuncu başına 3 sorgu yerine tüm eşleşme için 1 SELECT + 1 UPDATE yeterlidir.
    const locked = await client.query(
      `SELECT s.player_id, s.general_score, p.game_rights, p.game_rights_refill_at
       FROM player_scores s
       JOIN player_progress p ON p.player_id = s.player_id
       WHERE s.player_id = ANY($1::text[])
       ORDER BY s.player_id
       FOR UPDATE OF s, p`,
      [uniqueIds]
    );
    if (locked.rowCount !== uniqueIds.length) {
      const error = new Error('Oyuncu hak durumu bulunamadı.');
      error.statusCode = 409;
      error.publicCode = 'PLAYER_STATE_MISSING';
      throw error;
    }

    const byId = new Map(locked.rows.map((row) => [String(row.player_id), row]));
    const states = uniqueIds.map((playerId) => {
      const row = byId.get(playerId);
      return {
        playerId,
        ...normalizedGameRightConsumption(row, difficulty, wagerPoints, false),
      };
    });

    await client.query(
      `UPDATE player_progress AS p
       SET game_rights = v.remaining_rights,
           game_rights_refill_at = TO_TIMESTAMP(v.anchor_ms / 1000.0),
           updated_at = NOW()
       FROM UNNEST($1::text[], $2::integer[], $3::bigint[])
         AS v(player_id, remaining_rights, anchor_ms)
       WHERE p.player_id = v.player_id`,
      [
        states.map((item) => item.playerId),
        states.map((item) => item.remainingRights),
        states.map((item) => item.lastRefillTimeMillis),
      ]
    );

    await client.query('COMMIT');
    return true;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

async function refundGameRightInTransaction(client, playerId) {
  const state = await normalizeGameRightsInTransaction(client, playerId, true);
  const refunded = Math.min(GAME_RIGHT_MAX, state.remainingRights + 1);
  const anchor = refunded >= GAME_RIGHT_MAX
    ? Date.now()
    : state.lastRefillTimeMillis;
  await client.query(
    `UPDATE player_progress SET game_rights = $2,
       game_rights_refill_at = TO_TIMESTAMP($3 / 1000.0), updated_at = NOW()
     WHERE player_id = $1`,
    [playerId, refunded, anchor]
  );
}

async function refundConsumedGameRights(playerIds, gameKey = "target_number") {
  if (!pool) return new Map();
  const uniqueIds = [...new Set((playerIds || []).filter(Boolean).map(String))].sort();
  if (uniqueIds.length === 0) return new Map();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Nadir refund yolunda da oyuncu başına SELECT+UPDATE döngüsü kurma: bütün progress satırlarını
    // tek kilitli okumada normalize et, ardından tek batch UPDATE ile hakkı iade et.
    const locked = await client.query(
      `SELECT player_id, game_rights, game_rights_refill_at
       FROM player_progress
       WHERE player_id = ANY($1::text[])
       ORDER BY player_id
       FOR UPDATE`,
      [uniqueIds]
    );
    const now = Date.now();
    const byId = new Map(locked.rows.map((row) => [String(row.player_id), row]));
    const refunds = uniqueIds.map((playerId) => {
      const row = byId.get(playerId);
      if (!row) {
        const error = new Error('Oyuncu hak durumu bulunamadı.');
        error.statusCode = 409;
        error.publicCode = 'PLAYER_STATE_MISSING';
        throw error;
      }
      const stored = Math.max(0, Math.min(Number(row.game_rights ?? GAME_RIGHT_MAX), GAME_RIGHT_MAX));
      const anchor = new Date(row.game_rights_refill_at || now).getTime();
      const elapsed = Math.max(0, now - anchor);
      const refillCount = stored >= GAME_RIGHT_MAX ? 0 : Math.floor(elapsed / GAME_RIGHT_REFILL_MS);
      const normalizedRemaining = Math.min(GAME_RIGHT_MAX, stored + refillCount);
      const normalizedAnchor = normalizedRemaining >= GAME_RIGHT_MAX
        ? now
        : anchor + refillCount * GAME_RIGHT_REFILL_MS;
      const refunded = Math.min(GAME_RIGHT_MAX, normalizedRemaining + 1);
      return {
        playerId,
        remainingRights: refunded,
        anchorMillis: refunded >= GAME_RIGHT_MAX ? now : normalizedAnchor,
      };
    });

    await client.query(
      `UPDATE player_progress AS p
       SET game_rights = v.remaining_rights,
           game_rights_refill_at = TO_TIMESTAMP(v.anchor_ms / 1000.0),
           updated_at = NOW()
       FROM UNNEST($1::text[], $2::integer[], $3::bigint[])
         AS v(player_id, remaining_rights, anchor_ms)
       WHERE p.player_id = v.player_id`,
      [
        refunds.map((item) => item.playerId),
        refunds.map((item) => item.remainingRights),
        refunds.map((item) => item.anchorMillis),
      ]
    );

    const states = new Map();
    for (const playerId of uniqueIds) {
      states.set(playerId, {
        ...(await readAuthoritativePlayerState(client, playerId, normalizeBaseGameKey(gameKey))),
        generalDelta: 0,
        infiniteDelta: 0,
        xpDelta: 0,
      });
    }
    await client.query('COMMIT');
    return states;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

// Bot fallback bekleme bilgisi geçicidir; PostgreSQL yerine RAM'de tutulur.
// Render restartında kaybolması güvenlik sorunu değildir: oyuncu gerçek rakibi yeniden kısa süre arar.
const botFallbackEligibility = new Map();
const BOT_FALLBACK_RAM_MAX_AGE_MS = Math.max(BOT_FALLBACK_MIN_WAIT_MS * 4, 5 * 60_000);

async function markBotFallbackEligibility(playerId, gameKey, difficulty) {
  if (!playerId) return;
  const rawGameKey = String(gameKey || "target_number").trim().toLowerCase();
  const normalizedGameKey = rawGameKey.includes("_tournament")
    ? gameModeKey(rawGameKey, "tournament")
    : normalizeBaseGameKey(rawGameKey);
  const normalizedDifficulty = secureDifficulty(difficulty);
  const existing = botFallbackEligibility.get(String(playerId));
  if (
    existing &&
    existing.gameKey === normalizedGameKey &&
    existing.difficulty === normalizedDifficulty
  ) {
    return;
  }
  const now = Date.now();
  botFallbackEligibility.set(String(playerId), {
    gameKey: normalizedGameKey,
    difficulty: normalizedDifficulty,
    eligibleAt: now + BOT_FALLBACK_MIN_WAIT_MS,
    createdAt: now,
  });
}

async function clearBotFallbackEligibilityForPlayers(playerIds) {
  for (const playerId of new Set((playerIds || []).filter(Boolean).map(String))) {
    botFallbackEligibility.delete(playerId);
  }
}

async function consumeBotFallbackEligibilityInTransaction(
  _client,
  playerId,
  expectedGameKey,
  expectedDifficulty
) {
  const rawGameKey = String(expectedGameKey || "target_number").trim().toLowerCase();
  const normalizedGameKey = rawGameKey.includes("_tournament")
    ? gameModeKey(rawGameKey, "tournament")
    : normalizeBaseGameKey(rawGameKey);
  const normalizedDifficulty = secureDifficulty(expectedDifficulty);
  const key = String(playerId || "");
  const entry = botFallbackEligibility.get(key);
  if (
    !entry ||
    entry.gameKey !== normalizedGameKey ||
    entry.difficulty !== normalizedDifficulty ||
    Date.now() < Number(entry.eligibleAt || 0)
  ) {
    const error = new Error("Bot eşleşmesi için önce gerçek oyuncu aranmalıdır.");
    error.statusCode = 409;
    error.publicCode = "BOT_FALLBACK_NOT_READY";
    throw error;
  }
  botFallbackEligibility.delete(key);
}

function cleanupBotFallbackEligibility(now = Date.now()) {
  for (const [playerId, entry] of botFallbackEligibility) {
    if (now - Number(entry.createdAt || 0) > BOT_FALLBACK_RAM_MAX_AGE_MS) {
      botFallbackEligibility.delete(playerId);
    }
  }
}


function playerLevelForTotalXp(totalXpValue) {
  const totalXp = Math.max(0, Math.min(Number(totalXpValue || 0), 2_000_000_000));
  const calculated = Math.floor((1 + Math.sqrt(1 + 4 * totalXp)) / 2);
  return Math.max(1, Math.min(calculated, 1000));
}

function levelMilestoneReward(levelValue) {
  const level = Number(levelValue || 0);
  if (level < 10 || level > 1000 || level % 10 !== 0) return null;
  if (level % 20 === 10) {
    return { level, generalScore: level, diamonds: 0 };
  }
  return { level, generalScore: 0, diamonds: Math.floor(level / 10) };
}

function calculateLevelMilestoneSettlement(totalXpValue, claimedThroughValue) {
  const currentLevel = playerLevelForTotalXp(totalXpValue);
  const eligibleThroughLevel = Math.min(1000, Math.floor(currentLevel / 10) * 10);
  const claimedThroughLevel = Math.max(
    0,
    Math.min(1000, Math.floor(Number(claimedThroughValue || 0) / 10) * 10)
  );
  if (eligibleThroughLevel <= claimedThroughLevel) {
    return { claimedThroughLevel, generalDelta: 0, diamondDelta: 0 };
  }
  let generalDelta = 0;
  let diamondDelta = 0;
  for (let level = claimedThroughLevel + 10; level <= eligibleThroughLevel; level += 10) {
    const reward = levelMilestoneReward(level);
    if (!reward) continue;
    generalDelta += reward.generalScore;
    diamondDelta += reward.diamonds;
  }
  return {
    claimedThroughLevel: eligibleThroughLevel,
    generalDelta,
    diamondDelta,
  };
}

async function settleLevelMilestoneRewardsInTransaction(client, playerId) {
  const progressResult = await client.query(
    `SELECT total_xp, level_reward_claimed_through
     FROM player_progress
     WHERE player_id = $1
     FOR UPDATE`,
    [playerId]
  );
  const row = progressResult.rows[0];
  if (!row) return { claimedThroughLevel: 0, generalDelta: 0, diamondDelta: 0 };

  const currentLevel = playerLevelForTotalXp(row.total_xp);
  const eligibleThroughLevel = Math.min(1000, Math.floor(currentLevel / 10) * 10);
  const claimedThroughLevel = Math.max(
    0,
    Math.min(1000, Math.floor(Number(row.level_reward_claimed_through || 0) / 10) * 10)
  );

  if (eligibleThroughLevel <= claimedThroughLevel) {
    return { claimedThroughLevel, generalDelta: 0, diamondDelta: 0 };
  }

  let generalDelta = 0;
  let diamondDelta = 0;
  for (let level = claimedThroughLevel + 10; level <= eligibleThroughLevel; level += 10) {
    const reward = levelMilestoneReward(level);
    if (!reward) continue;
    generalDelta += reward.generalScore;
    diamondDelta += reward.diamonds;
  }

  if (generalDelta > 0) {
    await applyLeaderboardScoreDeltaInTransaction(client, playerId, generalDelta, 0);
  }

  await client.query(
    `UPDATE player_progress
     SET diamond_balance = LEAST(diamond_balance + $2, 2000000000),
         level_reward_claimed_through = $3,
         updated_at = NOW()
     WHERE player_id = $1`,
    [playerId, diamondDelta, eligibleThroughLevel]
  );

  return {
    claimedThroughLevel: eligibleThroughLevel,
    generalDelta,
    diamondDelta,
  };
}

async function ensurePlayerGameProgress(client, playerId, gameKey) {
  const baseGameKey = normalizeBaseGameKey(gameKey);
  await client.query(
    `INSERT INTO player_game_progress (player_id, game_key)
     VALUES ($1, $2)
     ON CONFLICT (player_id, game_key) DO NOTHING`,
    [playerId, baseGameKey]
  );
  return baseGameKey;
}

async function readPlayerGameProgress(client, playerId, gameKey, forUpdate = false) {
  const baseGameKey = await ensurePlayerGameProgress(client, playerId, gameKey);
  const result = await client.query(
    `SELECT * FROM player_game_progress
     WHERE player_id = $1 AND game_key = $2${forUpdate ? " FOR UPDATE" : ""}`,
    [playerId, baseGameKey]
  );
  return { gameKey: baseGameKey, row: result.rows[0] || {} };
}

async function normalizeHundredDailyAccessInTransaction(client, playerId, gameKey = "target_number", playerAlreadyEnsured = false) {
  if (!playerAlreadyEnsured) await ensureAuthenticatedPlayer(client, playerId);
  const baseGameKey = await ensurePlayerGameProgress(client, playerId, gameKey);
  const result = await client.query(
    `SELECT p.hundred_daily_key, p.hundred_daily_base_used, p.hundred_daily_base_used_count,
            p.hundred_daily_ad_used, p.hundred_rewarded_rights,
            gp.hundred_active, gp.hundred_stage
     FROM player_progress p
     JOIN player_game_progress gp ON gp.player_id = p.player_id AND gp.game_key = $2
     WHERE p.player_id = $1
     FOR UPDATE OF p, gp`,
    [playerId, baseGameKey]
  );
  const row = result.rows[0] || {};
  const todayKey = currentUtcDayKey();
  let dailyKey = String(row.hundred_daily_key || "");
  let baseUsedCount = Math.max(0, Math.min(
    Number(row.hundred_daily_base_used_count ?? (row.hundred_daily_base_used === true ? 1 : 0)),
    HUNDRED_DAILY_BASE_RIGHTS
  ));
  let adUsed = row.hundred_daily_ad_used === true;
  let rewardedRights = Math.max(0, Math.min(Number(row.hundred_rewarded_rights || 0), HUNDRED_DAILY_REWARDED_RIGHTS_MAX));

  if (dailyKey !== todayKey) {
    dailyKey = todayKey;
    baseUsedCount = 0;
    adUsed = false;
    rewardedRights = 0;
    await client.query(
      `UPDATE player_progress SET
         hundred_daily_key = $2,
         hundred_daily_base_used = FALSE,
         hundred_daily_base_used_count = 0,
         hundred_daily_ad_used = FALSE,
         hundred_rewarded_rights = 0,
         updated_at = NOW()
       WHERE player_id = $1`,
      [playerId, todayKey]
    );
  }

  const baseRightsRemaining = Math.max(0, HUNDRED_DAILY_BASE_RIGHTS - baseUsedCount);
  const active = row.hundred_active === true;
  return {
    gameKey: baseGameKey,
    active,
    stage: Math.max(0, Math.min(Number(row.hundred_stage || 0), 12)),
    dayKey: dailyKey,
    baseUsedCount,
    baseRightsRemaining,
    rewardedRightsRemaining: rewardedRights,
    rewardedAdUsedToday: adUsed,
    rewardedAdAvailable: !active && baseRightsRemaining <= 0 && !adUsed && rewardedRights <= 0,
    canStart: !active && (baseRightsRemaining + rewardedRights > 0),
    nextResetAtMillis: nextUtcDayStartMillis(),
  };
}

async function grantHundredRewardedRightInTransaction(client, playerId, gameKey = "target_number") {
  const access = await normalizeHundredDailyAccessInTransaction(client, playerId, gameKey, false);
  if (access.active) {
    const error = new Error("Aktif 100 kişilik oyun varken reklam hakkı alınamaz.");
    error.statusCode = 409; error.publicCode = "HUNDRED_RUN_ACTIVE"; throw error;
  }
  if (access.baseRightsRemaining > 0) {
    const error = new Error("Önce bugünkü 2 ücretsiz 100 kişilik oyun hakkını kullanmalısınız.");
    error.statusCode = 409; error.publicCode = "HUNDRED_FREE_RIGHT_AVAILABLE"; throw error;
  }
  if (access.rewardedAdUsedToday) {
    if (access.rewardedRightsRemaining > 0) return readAuthoritativePlayerState(client, playerId, access.gameKey);
    const error = new Error("Bugün reklam izleyerek alınabilecek 2 ek 100 kişilik oyun hakkını kullandınız.");
    error.statusCode = 409; error.publicCode = "HUNDRED_AD_ALREADY_USED"; throw error;
  }
  await client.query(
    `UPDATE player_progress SET
       hundred_daily_ad_used = TRUE,
       hundred_rewarded_rights = $2,
       updated_at = NOW()
     WHERE player_id = $1`,
    [playerId, HUNDRED_DAILY_REWARDED_RIGHTS_MAX]
  );
  return readAuthoritativePlayerState(client, playerId, access.gameKey);
}

async function grantTournamentTicketInTransaction(client, playerId, gameKey = "target_number") {
  await ensureAuthenticatedPlayer(client, playerId);
  const baseGameKey = await ensurePlayerGameProgress(client, playerId, gameKey);
  const result = await client.query(
    `SELECT tournament_tickets, tournament_reward_day_key, tournament_rewarded_tickets_today
     FROM player_progress WHERE player_id = $1 FOR UPDATE`,
    [playerId]
  );
  const row = result.rows[0] || {};
  const todayKey = currentUtcDayKey();
  let rewardedToday = String(row.tournament_reward_day_key || "") === todayKey
    ? Math.max(0, Math.min(Number(row.tournament_rewarded_tickets_today || 0), TOURNAMENT_REWARDED_DAILY_MAX))
    : 0;
  if (rewardedToday >= TOURNAMENT_REWARDED_DAILY_MAX) {
    const error = new Error("Bugün reklam izleyerek kazanabileceğiniz 15 turnuva biletini aldınız.");
    error.statusCode = 409; error.publicCode = "TOURNAMENT_REWARDED_DAILY_LIMIT"; throw error;
  }
  const grant = Math.min(TOURNAMENT_REWARDED_TICKETS_PER_AD, TOURNAMENT_REWARDED_DAILY_MAX - rewardedToday);
  rewardedToday += grant;
  await client.query(
    `UPDATE player_progress SET
       tournament_tickets = LEAST(tournament_tickets + $2, $3),
       tournament_reward_day_key = $4,
       tournament_rewarded_tickets_today = $5,
       updated_at = NOW()
     WHERE player_id = $1`,
    [playerId, grant, TOURNAMENT_TICKET_MAX, todayKey, rewardedToday]
  );
  const state = await readAuthoritativePlayerState(client, playerId, baseGameKey);
  return { ...state, rewardedTournamentTicketsGranted: grant, rewardedTournamentTicketsToday: rewardedToday,
    rewardedTournamentTicketsRemainingToday: Math.max(0, TOURNAMENT_REWARDED_DAILY_MAX - rewardedToday) };
}

async function enterTournamentInTransaction(client, playerId, gameKey = "target_number") {
  await ensureAuthenticatedPlayer(client, playerId);
  const baseGameKey = await ensurePlayerGameProgress(client, playerId, gameKey);
  const result = await client.query(
    `SELECT p.tournament_tickets,
            gp.tournament_entry_active, gp.tournament_stage, gp.tournament_rights,
            gp.tournament_bank, gp.tournament_completed
     FROM player_progress p
     JOIN player_game_progress gp ON gp.player_id = p.player_id AND gp.game_key = $2
     WHERE p.player_id = $1
     FOR UPDATE OF p, gp`,
    [playerId, baseGameKey]
  );
  const row = result.rows[0] || {};
  if (row.tournament_entry_active === true) return readAuthoritativePlayerState(client, playerId, baseGameKey);
  const tickets = Math.max(0, Number(row.tournament_tickets || 0));
  if (tickets < TOURNAMENT_ENTRY_TICKET_COST) {
    const error = new Error(`Turnuvaya girmek için ${TOURNAMENT_ENTRY_TICKET_COST} bilet gerekli.`);
    error.statusCode = 409; error.publicCode = "TOURNAMENT_TICKETS_REQUIRED"; throw error;
  }
  await client.query(
    `WITH ticket_update AS (
       UPDATE player_progress
       SET tournament_tickets = tournament_tickets - $3, updated_at = NOW()
       WHERE player_id = $1
     )
     UPDATE player_game_progress SET
       tournament_entry_active = TRUE,
       tournament_stage = 1,
       tournament_rights = 3,
       tournament_bank = 0,
       tournament_completed = FALSE,
       updated_at = NOW()
     WHERE player_id = $1 AND game_key = $2`,
    [playerId, baseGameKey, TOURNAMENT_ENTRY_TICKET_COST]
  );
  return readAuthoritativePlayerState(client, playerId, baseGameKey);
}

async function readAuthoritativePlayerState(client, playerId, gameKey = "target_number") {
  await ensureAuthenticatedPlayer(client, playerId);
  const baseGameKey = await ensurePlayerGameProgress(client, playerId, gameKey);
  const result = await client.query(
    `SELECT s.general_score, s.infinite_score,
            p.total_xp, p.diamond_balance, p.level_reward_claimed_through,
            p.tournament_tickets, p.tournament_reward_day_key, p.tournament_rewarded_tickets_today,
            p.hundred_daily_key, p.hundred_daily_base_used, p.hundred_daily_base_used_count,
            p.hundred_daily_ad_used, p.hundred_rewarded_rights,
            p.game_rights, p.game_rights_refill_at,
            gp.infinite_score AS game_infinite_score,
            gp.infinite_run_score, gp.infinite_next_stage,
            gp.tournament_stage, gp.tournament_rights, gp.tournament_bank,
            gp.tournament_completed, gp.tournament_entry_active,
            gp.hundred_active, gp.hundred_stage,
            pl.username, pl.country, pl.username_user_set,
            pl.username_change_count, pl.username_last_changed_at,
            pl.updated_at AS profile_updated_at
     FROM player_scores s
     JOIN player_progress p ON p.player_id = s.player_id
     JOIN player_game_progress gp ON gp.player_id = s.player_id AND gp.game_key = $2
     JOIN players pl ON pl.player_id = s.player_id
     WHERE s.player_id = $1
     FOR UPDATE OF s, p, gp`,
    [playerId, baseGameKey]
  );
  const row = result.rows[0] || {};
  const now = Date.now();

  const totalXp = Math.max(0, Math.min(Number(row.total_xp || 0), 2_000_000_000));
  const levelSettlement = calculateLevelMilestoneSettlement(totalXp, row.level_reward_claimed_through);
  const storedClaimedThrough = Math.max(0, Math.min(1000,
    Math.floor(Number(row.level_reward_claimed_through || 0) / 10) * 10));
  const levelSettlementNeeded = levelSettlement.claimedThroughLevel !== storedClaimedThrough;
  if (levelSettlement.generalDelta > 0) {
    await applyLeaderboardScoreDeltaInTransaction(client, playerId, levelSettlement.generalDelta, 0);
  }

  const todayKey = currentUtcDayKey();
  const hundredResetNeeded = String(row.hundred_daily_key || "") !== todayKey;
  const hundredBaseUsedCount = hundredResetNeeded ? 0 : Math.max(0, Math.min(
    Number(row.hundred_daily_base_used_count ?? (row.hundred_daily_base_used === true ? 1 : 0)),
    HUNDRED_DAILY_BASE_RIGHTS
  ));
  const hundredAdUsed = hundredResetNeeded ? false : row.hundred_daily_ad_used === true;
  const hundredRewardedRights = hundredResetNeeded ? 0 : Math.max(0,
    Math.min(Number(row.hundred_rewarded_rights || 0), HUNDRED_DAILY_REWARDED_RIGHTS_MAX));
  const hundredBaseRightsRemaining = Math.max(0, HUNDRED_DAILY_BASE_RIGHTS - hundredBaseUsedCount);
  const hundredActive = row.hundred_active === true;

  const storedGameRights = Math.max(0, Math.min(Number(row.game_rights ?? GAME_RIGHT_MAX), GAME_RIGHT_MAX));
  const storedGameRightsAnchor = new Date(row.game_rights_refill_at || now).getTime();
  const gameRightsElapsed = Math.max(0, now - storedGameRightsAnchor);
  const gameRightsRefillCount = storedGameRights >= GAME_RIGHT_MAX ? 0 : Math.floor(gameRightsElapsed / GAME_RIGHT_REFILL_MS);
  const gameRightsRemaining = Math.min(GAME_RIGHT_MAX, storedGameRights + gameRightsRefillCount);
  const gameRightsAnchor = gameRightsRemaining >= GAME_RIGHT_MAX
    ? now
    : storedGameRightsAnchor + gameRightsRefillCount * GAME_RIGHT_REFILL_MS;
  const gameRightsChanged = gameRightsRemaining !== storedGameRights;

  if (levelSettlementNeeded || hundredResetNeeded || gameRightsChanged) {
    await client.query(
      `UPDATE player_progress SET
         diamond_balance = LEAST(diamond_balance + $2, 2000000000),
         level_reward_claimed_through = $3,
         hundred_daily_key = $4,
         hundred_daily_base_used = $5,
         hundred_daily_base_used_count = $6,
         hundred_daily_ad_used = $7,
         hundred_rewarded_rights = $8,
         game_rights = $9,
         game_rights_refill_at = TO_TIMESTAMP($10 / 1000.0),
         updated_at = NOW()
       WHERE player_id = $1`,
      [
        playerId,
        levelSettlementNeeded ? levelSettlement.diamondDelta : 0,
        levelSettlementNeeded ? levelSettlement.claimedThroughLevel : storedClaimedThrough,
        todayKey,
        hundredBaseUsedCount > 0,
        hundredBaseUsedCount,
        hundredAdUsed,
        hundredRewardedRights,
        gameRightsRemaining,
        gameRightsAnchor,
      ]
    );
  }

  const globalGeneralScore = Math.max(0, Math.min(2_000_000_000,
    Number(row.general_score || 0) + (levelSettlementNeeded ? levelSettlement.generalDelta : 0)));
  const diamondBalance = Math.max(0, Math.min(2_000_000_000,
    Number(row.diamond_balance || 0) + (levelSettlementNeeded ? levelSettlement.diamondDelta : 0)));
  const rewardedTournamentToday = String(row.tournament_reward_day_key || "") === todayKey
    ? Math.max(0, Math.min(Number(row.tournament_rewarded_tickets_today || 0), TOURNAMENT_REWARDED_DAILY_MAX))
    : 0;

  return {
    gameKey: baseGameKey,
    generalScore: globalGeneralScore,
    infiniteScore: Math.max(0, Number(row.infinite_score || 0)),
    gameInfiniteScore: Math.max(0, Number(row.game_infinite_score || 0)),
    totalXp,
    diamondBalance,
    levelRewardClaimedThrough: levelSettlementNeeded ? levelSettlement.claimedThroughLevel : storedClaimedThrough,
    levelRewardSettlement: levelSettlementNeeded ? levelSettlement : {
      claimedThroughLevel: storedClaimedThrough, generalDelta: 0, diamondDelta: 0,
    },
    runScore: Math.max(0, Number(row.infinite_run_score || 0)),
    infiniteNextStage: Math.max(1, Number(row.infinite_next_stage || 1)),
    profile: {
      username: safeUsername(row.username || ""),
      userSet: row.username_user_set === true,
      changeCountAfterInitial: Math.max(0, Number(row.username_change_count || 0)),
      lastChangeTimeMillis: timestampMillis(row.username_last_changed_at),
      updatedAtMillis: timestampMillis(row.profile_updated_at),
      country: safeCountry(row.country),
    },
    tournament: {
      currentStage: Math.max(1, Math.min(Number(row.tournament_stage || 1), 8)),
      remainingRights: Math.max(0, Math.min(Number(row.tournament_rights ?? 3), 3)),
      totalScore: Math.max(0, Number(row.tournament_bank || 0)),
      completed: row.tournament_completed === true,
      tickets: Math.max(0, Number(row.tournament_tickets || 0)),
      ticketCost: TOURNAMENT_ENTRY_TICKET_COST,
      entryActive: row.tournament_entry_active === true,
      rewardedTicketsToday: rewardedTournamentToday,
      rewardedTicketsRemainingToday: Math.max(0, TOURNAMENT_REWARDED_DAILY_MAX - rewardedTournamentToday),
    },
    hundred: {
      active: hundredActive,
      stage: Math.max(0, Math.min(Number(row.hundred_stage || 0), 12)),
      dailyBaseRightsRemaining: hundredBaseRightsRemaining,
      rewardedRightsRemaining: hundredRewardedRights,
      rewardedAdUsedToday: hundredAdUsed,
      rewardedAdAvailable: !hundredActive && hundredBaseRightsRemaining <= 0 && !hundredAdUsed && hundredRewardedRights <= 0,
      canStart: !hundredActive && (hundredBaseRightsRemaining + hundredRewardedRights > 0),
      nextResetAtMillis: nextUtcDayStartMillis(),
      dayKey: todayKey,
    },
    gameRights: {
      remainingRights: gameRightsRemaining,
      maxRights: GAME_RIGHT_MAX,
      lastRefillTimeMillis: gameRightsAnchor,
      millisUntilNextRight: gameRightsRemaining >= GAME_RIGHT_MAX
        ? 0 : Math.max(0, GAME_RIGHT_REFILL_MS - (now - gameRightsAnchor)),
    },
  };
}

async function readAuthoritativePlayerStateReadMostly(playerId, gameKey = "target_number") {
  if (!pool) return null;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const state = await readAuthoritativePlayerState(client, playerId, gameKey);
    await client.query("COMMIT");
    return state;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

async function applyTournamentOutcomeInTransaction(
  client,
  playerId,
  won,
  requestedStage,
  gameKey = "target_number",
  playerAlreadyEnsured = false
) {
  void playerAlreadyEnsured;
  const baseGameKey = await ensurePlayerGameProgress(client, playerId, gameKey);
  const before = await readAuthoritativePlayerState(client, playerId, baseGameKey);
  const currentStage = Math.max(1, Math.min(Number(before.tournament?.currentStage || 1), 8));
  const remainingRights = Math.max(0, Math.min(Number(before.tournament?.remainingRights ?? 3), 3));
  const bank = Math.max(0, Number(before.tournament?.totalScore || 0));
  const completedBefore = before.tournament?.completed === true;
  const entryActive = before.tournament?.entryActive === true;
  const stage = Math.max(1, Math.min(Number(requestedStage || currentStage), 8));
  if (stage !== currentStage || completedBefore || remainingRights <= 0 || !entryActive) {
    const error = new Error("Turnuva aşaması sunucu ilerlemesiyle uyuşmuyor.");
    error.statusCode = 409; error.publicCode = "TOURNAMENT_STATE_MISMATCH"; throw error;
  }

  let nextStage = currentStage;
  let nextRights = remainingRights;
  let nextBank = bank;
  let completed = false;
  let nextEntryActive = entryActive;
  let awardedScore = 0;
  let xpDelta = 0;
  if (won === true) {
    const stageReward = tournamentStageReward(currentStage);
    nextBank = Math.min(2_000_000_000, bank + stageReward);
    xpDelta = stageReward;
    completed = currentStage >= 8;
    nextStage = completed ? 8 : currentStage + 1;
    if (completed) { awardedScore = nextBank; nextEntryActive = false; }
  } else if (won === false) {
    nextRights = Math.max(0, remainingRights - 1);
    if (nextRights === 0) {
      awardedScore = bank;
      nextStage = 1; nextRights = 3; nextBank = 0; completed = false; nextEntryActive = false;
    }
  }

  const totalXpAfter = Math.min(2_000_000_000, Number(before.totalXp || 0) + xpDelta);
  const levelSettlement = calculateLevelMilestoneSettlement(totalXpAfter, before.levelRewardClaimedThrough);
  const persistedGeneralDelta = awardedScore + levelSettlement.generalDelta;
  if (persistedGeneralDelta !== 0) {
    await applyLeaderboardScoreDeltaInTransaction(client, playerId, persistedGeneralDelta, 0);
  }
  await client.query(
    `UPDATE player_progress SET
       total_xp = $2,
       diamond_balance = LEAST(diamond_balance + $3, 2000000000),
       level_reward_claimed_through = $4,
       updated_at = NOW()
     WHERE player_id = $1`,
    [playerId, totalXpAfter, levelSettlement.diamondDelta, levelSettlement.claimedThroughLevel]
  );
  await client.query(
    `UPDATE player_game_progress SET
       tournament_stage = $3,
       tournament_rights = $4,
       tournament_bank = $5,
       tournament_completed = $6,
       tournament_entry_active = $7,
       updated_at = NOW()
     WHERE player_id = $1 AND game_key = $2`,
    [playerId, baseGameKey, nextStage, nextRights, nextBank, completed, nextEntryActive]
  );

  return {
    ...before,
    gameKey: baseGameKey,
    generalScore: Math.max(0, Math.min(2_000_000_000, Number(before.generalScore || 0) + persistedGeneralDelta)),
    totalXp: totalXpAfter,
    diamondBalance: Math.max(0, Math.min(2_000_000_000, Number(before.diamondBalance || 0) + levelSettlement.diamondDelta)),
    levelRewardClaimedThrough: levelSettlement.claimedThroughLevel,
    levelRewardSettlement: levelSettlement,
    generalDelta: awardedScore,
    infiniteDelta: 0,
    xpDelta,
    awardedScore,
    won,
    tournament: {
      ...before.tournament,
      currentStage: nextStage,
      remainingRights: nextRights,
      totalScore: nextBank,
      completed,
      entryActive: nextEntryActive,
      awardedScore,
    },
  };
}

async function applyTournamentOutcome(playerId, won, requestedStage, gameKey = "target_number") {
  if (!pool || !playerId) return null;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await applyTournamentOutcomeInTransaction(client, playerId, won, requestedStage, gameKey);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

function hundredDifficultyForStage(stageValue) {
  const stage = Math.max(1, Math.min(Number(stageValue || 1), 12));
  return stage <= 4 ? "Medium" : "Hard";
}

async function addPositiveGeneralAndXpInTransaction(client, playerId, generalDelta, xpDelta) {
  const safeGeneral = Math.max(0, Math.min(Number(generalDelta || 0), 2_000_000_000));
  const safeXp = Math.max(0, Math.min(Number(xpDelta || 0), 2_000_000_000));
  if (safeGeneral > 0) {
    await applyLeaderboardScoreDeltaInTransaction(client, playerId, safeGeneral, 0);
  }
  if (safeXp > 0) {
    await client.query(
      `UPDATE player_progress SET
         total_xp = LEAST(total_xp + $2, 2000000000), updated_at = NOW()
       WHERE player_id = $1`,
      [playerId, safeXp]
    );
  }
}

const HUNDRED_ELIMINATION_REWARDS = [
  20,   // 1. aşamada elenirse
  50,   // 2. aşamada elenirse
  100,  // 3. aşamada elenirse
  200,  // 4. aşamada elenirse
  350,  // 5. aşamada elenirse
  600,  // 6. aşamada elenirse
  900,  // 7. aşamada elenirse
  1300, // 8. aşamada elenirse
  1800, // 9. aşamada elenirse
  2500, // 10. aşamada elenirse
  3500, // 11. aşamada elenirse
  5000, // 12. aşamada elenirse
];

const HUNDRED_WIN_REWARD = 10_000;

function hundredEliminationReward(stageValue) {
  const stage = Math.max(1, Math.min(Number(stageValue || 1), HUNDRED_ELIMINATION_REWARDS.length));
  return HUNDRED_ELIMINATION_REWARDS[stage - 1];
}

async function completeHundredStageInTransaction(client, playerId, stageValue, gameKey = "target_number") {
  const baseGameKey = await ensurePlayerGameProgress(client, playerId, gameKey);
  const before = await readAuthoritativePlayerState(client, playerId, baseGameKey);
  const currentStage = Math.max(1, Math.min(Number(before.hundred?.stage || 1), 12));
  const stage = Math.max(1, Math.min(Number(stageValue || currentStage), 12));
  if (before.hundred?.active !== true || stage !== currentStage) {
    const error = new Error("100 kişilik oyun aşaması sunucu durumuyla uyuşmuyor.");
    error.statusCode = 409; error.publicCode = "HUNDRED_STATE_MISMATCH"; throw error;
  }

  let generalDelta = 0;
  let xpDelta = 0;
  let nextStage = currentStage + 1;
  let runCompleted = false;
  if (currentStage >= 12) {
    generalDelta = HUNDRED_WIN_REWARD;
    xpDelta = 480;
    nextStage = 0;
    runCompleted = true;
  }
  const totalXpAfter = Math.min(2_000_000_000, Number(before.totalXp || 0) + xpDelta);
  const levelSettlement = calculateLevelMilestoneSettlement(totalXpAfter, before.levelRewardClaimedThrough);
  const persistedGeneralDelta = generalDelta + levelSettlement.generalDelta;
  if (persistedGeneralDelta !== 0) await applyLeaderboardScoreDeltaInTransaction(client, playerId, persistedGeneralDelta, 0);
  await client.query(
    `UPDATE player_progress SET
       total_xp = $2,
       diamond_balance = LEAST(diamond_balance + $3, 2000000000),
       level_reward_claimed_through = $4,
       updated_at = NOW()
     WHERE player_id = $1`,
    [playerId, totalXpAfter, levelSettlement.diamondDelta, levelSettlement.claimedThroughLevel]
  );
  await client.query(
    `UPDATE player_game_progress SET
       hundred_active = $3,
       hundred_stage = $4,
       updated_at = NOW()
     WHERE player_id = $1 AND game_key = $2`,
    [playerId, baseGameKey, !runCompleted, nextStage]
  );

  return {
    ...before,
    gameKey: baseGameKey,
    generalScore: Math.max(0, Math.min(2_000_000_000, Number(before.generalScore || 0) + persistedGeneralDelta)),
    totalXp: totalXpAfter,
    diamondBalance: Math.max(0, Math.min(2_000_000_000, Number(before.diamondBalance || 0) + levelSettlement.diamondDelta)),
    levelRewardClaimedThrough: levelSettlement.claimedThroughLevel,
    levelRewardSettlement: levelSettlement,
    hundred: {
      ...before.hundred,
      active: !runCompleted,
      stage: nextStage,
      rewardedAdAvailable: runCompleted
        ? (before.hundred?.dailyBaseRightsRemaining <= 0 && before.hundred?.rewardedAdUsedToday !== true && Number(before.hundred?.rewardedRightsRemaining || 0) <= 0)
        : false,
      canStart: runCompleted
        ? ((Number(before.hundred?.dailyBaseRightsRemaining || 0) + Number(before.hundred?.rewardedRightsRemaining || 0)) > 0)
        : false,
    },
    generalDelta,
    infiniteDelta: 0,
    xpDelta,
    awardedScore: generalDelta,
    won: runCompleted ? true : null,
    hundredStage: nextStage,
    hundredRunCompleted: runCompleted,
  };
}

async function forfeitHundredRunInTransaction(client, playerId, gameKey = "target_number") {
  const baseGameKey = await ensurePlayerGameProgress(client, playerId, gameKey);
  const before = await readAuthoritativePlayerState(client, playerId, baseGameKey);
  if (before.hundred?.active !== true) {
    return { ...before, generalDelta: 0, infiniteDelta: 0, xpDelta: 0, awardedScore: 0, won: false,
      hundredStage: 0, hundredRunCompleted: true };
  }
  const stage = Math.max(1, Math.min(Number(before.hundred?.stage || 1), 12));
  const activeChallenge = await client.query(
    `SELECT challenge_id FROM secure_game_challenges
     WHERE player_id = $1 AND game_key = $2 AND mode = 'hundred' AND completed_at IS NULL
     ORDER BY created_at DESC LIMIT 1`,
    [playerId, baseGameKey]
  );
  await recordTaskEventInTransaction(client, {
    playerId,
    sourceKey: activeChallenge.rows[0]?.challenge_id ? `challenge:${activeChallenge.rows[0].challenge_id}` : `hundred-forfeit:${baseGameKey}:${stage}:${Date.now()}`,
    eventType: "game", gameKey: baseGameKey, multiplayer: true, won: false,
  });
  const generalDelta = hundredEliminationReward(stage);
  const xpDelta = stage * 40;
  const totalXpAfter = Math.min(2_000_000_000, Number(before.totalXp || 0) + xpDelta);
  const levelSettlement = calculateLevelMilestoneSettlement(totalXpAfter, before.levelRewardClaimedThrough);
  const persistedGeneralDelta = generalDelta + levelSettlement.generalDelta;
  if (persistedGeneralDelta !== 0) await applyLeaderboardScoreDeltaInTransaction(client, playerId, persistedGeneralDelta, 0);
  await client.query(
    `UPDATE player_progress SET
       total_xp = $2,
       diamond_balance = LEAST(diamond_balance + $3, 2000000000),
       level_reward_claimed_through = $4,
       updated_at = NOW()
     WHERE player_id = $1`,
    [playerId, totalXpAfter, levelSettlement.diamondDelta, levelSettlement.claimedThroughLevel]
  );
  await client.query(
    `UPDATE player_game_progress SET hundred_active = FALSE, hundred_stage = 0, updated_at = NOW()
     WHERE player_id = $1 AND game_key = $2`,
    [playerId, baseGameKey]
  );
  await client.query(
    `UPDATE secure_game_challenges SET
       completed_at = COALESCE(completed_at, NOW()),
       result = CASE WHEN completed_at IS NULL THEN '{"status":"forfeit"}'::jsonb ELSE result END
     WHERE player_id = $1 AND game_key = $2 AND mode = 'hundred' AND completed_at IS NULL`,
    [playerId, baseGameKey]
  );
  return {
    ...before,
    gameKey: baseGameKey,
    generalScore: Math.max(0, Math.min(2_000_000_000, Number(before.generalScore || 0) + persistedGeneralDelta)),
    totalXp: totalXpAfter,
    diamondBalance: Math.max(0, Math.min(2_000_000_000, Number(before.diamondBalance || 0) + levelSettlement.diamondDelta)),
    levelRewardClaimedThrough: levelSettlement.claimedThroughLevel,
    levelRewardSettlement: levelSettlement,
    hundred: { ...before.hundred, active: false, stage: 0,
      rewardedAdAvailable: before.hundred?.dailyBaseRightsRemaining <= 0 && before.hundred?.rewardedAdUsedToday !== true && Number(before.hundred?.rewardedRightsRemaining || 0) <= 0,
      canStart: (Number(before.hundred?.dailyBaseRightsRemaining || 0) + Number(before.hundred?.rewardedRightsRemaining || 0)) > 0 },
    generalDelta, infiniteDelta: 0, xpDelta, awardedScore: generalDelta, won: false,
    hundredStage: 0, hundredRunCompleted: true,
  };
}

function secureRandomInt(minInclusive, maxExclusive) {
  if (maxExclusive <= minInclusive) return minInclusive;
  return crypto.randomInt(minInclusive, maxExclusive);
}

const BOT_AVERAGE_REQUIRED_TWO_PLAYER_FINISHES = 5;
const BOT_MIN_FINISH_MS = 1_000;

function normalizeTwoPlayerFinishProfile(profile = {}) {
  const parsedFinishCount = Number(profile.finishCount || 0);
  const parsedFinishTotalMs = Number(profile.finishTotalMs || 0);
  const finishCount = Number.isFinite(parsedFinishCount)
    ? Math.max(0, Math.floor(parsedFinishCount))
    : 0;
  const finishTotalMs = Number.isFinite(parsedFinishTotalMs)
    ? Math.max(0, Math.floor(parsedFinishTotalMs))
    : 0;
  const averageFinishMs = finishCount > 0
    ? Math.round(finishTotalMs / finishCount)
    : null;
  return { finishCount, finishTotalMs, averageFinishMs };
}

async function readTwoPlayerFinishProfileInTransaction(client, playerId, gameKey = "target_number") {
  const normalizedGameKey = normalizeBaseGameKey(gameKey);
  await ensurePlayerGameProgress(client, playerId, normalizedGameKey);
  const result = await client.query(
    `SELECT two_player_finish_count, two_player_finish_total_ms
     FROM player_game_progress
     WHERE player_id = $1 AND game_key = $2
     FOR UPDATE`,
    [playerId, normalizedGameKey]
  );
  const row = result.rows[0] || {};
  return normalizeTwoPlayerFinishProfile({
    finishCount: row.two_player_finish_count,
    finishTotalMs: row.two_player_finish_total_ms,
  });
}

async function recordTwoPlayerFinishTimeInTransaction(client, playerId, elapsedMs, roundCountValue = 1, gameKey = "target_number") {
  const parsedElapsedMs = Number(elapsedMs);
  if (!Number.isFinite(parsedElapsedMs) || parsedElapsedMs <= 0) return;
  const roundCount = normalizeRoundCount(roundCountValue);
  const averagePerRoundElapsedMs = parsedElapsedMs / roundCount;
  const safeElapsedMs = Math.max(
    1,
    Math.min(Math.floor(averagePerRoundElapsedMs), gameDefinition(gameKey).roundDurationMs)
  );
  const normalizedGameKey = normalizeBaseGameKey(gameKey);
  await ensurePlayerGameProgress(client, playerId, normalizedGameKey);
  await client.query(
    `UPDATE player_game_progress
     SET two_player_finish_count = LEAST(two_player_finish_count + 1, 2000000000),
         two_player_finish_total_ms = LEAST(
           two_player_finish_total_ms + $2::bigint,
           9223372036854775807::bigint
         ),
         updated_at = NOW()
     WHERE player_id = $1 AND game_key = $3`,
    [playerId, safeElapsedMs, normalizedGameKey]
  );
}

async function recordTwoPlayerFinishTime(playerId, elapsedMs, roundCountValue = 1, gameKey = "target_number") {
  if (!pool || !playerId) return;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await ensureAuthenticatedPlayer(client, playerId);
    await recordTwoPlayerFinishTimeInTransaction(client, playerId, elapsedMs, roundCountValue, gameKey);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Bot bitirme algoritması bütün oyunlarda aynıdır.
 * Değişen tek şey GAME_DEFINITIONS içindeki kalibrasyon aralığı, alt/üst sınır ve varyanstır.
 */
function createTwoPlayerBotFinishMs(finishProfile = {}, gameKey = "target_number") {
  const profile = normalizeTwoPlayerFinishProfile(finishProfile);
  const config = gameDefinition(gameKey);
  const absoluteMaxMs = Math.max(BOT_MIN_FINISH_MS, Number(config.roundDurationMs || 1) - 1_000);

  // İlk 5 normal ikili oyun kalibrasyondur. Burada temel kalibrasyon aralığı kullanılır;
  // createGameAwareBotPlan en sonda oyunun kendi min/max sınırını uygular. Bu iki aşamalı
  // yapı Hedef Sayıyı Bul'un eski davranışını aynen korur.
  if (
    profile.finishCount < BOT_AVERAGE_REQUIRED_TWO_PLAYER_FINISHES ||
    profile.averageFinishMs === null
  ) {
    const calibrationMinMs = Math.max(
      BOT_MIN_FINISH_MS,
      Math.min(Number(config.botCalibrationMinMs || BOT_MIN_FINISH_MS), absoluteMaxMs)
    );
    const calibrationMaxMs = Math.max(
      calibrationMinMs,
      Math.min(Number(config.botCalibrationMaxMs || absoluteMaxMs), absoluteMaxMs)
    );
    return secureRandomInt(calibrationMinMs, calibrationMaxMs + 1);
  }

  const averageFinishMs = Math.max(
    BOT_MIN_FINISH_MS,
    Math.min(profile.averageFinishMs, absoluteMaxMs)
  );
  // Varyans da diğer bot süreleri gibi yalnız oyun tanımından gelir.
  const varianceMs = Math.max(0, Number(config.botAverageVarianceMs ?? 7_000));
  const minimumFinishMs = Math.max(
    BOT_MIN_FINISH_MS,
    averageFinishMs - varianceMs
  );
  const maximumFinishMs = Math.min(
    absoluteMaxMs,
    averageFinishMs + varianceMs
  );

  return secureRandomInt(minimumFinishMs, maximumFinishMs + 1);
}

function createSecureTwoPlayerBotPlan(gameKey, difficulty, finishProfile = {}) {
  const cannotFinishBps = difficulty === "Hard" ? 2530 : 1070;
  const roll = secureRandomInt(0, 10000);
  if (roll < 560) {
    return { finishMs: null, leaveMs: secureRandomInt(0, 120) * 1000 };
  }
  if (roll < 560 + cannotFinishBps) {
    return { finishMs: null, leaveMs: null };
  }

  return {
    finishMs: createTwoPlayerBotFinishMs(finishProfile, gameKey),
    leaveMs: null,
  };
}

function createGameAwareBotPlan(gameKey, difficulty, finishProfile = {}) {
  const config = gameDefinition(gameKey);
  const baseGameKey = normalizeBaseGameKey(gameKey);

  // Oyun-bazlı %21 özel yenilgi davranışları diğer bot kurallarından tamamen izoledir.
  // Kalan %79'da ayrılma / çözememe / kalibrasyon dahil ortak bot motoru aynen çalışır.
  const wrongShortestPathRoute = baseGameKey === "shortest_path" && secureRandomInt(0, 10000) < 2100;
  const digitAttackForcedLoss = baseGameKey === "digit_attack" && secureRandomInt(0, 10000) < 2100;
  const digitAttackLossMaxMs = Math.max(28_000, Math.min(70_000, Number(config.roundDurationMs || 120_000) - 1_000));
  const plan = wrongShortestPathRoute
    ? {
        finishMs: createTwoPlayerBotFinishMs(finishProfile, gameKey),
        leaveMs: null,
        wrongRoute: true,
      }
    : digitAttackForcedLoss
      ? {
          // Rakam Saldırısı özel yenilgisi hiçbir zaman 28. saniyeden önce gerçekleşmez.
          finishMs: secureRandomInt(28_000, digitAttackLossMaxMs + 1),
          leaveMs: null,
          forcedLoss: true,
          forcedLossReason: "bot_three_mistakes",
        }
      : createSecureTwoPlayerBotPlan(gameKey, difficulty, finishProfile);

  if (plan.finishMs === null || plan.finishMs === undefined) return plan;
  const absoluteMaxMs = Math.max(BOT_MIN_FINISH_MS, Number(config.roundDurationMs || 1) - 1_000);
  if (plan.forcedLoss === true) {
    // Özel Rakam Saldırısı yenilgisi normal bitirme alt sınırına sıkıştırılmaz;
    // yalnız 28. saniye ve tur sonu güvenlik sınırları uygulanır.
    return {
      ...plan,
      finishMs: Math.max(28_000, Math.min(Number(plan.finishMs), absoluteMaxMs)),
    };
  }
  const gameMinMs = Math.max(BOT_MIN_FINISH_MS, Math.min(Number(config.botFinishMinMs || BOT_MIN_FINISH_MS), absoluteMaxMs));
  const gameMaxMs = Math.max(gameMinMs, Math.min(Number(config.botFinishMaxMs || absoluteMaxMs), absoluteMaxMs));
  return {
    ...plan,
    finishMs: Math.max(gameMinMs, Math.min(Number(plan.finishMs), gameMaxMs)),
  };
}

function botPlanTimeMs(value) {
  if (value === null || value === undefined || value === "") return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : null;
}

function botOutcomeForElapsed(plan, elapsedMs, solvedByPlayer) {
  const leaveMs = botPlanTimeMs(plan?.leaveMs);
  const finishMs = botPlanTimeMs(plan?.finishMs);
  if (leaveMs !== null && elapsedMs >= leaveMs) {
    return { resolvable: true, won: true, reason: "bot_left" };
  }
  if (finishMs !== null && elapsedMs >= finishMs) {
    if (plan?.wrongRoute === true) {
      return { resolvable: true, won: true, reason: "bot_wrong_route" };
    }
    if (plan?.forcedLoss === true) {
      return { resolvable: true, won: true, reason: safeText(plan.forcedLossReason, "bot_failed", 48) };
    }
    return { resolvable: true, won: false, reason: "bot_finished" };
  }
  if (solvedByPlayer) {
    return { resolvable: true, won: true, reason: "player_solved_first" };
  }
  return { resolvable: false, won: null, reason: "too_early" };
}

function twoPlayerBotRewards(difficulty, won, wagerPoints = 0) {
  const hard = secureDifficulty(difficulty) === "Hard";
  const points = Math.max(minimumTwoPlayerStake(difficulty), Math.floor(Number(wagerPoints || 0)));
  return {
    generalDelta: won ? points : -points,
    infiniteDelta: 0,
    xpDelta: won ? (hard ? 30 : 20) : 0,
  };
}

function compactChallengeResult(response) {
  return {
    status: "completed",
    summary: {
      generalDelta: Number(response?.generalDelta || 0),
      infiniteDelta: Number(response?.infiniteDelta || 0),
      xpDelta: Number(response?.xpDelta || 0),
      won: response?.won === null || response?.won === undefined ? null : response.won === true,
      outcomeReason: response?.outcomeReason || null,
      elapsedServerMs: Math.max(0, Number(response?.elapsedServerMs || 0)),
      awardedScore: Math.max(0, Number(response?.awardedScore || 0)),
      hundredStage: Math.max(0, Number(response?.hundredStage || 0)),
      hundredRunCompleted: response?.hundredRunCompleted === true,
      runScore: Math.max(0, Number(response?.runScore || 0)),
      gameKey: normalizeBaseGameKey(response?.gameKey),
      gameInfiniteScore: Math.max(0, Number(response?.gameInfiniteScore || 0)),
    },
  };
}

async function rebuildStoredChallengeResponseInTransaction(client, playerId, storedResult) {
  // Eski deploy'larda result.response tam cevap içeriyordu; migration gerektirmeden onu desteklemeye devam et.
  if (storedResult?.response) return storedResult.response;
  const summary = storedResult?.summary;
  if (!summary || storedResult?.status !== "completed") return null;
  const state = await readAuthoritativePlayerState(client, playerId, summary.gameKey || "target_number");
  return {
    ok: true,
    generalDelta: Number(summary.generalDelta || 0),
    infiniteDelta: Number(summary.infiniteDelta || 0),
    xpDelta: Number(summary.xpDelta || 0),
    ...state,
    runScore: Math.max(0, Number(state.runScore || summary.runScore || 0)),
    won: summary.won === null || summary.won === undefined ? null : summary.won === true,
    outcomeReason: summary.outcomeReason || null,
    elapsedServerMs: Math.max(0, Number(summary.elapsedServerMs || 0)),
    awardedScore: Math.max(0, Number(summary.awardedScore || 0)),
    hundredStage: Math.max(0, Number(summary.hundredStage || 0)),
    hundredRunCompleted: summary.hundredRunCompleted === true,
  };
}

function safeTwoPlayerFinishSample(elapsedMs, roundCountValue = 1, gameKey = "target_number") {
  const parsedElapsedMs = Number(elapsedMs);
  if (!Number.isFinite(parsedElapsedMs) || parsedElapsedMs <= 0) return null;
  const roundCount = normalizeRoundCount(roundCountValue);
  const roundLimitMs = gameDefinition(gameKey).roundDurationMs;
  return Math.max(1, Math.min(Math.floor(parsedElapsedMs / roundCount), roundLimitMs));
}

async function applyTwoPlayerBotRewardsInTransaction(
  client,
  playerId,
  rewards,
  { finishElapsedMs = null, finishRoundCount = 1, gameKey = "target_number" } = {}
) {
  // Tek full state kilidi hem mevcut score/progress değerlerini hem de bakım normalizasyonlarını verir.
  // Sonrasında ayrı finish UPDATE + score UPDATE + XP UPDATE + final full-state SELECT yerine
  // score/progress değişikliklerini tek CTE statement'ında uygularız.
  const before = await readAuthoritativePlayerState(client, playerId, gameKey);
  const safeXpDelta = Math.max(0, Math.min(Number(rewards?.xpDelta || 0), 2_000_000_000));
  const totalXpAfter = Math.min(2_000_000_000, Math.max(0, Number(before.totalXp || 0)) + safeXpDelta);
  const levelSettlement = calculateLevelMilestoneSettlement(
    totalXpAfter,
    before.levelRewardClaimedThrough
  );
  const gameGeneralDelta = Number(rewards?.generalDelta || 0);
  const persistedGeneralDelta = gameGeneralDelta + levelSettlement.generalDelta;
  const finishSampleMs = safeTwoPlayerFinishSample(finishElapsedMs, finishRoundCount, gameKey);

  const progressNeedsUpdate =
    safeXpDelta > 0 ||
    levelSettlement.diamondDelta > 0 ||
    levelSettlement.claimedThroughLevel !== before.levelRewardClaimedThrough ||
    finishSampleMs !== null;

  if (persistedGeneralDelta !== 0 || progressNeedsUpdate) {
    const monthKey = currentMonthKey();
    // Score + XP/finish/level progress tek PostgreSQL statement/round-trip. Score değişmiyorsa
    // score_update CTE'si 0 satır, progress değişmiyorsa final UPDATE 0 satır etkiler.
    await client.query(
      `WITH score_update AS (
         UPDATE player_scores
         SET general_score = GREATEST(0, LEAST(general_score::bigint + $2::bigint, 2000000000))::integer,
             monthly_general_score = CASE
               WHEN monthly_key = $8 THEN
                 GREATEST(0, LEAST(monthly_general_score::bigint + $2::bigint, 2000000000))::integer
               ELSE GREATEST(0, LEAST($2::bigint, 2000000000))::integer
             END,
             monthly_infinite_score = CASE WHEN monthly_key = $8 THEN monthly_infinite_score ELSE 0 END,
             monthly_key = $8,
             monthly_updated_at = NOW(),
             updated_at = NOW()
         WHERE player_id = $1 AND $2::bigint <> 0
         RETURNING player_id
       )
       UPDATE player_progress
       SET total_xp = $3,
           diamond_balance = LEAST(diamond_balance + $4, 2000000000),
           level_reward_claimed_through = $5,
           two_player_finish_count = LEAST(
             two_player_finish_count + CASE WHEN $6::bigint IS NULL THEN 0 ELSE 1 END,
             2000000000
           ),
           two_player_finish_total_ms = LEAST(
             two_player_finish_total_ms + COALESCE($6::bigint, 0),
             9223372036854775807::bigint
           ),
           updated_at = NOW()
       WHERE player_id = $1 AND $7::boolean`,
      [
        playerId,
        persistedGeneralDelta,
        totalXpAfter,
        levelSettlement.diamondDelta,
        levelSettlement.claimedThroughLevel,
        finishSampleMs,
        progressNeedsUpdate,
        monthKey,
      ]
    );
    if (finishSampleMs !== null) {
      await ensurePlayerGameProgress(client, playerId, gameKey);
      await client.query(
        `UPDATE player_game_progress
         SET two_player_finish_count = LEAST(two_player_finish_count + 1, 2000000000),
             two_player_finish_total_ms = LEAST(
               two_player_finish_total_ms + $3::bigint,
               9223372036854775807::bigint
             ),
             updated_at = NOW()
         WHERE player_id = $1 AND game_key = $2`,
        [playerId, normalizeBaseGameKey(gameKey), finishSampleMs]
      );
    }
  }

  return {
    ...before,
    generalScore: Math.max(0, Math.min(2_000_000_000, Number(before.generalScore || 0) + persistedGeneralDelta)),
    totalXp: totalXpAfter,
    diamondBalance: Math.max(0, Math.min(2_000_000_000,
      Number(before.diamondBalance || 0) + levelSettlement.diamondDelta)),
    levelRewardClaimedThrough: levelSettlement.claimedThroughLevel,
    levelRewardSettlement: levelSettlement,
    generalDelta: gameGeneralDelta,
    infiniteDelta: 0,
    xpDelta: safeXpDelta,
  };
}

async function settleTwoPlayerBotChallengeAsDrawInTransaction(
  client,
  challenge,
  playerId,
  gameKey = challenge?.game_key || "target_number",
  elapsedServerMs = Math.max(0, Date.now() - new Date(challenge.created_at).getTime())
) {
  const baseGameKey = normalizeBaseGameKey(gameKey);
  const state = await readAuthoritativePlayerState(client, playerId, baseGameKey);
  const response = {
    ok: true,
    gameKey: baseGameKey,
    generalDelta: 0,
    infiniteDelta: 0,
    xpDelta: 0,
    ...state,
    won: null,
    outcomeReason: "time_draw",
    elapsedServerMs,
  };

  await recordTaskEventInTransaction(client, {
    playerId,
    sourceKey: `challenge:${challenge.challenge_id}`,
    eventType: "game",
    gameKey: baseGameKey,
    multiplayer: true,
    won: false,
  });

  await client.query(
    `UPDATE secure_game_challenges
     SET completed_at = NOW(), result = $2::jsonb
     WHERE challenge_id = $1 AND completed_at IS NULL`,
    [challenge.challenge_id, JSON.stringify(compactChallengeResult(response))]
  );
  return response;
}

async function settleBotChallengeAsForfeitInTransaction(client, challenge, playerId, gameKey = challenge?.game_key || "target_number") {
  const baseGameKey = normalizeBaseGameKey(gameKey);
  const elapsedServerMs = Math.max(0, Date.now() - new Date(challenge.created_at).getTime());
  let response;
  if (challenge.mode === "tournament_bot") {
    const tournamentResult = await applyTournamentOutcomeInTransaction(
      client, playerId, false, Number(challenge.stage), baseGameKey
    );
    response = {
      ok: true,
      gameKey: baseGameKey,
      ...tournamentResult,
      runScore: tournamentResult.runScore || 0,
      won: false,
      outcomeReason: "player_forfeit",
      elapsedServerMs,
    };
  } else {
    const rewards = twoPlayerBotRewards(challenge.difficulty, false, challenge.wager_points);
    const state = await applyTwoPlayerBotRewardsInTransaction(client, playerId, rewards, { gameKey: baseGameKey });
    response = {
      ok: true,
      gameKey: baseGameKey,
      ...state,
      won: false,
      outcomeReason: "player_forfeit",
      elapsedServerMs,
    };
  }
  await recordTaskEventInTransaction(client, {
    playerId,
    sourceKey: `challenge:${challenge.challenge_id}`,
    eventType: "game",
    gameKey: baseGameKey,
    multiplayer: true,
    won: false,
  });
  await client.query(
    `UPDATE secure_game_challenges SET completed_at = NOW(), result = $2::jsonb
     WHERE challenge_id = $1 AND completed_at IS NULL`,
    [challenge.challenge_id, JSON.stringify(compactChallengeResult(response))]
  );
  return response;
}

function validateEqualSumChallengeAnswer(puzzle, numberSlotsRaw) {
  const target = Number(puzzle?.target);
  const grid = Array.isArray(numberSlotsRaw) ? numberSlotsRaw.map(Number) : [];
  const initialGrid = Array.isArray(puzzle?.initialGrid) ? puzzle.initialGrid : [];
  const poolNumbers = Array.isArray(puzzle?.numbers) ? puzzle.numbers.map(Number) : [];
  if (!Number.isInteger(target) || target < 12 || target > 50) return false;
  if (grid.length !== 16 || initialGrid.length !== 16 || poolNumbers.length !== 8) return false;
  if (!grid.every(Number.isInteger)) return false;

  const usedMovable = [];
  for (let index = 0; index < 16; index += 1) {
    const fixed = initialGrid[index];
    if (fixed !== null && fixed !== undefined) {
      if (!Number.isInteger(Number(fixed)) || grid[index] !== Number(fixed)) return false;
    } else {
      usedMovable.push(grid[index]);
    }
  }
  const expected = [...poolNumbers].sort((a, b) => a - b);
  const actual = [...usedMovable].sort((a, b) => a - b);
  if (expected.length !== actual.length || !expected.every((value, index) => value === actual[index])) return false;

  const lines = [];
  for (let row = 0; row < 4; row += 1) lines.push(grid.slice(row * 4, row * 4 + 4));
  for (let col = 0; col < 4; col += 1) lines.push([grid[col], grid[4 + col], grid[8 + col], grid[12 + col]]);
  if (!lines.every((line) => lineHasFourDistinctValues(line) && line.reduce((sum, value) => sum + value, 0) === target)) return false;
  const signatures = lines.map((line) => line.join(","));
  return new Set(signatures).size === signatures.length;
}

function normalizeGameAnswer(numberSlotsRaw, operatorsRaw, answerRaw) {
  const answer = answerRaw && typeof answerRaw === "object" && !Array.isArray(answerRaw)
    ? { ...answerRaw }
    : {};
  if (!Array.isArray(answer.numberSlots) && Array.isArray(numberSlotsRaw)) {
    answer.numberSlots = numberSlotsRaw;
  }
  if (!Array.isArray(answer.operators) && Array.isArray(operatorsRaw)) {
    answer.operators = operatorsRaw;
  }
  return answer;
}

function validateTargetNumberChallengeAnswer(puzzle, answer = {}) {
  const numbers = Array.isArray(puzzle?.numbers) ? puzzle.numbers.map(Number) : [];
  const numberSlots = Array.isArray(answer.numberSlots) ? answer.numberSlots.map(Number) : [];
  const operators = Array.isArray(answer.operators) ? answer.operators.map(String) : [];
  if (numberSlots.length !== numbers.length || operators.length !== numbers.length - 1) return false;
  const sorted = [...numberSlots].sort((a, b) => a - b);
  if (!sorted.every((value, index) => Number.isInteger(value) && value === index)) return false;
  const orderedNumbers = numberSlots.map((index) => numbers[index]);
  const result = evaluateExpression(orderedNumbers, operators);
  return result !== null && Math.abs(result - Number(puzzle.target)) < 0.0001;
}


const DIGIT_ATTACK_REQUIRED_HITS = 20;
const DIGIT_ATTACK_MAX_MISTAKES = 3;
const DIGIT_ATTACK_WAVE_COUNT = 20;
const DIGIT_ATTACK_WAVE_STRIDE = 6;

function digitAttackApply(baseValue, operationValue, operandValue) {
  const base = Number(baseValue);
  const operation = Number(operationValue);
  const operand = Number(operandValue);
  if (!Number.isInteger(base) || !Number.isInteger(operation) || !Number.isInteger(operand)) return null;
  if (operation === 0) return base + operand;
  if (operation === 1) return base - operand;
  if (operation === 2) return base * operand;
  if (operation === 3) return operand !== 0 && base % operand === 0 ? base / operand : null;
  return null;
}

function digitAttackDecodeWaves(numbersRaw) {
  const numbers = Array.isArray(numbersRaw) ? numbersRaw.map(Number) : [];
  if (numbers.length !== DIGIT_ATTACK_WAVE_COUNT * DIGIT_ATTACK_WAVE_STRIDE) return null;
  const waves = [];
  for (let offset = 0; offset < numbers.length; offset += DIGIT_ATTACK_WAVE_STRIDE) {
    waves.push({
      base: numbers[offset],
      target: numbers[offset + 1],
      operation: numbers[offset + 2],
      operands: numbers.slice(offset + 3, offset + 6),
    });
  }
  return waves;
}

function digitAttackCorrectLane(wave) {
  if (!wave || !Array.isArray(wave.operands)) return -1;
  const matches = wave.operands
    .map((operand, lane) => digitAttackApply(wave.base, wave.operation, operand) === wave.target ? lane : -1)
    .filter((lane) => lane >= 0);
  return matches.length === 1 ? matches[0] : -1;
}

function isDigitAttackPuzzleEncodingValid(puzzle) {
  if (Number(puzzle?.target) !== DIGIT_ATTACK_REQUIRED_HITS) return false;
  const waves = digitAttackDecodeWaves(puzzle?.numbers);
  if (!waves) return false;
  const operationCounts = [0, 0, 0, 0];
  let previousTarget = null;
  for (let index = 0; index < waves.length; index += 1) {
    const wave = waves[index];
    // İlk alt sayı 4-10 arasındadır. Sonraki her dalganın alt sayısı bir önceki
    // hedefe eşittir ve zincirin hiçbir aşamasında 4'ün altına düşmez.
    if (!Number.isInteger(wave.base) || wave.base < 4 || wave.base >= 100) return false;
    if (index === 0 && wave.base > 10) return false;
    if (index > 0 && wave.base !== previousTarget) return false;
    if (!Number.isInteger(wave.target) || wave.target < 4 || wave.target >= 100) return false;
    if (wave.target === wave.base) return false;
    if (!Number.isInteger(wave.operation) || wave.operation < 0 || wave.operation > 3) return false;
    if (!Array.isArray(wave.operands) || wave.operands.length !== 3) return false;
    if (!wave.operands.every((value) => Number.isInteger(value) && value >= 1 && value <= 40)) return false;
    if (new Set(wave.operands).size !== 3) return false;
    const correctLane = digitAttackCorrectLane(wave);
    if (correctLane < 0) return false;
    const correctOperand = wave.operands[correctLane];
    const correctOperandAllowed = wave.operation === 0 || wave.operation === 1
      ? correctOperand >= 9 && correctOperand <= 25
      : correctOperand >= 2 && correctOperand <= 5;
    if (!correctOperandAllowed) return false;
    if (wave.operands.some((operand, lane) => lane !== correctLane &&
        (Math.abs(operand - correctOperand) < 1 || Math.abs(operand - correctOperand) > 2))) return false;
    previousTarget = wave.target;
    operationCounts[wave.operation] += 1;
  }
  return operationCounts.every((count) => count === DIGIT_ATTACK_WAVE_COUNT / 4);
}

function digitAttackNearbyOperands(base, operation, correctOperand, target) {
  // Yanlış iki taş doğru operandın en fazla 2 eksiği/fazlasıdır.
  const deltas = shuffled([-1, 1, -2, 2]);
  const result = [correctOperand];
  for (const delta of deltas) {
    const candidate = correctOperand + delta;
    if (candidate < 1 || candidate > 40 || result.includes(candidate)) continue;
    if (digitAttackApply(base, operation, candidate) === target) continue;
    result.push(candidate);
    if (result.length === 3) break;
  }
  return result.length === 3 ? shuffled(result) : null;
}

function digitAttackCanUseOperation(base, operation) {
  if (!Number.isInteger(base) || base < 4 || base >= 100) return false;
  if (operation === 0) return base <= 90; // Doğru toplama operandı +9..+25 ve hedef <100.
  if (operation === 1) return base >= 13; // Doğru çıkarma operandı -9..-25 ve hedef >=4.
  if (operation === 2) return base <= 49; // Doğru çarpan ×2..×5 ve hedef <100.
  if (operation === 3) {
    // Doğru bölen ÷2..÷5; bölüm de sonraki alt sayı olacağı için en az 4 olmalı.
    for (let divisor = 2; divisor <= 5; divisor += 1) {
      if (base % divisor === 0 && base / divisor >= 4) return true;
    }
    return false;
  }
  return false;
}

function generateDigitAttackWaveFromBase(base, operation, nextOperation = null) {
  let candidates = [];
  if (operation === 0) {
    const maxOperand = Math.min(25, 99 - base);
    candidates = maxOperand >= 9
      ? Array.from({ length: maxOperand - 8 }, (_, index) => index + 9)
      : [];
  } else if (operation === 1) {
    const maxOperand = Math.min(25, base - 4);
    candidates = maxOperand >= 9
      ? Array.from({ length: maxOperand - 8 }, (_, index) => index + 9)
      : [];
  } else if (operation === 2) {
    const maxOperand = Math.min(5, Math.floor(99 / base));
    candidates = maxOperand >= 2
      ? Array.from({ length: maxOperand - 1 }, (_, index) => index + 2)
      : [];
  } else if (operation === 3) {
    candidates = [2, 3, 4, 5]
      .filter((operand) => base % operand === 0 && base / operand >= 4);
  }

  for (const correctOperand of shuffled(candidates)) {
    const target = digitAttackApply(base, operation, correctOperand);
    if (!Number.isInteger(target) || target < 4 || target >= 100 || target === base) continue;
    if (nextOperation !== null && !digitAttackCanUseOperation(target, nextOperation)) continue;
    const operands = digitAttackNearbyOperands(base, operation, correctOperand, target);
    if (!operands) continue;
    const wave = { base, target, operation, operands };
    if (digitAttackCorrectLane(wave) < 0) continue;
    return wave;
  }
  return null;
}

function generateDigitAttackPuzzle() {
  // Dört işlemin her biri tam 5 kez bulunur. İşlem sırası rastgele kalır; fakat
  // hedef bir sonraki dalganın alt sayısı olduğundan zincirin tamamı birlikte üretilir.
  for (let puzzleAttempt = 0; puzzleAttempt < 2500; puzzleAttempt += 1) {
    const operations = shuffled(Array.from({ length: 5 }, () => [0, 1, 2, 3]).flat());
    let base = secureRandomInt(4, 11);
    const waves = [];
    let failed = false;

    for (let index = 0; index < operations.length; index += 1) {
      const operation = operations[index];
      const nextOperation = index + 1 < operations.length ? operations[index + 1] : null;
      if (!digitAttackCanUseOperation(base, operation)) {
        failed = true;
        break;
      }
      const wave = generateDigitAttackWaveFromBase(base, operation, nextOperation);
      if (!wave) {
        failed = true;
        break;
      }
      waves.push(wave);
      base = wave.target;
    }

    if (failed || waves.length !== DIGIT_ATTACK_WAVE_COUNT) continue;
    const numbers = waves.flatMap((wave) => [wave.base, wave.target, wave.operation, ...wave.operands]);
    const puzzle = {
      difficulty: "Standard",
      target: DIGIT_ATTACK_REQUIRED_HITS,
      numbers,
      gameKey: "digit_attack",
      initialGrid: [],
    };
    if (isDigitAttackPuzzleEncodingValid(puzzle)) return puzzle;
  }
  throw new Error("Rakam Saldırısı zincir bulmacası üretilemedi.");
}

function normalizeDigitAttackChoices(answer = {}) {
  if (!Array.isArray(answer.choices)) return null;
  const choices = answer.choices.map(Number);
  if (choices.length < 1 || choices.length > DIGIT_ATTACK_WAVE_COUNT) return null;
  if (!choices.every((lane) => Number.isInteger(lane) && lane >= 0 && lane <= 2)) return null;
  return choices;
}

function digitAttackEvaluateAnswer(puzzle, answer = {}) {
  if (!isDigitAttackPuzzleEncodingValid(puzzle)) return null;
  const choices = normalizeDigitAttackChoices(answer);
  if (!choices) return null;
  const waves = digitAttackDecodeWaves(puzzle.numbers);
  let correct = 0;
  let mistakes = 0;
  for (let index = 0; index < choices.length; index += 1) {
    const correctLane = digitAttackCorrectLane(waves[index]);
    if (choices[index] === correctLane) correct += 1;
    else mistakes += 1;
    const lost = mistakes >= DIGIT_ATTACK_MAX_MISTAKES;
    const completedAllWaves = index + 1 >= DIGIT_ATTACK_WAVE_COUNT;
    if (lost || completedAllWaves) {
      if (index !== choices.length - 1) return null;
      return { terminal: true, won: !lost && completedAllWaves, correct, mistakes };
    }
  }
  return { terminal: false, won: false, correct, mistakes };
}

function validateDigitAttackChallengeAnswer(puzzle, answer = {}) {
  const result = digitAttackEvaluateAnswer(puzzle, answer);
  if (!result || !result.terminal) return false;
  if (Number(answer.correctCount) !== result.correct) return false;
  if (Number(answer.mistakes) !== result.mistakes) return false;
  const expectedOutcome = result.won ? "completed" : "three_mistakes";
  return safeText(answer.outcome, "", 32) === expectedOutcome;
}

function digitAttackAnswerIsWinning(puzzle, answer = {}) {
  const result = digitAttackEvaluateAnswer(puzzle, answer);
  return result?.terminal === true && result.won === true;
}


// Rakam Saldırısı gerçek zamanlı akış motoru.
// Oyuncu bağlıyken her temas sunucuya bildirilir. Bağlantı koptuğunda ise son bilinen
// alt-taş şeridi kullanılarak 4.5 saniyelik dalga ritmi sunucuda ilerlemeye devam eder.
const DIGIT_ATTACK_FLOW_FALL_MS = 4_500;

function isDigitAttackRealtimeRoom(room) {
  return normalizeBaseGameKey(room?.gameKey) === "digit_attack" &&
    isDigitAttackPuzzleEncodingValid(room?.puzzle);
}

function clearDigitAttackAutoHandle(participant) {
  if (participant?.digitAttackAutoHandle) {
    clearTimeout(participant.digitAttackAutoHandle);
    participant.digitAttackAutoHandle = null;
  }
}

function resetDigitAttackParticipantFlow(room, participant) {
  clearDigitAttackAutoHandle(participant);
  participant.digitAttackChoices = [];
  participant.digitAttackLane = 1;
  participant.digitAttackCorrect = 0;
  participant.digitAttackMistakes = 0;
  participant.digitAttackWaveStartedAt = Number(room?.startsAtMillis || Date.now());
}

function ensureDigitAttackParticipantFlow(room, participant) {
  if (!isDigitAttackRealtimeRoom(room) || !participant) return null;
  if (!Array.isArray(participant.digitAttackChoices)) {
    resetDigitAttackParticipantFlow(room, participant);
  }
  participant.digitAttackLane = Math.max(0, Math.min(2, Number(participant.digitAttackLane ?? 1) || 0));
  participant.digitAttackCorrect = Math.max(0, Number(participant.digitAttackCorrect || 0));
  participant.digitAttackMistakes = Math.max(0, Number(participant.digitAttackMistakes || 0));
  participant.digitAttackWaveStartedAt = Math.max(
    Number(room?.startsAtMillis || room?.createdAt || Date.now()),
    Number(participant.digitAttackWaveStartedAt || room?.startsAtMillis || Date.now())
  );
  return participant;
}

function digitAttackProgressSlots(room, participant) {
  const state = ensureDigitAttackParticipantFlow(room, participant);
  if (!state) return null;
  const choices = state.digitAttackChoices.slice(0, DIGIT_ATTACK_WAVE_COUNT);
  return [
    choices.length,
    state.digitAttackCorrect,
    state.digitAttackMistakes,
    state.digitAttackLane,
    ...Array.from({ length: DIGIT_ATTACK_WAVE_COUNT }, (_, index) =>
      index < choices.length ? choices[index] : null
    ),
  ];
}

function emitDigitAttackState(room, participant) {
  if (!room || !participant || !isDigitAttackRealtimeRoom(room)) return;
  emitToRoomParticipant(participant, "digit_attack_state", {
    roomId: room.roomId,
    roundIndex: room.roundIndex,
    progressSlots: digitAttackProgressSlots(room, participant),
    waveStartedAtMillis: Number(participant.digitAttackWaveStartedAt || room.startsAtMillis || Date.now()),
  });
}

function applyRealtimeDigitAttackChoice(room, participant, laneValue, expectedWaveIndex = null, source = "player") {
  const state = ensureDigitAttackParticipantFlow(room, participant);
  if (!state || room.resolved || participant.finishedRoundIndex === room.roundIndex) return false;
  if (Date.now() < Number(room.startsAtMillis || room.createdAt || 0)) return false;

  const waves = digitAttackDecodeWaves(room.puzzle?.numbers);
  if (!waves) return false;
  const waveIndex = state.digitAttackChoices.length;
  if (expectedWaveIndex !== null && Number(expectedWaveIndex) !== waveIndex) {
    // Eski/stale istemci teması authoritative akışı geri saramaz.
    emitDigitAttackState(room, participant);
    return false;
  }
  if (waveIndex >= DIGIT_ATTACK_WAVE_COUNT) return false;

  const lane = Math.max(0, Math.min(2, Math.floor(Number(laneValue) || 0)));
  state.digitAttackChoices.push(lane);
  if (lane === digitAttackCorrectLane(waves[waveIndex])) state.digitAttackCorrect += 1;
  else state.digitAttackMistakes += 1;
  // Her temastan sonra yeni alt taş merkezde doğar. Bağlantı kopukken ilk kaçırılan
  // dalga oyuncunun son şeridini, sonraki kaçırılan dalgalar merkez şeridi kullanır.
  state.digitAttackLane = 1;

  const elapsedMs = Math.max(1, Date.now() - Number(room.startsAtMillis || room.createdAt || Date.now()));
  const lost = state.digitAttackMistakes >= DIGIT_ATTACK_MAX_MISTAKES;
  const completed = state.digitAttackChoices.length >= DIGIT_ATTACK_WAVE_COUNT;

  if (lost || completed) {
    const wasAway = !participant.connected || participant.backgrounded || Boolean(participant.awaySince);
    const preservedAwaySince = participant.awaySince || Date.now();
    const preservedReconnectDeadline = participant.reconnectDeadlineAt || (preservedAwaySince + ROOM_RECONNECT_TIMEOUT_MS);
    clearDigitAttackAutoHandle(state);

    if (lost) {
      registerRealtimeRoundLoss(
        room,
        participant,
        elapsedMs,
        source === "away" ? "digit_attack_away_three_mistakes" : "three_mistakes"
      );
    } else {
      registerRealtimeRoundFinish(room, participant, elapsedMs);
    }

    // Çok elli maçta bir el bağlantı kesikken sonuçlanabilir. Ortak round motoru
    // clearParticipantAwayState çağırdığı için kopuk oyuncuyu yanlışlıkla bağlı saymamak adına
    // aynı away oturumunu sonraki ele taşı ve canlı akışı orada da sürdür.
    if (wasAway && !room.resolved) {
      participant.connected = false;
      participant.backgrounded = true;
      participant.awaySince = preservedAwaySince;
      participant.reconnectDeadlineAt = preservedReconnectDeadline;
      scheduleParticipantAwayTimeout(room, participant.playerId);
      scheduleDigitAttackAwayFlow(room, participant.playerId);
    }
    return true;
  }

  state.digitAttackWaveStartedAt = Date.now();
  emitDigitAttackState(room, participant);
  // `away` kaynaklı catch-up zaten advanceDigitAttackAwayFlowToNow döngüsü içindedir.
  // Buradan yeniden schedule çağırmak recursive catch-up oluşturur; yalnız canlı oyuncu
  // tam bu sırada away durumuna geçtiyse yeni zamanlayıcı kur.
  if (source !== "away" && (!participant.connected || participant.backgrounded || participant.awaySince)) {
    scheduleDigitAttackAwayFlow(room, participant.playerId);
  }
  return true;
}

function advanceDigitAttackAwayFlowToNow(room, participant) {
  const state = ensureDigitAttackParticipantFlow(room, participant);
  if (!state || room.resolved || participant.finishedRoundIndex === room.roundIndex) return;
  if (participant.connected && !participant.backgrounded && !participant.awaySince) return;

  let guard = DIGIT_ATTACK_WAVE_COUNT + 2;
  const now = Date.now();
  while (guard-- > 0 && !room.resolved && participant.finishedRoundIndex !== room.roundIndex) {
    const dueAt = Number(state.digitAttackWaveStartedAt || room.startsAtMillis || now) + DIGIT_ATTACK_FLOW_FALL_MS;
    if (dueAt > now) break;
    // Gecikmeli callback / uygulamanın tamamen kapalı kalması durumunda geçmiş dalgaları
    // tek tek işler; sonraki başlangıcı gerçek ritme göre ilerletir.
    const previousStart = Number(state.digitAttackWaveStartedAt || dueAt - DIGIT_ATTACK_FLOW_FALL_MS);
    const applied = applyRealtimeDigitAttackChoice(room, participant, state.digitAttackLane, null, "away");
    if (!applied || room.resolved || participant.finishedRoundIndex === room.roundIndex) break;
    state.digitAttackWaveStartedAt = previousStart + DIGIT_ATTACK_FLOW_FALL_MS;
  }
}

function scheduleDigitAttackAwayFlow(room, playerId) {
  const participant = getParticipant(room, playerId);
  const state = ensureDigitAttackParticipantFlow(room, participant);
  if (!state || room.resolved || participant.finishedRoundIndex === room.roundIndex) return;
  if (participant.connected && !participant.backgrounded && !participant.awaySince) return;

  clearDigitAttackAutoHandle(state);
  advanceDigitAttackAwayFlowToNow(room, participant);
  if (room.resolved || participant.finishedRoundIndex === room.roundIndex) return;

  const dueAt = Number(state.digitAttackWaveStartedAt || room.startsAtMillis || Date.now()) + DIGIT_ATTACK_FLOW_FALL_MS;
  const waitMs = Math.max(0, dueAt - Date.now());
  state.digitAttackAutoHandle = setTimeout(() => {
    state.digitAttackAutoHandle = null;
    const liveRoom = realtimeRooms.get(room.roomId);
    const liveParticipant = getParticipant(liveRoom, playerId);
    if (!liveRoom || !liveParticipant || liveRoom.resolved) return;
    if (liveParticipant.connected && !liveParticipant.backgrounded && !liveParticipant.awaySince) return;
    advanceDigitAttackAwayFlowToNow(liveRoom, liveParticipant);
    scheduleDigitAttackAwayFlow(liveRoom, playerId);
  }, waitMs);
  state.digitAttackAutoHandle.unref?.();
}

const SHORTEST_PATH_EDGE_PAIRS = Object.freeze([
  [0, 1], [0, 2], [0, 3], [0, 4],
  [1, 2], [1, 3], [1, 4],
  [2, 3], [2, 4],
  [3, 4],
]);

const SHORTEST_PATH_ROUTE_ORDERS = Object.freeze((() => {
  const values = [1, 2, 3, 4];
  const routes = [];
  for (const a of values) for (const b of values) for (const c of values) for (const d of values) {
    const route = [a, b, c, d];
    if (new Set(route).size === 4) routes.push(Object.freeze(route));
  }
  return routes;
})());

function shortestPathEdgeIndex(aValue, bValue) {
  const a = Math.min(Number(aValue), Number(bValue));
  const b = Math.max(Number(aValue), Number(bValue));
  return SHORTEST_PATH_EDGE_PAIRS.findIndex(([left, right]) => left === a && right === b);
}

function shortestPathDistance(numbers, a, b) {
  const index = shortestPathEdgeIndex(a, b);
  if (index < 0 || index >= numbers.length) return null;
  const value = Number(numbers[index]);
  return Number.isInteger(value) ? value : null;
}

function shortestPathRouteTotal(numbersRaw, routeOrderRaw) {
  const numbers = Array.isArray(numbersRaw) ? numbersRaw.map(Number) : [];
  const routeOrder = Array.isArray(routeOrderRaw) ? routeOrderRaw.map(Number) : [];
  if (numbers.length !== 10 || routeOrder.length !== 4 || new Set(routeOrder).size !== 4) return null;
  if (!routeOrder.every((value) => Number.isInteger(value) && value >= 1 && value <= 4)) return null;
  const fullRoute = [0, ...routeOrder, 0];
  let total = 0;
  for (let i = 0; i < fullRoute.length - 1; i += 1) {
    const distance = shortestPathDistance(numbers, fullRoute[i], fullRoute[i + 1]);
    if (distance === null) return null;
    total += distance;
  }
  return total;
}

function shortestPathWinningRoutes(numbers) {
  const totals = SHORTEST_PATH_ROUTE_ORDERS.map((route) => ({ route, total: shortestPathRouteTotal(numbers, route) }));
  const minimum = Math.min(...totals.map((item) => item.total ?? Number.MAX_SAFE_INTEGER));
  return {
    minimum,
    routes: totals.filter((item) => item.total === minimum).map((item) => item.route),
  };
}

function isShortestPathPuzzleEncodingValid(puzzle) {
  const numbers = Array.isArray(puzzle?.numbers) ? puzzle.numbers.map(Number) : [];
  if (numbers.length !== 10) return false;
  if (!numbers.every((value) => Number.isInteger(value) && value >= 5 && value <= 25)) return false;
  if (new Set(numbers).size !== 10) return false;
  const winning = shortestPathWinningRoutes(numbers);
  if (!Number.isInteger(winning.minimum) || Number(puzzle?.target) !== winning.minimum) return false;
  // Ters yönde dolaşmak aynı çevrimi verir; bu yüzden tek bir geometrik en kısa rota
  // tam olarak iki yönlü permütasyon olarak görünmelidir.
  if (winning.routes.length !== 2) return false;
  const first = winning.routes[0];
  const second = winning.routes[1];
  return first.every((value, index) => value === second[second.length - 1 - index]);
}

function generateShortestPathPuzzle() {
  const candidates = Array.from({ length: 21 }, (_, index) => index + 5);
  for (let attempt = 0; attempt < 500; attempt += 1) {
    const shuffled = [...candidates];
    for (let i = shuffled.length - 1; i > 0; i -= 1) {
      const j = secureRandomInt(0, i + 1);
      [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
    }
    const numbers = shuffled.slice(0, 10);
    const winning = shortestPathWinningRoutes(numbers);
    if (winning.routes.length !== 2) continue;
    const first = winning.routes[0];
    const second = winning.routes[1];
    const reversePair = first.every((value, index) => value === second[second.length - 1 - index]);
    if (!reversePair) continue;
    return {
      difficulty: "Standard",
      target: winning.minimum,
      numbers,
      gameKey: "shortest_path",
      initialGrid: [],
    };
  }
  // Kriptografik rastgele üretimde bu kola pratikte düşülmez. Yine de servis hiçbir zaman
  // geçersiz bulmaca döndürmesin diye önceden doğrulanmış deterministik bir dağılım tutulur.
  const fallbackNumbers = [6, 21, 17, 12, 9, 25, 14, 7, 19, 11];
  const winning = shortestPathWinningRoutes(fallbackNumbers);
  if (winning.routes.length !== 2) throw new Error("En Kısa Yol bulmacası üretilemedi.");
  return {
    difficulty: "Standard",
    target: winning.minimum,
    numbers: fallbackNumbers,
    gameKey: "shortest_path",
    initialGrid: [],
  };
}

function normalizeShortestPathRoute(answer = {}) {
  if (!Array.isArray(answer.route)) return null;
  const raw = answer.route.map(Number);
  const route = raw.length === 6 && raw[0] === 0 && raw[5] === 0 ? raw.slice(1, 5) : raw;
  if (route.length !== 4 || new Set(route).size !== 4) return null;
  if (!route.every((value) => Number.isInteger(value) && value >= 1 && value <= 4)) return null;
  return route;
}

function validateShortestPathChallengeAnswer(puzzle, answer = {}) {
  if (!isShortestPathPuzzleEncodingValid(puzzle)) return false;
  return normalizeShortestPathRoute(answer) !== null;
}

function shortestPathAnswerIsWinning(puzzle, answer = {}) {
  const route = normalizeShortestPathRoute(answer);
  if (route === null || !isShortestPathPuzzleEncodingValid(puzzle)) return false;
  return shortestPathRouteTotal(puzzle.numbers, route) === Number(puzzle.target);
}

const GAME_HANDLERS = Object.freeze({
  target_number: Object.freeze({
    key: "target_number",
    createPuzzle: (difficultyValue) => ({
      ...generateSecurePuzzle(difficultyValue),
      gameKey: "target_number",
      initialGrid: [],
    }),
    validateAnswer: (puzzle, answer) => validateTargetNumberChallengeAnswer(puzzle, answer),
  }),
  equal_sum: Object.freeze({
    key: "equal_sum",
    createPuzzle: () => generateEqualSumPuzzle(),
    validateAnswer: (puzzle, answer) =>
      validateEqualSumChallengeAnswer(puzzle, Array.isArray(answer?.numberSlots) ? answer.numberSlots : []),
  }),
  total_equals: Object.freeze({
    key: "total_equals",
    createPuzzle: () => generateTotalEqualsPuzzle(),
    validateAnswer: (puzzle, answer) => validateTotalEqualsChallengeAnswer(puzzle, answer),
  }),
  next_number: Object.freeze({
    key: "next_number",
    createPuzzle: () => generateNextNumberPuzzle(),
    validateAnswer: (puzzle, answer) => validateNextNumberChallengeAnswer(puzzle, answer),
  }),
  equation_hunt: Object.freeze({
    key: "equation_hunt",
    createPuzzle: () => generateEquationHuntPuzzle(),
    validateAnswer: (puzzle, answer) => validateEquationHuntChallengeAnswer(puzzle, answer),
  }),
  digit_attack: Object.freeze({
    key: "digit_attack",
    createPuzzle: () => generateDigitAttackPuzzle(),
    // 20 dalgayı 3 yanlışa ulaşmadan tamamlama kazanır; üçüncü yanlış temas geçerli bir mağlubiyet gönderimidir.
    validateAnswer: (puzzle, answer) => validateDigitAttackChallengeAnswer(puzzle, answer),
    isWinningAnswer: (puzzle, answer) => digitAttackAnswerIsWinning(puzzle, answer),
  }),
  shortest_path: Object.freeze({
    key: "shortest_path",
    createPuzzle: () => generateShortestPathPuzzle(),
    // Yanlış rota da biçimsel olarak geçerli bir "gönderim"dir; kazanıp kazanmadığı
    // challengeAnswerIsWinning ile ayrıca hesaplanır ve kayıp olarak işlenir.
    validateAnswer: (puzzle, answer) => validateShortestPathChallengeAnswer(puzzle, answer),
    isWinningAnswer: (puzzle, answer) => shortestPathAnswerIsWinning(puzzle, answer),
  }),
  consecutive: Object.freeze({
    key: "consecutive",
    createPuzzle: () => generateConsecutivePuzzle(),
    validateAnswer: (puzzle, answer) => validateConsecutiveChallengeAnswer(puzzle, answer),
  }),
});

function gameHandler(value) {
  const base = normalizeBaseGameKey(value);
  const handler = GAME_HANDLERS[base];
  if (!handler) throw unsupportedGameError(base);
  return handler;
}

function validateChallengeAnswer(puzzle, numberSlotsRaw, operatorsRaw, answerRaw) {
  const answer = normalizeGameAnswer(numberSlotsRaw, operatorsRaw, answerRaw);
  return gameHandler(puzzle?.gameKey).validateAnswer(puzzle, answer);
}

function challengeAnswerIsWinning(puzzle, numberSlotsRaw, operatorsRaw, answerRaw) {
  const answer = normalizeGameAnswer(numberSlotsRaw, operatorsRaw, answerRaw);
  const handler = gameHandler(puzzle?.gameKey);
  if (!handler.validateAnswer(puzzle, answer)) return false;
  return typeof handler.isWinningAnswer === "function"
    ? handler.isWinningAnswer(puzzle, answer) === true
    : true;
}

async function ensureAuthenticatedPlayer(client, playerId) {
  // Normal kullanıcıda üç INSERT denemek yerine tek hafif SELECT ile satırların tam olduğunu doğrula.
  const existing = await client.query(
    `SELECT 1
     FROM players pl
     JOIN player_scores s ON s.player_id = pl.player_id
     JOIN player_progress p ON p.player_id = pl.player_id
     WHERE pl.player_id = $1
     LIMIT 1`,
    [playerId]
  );
  if (existing.rowCount > 0) return false;

  const fallbackUsername = `Oyuncu_${String(playerId).slice(-8)}`;
  await client.query(
    `INSERT INTO players (player_id, username, country, created_at, updated_at)
     VALUES ($1, $2, 'TR', NOW(), NOW())
     ON CONFLICT (player_id) DO NOTHING`,
    [playerId, fallbackUsername]
  );
  await client.query(
    `INSERT INTO player_scores (player_id)
     VALUES ($1)
     ON CONFLICT (player_id) DO NOTHING`,
    [playerId]
  );
  await client.query(
    `INSERT INTO player_progress (player_id, total_xp, updated_at)
     VALUES ($1, 0, NOW())
     ON CONFLICT (player_id) DO NOTHING`,
    [playerId]
  );
  return true;
}

function normalizeGameplayDeviceId(value) {
  const deviceId = safeText(value, "", 128);
  return /^device_[a-f0-9]{32}$/i.test(deviceId) ? deviceId.toLowerCase() : "";
}

function normalizeGameplaySessionId(value) {
  const sessionId = safeText(value, "", 128);
  return /^[a-f0-9-]{20,128}$/i.test(sessionId) ? sessionId.toLowerCase() : "";
}

function gameplaySessionIdFromRequest(req) {
  return normalizeGameplaySessionId(req.headers["x-game-session-id"]);
}

async function readAndMaybeRenewGameplaySession(queryable, playerId, sessionId) {
  // Tek SQL statement: normalde yalnız SELECT sonucu döner. Session bitmeye yaklaştığında ve
  // zaten gerçek bir authoritative istek gelmişken expiry seyrek olarak yenilenir. Böylece
  // heartbeat/polling yoktur; PostgreSQL yazımı varsayılan 30 dk TTL'de en fazla yaklaşık
  // 20 dakikada bir ve yalnız aktif trafik varsa gerçekleşir.
  return queryable.query(
    `WITH renewed AS (
       UPDATE player_game_sessions
       SET expires_at = NOW() + ($3::integer * INTERVAL '1 second')
       WHERE player_id = $1
         AND session_id = $2
         AND expires_at > NOW()
         AND expires_at <= NOW() + ($4::integer * INTERVAL '1 second')
       RETURNING session_id, device_id, game_key, created_at, expires_at, protocol_version
     ), current_session AS (
       SELECT session_id, device_id, game_key, created_at, expires_at, protocol_version
       FROM player_game_sessions
       WHERE player_id = $1
         AND session_id = $2
         AND expires_at > NOW()
         AND NOT EXISTS (SELECT 1 FROM renewed)
     )
     SELECT * FROM renewed
     UNION ALL
     SELECT * FROM current_session
     LIMIT 1`,
    [playerId, sessionId, GAMEPLAY_SESSION_ACTIVE_TTL_SECONDS, GAMEPLAY_SESSION_RENEW_BEFORE_SECONDS]
  );
}

async function requireGameplaySession(req, res, next) {
  if (!requireDatabase(res)) return;
  const sessionId = gameplaySessionIdFromRequest(req);
  if (!sessionId) {
    res.status(409).json({
      ok: false,
      code: "GAME_SESSION_REQUIRED",
      message: "Oyunu başlatmak için aktif cihaz oyun oturumu gerekli.",
    });
    return;
  }

  try {
    const result = await readAndMaybeRenewGameplaySession(pool, req.auth.sub, sessionId);
    if (result.rowCount === 0) {
      res.status(409).json({
        ok: false,
        code: "GAME_SESSION_REPLACED",
        message: "Bu oyun oturumu artık aktif değil veya aynı cihazdaki daha yeni bir oturum tarafından değiştirildi.",
      });
      return;
    }
    req.gameplaySession = result.rows[0];
    next();
  } catch (error) {
    console.error("gameplay session middleware error:", error);
    res.status(500).json({
      ok: false,
      code: "GAME_SESSION_ERROR",
      message: "Oyun cihaz oturumu doğrulanamadı.",
    });
  }
}

async function socketHasActiveGameplaySession(socket, playerId, errorEvent = "match_error") {
  if (!pool) {
    socket.emit(errorEvent, { code: "DATABASE_REQUIRED", message: "Sunucu veritabanı hazır değil." });
    return false;
  }
  const sessionId = normalizeGameplaySessionId(socket.data?.gameSessionId);
  if (!sessionId) {
    socket.emit(errorEvent, {
      code: "GAME_SESSION_REQUIRED",
      message: "Bu cihaz için aktif oyun oturumu bulunamadı.",
    });
    return false;
  }
  try {
    const result = await readAndMaybeRenewGameplaySession(pool, playerId, sessionId);
    if (result.rowCount === 0) {
      socket.emit(errorEvent, {
        code: "GAME_SESSION_REPLACED",
        message: "Oyun oturumunuz artık aktif değil veya aynı cihazdaki daha yeni bir oturum tarafından değiştirildi.",
      });
      return false;
    }
    return true;
  } catch (error) {
    console.error("socket gameplay session check error:", error);
    socket.emit(errorEvent, { code: "GAME_SESSION_ERROR", message: "Oyun oturumu doğrulanamadı." });
    return false;
  }
}


function normalizeGuestId(value) {
  const guestId = safeText(value, "", 64).toLowerCase();
  return /^guest_[a-f0-9]{32}$/.test(guestId) ? guestId : "";
}

function normalizeGuestSecret(value) {
  const secret = safeText(value, "", 128).toLowerCase();
  return /^[a-f0-9]{64}$/.test(secret) ? secret : "";
}

function hashGuestSecret(secret) {
  if (!SESSION_SECRET) throw new Error("SESSION_SECRET tanımlı değil.");
  return crypto.createHmac("sha256", SESSION_SECRET).update(String(secret)).digest("hex");
}

function constantTimeHexEquals(left, right) {
  try {
    const leftBuffer = Buffer.from(String(left || ""), "hex");
    const rightBuffer = Buffer.from(String(right || ""), "hex");
    return leftBuffer.length > 0 &&
      leftBuffer.length === rightBuffer.length &&
      crypto.timingSafeEqual(leftBuffer, rightBuffer);
  } catch (_) {
    return false;
  }
}

async function authenticateGuestPlayer(client, guestIdRaw, guestSecretRaw) {
  const guestId = normalizeGuestId(guestIdRaw);
  const guestSecret = normalizeGuestSecret(guestSecretRaw);
  if (!guestId || !guestSecret) {
    const error = new Error("Geçerli misafir kimliği gerekli.");
    error.statusCode = 400;
    throw error;
  }

  const expectedHash = hashGuestSecret(guestSecret);
  let credential = await client.query(
    `SELECT guest_id, secret_hash, linked_player_id, updated_at
     FROM guest_credentials
     WHERE guest_id = $1
     FOR UPDATE`,
    [guestId]
  );

  if (credential.rowCount === 0) {
    await ensureAuthenticatedPlayer(client, guestId);
    await client.query(
      `INSERT INTO guest_credentials (guest_id, secret_hash, created_at, updated_at)
       VALUES ($1, $2, NOW(), NOW())
       ON CONFLICT (guest_id) DO NOTHING`,
      [guestId, expectedHash]
    );
    credential = await client.query(
      `SELECT guest_id, secret_hash, linked_player_id, updated_at
       FROM guest_credentials
       WHERE guest_id = $1
       FOR UPDATE`,
      [guestId]
    );
  }

  const row = credential.rows[0];
  if (!row || !constantTimeHexEquals(row.secret_hash, expectedHash)) {
    const error = new Error("Misafir kimliği doğrulanamadı.");
    error.statusCode = 401;
    throw error;
  }

  // 90 günlük pasif hesap temizliği için last-activity gerekir; fakat her açılışta WAL üretmemek için
  // credential timestamp'i en fazla haftada bir yenilenir. Skor/progress/görev/challenge güncellemeleri
  // zaten kendi updated_at alanlarıyla daha yeni etkinliği ayrıca korur.
  const lastGuestTouch = new Date(row.updated_at || 0).getTime();
  if (!row.linked_player_id && Date.now() - lastGuestTouch >= GUEST_ACTIVITY_TOUCH_MS) {
    await client.query(
      `UPDATE guest_credentials SET updated_at = NOW()
       WHERE guest_id = $1 AND updated_at < NOW() - ($2::integer * INTERVAL '1 day')`,
      [guestId, GUEST_ACTIVITY_TOUCH_DAYS]
    );
  }

  if (row.linked_player_id) {
    // Guest sırrı, PGS hesabı bağlandıktan sonra kalıcı alternatif giriş anahtarı olarak kullanılamaz.
    const error = new Error("Bu misafir hesabı Play Games hesabına bağlandı. Play Games ile tekrar oturum açın.");
    error.statusCode = 409;
    error.publicCode = "GUEST_ALREADY_LINKED";
    throw error;
  }

  await ensureAuthenticatedPlayer(client, guestId);
  // Son-görülme yazımı yukarıda haftalık eşikle sınırlandığı için her token yenilemede WAL üretilmez.
  return guestId;
}

async function migrateGuestPlayerToPlayGames(client, guestIdRaw, guestSecretRaw, playGamesPlayerId) {
  const guestId = normalizeGuestId(guestIdRaw);
  const guestSecret = normalizeGuestSecret(guestSecretRaw);
  if (!guestId || !guestSecret || !playGamesPlayerId || guestId === playGamesPlayerId) {
    return { migrated: false, reason: "NO_GUEST" };
  }

  const credentialResult = await client.query(
    `SELECT guest_id, secret_hash, linked_player_id, updated_at
     FROM guest_credentials
     WHERE guest_id = $1
     FOR UPDATE`,
    [guestId]
  );
  const credential = credentialResult.rows[0];
  if (!credential) return { migrated: false, reason: "GUEST_NOT_ON_SERVER" };

  const expectedHash = hashGuestSecret(guestSecret);
  if (!constantTimeHexEquals(credential.secret_hash, expectedHash)) {
    return { migrated: false, reason: "GUEST_SECRET_MISMATCH" };
  }

  if (credential.linked_player_id) {
    return {
      migrated: credential.linked_player_id === playGamesPlayerId,
      reason: credential.linked_player_id === playGamesPlayerId ? "ALREADY_LINKED" : "LINKED_TO_OTHER_ACCOUNT",
    };
  }

  await ensureAuthenticatedPlayer(client, playGamesPlayerId);
  const guestPlayer = await client.query(
    `SELECT player_id FROM players WHERE player_id = $1 FOR UPDATE`,
    [guestId]
  );

  // Silinmiş/boş guest kimliği hedef hesabın tek migration hakkını tüketmez.
  if (guestPlayer.rowCount === 0) {
    return { migrated: false, reason: "EMPTY_GUEST_NOT_MIGRATED" };
  }

  // Hedef Play Games hesabı ve kaynak guest için tek kullanımlık migration slotunu atomik olarak al.
  // Aynı anda iki istek gelse bile PRIMARY KEY/UNIQUE + ON CONFLICT yalnız birinin ilerlemesini sağlar.
  const migrationClaim = await client.query(
    `INSERT INTO play_games_guest_migrations (target_player_id, guest_id, migrated_at)
     VALUES ($1, $2, NOW())
     ON CONFLICT DO NOTHING
     RETURNING target_player_id, guest_id`,
    [playGamesPlayerId, guestId]
  );

  if (migrationClaim.rowCount === 0) {
    const existingTarget = await client.query(
      `SELECT guest_id FROM play_games_guest_migrations WHERE target_player_id = $1`,
      [playGamesPlayerId]
    );
    if (existingTarget.rowCount > 0) {
      const existingGuestId = String(existingTarget.rows[0]?.guest_id || "");
      return {
        migrated: existingGuestId === guestId,
        reason: existingGuestId === guestId ? "ALREADY_MIGRATED" : "TARGET_ALREADY_MIGRATED",
      };
    }

    const existingGuest = await client.query(
      `SELECT target_player_id FROM play_games_guest_migrations WHERE guest_id = $1`,
      [guestId]
    );
    if (existingGuest.rowCount > 0) {
      return { migrated: false, reason: "GUEST_ALREADY_MIGRATED" };
    }

    return { migrated: false, reason: "MIGRATION_CONFLICT" };
  }

  // Kullanıcı tarafından seçilmiş misafir profilini, PGS hedefinde henüz kullanıcı adı
  // belirlenmediyse taşı. PGS tarafında zaten kullanıcı tarafından belirlenmiş profil varsa onu koru.
  await client.query(
    `UPDATE players AS target
     SET username = CASE
           WHEN NOT target.username_user_set AND guest.username_user_set THEN guest.username
           ELSE target.username
         END,
         country = CASE
           WHEN NOT target.username_user_set AND guest.username_user_set THEN guest.country
           ELSE target.country
         END,
         username_user_set = target.username_user_set OR guest.username_user_set,
         username_change_count = GREATEST(target.username_change_count, guest.username_change_count),
         username_last_changed_at = GREATEST(target.username_last_changed_at, guest.username_last_changed_at),
         updated_at = NOW()
     FROM players AS guest
     WHERE target.player_id = $2 AND guest.player_id = $1`,
    [guestId, playGamesPlayerId]
  );

  // Puan ve XP misafir hesabında da yalnızca sunucunun doğruladığı oyun sonuçlarıyla oluşur.
  // Bu nedenle iki ayrık geçmişi toplamak güvenlidir; Int üst sınırında kırpılır.
  const migrationMonthKey = currentMonthKey();
  await client.query(
    `UPDATE player_scores AS target
     SET general_score = LEAST(target.general_score::bigint + guest.general_score::bigint, 2000000000)::integer,
         infinite_score = LEAST(target.infinite_score::bigint + guest.infinite_score::bigint, 2000000000)::integer,
         monthly_general_score = LEAST(
           (CASE WHEN target.monthly_key = $3 THEN target.monthly_general_score ELSE 0 END)::bigint +
           (CASE WHEN guest.monthly_key = $3 THEN guest.monthly_general_score ELSE 0 END)::bigint,
           2000000000
         )::integer,
         monthly_infinite_score = LEAST(
           (CASE WHEN target.monthly_key = $3 THEN target.monthly_infinite_score ELSE 0 END)::bigint +
           (CASE WHEN guest.monthly_key = $3 THEN guest.monthly_infinite_score ELSE 0 END)::bigint,
           2000000000
         )::integer,
         monthly_key = $3,
         monthly_updated_at = NOW(),
         updated_at = NOW()
     FROM player_scores AS guest
     WHERE target.player_id = $2 AND guest.player_id = $1`,
    [guestId, playGamesPlayerId, migrationMonthKey]
  );

  // Günlük 100 kişilik hakları iki hesap için de bugüne normalize et; böylece eski günün
  // reklam/ücretsiz hak bayrakları PGS hesabına yanlışlıkla taşınmaz.
  await normalizeHundredDailyAccessInTransaction(client, guestId);
  await normalizeHundredDailyAccessInTransaction(client, playGamesPlayerId);

  await client.query(
    `UPDATE player_progress AS target
     SET total_xp = LEAST(target.total_xp::bigint + guest.total_xp::bigint, 2000000000)::integer,
         infinite_run_score = GREATEST(target.infinite_run_score, guest.infinite_run_score),
         infinite_next_stage = GREATEST(target.infinite_next_stage, guest.infinite_next_stage),
         tournament_stage = GREATEST(target.tournament_stage, guest.tournament_stage),
         tournament_rights = GREATEST(target.tournament_rights, guest.tournament_rights),
         tournament_bank = GREATEST(target.tournament_bank, guest.tournament_bank),
         tournament_completed = target.tournament_completed OR guest.tournament_completed,
         tournament_tickets = LEAST(target.tournament_tickets::bigint + guest.tournament_tickets::bigint, 9999)::integer,
         tournament_reward_day_key = GREATEST(target.tournament_reward_day_key, guest.tournament_reward_day_key),
         tournament_rewarded_tickets_today = LEAST(target.tournament_rewarded_tickets_today + guest.tournament_rewarded_tickets_today, 15),
         tournament_entry_active = target.tournament_entry_active OR guest.tournament_entry_active,
         hundred_active = target.hundred_active OR guest.hundred_active,
         hundred_stage = GREATEST(target.hundred_stage, guest.hundred_stage),
         hundred_daily_key = GREATEST(target.hundred_daily_key, guest.hundred_daily_key),
         hundred_daily_base_used = target.hundred_daily_base_used OR guest.hundred_daily_base_used,
         hundred_daily_base_used_count = GREATEST(target.hundred_daily_base_used_count, guest.hundred_daily_base_used_count),
         hundred_daily_ad_used = target.hundred_daily_ad_used OR guest.hundred_daily_ad_used,
         hundred_rewarded_rights = GREATEST(target.hundred_rewarded_rights, guest.hundred_rewarded_rights),
         game_rights = GREATEST(target.game_rights, guest.game_rights),
         game_rights_refill_at = LEAST(target.game_rights_refill_at, guest.game_rights_refill_at),
         diamond_balance = LEAST(target.diamond_balance::bigint + guest.diamond_balance::bigint, 2000000000)::integer,
         level_reward_claimed_through = GREATEST(target.level_reward_claimed_through, guest.level_reward_claimed_through),
         two_player_finish_count = LEAST(target.two_player_finish_count::bigint + guest.two_player_finish_count::bigint, 2000000000)::integer,
         two_player_finish_total_ms = LEAST(target.two_player_finish_total_ms::numeric + guest.two_player_finish_total_ms::numeric, 9223372036854775807)::bigint,
         updated_at = NOW()
     FROM player_progress AS guest
     WHERE target.player_id = $2 AND guest.player_id = $1`,
    [guestId, playGamesPlayerId]
  );

  // Oyun bazlı sonsuz/turnuva/100'lü ilerlemeleri game_key bazında birleştir.
  // Aynı oyunda iki ayrı geçmiş varsa yüksek skor ve en ileri aşama korunur; ortak hak/biletler
  // player_progress üzerinde kaldığı için burada çoğaltılmaz.
  await client.query(
    `INSERT INTO player_game_progress (
       player_id, game_key, infinite_score, infinite_run_score, infinite_next_stage,
       tournament_stage, tournament_rights, tournament_bank, tournament_completed,
       tournament_entry_active, hundred_active, hundred_stage,
       two_player_finish_count, two_player_finish_total_ms, stats, updated_at
     )
     SELECT $2, game_key, infinite_score, infinite_run_score, infinite_next_stage,
            tournament_stage, tournament_rights, tournament_bank, tournament_completed,
            tournament_entry_active, hundred_active, hundred_stage,
            two_player_finish_count, two_player_finish_total_ms, stats, NOW()
     FROM player_game_progress
     WHERE player_id = $1
     ON CONFLICT (player_id, game_key) DO UPDATE SET
       infinite_score = GREATEST(player_game_progress.infinite_score, EXCLUDED.infinite_score),
       infinite_run_score = GREATEST(player_game_progress.infinite_run_score, EXCLUDED.infinite_run_score),
       infinite_next_stage = GREATEST(player_game_progress.infinite_next_stage, EXCLUDED.infinite_next_stage),
       tournament_stage = GREATEST(player_game_progress.tournament_stage, EXCLUDED.tournament_stage),
       tournament_rights = GREATEST(player_game_progress.tournament_rights, EXCLUDED.tournament_rights),
       tournament_bank = GREATEST(player_game_progress.tournament_bank, EXCLUDED.tournament_bank),
       tournament_completed = player_game_progress.tournament_completed OR EXCLUDED.tournament_completed,
       tournament_entry_active = player_game_progress.tournament_entry_active OR EXCLUDED.tournament_entry_active,
       hundred_active = player_game_progress.hundred_active OR EXCLUDED.hundred_active,
       hundred_stage = GREATEST(player_game_progress.hundred_stage, EXCLUDED.hundred_stage),
       two_player_finish_count = LEAST(
         player_game_progress.two_player_finish_count::bigint + EXCLUDED.two_player_finish_count::bigint,
         2000000000
       )::integer,
       two_player_finish_total_ms = LEAST(
         player_game_progress.two_player_finish_total_ms + EXCLUDED.two_player_finish_total_ms,
         9223372036854775807::bigint
       ),
       stats = CASE
         WHEN EXCLUDED.updated_at > player_game_progress.updated_at THEN EXCLUDED.stats
         ELSE player_game_progress.stats
       END,
       updated_at = NOW()`,
    [guestId, playGamesPlayerId]
  );

  // Global sonsuz puan, bütün oyunların oyun-bazlı yüksek skor toplamıdır.
  await client.query(
    `UPDATE player_scores
     SET infinite_score = LEAST(COALESCE((
       SELECT SUM(infinite_score)::bigint FROM player_game_progress WHERE player_id = $1
     ), 0), 2000000000)::integer,
         updated_at = NOW()
     WHERE player_id = $1`,
    [playGamesPlayerId]
  );

  // Tamamlanmamış güvenli challenge'lar ve görev geçmişleri de hedef hesaba bağlanır.
  await client.query(
    `UPDATE secure_game_challenges SET player_id = $2 WHERE player_id = $1`,
    [guestId, playGamesPlayerId]
  );

  // Yeni aggregate görev durumunu da PGS hesabına birleştir. Eski ham event'ler helper içinde
  // yalnızca bir kez içeri alınır; bundan sonra geçmiş taraması yapılmaz.
  await mergeTaskAggregateStateForGuest(client, guestId, playGamesPlayerId);

  // Kopyalama tamamlandıktan sonra eski guest player satırı silinir; FK'li eski satırlar cascade olur.
  await client.query(`DELETE FROM players WHERE player_id = $1`, [guestId]);
  await client.query(
    `UPDATE guest_credentials
     SET linked_player_id = $2, linked_at = NOW(), updated_at = NOW()
     WHERE guest_id = $1`,
    [guestId, playGamesPlayerId]
  );

  return { migrated: true, reason: "MIGRATED" };
}

async function applyAuthoritativeScoreDelta(playerId, generalDelta, infiniteDelta, xpDelta, gameKey = "target_number") {
  if (!pool || !playerId) return null;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    // Gerçek zamanlı oda katılımcısı odaya alınmadan önce imzalı session token ve
    // gameplay sessionId doğrulanır; oyuncunun DB satırları da o aşamada garanti edilir.
    // Buradaki ikinci ensureAuthenticatedPlayer() her ödülde gereksiz bir SELECT idi.
    await applyLeaderboardScoreDeltaInTransaction(
      client,
      playerId,
      generalDelta,
      infiniteDelta
    );
    await client.query(
      `UPDATE player_progress SET
         total_xp = GREATEST(0, LEAST(total_xp + $2, 2000000000)),
         updated_at = NOW()
       WHERE player_id = $1`,
      [playerId, xpDelta]
    );
    const state = await readAuthoritativePlayerState(client, playerId, normalizeBaseGameKey(gameKey));
    await client.query("COMMIT");
    return {
      ...state,
      generalDelta,
      infiniteDelta,
      xpDelta,
    };
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

async function recordRealtimeRoomTasksInTransaction(client, room, realWinner, realLoser) {
  const sourceKey = `room:${room.roomId}`;
  const gameKey = normalizeBaseGameKey(room.gameKey);
  if (realWinner) {
    await recordTaskEventInTransaction(client, {
      playerId: realWinner.playerId,
      sourceKey,
      eventType: "game",
      gameKey,
      multiplayer: true,
      won: true,
      playerAlreadyEnsured: true,
    });
  }
  if (realLoser) {
    await recordTaskEventInTransaction(client, {
      playerId: realLoser.playerId,
      sourceKey,
      eventType: "game",
      gameKey,
      multiplayer: true,
      won: false,
      playerAlreadyEnsured: true,
    });
  }
}

function safeTwoPlayerFinishSampleMs(elapsedMs, roundCountValue = 1, gameKey = "target_number") {
  const parsedElapsedMs = Number(elapsedMs);
  if (!Number.isFinite(parsedElapsedMs) || parsedElapsedMs <= 0) return null;
  const roundCount = normalizeRoundCount(roundCountValue);
  const roundLimitMs = gameDefinition(gameKey).roundDurationMs;
  return Math.max(1, Math.min(Math.floor(parsedElapsedMs / roundCount), roundLimitMs));
}

async function applyNormalRealtimeRewardsBatchInTransaction(client, room, realWinner, realLoser) {
  const reward = Math.max(minimumTwoPlayerStake(room.difficulty), Number(room.stakePoints || 0));
  const winnerXp = 20;
  const entries = [];
  if (realWinner) {
    entries.push({
      playerId: realWinner.playerId,
      generalDelta: reward,
      xpDelta: winnerXp,
      finishSampleMs: ["shortest_path", "digit_attack"].includes(normalizeBaseGameKey(room.gameKey)) &&
        realWinner.wonRoundBecauseOpponentWrongAnswer === true
        ? null
        : safeTwoPlayerFinishSampleMs(realWinner.totalElapsedMs, room.roundCount, room.gameKey),
    });
  }
  if (realLoser) {
    entries.push({ playerId: realLoser.playerId, generalDelta: -reward, xpDelta: 0, finishSampleMs: null });
  }
  if (entries.length === 0) return { reward, winnerXp };

  const monthKey = currentMonthKey();
  // player_scores (iki oyuncu) + kazananın XP/finish profili tek PostgreSQL round-trip'te.
  await client.query(
    `WITH changes AS (
       SELECT * FROM UNNEST(
         $1::text[], $2::bigint[], $3::integer[], $4::bigint[]
       ) AS c(player_id, general_delta, xp_delta, finish_sample_ms)
     ), score_updates AS (
       UPDATE player_scores AS s
       SET general_score = GREATEST(0, LEAST(s.general_score::bigint + c.general_delta, 2000000000))::integer,
           monthly_general_score = CASE
             WHEN s.monthly_key = $5 THEN
               GREATEST(0, LEAST(s.monthly_general_score::bigint + c.general_delta, 2000000000))::integer
             ELSE GREATEST(0, LEAST(c.general_delta, 2000000000))::integer
           END,
           -- Normal ikili oyunda infinite delta 0'dır; ay değiştiyse eski ayın infinite skoru
           -- yeni monthly_key altında taşınmamalı. Eski helper'ın ay rollover semantiğini koru.
           monthly_infinite_score = CASE WHEN s.monthly_key = $5 THEN s.monthly_infinite_score ELSE 0 END,
           monthly_key = $5,
           monthly_updated_at = NOW(),
           updated_at = NOW()
       FROM changes c
       WHERE s.player_id = c.player_id
       RETURNING s.player_id
     )
     UPDATE player_progress AS p
     SET total_xp = LEAST(p.total_xp + c.xp_delta, 2000000000),
         two_player_finish_count = LEAST(
           p.two_player_finish_count + CASE WHEN c.finish_sample_ms IS NULL THEN 0 ELSE 1 END,
           2000000000
         ),
         two_player_finish_total_ms = LEAST(
           p.two_player_finish_total_ms + COALESCE(c.finish_sample_ms, 0),
           9223372036854775807::bigint
         ),
         updated_at = NOW()
     FROM changes c
     WHERE p.player_id = c.player_id
       AND (c.xp_delta <> 0 OR c.finish_sample_ms IS NOT NULL)`,
    [
      entries.map((item) => item.playerId),
      entries.map((item) => item.generalDelta),
      entries.map((item) => item.xpDelta),
      entries.map((item) => item.finishSampleMs),
      monthKey,
    ]
  );
  const finishEntries = entries.filter((item) => item.finishSampleMs !== null);
  if (finishEntries.length > 0) {
    for (const item of finishEntries) {
      await ensurePlayerGameProgress(client, item.playerId, room.gameKey);
    }
    await client.query(
      `WITH changes AS (
         SELECT * FROM UNNEST($1::text[], $2::bigint[]) AS c(player_id, finish_sample_ms)
       )
       UPDATE player_game_progress AS gp
       SET two_player_finish_count = LEAST(gp.two_player_finish_count + 1, 2000000000),
           two_player_finish_total_ms = LEAST(
             gp.two_player_finish_total_ms + c.finish_sample_ms,
             9223372036854775807::bigint
           ),
           updated_at = NOW()
       FROM changes c
       WHERE gp.player_id = c.player_id AND gp.game_key = $3`,
      [
        finishEntries.map((item) => item.playerId),
        finishEntries.map((item) => item.finishSampleMs),
        normalizeBaseGameKey(room.gameKey),
      ]
    );
  }
  return { reward, winnerXp };
}

async function settleNormalRealtimeRoom(room, realWinner, realLoser) {
  if (!pool) return { winnerState: null, loserState: null };
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { reward, winnerXp } = await applyNormalRealtimeRewardsBatchInTransaction(
      client, room, realWinner, realLoser
    );

    // Görev event'i de artık oyuncu başına SELECT+full-JSON UPSERT değil tek targeted UPSERT'tir.
    await recordRealtimeRoomTasksInTransaction(client, room, realWinner, realLoser);

    const winnerState = realWinner
      ? { ...(await readAuthoritativePlayerState(client, realWinner.playerId, normalizeBaseGameKey(room.gameKey))), generalDelta: reward, infiniteDelta: 0, xpDelta: winnerXp }
      : null;
    const loserState = realLoser
      ? { ...(await readAuthoritativePlayerState(client, realLoser.playerId, normalizeBaseGameKey(room.gameKey))), generalDelta: -reward, infiniteDelta: 0, xpDelta: 0 }
      : null;

    await client.query('COMMIT');
    return { winnerState, loserState };
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

async function settleTournamentRealtimeRoom(room, realWinner, realLoser) {
  if (!pool) return { winnerState: null, loserState: null };
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const winnerState = realWinner
      ? await applyTournamentOutcomeInTransaction(client, realWinner.playerId, true, realWinner.tournamentStage, normalizeBaseGameKey(room.gameKey), true)
      : null;
    const loserState = realLoser
      ? await applyTournamentOutcomeInTransaction(client, realLoser.playerId, false, realLoser.tournamentStage, normalizeBaseGameKey(room.gameKey), true)
      : null;
    await recordRealtimeRoomTasksInTransaction(client, room, realWinner, realLoser);
    await client.query("COMMIT");
    return { winnerState, loserState };
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

async function settleFriendRoomTasks(room, realWinner, realLoser) {
  if (!pool || (!realWinner && !realLoser)) return;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await recordRealtimeRoomTasksInTransaction(client, room, realWinner, realLoser);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

async function awardRealtimeRoom(room, winner, loser) {
  if (!room || room.awardedAt) return;
  room.awardedAt = Date.now();

  const realWinner = winner && !winner.isBot ? winner : null;
  const realLoser = loser && !loser.isBot ? loser : null;

  if (room.isFriend) {
    await settleFriendRoomTasks(room, realWinner, realLoser);
    return;
  }

  if (String(room.gameKey || "").endsWith("_tournament")) {
    const { winnerState, loserState } = await settleTournamentRealtimeRoom(room, realWinner, realLoser);
    const winnerSocket = realWinner?.socketId ? io.sockets.sockets.get(realWinner.socketId) : null;
    const loserSocket = realLoser?.socketId ? io.sockets.sockets.get(realLoser.socketId) : null;
    if (winnerSocket && winnerState) winnerSocket.emit("authoritative_tournament", winnerState);
    if (loserSocket && loserState) loserSocket.emit("authoritative_tournament", loserState);
    return;
  }

  if (String(room.gameKey || "").endsWith("_tournament") || String(room.gameKey || "").endsWith("_hundred")) return;
  const { winnerState, loserState } = await settleNormalRealtimeRoom(room, realWinner, realLoser);
  const winnerSocket = realWinner?.socketId ? io.sockets.sockets.get(realWinner.socketId) : null;
  const loserSocket = realLoser?.socketId ? io.sockets.sockets.get(realLoser.socketId) : null;
  if (winnerSocket && winnerState) winnerSocket.emit("authoritative_reward", winnerState);
  if (loserSocket && loserState) loserSocket.emit("authoritative_reward", loserState);
}

app.post("/auth/guest", guestAuthRateLimit, async (req, res) => {
  if (!requireDatabase(res)) return;
  const guestId = normalizeGuestId(req.body.guestId);
  const guestSecret = normalizeGuestSecret(req.body.guestSecret);
  if (!guestId || !guestSecret) {
    res.status(400).json({ ok: false, code: "INVALID_GUEST", message: "Geçerli misafir kimliği gerekli." });
    return;
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const playerId = await authenticateGuestPlayer(client, guestId, guestSecret);
    await client.query("COMMIT");
    const sessionToken = createSessionToken(playerId);
    res.json({
      ok: true,
      playerId,
      guest: playerId.startsWith("guest_"),
      sessionToken,
      expiresAtMillis: Date.now() + SESSION_TTL_SECONDS * 1000,
    });
  } catch (error) {
    await client.query("ROLLBACK");
    console.error("guest auth error:", error.message);
    res.status(Number(error.statusCode || 500)).json({
      ok: false,
      code: "GUEST_AUTH_FAILED",
      message: error.statusCode === 401 ? "Misafir kimliği doğrulanamadı." : "Misafir oturumu kurulamadı.",
    });
  } finally {
    client.release();
  }
});

app.post("/auth/play-games", playGamesAuthRateLimit, async (req, res) => {
  const authCode = safeText(req.body.authCode, "", 4096);
  const guestId = normalizeGuestId(req.body.guestId);
  const guestSecret = normalizeGuestSecret(req.body.guestSecret);
  if (!authCode) {
    res.status(400).json({ ok: false, message: "Play Games yetkilendirme kodu gerekli." });
    return;
  }
  try {
    const playerId = await exchangePlayGamesAuthCode(authCode);
    let guestMigration = { migrated: false, reason: "NO_GUEST" };
    if (pool) {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        await ensureAuthenticatedPlayer(client, playerId);
        if (guestId && guestSecret) {
          guestMigration = await migrateGuestPlayerToPlayGames(
            client,
            guestId,
            guestSecret,
            playerId
          );
        }
        await client.query("COMMIT");
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        client.release();
      }
    }
    const sessionToken = createSessionToken(playerId);
    res.json({
      ok: true,
      playerId,
      sessionToken,
      guestMigrated: Boolean(guestMigration.migrated),
      guestMigrationReason: guestMigration.reason,
      expiresAtMillis: Date.now() + SESSION_TTL_SECONDS * 1000,
    });
  } catch (error) {
    console.error("play games auth error:", error.message);
    res.status(Number(error.statusCode || 401)).json({
      ok: false,
      code: "PLAY_GAMES_AUTH_FAILED",
      message: "Play Games hesabı sunucuda doğrulanamadı.",
    });
  }
});

function disconnectSupersededGameplaySockets(playerId, newestSessionId) {
  // Aynı Render instance'ındaki eski socket'i hemen kapat; DB doğrulaması yine asıl güvenlik katmanıdır.
  // Birden fazla instance olsa bile eski socket'in sonraki authoritative işlemi sessionId SELECT'inde reddedilir.
  try {
    for (const socket of io.sockets.sockets.values()) {
      if (
        socket.data?.playerId === playerId &&
        socket.data?.gameSessionId &&
        socket.data.gameSessionId !== newestSessionId
      ) {
        socket.emit("match_error", {
          code: "GAME_SESSION_REPLACED",
          message: "Bu hesapta daha yeni bir oyun oturumu açıldı.",
        });
        socket.disconnect(true);
      }
    }
  } catch (error) {
    console.error("superseded gameplay socket disconnect error:", error);
  }
}

app.post("/game-session/acquire", requireAuth, gameplayAcquireRateLimit, async (req, res) => {
  if (!requireDatabase(res)) return;
  const deviceId = normalizeGameplayDeviceId(req.body.deviceId);
  if (!deviceId) {
    res.status(400).json({
      ok: false,
      code: "DEVICE_ID_REQUIRED",
      message: "Bu cihaz için güvenli oyun kimliği oluşturulamadı.",
    });
    return;
  }
  const gameKey = safeText(req.body.gameKey, "unknown_game", 64) || "unknown_game";
  const protocolVersion = Math.max(4, Math.min(100, Number(req.body.protocolVersion || 4) || 4));
  const sessionId = crypto.randomUUID
    ? crypto.randomUUID()
    : crypto.randomBytes(24).toString("hex");

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // Hibrit kural:
    // 1) Aynı cihaz -> newest wins. Eski sessionId atomik olarak yenisiyle değiştirilir.
    // 2) Farklı cihaz + aktif session -> dokunulmaz ve yeni oyun reddedilir.
    // 3) Farklı cihaz + expired session -> yeni cihaz session'ı devralabilir.
    // ON CONFLICT ... WHERE koşulu aynı anda iki cihaz yarışsa bile yalnız bir aktif sahibi bırakır.
    const sessionResult = await client.query(
      `INSERT INTO player_game_sessions
       (player_id, session_id, device_id, game_key, created_at, expires_at, protocol_version)
       VALUES (
         $1, $2, $3, $4, NOW(),
         NOW() + ($6::integer * INTERVAL '1 second'),
         $5
       )
       ON CONFLICT (player_id) DO UPDATE SET
         session_id = EXCLUDED.session_id,
         device_id = EXCLUDED.device_id,
         game_key = EXCLUDED.game_key,
         created_at = NOW(),
         expires_at = EXCLUDED.expires_at,
         protocol_version = EXCLUDED.protocol_version
       WHERE player_game_sessions.device_id = EXCLUDED.device_id
          OR player_game_sessions.expires_at <= NOW()
       RETURNING session_id, device_id, game_key, created_at, expires_at, protocol_version`,
      [
        req.auth.sub,
        sessionId,
        deviceId,
        gameKey,
        protocolVersion,
        GAMEPLAY_SESSION_ACTIVE_TTL_SECONDS,
      ]
    );

    if (sessionResult.rowCount === 0) {
      // Bu ikinci SELECT yalnız gerçekten başka cihazda aktif oyun olduğu durumda çalışır.
      const blockingResult = await client.query(
        `SELECT game_key, created_at, expires_at
         FROM player_game_sessions
         WHERE player_id = $1 AND expires_at > NOW()
         LIMIT 1`,
        [req.auth.sub]
      );
      await client.query("COMMIT");

      const blocking = blockingResult.rows[0] || {};
      res.status(409).json({
        ok: false,
        code: "GAME_ACTIVE_ON_OTHER_DEVICE",
        message: "Şu anda başka bir cihazda oyun oynuyorsunuz. Diğer cihazdaki oyundan çıktıktan sonra tekrar deneyin.",
        activeGameKey: blocking.game_key || null,
        activeSinceMillis: blocking.created_at ? new Date(blocking.created_at).getTime() : null,
        expiresAtMillis: blocking.expires_at ? new Date(blocking.expires_at).getTime() : null,
      });
      return;
    }

    await client.query("COMMIT");
    const activeSession = sessionResult.rows[0];
    // Yalnız aynı cihazda daha eski bir socket varsa newest-wins nedeniyle kapatılır.
    // Farklı cihazdaki aktif oyun acquire aşamasında zaten reddedildiğinden burada çalınamaz.
    disconnectSupersededGameplaySockets(req.auth.sub, activeSession.session_id);
    res.json({
      ok: true,
      sessionId: activeSession.session_id,
      gameKey: activeSession.game_key,
      createdAtMillis: new Date(activeSession.created_at).getTime(),
      expiresAtMillis: new Date(activeSession.expires_at).getTime(),
      protocolVersion: Number(activeSession.protocol_version || 4),
      newestWins: true,
      crossDeviceActiveGameLock: true,
    });
  } catch (error) {
    await client.query("ROLLBACK");
    console.error("game-session acquire error:", error);
    res.status(500).json({ ok: false, code: "GAME_SESSION_ERROR", message: "Oyun cihaz oturumu başlatılamadı." });
  } finally {
    client.release();
  }
});


app.post("/game-session/release", requireAuth, async (req, res) => {
  if (!requireDatabase(res)) return;
  const sessionId = normalizeGameplaySessionId(req.body.sessionId);
  if (!sessionId) {
    res.json({ ok: true, released: false });
    return;
  }
  try {
    // Eski cihaz release gönderirse yeni oturumu silemez; yalnızca kendi sessionId'si eşleşirse silinir.
    const result = await pool.query(
      `DELETE FROM player_game_sessions
       WHERE player_id = $1 AND session_id = $2`,
      [req.auth.sub, sessionId]
    );
    res.json({ ok: true, released: result.rowCount > 0 });
  } catch (error) {
    console.error("game-session release error:", error);
    res.status(500).json({ ok: false, code: "GAME_SESSION_ERROR", message: "Oyun oturumu bırakılamadı." });
  }
});

app.get("/player/state", requireAuth, async (req, res) => {
  if (!requireDatabase(res)) return;
  const playerId = req.auth.sub;
  const gameKey = normalizeBaseGameKey(req.query.gameKey);
  try {
    const initialState = await readAuthoritativePlayerStateReadMostly(playerId, gameKey);
    const shouldSettleAbandonedHundred = initialState?.hundred?.active === true;
    let state = initialState;
    if (shouldSettleAbandonedHundred) {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        state = await forfeitHundredRunInTransaction(client, playerId, gameKey);
        await client.query('COMMIT');
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }
    }
    res.json({ ok: true, abandonedHundredSettled: shouldSettleAbandonedHundred, ...state });
  } catch (error) {
    sendLeaderboardError(res, error, "Oyuncu durumu yüklenemedi.", "player state error:");
  }
});

app.post("/game/hundred/start", requireAuth, challengeMutationRateLimit, requireGameplaySession, async (req, res) => {
  if (!requireDatabase(res)) return;
  const fresh = req.body.fresh === true;
  const gameKey = normalizeBaseGameKey(req.body.gameKey);
  const challengeId = crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString("hex");
  const lifetimeMs = gameDefinition(gameKey).hundredStageDurationMs;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const access = await normalizeHundredDailyAccessInTransaction(client, req.auth.sub, gameKey, false);
    // normalizeHundred... aynı progress satırını FOR UPDATE ile zaten okudu/kilitledi.
    const before = {
      hundred_active: access.active,
      hundred_stage: access.stage,
      hundred_daily_base_used_count: access.baseUsedCount,
      hundred_rewarded_rights: access.rewardedRightsRemaining,
    };

    if (fresh) {
      if (before.hundred_active === true) {
        const error = new Error("Zaten aktif bir 100 kişilik oyununuz var.");
        error.statusCode = 409;
        error.publicCode = "HUNDRED_RUN_ACTIVE";
        throw error;
      }

     /* if (access.baseRightsRemaining > 0) {
        await client.query(
          `UPDATE player_progress SET
             hundred_daily_base_used_count = LEAST(hundred_daily_base_used_count + 1, $2),
             hundred_daily_base_used = TRUE,
             updated_at = NOW()
           WHERE player_id = $1`,
          [req.auth.sub, HUNDRED_DAILY_BASE_RIGHTS]
        );
        await client.query(
          `UPDATE player_game_progress SET hundred_active = TRUE, hundred_stage = 1, updated_at = NOW()
           WHERE player_id = $1 AND game_key = $2`,
          [req.auth.sub, gameKey]
        );
      } else if (Number(before.hundred_rewarded_rights || 0) > 0) {
        await client.query(
          `UPDATE player_progress SET hundred_rewarded_rights = hundred_rewarded_rights - 1, updated_at = NOW()
           WHERE player_id = $1`,
          [req.auth.sub]
        );
        await client.query(
          `UPDATE player_game_progress SET hundred_active = TRUE, hundred_stage = 1, updated_at = NOW()
           WHERE player_id = $1 AND game_key = $2`,
          [req.auth.sub, gameKey]
        );
      } else {
        const error = new Error("Bugünkü 2 ücretsiz 100 kişilik oyun hakkınız bitti. Reklam izleyerek 2 ek oyun hakkı kazanabilirsiniz.");
        error.statusCode = 409;
        error.publicCode = "HUNDRED_DAILY_RIGHT_EXHAUSTED";
        throw error;
      }  */
	   await client.query(
    `UPDATE player_game_progress
     SET hundred_active = TRUE,
         hundred_stage = 1,
         updated_at = NOW()
     WHERE player_id = $1 AND game_key = $2`,
    [req.auth.sub, gameKey]
  );
    }

    // access satırı transaction başında FOR UPDATE ile okundu. Fresh başlangıçta az önce
    // stage=1 yazdık; devam oyununda da access.stage zaten kilitli satırdan geldi.
    const activeAfterStart = fresh ? true : access.active;
    if (!activeAfterStart) {
      const error = new Error("100 kişilik oyun aktif değil.");
      error.statusCode = 409;
      throw error;
    }
    const stage = fresh
      ? 1
      : Math.max(1, Math.min(Number(access.stage || 1), 12));
    const difficulty = hundredDifficultyForStage(stage);
    const puzzle = generatePuzzleForGame(gameKey, difficulty);
    // Eski aktif 100 kişilik challenge'ı kapatma + yenisini eklemeyi tek DB round-trip'te yap.
    await client.query(
      `WITH superseded AS (
         UPDATE secure_game_challenges
         SET completed_at = NOW(), result = '{"status":"superseded"}'::jsonb
         WHERE player_id = $2 AND game_key = $3 AND mode = 'hundred' AND completed_at IS NULL
         RETURNING challenge_id
       )
       INSERT INTO secure_game_challenges
         (challenge_id, player_id, game_key, mode, difficulty, stage, puzzle, expires_at)
       VALUES ($1, $2, $3, 'hundred', $4, $5, $6::jsonb,
               NOW() + ($7 * INTERVAL '1 millisecond'))`,
      [challengeId, req.auth.sub, gameKey, difficulty, stage, JSON.stringify(puzzle), lifetimeMs]
    );
    await client.query("COMMIT");
    res.json({
      ok: true,
      challengeId,
      mode: "hundred",
      gameKey,
      stage,
      puzzle,
      expiresAtMillis: Date.now() + lifetimeMs,
    });
  } catch (error) {
    await client.query("ROLLBACK");
    sendLeaderboardError(res, error, "100 kişilik oyun başlatılamadı.", "hundred start error:");
  } finally {
    client.release();
  }
});

app.post("/game/hundred/forfeit", requireAuth, async (req, res) => {
  if (!requireDatabase(res)) return;
  const gameKey = normalizeBaseGameKey(req.body.gameKey);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const response = await forfeitHundredRunInTransaction(client, req.auth.sub, gameKey);
    await client.query("COMMIT");
    res.json({ ok: true, ...response, elapsedServerMs: 0, runScore: response.runScore || 0 });
  } catch (error) {
    await client.query("ROLLBACK");
    sendLeaderboardError(res, error, "100 kişilik oyun sonucu işlenemedi.", "hundred forfeit error:");
  } finally {
    client.release();
  }
});

app.post("/game/tournament/state", requireAuth, async (req, res) => {
  if (!requireDatabase(res)) return;
  const gameKey = normalizeBaseGameKey(req.body.gameKey);
  try {
    const state = await readAuthoritativePlayerStateReadMostly(req.auth.sub, gameKey);
    res.json({ ok: true, ...state });
  } catch (error) {
    sendLeaderboardError(res, error, "Turnuva durumu alınamadı.", "tournament state error:");
  }
});

app.post("/game/hundred/rewarded-ad", requireAuth, async (req, res) => {
  if (!requireDatabase(res)) return;
  const gameKey = normalizeBaseGameKey(req.body.gameKey);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const state = await grantHundredRewardedRightInTransaction(client, req.auth.sub, gameKey);
    await client.query("COMMIT");
    res.json({ ok: true, ...state });
  } catch (error) {
    await client.query("ROLLBACK");
    sendLeaderboardError(res, error, "Ek 100 kişilik oyun hakkı verilemedi.", "hundred rewarded ad error:");
  } finally {
    client.release();
  }
});

app.post("/game/tournament/rewarded-ticket", requireAuth, async (req, res) => {
  if (!requireDatabase(res)) return;
  const gameKey = normalizeBaseGameKey(req.body.gameKey);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const state = await grantTournamentTicketInTransaction(client, req.auth.sub, gameKey);
    await client.query("COMMIT");
    res.json({ ok: true, ...state });
  } catch (error) {
    await client.query("ROLLBACK");
    sendLeaderboardError(res, error, "Turnuva bileti verilemedi.", "tournament rewarded ticket error:");
  } finally {
    client.release();
  }
});

app.post("/game/tournament/enter", requireAuth, async (req, res) => {
  if (!requireDatabase(res)) return;
  const gameKey = normalizeBaseGameKey(req.body.gameKey);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const state = await enterTournamentInTransaction(client, req.auth.sub, gameKey);
    await client.query("COMMIT");
    res.json({ ok: true, ...state, awardedScore: 0 });
  } catch (error) {
    await client.query("ROLLBACK");
    sendLeaderboardError(res, error, "Turnuvaya giriş yapılamadı.", "tournament enter error:");
  } finally {
    client.release();
  }
});

// Eski istemcilerin /reset çağrısı da artık ücretsiz yeni turnuva başlatamaz.
// Aynı 5 biletlik authoritative giriş kuralını uygular.
app.post("/game/tournament/reset", requireAuth, async (req, res) => {
  if (!requireDatabase(res)) return;
  const gameKey = normalizeBaseGameKey(req.body.gameKey);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const state = await enterTournamentInTransaction(client, req.auth.sub, gameKey);
    await client.query("COMMIT");
    res.json({ ok: true, ...state, awardedScore: 0 });
  } catch (error) {
    await client.query("ROLLBACK");
    sendLeaderboardError(res, error, "Turnuva sıfırlanamadı.", "tournament reset error:");
  } finally {
    client.release();
  }
});

app.post("/game/bot/start", requireAuth, challengeMutationRateLimit, requireGameplaySession, async (req, res) => {
  if (!requireDatabase(res)) return;
  const gameKey = normalizeBaseGameKey(req.body.gameKey);
  const tournamentMode = req.body.mode === "tournament";
  const matchMode = safeText(req.body.matchMode, "quick", 32);
  const immediateBotMode = !tournamentMode && ["quick", "ready_room", "open_table"].includes(matchMode);
  const challengeId = crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString("hex");
  const lifetimeMs = gameDefinition(gameKey).roundDurationMs;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await ensurePlayerGameProgress(client, req.auth.sub, gameKey);
    const requestedDifficulty = secureDifficulty(req.body.difficulty);
    if (!immediateBotMode) {
      await consumeBotFallbackEligibilityInTransaction(
        client,
        req.auth.sub,
        gameModeKey(gameKey, tournamentMode ? "tournament" : "normal"),
        requestedDifficulty
      );
    }

    let stakePoints = 0;
    let finishProfile = null;
    let tournamentResponse = null;
    if (!tournamentMode) {
      const consumed = await consumeGameRightInTransaction(
        client,
        req.auth.sub,
        requestedDifficulty,
        req.body.wagerPoints,
        matchMode === "quick",
        gameKey
      );
      if (matchMode === "open_table") {
        assertOpenTableStake(req.body.wagerPoints, consumed.generalScore, requestedDifficulty);
      }
      stakePoints = consumed.stakePoints;
      finishProfile = consumed.finishProfile;
      tournamentResponse = consumed.tournamentResponse;
    }

    let stage = 1;
    let difficulty = requestedDifficulty;
    const challengeMode = tournamentMode ? "tournament_bot" : "two_player_bot";

    const activeResult = await client.query(
      `SELECT * FROM secure_game_challenges
       WHERE player_id = $1 AND game_key = $2 AND mode = $3 AND completed_at IS NULL
       ORDER BY created_at ASC FOR UPDATE`,
      [req.auth.sub, gameKey, challengeMode]
    );
    for (const activeChallenge of activeResult.rows) {
      const elapsedServerMs = Math.max(0, Date.now() - new Date(activeChallenge.created_at).getTime());
      const normalOutcome = botOutcomeForElapsed(activeChallenge.result?.plan || {}, elapsedServerMs, false);
      const expiredAt = new Date(activeChallenge.expires_at).getTime();
      const isExpiredUnfinishedTwoPlayerBot =
        activeChallenge.mode === "two_player_bot" &&
        Number.isFinite(expiredAt) &&
        Date.now() >= expiredAt &&
        !normalOutcome.resolvable;
      if (isExpiredUnfinishedTwoPlayerBot) {
        await settleTwoPlayerBotChallengeAsDrawInTransaction(client, activeChallenge, req.auth.sub, gameKey);
      } else {
        await settleBotChallengeAsForfeitInTransaction(client, activeChallenge, req.auth.sub, gameKey);
      }
    }

    if (tournamentMode) {
      const progressResult = await client.query(
        `SELECT gp.tournament_stage, gp.tournament_rights, gp.tournament_bank,
                gp.tournament_completed, gp.tournament_entry_active,
                p.tournament_tickets, gp.two_player_finish_count, gp.two_player_finish_total_ms
         FROM player_game_progress gp
         JOIN player_progress p ON p.player_id = gp.player_id
         WHERE gp.player_id = $1 AND gp.game_key = $2
         FOR UPDATE OF gp, p`,
        [req.auth.sub, gameKey]
      );
      const progress = progressResult.rows[0] || {};
      if (
        progress.tournament_entry_active !== true ||
        progress.tournament_completed === true ||
        Number(progress.tournament_rights || 0) <= 0
      ) {
        const error = new Error("Turnuva şu anda başlatılamıyor. Yeni seri için 5 biletle giriş yapılmalıdır.");
        error.statusCode = 409;
        throw error;
      }
      stage = Math.max(1, Math.min(Number(progress.tournament_stage || 1), 8));
      difficulty = "Standard";
      finishProfile = normalizeTwoPlayerFinishProfile({
        finishCount: progress.two_player_finish_count,
        finishTotalMs: progress.two_player_finish_total_ms,
      });
      tournamentResponse = {
        currentStage: stage,
        remainingRights: Math.max(0, Math.min(Number(progress.tournament_rights ?? 3), 3)),
        totalScore: Math.max(0, Number(progress.tournament_bank || 0)),
        completed: progress.tournament_completed === true,
        tickets: Math.max(0, Number(progress.tournament_tickets || 0)),
        ticketCost: TOURNAMENT_ENTRY_TICKET_COST,
        entryActive: progress.tournament_entry_active === true,
      };
    }

    const puzzle = generatePuzzleForGame(gameKey, difficulty);
    const plan = createGameAwareBotPlan(gameKey, difficulty, finishProfile || {});
    await client.query(
      `INSERT INTO secure_game_challenges
       (challenge_id, player_id, game_key, mode, difficulty, stage, puzzle, wager_points, expires_at, result)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8,
               NOW() + ($9 * INTERVAL '1 millisecond'), $10::jsonb)`,
      [challengeId, req.auth.sub, gameKey, challengeMode, difficulty, stage,
       JSON.stringify(puzzle), stakePoints, lifetimeMs, JSON.stringify({ status: "active", plan, matchMode, gameKey })]
    );
    await client.query("COMMIT");
    res.json({
      ok: true,
      gameKey,
      challengeId,
      mode: challengeMode,
      stage,
      puzzle,
      finishMs: plan.finishMs,
      leaveMs: plan.leaveMs,
      stakePoints,
      matchMode,
      tournament: tournamentResponse,
      expiresAtMillis: Date.now() + lifetimeMs,
    });
  } catch (error) {
    await client.query("ROLLBACK");
    sendLeaderboardError(res, error, "Bot eşleşmesi başlatılamadı.", "bot start error:");
  } finally {
    client.release();
  }
});

app.post("/game/challenges/start", requireAuth, challengeMutationRateLimit, requireGameplaySession, async (req, res) => {
  if (!requireDatabase(res)) return;
  const mode = safeText(req.body.mode, "", 32);
  if (mode !== "infinite") {
    res.status(400).json({ ok: false, message: "Bu endpoint yalnızca sonsuz modu destekler." });
    return;
  }
  const gameKey = normalizeBaseGameKey(req.body.gameKey);
  const requestedDifficulty = secureDifficulty(req.body.difficulty);
  const freshInfiniteRun = req.body.fresh === true;
  const challengeId = crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString("hex");
  const lifetimeMs = 7 * 24 * 60 * 60 * 1000;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await ensurePlayerGameProgress(client, req.auth.sub, gameKey);

    if (freshInfiniteRun) {
      await client.query(
        `UPDATE player_game_progress
         SET infinite_run_score = 0, infinite_next_stage = 1, updated_at = NOW()
         WHERE player_id = $1 AND game_key = $2`,
        [req.auth.sub, gameKey]
      );
    }
    const progressResult = await client.query(
      `SELECT infinite_next_stage
       FROM player_game_progress
       WHERE player_id = $1 AND game_key = $2
       FOR UPDATE`,
      [req.auth.sub, gameKey]
    );
    const stage = Math.max(1, Math.min(Number(progressResult.rows[0]?.infinite_next_stage || 1), 1000));
    const difficultyResolver = gameDefinition(gameKey).infiniteDifficultyForStage;
    const difficulty = typeof difficultyResolver === "function"
      ? secureDifficulty(difficultyResolver(stage, requestedDifficulty))
      : requestedDifficulty;
    const puzzle = generatePuzzleForGame(gameKey, difficulty);

    await client.query(
      `WITH superseded AS (
         UPDATE secure_game_challenges
         SET completed_at = NOW(), result = '{"status":"superseded"}'::jsonb
         WHERE player_id = $2 AND game_key = $3 AND mode = $4 AND completed_at IS NULL
         RETURNING challenge_id
       )
       INSERT INTO secure_game_challenges
         (challenge_id, player_id, game_key, mode, difficulty, stage, puzzle, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, NOW() + ($8 * INTERVAL '1 millisecond'))`,
      [challengeId, req.auth.sub, gameKey, mode, difficulty, stage, JSON.stringify(puzzle), lifetimeMs]
    );
    await client.query("COMMIT");
    res.json({
      ok: true,
      gameKey,
      challengeId,
      mode,
      stage,
      puzzle,
      expiresAtMillis: Date.now() + lifetimeMs,
    });
  } catch (error) {
    await client.query("ROLLBACK");
    sendLeaderboardError(res, error, "Güvenli oyun başlatılamadı.", "challenge start error:");
  } finally {
    client.release();
  }
});

app.post("/game/challenges/complete", requireAuth, challengeMutationRateLimit, requireGameplaySession, async (req, res) => {
  if (!requireDatabase(res)) return;
  const challengeId = safeText(req.body.challengeId, "", 128);
  if (!challengeId) {
    res.status(400).json({ ok: false, message: "challengeId zorunlu." });
    return;
  }
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await client.query(
      `SELECT * FROM secure_game_challenges
       WHERE challenge_id = $1 AND player_id = $2
         AND mode IN ('infinite', 'two_player_bot', 'tournament_bot', 'hundred')
       FOR UPDATE`,
      [challengeId, req.auth.sub]
    );
    if (result.rowCount === 0) {
      const error = new Error("Oyun doğrulama kaydı bulunamadı."); error.statusCode = 404; throw error;
    }
    const challenge = result.rows[0];
    const gameKey = normalizeBaseGameKey(challenge.game_key || challenge.puzzle?.gameKey);
    if (challenge.completed_at) {
      const previousResponse = await rebuildStoredChallengeResponseInTransaction(client, req.auth.sub, challenge.result);
      if (previousResponse) {
        await client.query("COMMIT");
        res.json(previousResponse);
        return;
      }
      const error = new Error("Bu oyun sonucu daha önce işlendi."); error.statusCode = 409; throw error;
    }
    if (Date.now() > new Date(challenge.expires_at).getTime()) {
      const error = new Error("Oyun süresi doldu."); error.statusCode = 409; throw error;
    }
    const elapsedServerMs = Date.now() - new Date(challenge.created_at).getTime();
    if (elapsedServerMs < 500) {
      const error = new Error("Sonuç olağan dışı hızda gönderildi."); error.statusCode = 409; throw error;
    }
    if (challenge.mode === "hundred" && elapsedServerMs > gameDefinition(gameKey).hundredStageDurationMs) {
      const error = new Error("100 kişilik oyun aşamasının süresi doldu.");
      error.statusCode = 409;
      error.publicCode = "HUNDRED_STAGE_EXPIRED";
      throw error;
    }
    if (!validateChallengeAnswer(challenge.puzzle, req.body.numberSlots, req.body.operators, req.body.answer)) {
      const error = new Error("Oyun sonucu sunucuda doğrulanamadı."); error.statusCode = 422; throw error;
    }
    const answerWon = challengeAnswerIsWinning(
      challenge.puzzle, req.body.numberSlots, req.body.operators, req.body.answer
    );
    const wrongAnswerReason = gameKey === "shortest_path"
      ? "wrong_route"
      : gameKey === "digit_attack" ? "three_mistakes" : "wrong_answer";

    let won = null;
    let outcomeReason = null;
    let rewards = challengeRewards(challenge.mode, challenge.stage);
    if (challenge.mode === "two_player_bot" || challenge.mode === "tournament_bot") {
      const outcome = answerWon
        ? botOutcomeForElapsed(challenge.result?.plan || {}, elapsedServerMs, true)
        : { resolvable: true, won: false, reason: wrongAnswerReason };
      won = outcome.won;
      outcomeReason = outcome.reason;
      rewards = twoPlayerBotRewards(challenge.difficulty, won === true, challenge.wager_points);
    }

    if (challenge.mode === "hundred") {
      const hundredResult = answerWon
        ? await completeHundredStageInTransaction(client, req.auth.sub, Number(challenge.stage), gameKey)
        : await forfeitHundredRunInTransaction(client, req.auth.sub, gameKey);
      if (answerWon) {
        await recordTaskEventInTransaction(client, {
          playerId: req.auth.sub,
          sourceKey: `challenge:${challengeId}`,
          eventType: "game",
          gameKey,
          multiplayer: true,
          won: true,
        });
      }
      const response = {
        ok: true, gameKey, ...hundredResult,
        runScore: hundredResult.runScore || 0,
        won: answerWon ? hundredResult.won : false,
        outcomeReason: answerWon ? null : wrongAnswerReason,
        elapsedServerMs,
      };
      await client.query(
        `UPDATE secure_game_challenges SET completed_at = NOW(), result = $2::jsonb WHERE challenge_id = $1`,
        [challengeId, JSON.stringify(compactChallengeResult(response))]
      );
      await client.query("COMMIT");
      res.json(response);
      return;
    }

    if (challenge.mode === "tournament_bot") {
      const tournamentResult = await applyTournamentOutcomeInTransaction(
        client, req.auth.sub, won, Number(challenge.stage), gameKey
      );
      await recordTaskEventInTransaction(client, {
        playerId: req.auth.sub,
        sourceKey: `challenge:${challengeId}`,
        eventType: "game",
        gameKey,
        multiplayer: true,
        won: won === true,
      });
      const response = {
        ok: true, gameKey, ...tournamentResult,
        runScore: tournamentResult.runScore || 0,
        won, outcomeReason, elapsedServerMs,
      };
      await client.query(
        `UPDATE secure_game_challenges SET completed_at = NOW(), result = $2::jsonb WHERE challenge_id = $1`,
        [challengeId, JSON.stringify(compactChallengeResult(response))]
      );
      await client.query("COMMIT");
      res.json(response);
      return;
    }

    let infiniteRunScore = 0;
    let state;
    if (challenge.mode === "infinite" && !answerWon) {
      await ensurePlayerGameProgress(client, req.auth.sub, gameKey);
      await client.query(
        `UPDATE player_game_progress
         SET infinite_run_score = 0, infinite_next_stage = 1, updated_at = NOW()
         WHERE player_id = $1 AND game_key = $2`,
        [req.auth.sub, gameKey]
      );
      state = await readAuthoritativePlayerState(client, req.auth.sub, gameKey);
      await recordTaskEventInTransaction(client, {
        playerId: req.auth.sub,
        sourceKey: `challenge:${challengeId}`,
        eventType: "game",
        gameKey,
        multiplayer: false,
        won: false,
      });
      const response = {
        ok: true, gameKey, ...state,
        generalDelta: 0, infiniteDelta: 0, xpDelta: 0,
        runScore: 0, won: false, outcomeReason: wrongAnswerReason, elapsedServerMs,
      };
      await client.query(
        `UPDATE secure_game_challenges SET completed_at = NOW(), result = $2::jsonb WHERE challenge_id = $1`,
        [challengeId, JSON.stringify(compactChallengeResult(response))]
      );
      await client.query("COMMIT");
      res.json(response);
      return;
    }
    if (challenge.mode === "infinite") {
      await ensurePlayerGameProgress(client, req.auth.sub, gameKey);
      const progressBefore = await client.query(
        `SELECT infinite_score, infinite_run_score FROM player_game_progress
         WHERE player_id = $1 AND game_key = $2 FOR UPDATE`,
        [req.auth.sub, gameKey]
      );
      const oldHighScore = Math.max(0, Number(progressBefore.rows[0]?.infinite_score || 0));
      const oldRunScore = Math.max(0, Number(progressBefore.rows[0]?.infinite_run_score || 0));
      infiniteRunScore = Math.min(2_000_000_000, oldRunScore + Math.max(0, Number(rewards.infiniteDelta || 0)));
      const newHighScore = Math.max(oldHighScore, infiniteRunScore);
      const highScoreDelta = Math.max(0, newHighScore - oldHighScore);

      await client.query(
        `UPDATE player_game_progress
         SET infinite_score = $3,
             infinite_run_score = $4,
             infinite_next_stage = GREATEST(infinite_next_stage, $5 + 1),
             updated_at = NOW()
         WHERE player_id = $1 AND game_key = $2`,
        [req.auth.sub, gameKey, newHighScore, infiniteRunScore, Number(challenge.stage)]
      );
      await client.query(
        `UPDATE player_progress
         SET total_xp = LEAST(total_xp + $2, 2000000000), updated_at = NOW()
         WHERE player_id = $1`,
        [req.auth.sub, rewards.xpDelta]
      );
      if (highScoreDelta > 0 || Number(rewards.generalDelta || 0) !== 0) {
        await applyLeaderboardScoreDeltaInTransaction(
          client, req.auth.sub, Number(rewards.generalDelta || 0), highScoreDelta
        );
      }
      state = await readAuthoritativePlayerState(client, req.auth.sub, gameKey);
      await recordTaskEventInTransaction(client, {
        playerId: req.auth.sub,
        sourceKey: `challenge:${challengeId}`,
        eventType: "game",
        gameKey,
        multiplayer: false,
        won: true,
      });
    } else {
      state = await applyTwoPlayerBotRewardsInTransaction(
        client,
        req.auth.sub,
        rewards,
        { finishElapsedMs: answerWon ? elapsedServerMs : null, gameKey }
      );
      await recordTaskEventInTransaction(client, {
        playerId: req.auth.sub,
        sourceKey: `challenge:${challengeId}`,
        eventType: "game",
        gameKey,
        multiplayer: true,
        won: won === true,
      });
    }
    const response = {
      ok: true,
      gameKey,
      ...state,
      generalDelta: Number(rewards.generalDelta || 0),
      infiniteDelta: Number(rewards.infiniteDelta || 0),
      xpDelta: Number(rewards.xpDelta || 0),
      runScore: Number(state.runScore || infiniteRunScore || 0),
      won,
      outcomeReason,
      elapsedServerMs,
    };
    await client.query(
      `UPDATE secure_game_challenges SET completed_at = NOW(), result = $2::jsonb WHERE challenge_id = $1`,
      [challengeId, JSON.stringify(compactChallengeResult(response))]
    );
    await client.query("COMMIT");
    res.json(response);
  } catch (error) {
    await client.query("ROLLBACK");
    sendLeaderboardError(res, error, "Oyun sonucu doğrulanamadı.", "challenge complete error:");
  } finally {
    client.release();
  }
});

app.post("/game/bot/resolve", requireAuth, requireGameplaySession, async (req, res) => {
  if (!requireDatabase(res)) return;
  const challengeId = safeText(req.body.challengeId, "", 128);
  if (!challengeId) {
    res.status(400).json({ ok: false, message: "challengeId zorunlu." });
    return;
  }
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await client.query(
      `SELECT * FROM secure_game_challenges
       WHERE challenge_id = $1 AND player_id = $2
         AND mode IN ('two_player_bot', 'tournament_bot')
       FOR UPDATE`,
      [challengeId, req.auth.sub]
    );
    if (result.rowCount === 0) {
      const error = new Error("Bot eşleşmesi bulunamadı."); error.statusCode = 404; throw error;
    }
    const challenge = result.rows[0];
    const gameKey = normalizeBaseGameKey(challenge.game_key || challenge.puzzle?.gameKey);
    if (challenge.completed_at) {
      const previousResponse = await rebuildStoredChallengeResponseInTransaction(
        client,
        req.auth.sub,
        challenge.result
      );
      if (previousResponse) {
        await client.query("COMMIT");
        res.json(previousResponse);
        return;
      }
      const error = new Error("Bu bot eşleşmesi daha önce sonuçlandı."); error.statusCode = 409; throw error;
    }
    const elapsedServerMs = Math.max(0, Date.now() - new Date(challenge.created_at).getTime());
    const timeoutAsDraw = req.body.timeoutAsDraw === true;
    let outcome = botOutcomeForElapsed(challenge.result?.plan || {}, elapsedServerMs, false);

    if (!outcome.resolvable && timeoutAsDraw && challenge.mode === "two_player_bot") {
      const expiresAt = new Date(challenge.expires_at).getTime();
      if (Number.isFinite(expiresAt) && Date.now() >= expiresAt) {
        outcome = { resolvable: true, won: null, reason: "time_draw" };
      }
    }

    if (!outcome.resolvable) {
      const error = new Error("Bot eşleşmesi henüz sonuçlanmadı."); error.statusCode = 409; throw error;
    }

    let response;
    if (challenge.mode === "tournament_bot") {
      const tournamentResult = await applyTournamentOutcomeInTransaction(
        client, req.auth.sub, outcome.won, Number(challenge.stage), gameKey
      );
      response = {
        ok: true,
        ...tournamentResult,
        runScore: tournamentResult.runScore || 0,
        won: outcome.won,
        outcomeReason: outcome.reason,
        elapsedServerMs,
      };
    } else if (outcome.won === null) {
      response = await settleTwoPlayerBotChallengeAsDrawInTransaction(
        client,
        challenge,
        req.auth.sub,
        gameKey,
        elapsedServerMs
      );
    } else {
      const rewards = twoPlayerBotRewards(challenge.difficulty, outcome.won === true, challenge.wager_points);
      const state = await applyTwoPlayerBotRewardsInTransaction(client, req.auth.sub, rewards, { gameKey });
      response = {
        ok: true,
        ...state,
        generalDelta: rewards.generalDelta,
        infiniteDelta: 0,
        xpDelta: rewards.xpDelta,
        won: outcome.won,
        outcomeReason: outcome.reason,
        elapsedServerMs,
      };
    }

    if (outcome.won !== null) {
      await recordTaskEventInTransaction(client, {
        playerId: req.auth.sub,
        sourceKey: `challenge:${challengeId}`,
        eventType: "game",
        gameKey,
        multiplayer: true,
        won: outcome.won === true,
      });

      await client.query(
        `UPDATE secure_game_challenges
         SET completed_at = NOW(), result = $2::jsonb
         WHERE challenge_id = $1`,
        [challengeId, JSON.stringify(compactChallengeResult(response))]
      );
    }
    await client.query("COMMIT");
    res.json(response);
  } catch (error) {
    await client.query("ROLLBACK");
    sendLeaderboardError(res, error, "Bot eşleşmesi sonuçlandırılamadı.", "bot resolve error:");
  } finally {
    client.release();
  }
});

app.post("/game/bot/forfeit", requireAuth, async (req, res) => {
  if (!requireDatabase(res)) return;
  const challengeId = safeText(req.body.challengeId, "", 128);
  if (!challengeId) {
    res.status(400).json({ ok: false, message: "challengeId zorunlu." });
    return;
  }
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await client.query(
      `SELECT * FROM secure_game_challenges
       WHERE challenge_id = $1 AND player_id = $2
         AND mode IN ('two_player_bot', 'tournament_bot')
       FOR UPDATE`,
      [challengeId, req.auth.sub]
    );
    if (result.rowCount === 0) {
      const error = new Error("Bot eşleşmesi bulunamadı."); error.statusCode = 404; throw error;
    }
    const challenge = result.rows[0];
    const gameKey = normalizeBaseGameKey(challenge.game_key || challenge.puzzle?.gameKey);
    if (challenge.completed_at) {
      const previousResponse = await rebuildStoredChallengeResponseInTransaction(
        client,
        req.auth.sub,
        challenge.result
      );
      if (previousResponse) {
        await client.query("COMMIT");
        res.json(previousResponse);
        return;
      }
      const error = new Error("Bu bot eşleşmesi daha önce sonuçlandı.");
      error.statusCode = 409;
      throw error;
    }
    const elapsedServerMs = Math.max(0, Date.now() - new Date(challenge.created_at).getTime());
    let response;
    if (challenge.mode === "tournament_bot") {
      const tournamentResult = await applyTournamentOutcomeInTransaction(
        client, req.auth.sub, false, Number(challenge.stage), gameKey
      );
      response = {
        ok: true,
        ...tournamentResult,
        runScore: tournamentResult.runScore || 0,
        won: false,
        outcomeReason: "player_forfeit",
        elapsedServerMs,
      };
    } else {
      const rewards = twoPlayerBotRewards(challenge.difficulty, false, challenge.wager_points);
      const state = await applyTwoPlayerBotRewardsInTransaction(client, req.auth.sub, rewards, { gameKey });
      response = {
        ok: true,
        ...state,
        generalDelta: rewards.generalDelta,
        infiniteDelta: 0,
        xpDelta: rewards.xpDelta,
        won: false,
        outcomeReason: "player_forfeit",
        elapsedServerMs,
      };
    }
    await recordTaskEventInTransaction(client, {
      playerId: req.auth.sub,
      sourceKey: `challenge:${challengeId}`,
      eventType: "game",
      gameKey,
      multiplayer: true,
      won: false,
    });
    await client.query(
      `UPDATE secure_game_challenges SET completed_at = NOW(), result = $2::jsonb WHERE challenge_id = $1`,
      [challengeId, JSON.stringify(compactChallengeResult(response))]
    );
    await client.query("COMMIT");
    res.json(response);
  } catch (error) {
    await client.query("ROLLBACK");
    sendLeaderboardError(res, error, "Bot eşleşmesi terk sonucu işlenemedi.", "bot forfeit error:");
  } finally {
    client.release();
  }
});



app.get("/tasks/state", requireAuth, async (req, res) => {
  if (!requireDatabase(res)) return;
  try {
    // Claim tablosu kaldırıldığı için görev merkezi common path'te tek task-state SELECT +
    // tek read-mostly player-state SELECT ile, transaction açmadan yüklenebilir.
    const taskCenter = await readTaskCenterStateReadMostly(req.auth.sub);
    const state = await readAuthoritativePlayerStateReadMostly(req.auth.sub);
    res.json({ ok: true, taskCenter, ...state });
  } catch (error) {
    sendLeaderboardError(res, error, "Görevler yüklenemedi.", "task state error:");
  }
});

app.post("/tasks/login", requireAuth, async (req, res) => {
  if (!requireDatabase(res)) return;
  const client = await pool.connect();
  let taskCenter;
  try {
    await client.query("BEGIN");
    const daily = taskPeriodInfo("daily");
    const aggregate = await recordTaskEventInTransaction(client, {
      playerId: req.auth.sub,
      sourceKey: `login:${daily.key}`,
      eventType: "login",
    });
    taskCenter = await buildTaskCenterStateFromAggregate(
      client,
      req.auth.sub,
      aggregate || taskAggregateSkeleton()
    );
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    sendLeaderboardError(res, error, "Günlük giriş görevi kaydedilemedi.", "task login error:");
    return;
  } finally {
    client.release();
  }

  try {
    const state = await readAuthoritativePlayerStateReadMostly(req.auth.sub);
    res.json({ ok: true, taskCenter, ...state });
  } catch (error) {
    sendLeaderboardError(res, error, "Günlük giriş görevi kaydedildi ancak oyuncu durumu yüklenemedi.", "task login state error:");
  }
});

app.post("/tasks/claim", requireAuth, async (req, res) => {
  if (!requireDatabase(res)) return;
  const periodType = safeText(req.body.periodType, "daily", 16).toLowerCase();
  const taskCode = safeText(req.body.taskCode, "", 64).toLowerCase();
  if (!TASK_PERIOD_CONFIG[periodType] || !taskCode) {
    res.status(400).json({ ok: false, message: "Geçersiz görev ödülü isteği." });
    return;
  }
  const allowedCodes = new Set([...TASK_DEFINITIONS.map((item) => item.code), "all_complete"]);
  if (!allowedCodes.has(taskCode)) {
    res.status(400).json({ ok: false, message: "Bilinmeyen görev kodu." });
    return;
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const taskCenter = await claimTaskRewardInTransaction(
      client,
      req.auth.sub,
      periodType,
      taskCode
    );
    const state = await readAuthoritativePlayerState(client, req.auth.sub);
    await client.query("COMMIT");
    res.json({ ok: true, taskCenter, ...state });
  } catch (error) {
    await client.query("ROLLBACK");
    sendLeaderboardError(res, error, "Görev ödülü alınamadı.", "task claim error:");
  } finally {
    client.release();
  }
});

app.post(
  "/leaderboard/username/claim",
  requireAuth,
  async (req, res) => {
    if (!requireDatabase(res)) return;

    const playerId = req.auth.sub;
    const rawUsername = String(req.body.username ?? "");
    const validationError = validateRequestedUsername(rawUsername);
    if (validationError) {
      res.status(400).json({ ok: false, code: "INVALID_USERNAME", message: validationError });
      return;
    }
    const username = rawUsername;
    const country = safeCountry(req.body.country);

    const client = await pool.connect();

    try {
      await client.query("BEGIN");
      await ensureAuthenticatedPlayer(client, playerId);
      const currentResult = await client.query(
        `SELECT username, username_user_set, username_change_count, username_last_changed_at
         FROM players WHERE player_id = $1 FOR UPDATE`,
        [playerId]
      );
      const current = currentResult.rows[0] || {};
      const isInitial = current.username_user_set !== true;
      const changeCount = Math.max(0, Number(current.username_change_count || 0));
      if (!isInitial && String(current.username || "") === username) {
        await client.query("COMMIT");
        res.json({
          ok: true,
          username,
          changeCountAfterInitial: changeCount,
          lastChangeTimeMillis: current.username_last_changed_at
            ? new Date(current.username_last_changed_at).getTime()
            : 0,
        });
        return;
      }
      if (!isInitial && changeCount > 0 && current.username_last_changed_at) {
        const nextChangeAt = new Date(current.username_last_changed_at).getTime() + USERNAME_CHANGE_COOLDOWN_MS;
        if (Date.now() < nextChangeAt) {
          const error = new Error("Kullanıcı adını tekrar değiştirmek için 1 ay beklemelisin.");
          error.statusCode = 429;
          error.publicCode = "USERNAME_CHANGE_COOLDOWN";
          error.nextChangeAtMillis = nextChangeAt;
          throw error;
        }
      }

      await claimOrCreatePlayer(client, playerId, username, country);
      const nextChangeCount = isInitial ? 0 : changeCount + 1;
      await client.query(
        `UPDATE players SET username_user_set = TRUE,
           username_change_count = $2,
           username_last_changed_at = CASE WHEN $3 THEN username_last_changed_at ELSE NOW() END,
           updated_at = NOW()
         WHERE player_id = $1`,
        [playerId, nextChangeCount, isInitial]
      );

      await client.query("COMMIT");

      res.json({
        ok: true,
        username,
        changeCountAfterInitial: nextChangeCount,
        lastChangeTimeMillis: isInitial ? 0 : Date.now(),
      });
    } catch (error) {
      await client.query("ROLLBACK");

      sendLeaderboardError(
        res,
        error,
        "Kullanıcı adı kaydedilemedi.",
        "username claim error:"
      );
    } finally {
      client.release();
    }
  }
);

app.post(
  "/leaderboard/scores/sync",
  requireAuth,
  async (req, res) => {
    // Güvenlik: istemcinin gönderdiği toplam skor artık kabul edilmez.
    // Skor yalnızca sunucunun doğruladığı challenge sonucu ile değişir.
    res.json({ ok: true, skipped: true, serverAuthoritative: true });
  }
);

app.post(
  "/leaderboard/scores/add",
  requireAuth,
  async (req, res) => {
    // Güvenlik: APK'dan gelen serbest puan farkı kabul edilmez.
    // Uyumlu eski istemciler hata almadan devam eder; fakat puan yazılmaz.
    res.json({ ok: true, skipped: true, serverAuthoritative: true });
  }
);

const LEADERBOARD_SERVER_CACHE_TTL_MS = Math.max(
  10_000,
  Math.min(5 * 60_000, Number(process.env.LEADERBOARD_CACHE_TTL_MS || 60_000) || 60_000)
);
const LEADERBOARD_SERVER_CACHE_MAX_ENTRIES = Math.max(
  16,
  Math.min(2_000, Number(process.env.LEADERBOARD_CACHE_MAX_ENTRIES || 128) || 128)
);
const LEADERBOARD_SERVER_CACHE_CLEANUP_INTERVAL_MS = Math.max(
  10_000,
  Math.min(60_000, LEADERBOARD_SERVER_CACHE_TTL_MS)
);
const leaderboardResponseCache = new Map();
const leaderboardRequestsInFlight = new Map();

function cleanupLeaderboardResponseCache(now = Date.now()) {
  for (const [key, entry] of leaderboardResponseCache) {
    if (now - entry.createdAtMillis >= LEADERBOARD_SERVER_CACHE_TTL_MS) {
      leaderboardResponseCache.delete(key);
    }
  }

  while (leaderboardResponseCache.size > LEADERBOARD_SERVER_CACHE_MAX_ENTRIES) {
    const oldestKey = leaderboardResponseCache.keys().next().value;
    if (oldestKey === undefined) break;
    leaderboardResponseCache.delete(oldestKey);
  }
}

function setLeaderboardResponseCacheEntry(key, rows) {
  cleanupLeaderboardResponseCache();

  // Map ekleme sırasını LRU sırası olarak kullan: güncellenen anahtar en sona taşınır.
  leaderboardResponseCache.delete(key);
  leaderboardResponseCache.set(key, {
    createdAtMillis: Date.now(),
    rows,
  });

  cleanupLeaderboardResponseCache();
}

function leaderboardServerCacheKey({ scoreType, period, scope, country, monthKey }) {
  return [
    scoreType,
    period,
    scope,
    scope === "country" ? country : "*",
    period === "month" ? monthKey : "*",
  ].join("|");
}

async function queryLeaderboardTopRows({ scoreType, period, scope, country, monthKey }) {
  const scoreColumn = period === "month"
    ? (scoreType === "infinite" ? "monthly_infinite_score" : "monthly_general_score")
    : (scoreType === "infinite" ? "infinite_score" : "general_score");
  const values = [];
  const conditions = [`s.${scoreColumn} > 0`];

  if (period === "month") {
    values.push(monthKey);
    conditions.push(`s.monthly_key = $${values.length}`);
  }

  if (scope === "country") {
    values.push(country);
    conditions.push(`p.country = $${values.length}`);
  }

  const result = await pool.query(
    `SELECT
       p.username,
       p.country,
       s.${scoreColumn} AS score
     FROM player_scores s
     JOIN players p ON p.player_id = s.player_id
     WHERE ${conditions.join(" AND ")}
     ORDER BY
       s.${scoreColumn} DESC,
       s.player_id ASC
     LIMIT 50`,
    values
  );

  // Sorgu zaten yalnızca ilk 50 satırı döndürdüğü için pahalı ROW_NUMBER() gerekmez.
  return result.rows.map((row, index) => ({
    rank: index + 1,
    username: row.username,
    country: row.country,
    score: Number(row.score),
  }));
}

async function loadLeaderboardRowsCached(args) {
  const key = leaderboardServerCacheKey(args);
  const now = Date.now();
  cleanupLeaderboardResponseCache(now);

  const cached = leaderboardResponseCache.get(key);
  if (cached && now - cached.createdAtMillis < LEADERBOARD_SERVER_CACHE_TTL_MS) {
    // LRU: kullanılan anahtarı Map'in sonuna taşı. TTL ise oluşturulma zamanına göre devam eder.
    leaderboardResponseCache.delete(key);
    leaderboardResponseCache.set(key, cached);
    return cached.rows;
  }

  if (cached) {
    leaderboardResponseCache.delete(key);
  }

  // Aynı cache boşluğunda yüzlerce eşzamanlı istek gelirse yalnızca bir DB sorgusu çalışsın.
  const existingRequest = leaderboardRequestsInFlight.get(key);
  if (existingRequest) return existingRequest;

  const request = queryLeaderboardTopRows(args)
    .then((rows) => {
      setLeaderboardResponseCacheEntry(key, rows);
      return rows;
    })
    .finally(() => {
      if (leaderboardRequestsInFlight.get(key) === request) {
        leaderboardRequestsInFlight.delete(key);
      }
    });

  leaderboardRequestsInFlight.set(key, request);
  return request;
}

app.get("/leaderboard", requireAuth, async (req, res) => {
  if (!requireDatabase(res)) return;

  const scoreType = req.query.scoreType === "infinite" ? "infinite" : "general";
  const period = req.query.period === "month" ? "month" : "all";
  const scope = req.query.scope === "country" ? "country" : "world";
  const country = safeCountry(req.query.country);
  const monthKey = currentMonthKey();

  try {
    const rows = await loadLeaderboardRowsCached({
      scoreType,
      period,
      scope,
      country,
      monthKey,
    });

    res.json({
      ok: true,
      scoreType,
      period,
      scope,
      country,
      monthKey,
      rows,
    });
  } catch (error) {
    console.error("leaderboard get error:", {
      message: error.message,
      code: error.code,
      detail: error.detail,
      stack: error.stack,
    });

    res.status(500).json({
      ok: false,
      message: "Skor tablosu alınamadı.",
    });
  }
});

const io = new Server(server, {
  path: SOCKET_PATH,

  cors: {
    origin: true,
    methods: ["GET", "POST"],
    credentials: false,
  },

  transports: [
    "websocket",
    "polling",
  ],

  allowEIO3: true,
  pingInterval: 25_000,
  pingTimeout: 20_000,

  allowRequest: (req, callback) => {
    if (process.env.LOG_SOCKET_HANDSHAKES === 'true') {
      console.log(
        'Socket.IO handshake request:',
        req.url,
        'origin:',
        req.headers.origin || '-'
      );
    }
    const clientIp = forwardedClientIp(req);
    const limit = consumeSecurityRateLimit(
      "socket-handshake",
      clientIp,
      Math.max(10, Math.min(200, Number(process.env.SOCKET_HANDSHAKE_RATE_LIMIT_PER_MINUTE || 40) || 40)),
      60_000
    );
    if (!limit.allowed) {
      callback("RATE_LIMITED", false);
      return;
    }
    callback(null, true);
  },
});

const waitingQueues = new Map();
const activeRooms = new Map();
const realtimeRooms = new Map();
const privateRooms = new Map();
const publicOpenTables = new Map();
const generatedLobbyBots = new Map();

const TWO_PLAYER_ROOM_GROUPS = [
  { id: "acemi", title: "Acemi Masaları", subtitle: "10 - 100", minScore: 10, maxScore: 100 },
  { id: "bronz", title: "Bronz Salon", subtitle: "80 - 500", minScore: 80, maxScore: 500 },
  { id: "gumus", title: "Gümüş Salon", subtitle: "250 - 2.000", minScore: 250, maxScore: 2_000 },
  { id: "altin", title: "Altın Salon", subtitle: "1.000 - 10.000", minScore: 1_000, maxScore: 10_000 },
  { id: "platin", title: "Platin Salon", subtitle: "4.000 - 50.000", minScore: 4_000, maxScore: 50_000 },
  { id: "elmas", title: "Elmas Salon", subtitle: "20.000 - 200.000", minScore: 20_000, maxScore: 200_000 },
  { id: "efsane", title: "Efsane Salon", subtitle: "200.000 - 2.000.000", minScore: 200_000, maxScore: 2_000_000 },
  { id: "sonsuz", title: "Sonsuz Masa", subtitle: "1.000.000 ve üzeri", minScore: 1_000_000, maxScore: null },
];

const LOBBY_BOT_FIRST_PARTS = [
  "Atlas", "Luna", "Nova", "Mira", "Arda", "Sora", "Raven", "Astra",
  "Deniz", "Leo", "Nora", "Akira", "Mert", "Mila", "Vega", "Jin",
  "Kuzey", "Sofia", "Noah", "Vera", "Ember", "Orion", "Arya", "Kai",
];
const LOBBY_BOT_SECOND_PARTS = [
  "Fox", "Sky", "Prime", "Storm", "Ruzgar", "Nova", "Moon", "Wolf",
  "Star", "Blade", "Wave", "Pixel", "Spark", "Zen", "Knight", "Dream",
];
const LOBBY_BOT_COUNTRIES = [
  "TR", "US", "GB", "ES", "FR", "DE", "IT", "BR", "MX", "ID", "RU", "UA",
  "JP", "CN", "KR", "TH", "EG", "SA", "IR", "IN", "BD", "PK", "VN", "AR",
];

function createLobbyBotIdentity(usedNames = new Set()) {
  for (let attempt = 0; attempt < 40; attempt += 1) {
    const first = LOBBY_BOT_FIRST_PARTS[secureRandomInt(0, LOBBY_BOT_FIRST_PARTS.length)];
    const second = LOBBY_BOT_SECOND_PARTS[secureRandomInt(0, LOBBY_BOT_SECOND_PARTS.length)];
    const number = secureRandomInt(1, 1000);
    const pattern = secureRandomInt(0, 5);
    const name = pattern === 0
      ? `${first}${second}`
      : pattern === 1
        ? `${first}.${second}`
        : pattern === 2
          ? `${first}${number}`
          : pattern === 3
            ? `${second}${first}`
            : `${first}_${second}${secureRandomInt(1, 100)}`;
    if (!usedNames.has(name)) {
      usedNames.add(name);
      return {
        name,
        country: LOBBY_BOT_COUNTRIES[secureRandomInt(0, LOBBY_BOT_COUNTRIES.length)],
      };
    }
  }
  const fallbackName = `Oyuncu${crypto.randomBytes(4).toString("hex")}`;
  usedNames.add(fallbackName);
  return { name: fallbackName, country: "TR" };
}

function roomGroupForStake(stakePoints) {
  const stake = Math.max(0, Number(stakePoints || 0));
  return TWO_PLAYER_ROOM_GROUPS.find((group) =>
    stake >= group.minScore && (group.maxScore == null || stake <= group.maxScore)
  ) || TWO_PLAYER_ROOM_GROUPS[TWO_PLAYER_ROOM_GROUPS.length - 1];
}

function roomTargetCount(groupIndex) {
  if (groupIndex <= 4) return 10;
  if (groupIndex === 5) return secureRandomInt(5, 11);
  return secureRandomInt(2, 6);
}

function generatedRoomRoundCount(groupIndex, currentMultiRoomCount, targetCount) {
  if (groupIndex < 3) return 1;
  const desiredMultiRoomCount = Math.round(targetCount / 2);
  return currentMultiRoomCount < desiredMultiRoomCount ? secureRandomInt(2, 4) : 1;
}

function expireGeneratedLobbyBots() {
  const now = Date.now();
  for (const [listingId, bot] of generatedLobbyBots.entries()) {
    if (now - Number(bot.createdAt || 0) > 3 * 60 * 1000) generatedLobbyBots.delete(listingId);
  }
}

function randomStakeForGroup(group, difficulty) {
  const minimum = Math.max(group.minScore, minimumTwoPlayerStake(difficulty));
  const maximum = group.maxScore == null
    ? Math.min(2_000_000_000, Math.max(minimum, minimum * secureRandomInt(2, 15)))
    : Math.max(minimum, group.maxScore);

  if (maximum <= minimum) return minimum;

  // Hazır odalardaki botların büyük çoğunluğunu salonun alt puan sınırına yakın tut.
  // Kapalı aralıklı salonlarda alt band, toplam puan aralığının ilk 1/6'sıdır.
  // Örn. Efsane Salon: 200.000 - 2.000.000 => alt bant 200.000 - 500.000.
  // Botların %75'i bu alt banttan, %25'i ise kalan üst aralıktan seçilir.
  const preferredMaximum = group.maxScore == null
    ? Math.min(maximum, minimum + Math.max(1, Math.floor(minimum * 1.5)))
    : Math.min(maximum, minimum + Math.max(1, Math.ceil((maximum - minimum) / 6)));

  const shouldUseLowerBand = preferredMaximum >= maximum || secureRandomInt(0, 100) < 75;
  if (shouldUseLowerBand) {
    return randomStakeWithNaturalEnding(minimum, preferredMaximum);
  }

  return randomStakeWithNaturalEnding(preferredMaximum + 1, maximum);
}

const LOBBY_EVENT_DEBOUNCE_MS = Math.max(100, Math.min(2_000,
  Number(process.env.LOBBY_EVENT_DEBOUNCE_MS || 500) || 500));
// Eski uygulama sürümleri scoped lobby aboneliğini bilmez. Geçiş döneminde yalnız bu eski
// socket'lere legacy event gönderilir; yeni istemciler global yayından tamamen çıkarılır.
const ENABLE_LEGACY_LOBBY_BROADCAST = process.env.ENABLE_LEGACY_LOBBY_BROADCAST === 'true';
const lobbyChangeTimers = new Map();

function lobbySocketRoom(difficulty, gameKey = "target_number") {
  return `lobby:${normalizeBaseGameKey(gameKey)}:${secureDifficulty(difficulty)}`;
}

function emitRoomLobbyChanged(difficulty, gameKey = "target_number") {
  const normalizedDifficulty = secureDifficulty(difficulty);
  const baseGameKey = normalizeBaseGameKey(gameKey);
  const timerKey = `${baseGameKey}:${normalizedDifficulty}`;
  const previous = lobbyChangeTimers.get(timerKey);
  if (previous) clearTimeout(previous);
  const timer = setTimeout(() => {
    lobbyChangeTimers.delete(timerKey);
    const payload = { gameKey: baseGameKey, difficulty: normalizedDifficulty, changedAtMillis: Date.now() };
    io.to(lobbySocketRoom(normalizedDifficulty, baseGameKey)).emit("room_lobby_changed", payload);
    if (ENABLE_LEGACY_LOBBY_BROADCAST) {
      for (const connectedSocket of io.sockets.sockets.values()) {
        if (connectedSocket.data?.supportsScopedLobbyEvents === true) continue;
        connectedSocket.emit("room_lobby_changed", payload);
      }
    }
  }, LOBBY_EVENT_DEBOUNCE_MS);
  timer.unref?.();
  lobbyChangeTimers.set(timerKey, timer);
}

function removeOpenTablesForSocket(socketId) {
  const changed = new Set();
  for (const [listingId, table] of publicOpenTables.entries()) {
    if (table.ownerSocketId === socketId) {
      changed.add(`${normalizeBaseGameKey(table.gameKey)}::${table.difficulty}`);
      publicOpenTables.delete(listingId);
    }
  }
  for (const item of changed) {
    const [gameKey, difficulty] = item.split("::");
    emitRoomLobbyChanged(difficulty, gameKey);
  }
}

function expireOldOpenTables() {
  const now = Date.now();
  const changed = new Set();
  for (const [listingId, table] of publicOpenTables.entries()) {
    if (now - table.createdAt > 15 * 60 * 1000 || !io.sockets.sockets.get(table.ownerSocketId)) {
      changed.add(`${normalizeBaseGameKey(table.gameKey)}::${table.difficulty}`);
      publicOpenTables.delete(listingId);
    }
  }
  for (const item of changed) {
    const [gameKey, difficulty] = item.split("::");
    emitRoomLobbyChanged(difficulty, gameKey);
  }
}

const PRIVATE_ROOM_TTL_MS = Number(
  process.env.PRIVATE_ROOM_TTL_MS ||
    15 * 60 * 1000
);

const ROOM_RECONNECT_TIMEOUT_MS = Number(
  process.env.ROOM_RECONNECT_TIMEOUT_MS ||
    60 * 1000
);

const TWO_PLAYER_PREPARE_MS = Number(
  process.env.TWO_PLAYER_PREPARE_MS ||
    10 * 1000
);

const RESOLVED_ROOM_TTL_MS = Number(
  process.env.RESOLVED_ROOM_TTL_MS ||
    10 * 60 * 1000
);

function normalizeMatchGameKey(value) {
  const raw = String(value || "target_number").trim().toLowerCase().slice(0, 96);
  const base = normalizeBaseGameKey(raw);
  if (/_tournament(?:_stage_\d+)?$/i.test(raw)) return `${base}_tournament`;
  if (/_hundred(?:_stage_\d+)?$/i.test(raw)) return `${base}_hundred`;
  return base;
}

function queueKey(gameKey, difficulty) {
  return `${String(
    gameKey || "default"
  )}::${String(
    difficulty || "default"
  )}`;
}

function safePlayerId(value, fallback = "") {
  const cleaned = String(
    value || fallback || ""
  )
    .trim()
    .replace(/[^a-zA-Z0-9_.:-]/g, "")
    .slice(0, 96);

  return (
    cleaned ||
    String(fallback || "")
      .trim()
      .slice(0, 96)
  );
}

function matchmakingPlayerKey(playerId) {
  const secret = SESSION_SECRET || "target-number-matchmaking";
  return crypto
    .createHmac("sha256", secret)
    .update(String(playerId || ""))
    .digest("base64url")
    .slice(0, 32);
}

function safePlayer(
  rawPlayer,
  fallbackId = ""
) {
  const id = safePlayerId(
    rawPlayer?.id,
    fallbackId
  );

  const name =
    String(rawPlayer?.name || "Oyuncu")
      .trim()
      .slice(0, 24) || "Oyuncu";

  const country = String(
    rawPlayer?.country || ""
  )
    .trim()
    .toUpperCase()
    .slice(0, 3);

  return {
    id,
    name,
    country,
  };
}

function normalizeRoomCode(value) {
  return String(value || "")
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, "")
    .slice(0, 6);
}

function generateRoomCode() {
  const alphabet =
    "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

  let code = "";

  for (let i = 0; i < 6; i += 1) {
    code += alphabet[
      crypto.randomInt(
        0,
        alphabet.length
      )
    ];
  }

  return code;
}

function generateUniqueRoomCode() {
  for (
    let attempt = 0;
    attempt < 32;
    attempt += 1
  ) {
    const code = generateRoomCode();

    if (!privateRooms.has(code)) {
      return code;
    }
  }

  return crypto
    .randomBytes(4)
    .toString("hex")
    .toUpperCase()
    .slice(0, 6);
}

function roomParticipants(room) {
  return Object.values(
    room?.participants || {}
  );
}

function getParticipant(room, playerId) {
  if (!room || !playerId) {
    return null;
  }

  return (
    room.participants[playerId] ||
    null
  );
}

function getOpponentParticipant(
  room,
  playerId
) {
  return (
    roomParticipants(room).find(
      (participant) =>
        participant.playerId !== playerId
    ) || null
  );
}

function clearParticipantTimeout(
  participant
) {
  if (participant?.timeoutHandle) {
    clearTimeout(
      participant.timeoutHandle
    );

    participant.timeoutHandle = null;
  }
  clearDigitAttackAutoHandle(participant);
}

function clearRoomTimeouts(room) {
  roomParticipants(room).forEach(
    clearParticipantTimeout
  );
  if (room?.deadlineHandle) {
    clearTimeout(room.deadlineHandle);
    room.deadlineHandle = null;
  }
  if (room?.botFinishHandle) {
    clearTimeout(room.botFinishHandle);
    room.botFinishHandle = null;
  }
}

function attachSocketToRoom(
  socket,
  room,
  playerId
) {
  const participant = getParticipant(
    room,
    playerId
  );

  if (!participant) return;

  participant.socketId = socket.id;
  participant.connected = true;

  socket.join(room.roomId);

  activeRooms.set(socket.id, {
    roomId: room.roomId,
    playerId,
  });
}

function clearParticipantAwayState(
  room,
  playerId
) {
  const participant = getParticipant(
    room,
    playerId
  );

  if (!participant) return;

  clearParticipantTimeout(participant);

  participant.connected = true;
  participant.awaySince = null;
  participant.backgrounded = false;
  participant.reconnectDeadlineAt = null;
}

function markRoomResolved(
  room,
  reason,
  winnerPlayerId,
  loserPlayerId
) {
  if (!room || room.resolved) return;

  room.resolved = true;
  room.resolvedReason = reason;

  room.winnerPlayerId =
    winnerPlayerId || null;

  room.loserPlayerId =
    loserPlayerId || null;

  room.resolvedAt = Date.now();

  clearRoomTimeouts(room);
}

async function resolveRoomByGameDeadline(roomId) {
  const room = realtimeRooms.get(roomId);
  if (!room || room.resolved) return;

  const participants = roomParticipants(room);
  markRoomResolved(room, "game_deadline", null, null);

  try {
    if (!room.isFriend && String(room.gameKey || "").endsWith("_tournament")) {
      const states = await Promise.all(
        participants.map((participant) =>
          applyTournamentOutcome(participant.playerId, false, participant.tournamentStage, normalizeBaseGameKey(room.gameKey))
        )
      );
      participants.forEach((participant, index) => {
        const participantSocket = participant.socketId
          ? io.sockets.sockets.get(participant.socketId)
          : null;
        if (participantSocket && states[index]) {
          participantSocket.emit("authoritative_tournament", states[index]);
        }
      });
    } else if (!room.isFriend && !String(room.gameKey || "").endsWith("_tournament") && !String(room.gameKey || "").endsWith("_hundred")) {
      const reward = Math.max(minimumTwoPlayerStake(room.difficulty), Number(room.stakePoints || 0));
      const states = await Promise.all(
        participants.map((participant) =>
          applyAuthoritativeScoreDelta(participant.playerId, -reward, 0, 0, normalizeBaseGameKey(room.gameKey))
        )
      );
      participants.forEach((participant, index) => {
        const participantSocket = participant.socketId
          ? io.sockets.sockets.get(participant.socketId)
          : null;
        if (participantSocket && states[index]) {
          participantSocket.emit("authoritative_reward", states[index]);
        }
      });
    }
    await Promise.all(
      participants.map((participant) =>
        recordTaskGameEvent(
          participant.playerId,
          `room:${room.roomId}`,
          normalizeBaseGameKey(room.gameKey),
          true,
          false
        )
      )
    );
    room.awardedAt = Date.now();
  } catch (error) {
    console.error("realtime game deadline reward error:", error);
  }

  realtimeLog("Realtime match deadline reached:", roomId, room.gameKey);
}

function resolveRoomByAwayTimeout(
  roomId,
  loserPlayerId
) {
  const room = realtimeRooms.get(roomId);

  if (!room || room.resolved) return;

  const loser = getParticipant(
    room,
    loserPlayerId
  );

  const opponent =
    getOpponentParticipant(
      room,
      loserPlayerId
    );

  if (!loser || loser.finishedAt) return;

  markRoomResolved(
    room,
    "timeout",
    opponent?.playerId,
    loserPlayerId
  );

  awardRealtimeRoom(room, opponent, loser).catch((error) => {
    console.error("realtime timeout reward error:", error);
  });

  const opponentSocket =
    opponent?.socketId
      ? io.sockets.sockets.get(
          opponent.socketId
        )
      : null;

  if (
    opponentSocket &&
    !opponent.finishedAt
  ) {
    opponentSocket.emit(
      "opponent_left",
      {
        roomId,
        reason: "timeout",
      }
    );
  }

  const loserSocket = loser.socketId
    ? io.sockets.sockets.get(
        loser.socketId
      )
    : null;

  if (loserSocket) {
    loserSocket.emit(
      "resume_error",
      {
        code: "RECONNECT_EXPIRED",
        message:
          "1 dakika içinde oyuna dönmediğiniz için mağlup sayıldınız.",
        opponentFinishedMs: Number(
          opponent?.elapsedMs || 0
        ),
      }
    );
  }

  realtimeLog(
    "Reconnect timeout loss:",
    roomId,
    loserPlayerId
  );
}

function scheduleParticipantAwayTimeout(
  room,
  playerId
) {
  const participant = getParticipant(
    room,
    playerId
  );

  if (
    !room ||
    room.resolved ||
    !participant ||
    participant.finishedAt
  ) {
    return;
  }

  if (!participant.awaySince) {
    participant.awaySince = Date.now();
  }

  participant.reconnectDeadlineAt =
    participant.awaySince +
    ROOM_RECONNECT_TIMEOUT_MS;

  clearParticipantTimeout(participant);

  const waitMs = Math.max(
    0,
    participant.reconnectDeadlineAt -
      Date.now()
  );

  participant.timeoutHandle =
    setTimeout(() => {
      resolveRoomByAwayTimeout(
        room.roomId,
        playerId
      );
    }, waitMs);

  if (
    typeof participant.timeoutHandle
      .unref === "function"
  ) {
    participant.timeoutHandle.unref();
  }
}

function emitToRoomParticipant(participant, eventName, payload) {
  if (!participant?.socketId) return;
  const targetSocket = io.sockets.sockets.get(participant.socketId);
  if (targetSocket) targetSocket.emit(eventName, payload);
}

function realtimeRoundWinner(room, first, second) {
  const roundLimitMs = gameDefinition(room?.gameKey).roundDurationMs;
  const firstElapsed = Number(first?.roundElapsedMs ?? roundLimitMs);
  const secondElapsed = Number(second?.roundElapsedMs ?? roundLimitMs);
  if (firstElapsed < secondElapsed) return first;
  if (secondElapsed < firstElapsed) return second;
  return String(first?.playerId || "").localeCompare(String(second?.playerId || "")) <= 0 ? first : second;
}

function realtimeMatchWinner(room) {
  const participants = roomParticipants(room);
  if (participants.length !== 2) return participants[0] || null;
  const [first, second] = participants;
  if (room.roundCount === 3) {
    if (first.roundWins >= 2) return first;
    if (second.roundWins >= 2) return second;
  }
  if (room.roundIndex + 1 < room.roundCount) return null;
  if (first.roundWins !== second.roundWins) return first.roundWins > second.roundWins ? first : second;
  if (first.totalElapsedMs !== second.totalElapsedMs) {
    return first.totalElapsedMs < second.totalElapsedMs ? first : second;
  }
  return String(first.playerId).localeCompare(String(second.playerId)) <= 0 ? first : second;
}

function finishRealtimeMatch(room, winner, reason = "rounds_completed") {
  if (!room || room.resolved || !winner) return;
  const loser = getOpponentParticipant(room, winner.playerId);
  markRoomResolved(room, reason, winner.playerId, loser?.playerId);

  roomParticipants(room).forEach((participant) => {
    const opponent = getOpponentParticipant(room, participant.playerId);
    emitToRoomParticipant(participant, "match_completed", {
      roomId: room.roomId,
      won: participant.playerId === winner.playerId,
      myRoundWins: Number(participant.roundWins || 0),
      opponentRoundWins: Number(opponent?.roundWins || 0),
      myTotalElapsedMs: Number(participant.totalElapsedMs || 0),
      opponentTotalElapsedMs: Number(opponent?.totalElapsedMs || 0),
    });
  });

  awardRealtimeRoom(room, winner, loser).catch((error) => {
    console.error("realtime reward error:", error);
  });
}

function scheduleRealtimeRound(room, prepareMs = 3_000) {
  if (!room || room.resolved) return;
  if (room.deadlineHandle) clearTimeout(room.deadlineHandle);
  if (room.botFinishHandle) clearTimeout(room.botFinishHandle);

  room.puzzle = room.puzzles[room.roundIndex] || generatePuzzleForGame(room.gameKey, room.difficulty);
  const safePrepareMs = Math.max(0, Math.min(Number(prepareMs || 0), 30_000));
  room.startsAtMillis = Date.now() + safePrepareMs;

  roomParticipants(room).forEach((participant) => {
    participant.finishedAt = null;
    participant.elapsedMs = null;
    participant.roundElapsedMs = null;
    participant.finishedRoundIndex = null;
    if (isDigitAttackRealtimeRoom(room)) {
      resetDigitAttackParticipantFlow(room, participant);
    } else {
      clearDigitAttackAutoHandle(participant);
    }
  });

  const roundLimitMs = gameDefinition(room.gameKey).roundDurationMs;
  room.deadlineHandle = setTimeout(() => {
    if (room.resolved) return;
    roomParticipants(room).forEach((participant) => {
      if (participant.finishedRoundIndex !== room.roundIndex) {
        participant.finishedAt = Date.now();
        participant.elapsedMs = roundLimitMs;
        participant.roundElapsedMs = roundLimitMs;
        participant.finishedRoundIndex = room.roundIndex;
      }
    });
    resolveRealtimeRound(room);
  }, safePrepareMs + roundLimitMs);
  if (typeof room.deadlineHandle.unref === "function") room.deadlineHandle.unref();

  const botParticipant = roomParticipants(room).find((participant) => participant.isBot);
  if (botParticipant) {
    const botPlan = createGameAwareBotPlan(room.gameKey, room.difficulty, room.botFinishProfile || {});
    const botElapsedMs = botPlan.finishMs == null
      ? Math.max(1, roundLimitMs - 1)
      : Math.min(botPlan.finishMs, Math.max(1, roundLimitMs - 1));
    room.botFinishHandle = setTimeout(() => {
      if (botPlan.wrongRoute === true || botPlan.forcedLoss === true) {
        registerRealtimeRoundLoss(
          room,
          botParticipant,
          botElapsedMs,
          botPlan.forcedLoss === true ? "bot_three_mistakes" : "bot_wrong_route"
        );
      } else {
        registerRealtimeRoundFinish(room, botParticipant, botElapsedMs);
      }
    }, safePrepareMs + botElapsedMs);
    if (typeof room.botFinishHandle.unref === "function") room.botFinishHandle.unref();
  }
}

function registerRealtimeRoundFinish(room, participant, elapsedMs) {
  if (!room || !participant || room.resolved) return;
  if (participant.finishedRoundIndex === room.roundIndex) return;
  const safeElapsedMs = Math.max(1, Math.min(Number(elapsedMs || 1), gameDefinition(room.gameKey).roundDurationMs));
  participant.finishedAt = Date.now();
  participant.elapsedMs = safeElapsedMs;
  participant.roundElapsedMs = safeElapsedMs;
  participant.finishedRoundIndex = room.roundIndex;
  clearParticipantAwayState(room, participant.playerId);

  const opponent = getOpponentParticipant(room, participant.playerId);
  emitToRoomParticipant(opponent, "opponent_finished", {
    roomId: room.roomId,
    elapsedMs: safeElapsedMs,
    roundIndex: room.roundIndex,
    roundCount: room.roundCount,
  });

  // Her el bir yarış olarak çalışır: doğru sonucu ilk gönderen oyuncu eli anında kazanır.
  // Özellikle 2 elli maçlarda daha önce 1-1 beraberliğini gerçek toplam süreyle çözmek
  // için ikinci oyuncunun da bitirmesi bekleniyordu. Bu bekleme kaldırıldı.
  // Eli henüz bitirmemiş rakibe o el için süre limiti yazılır; böylece 1-1 durumda
  // beraberlik bozucu toplam süre hesabı yine deterministik kalır ve kazanan ellerdeki
  // gerçek bitirme hızlarını karşılaştırır.
  const unfinishedOpponent = getOpponentParticipant(room, participant.playerId);
  if (unfinishedOpponent && unfinishedOpponent.finishedRoundIndex !== room.roundIndex) {
    unfinishedOpponent.finishedAt = Date.now();
    unfinishedOpponent.elapsedMs = gameDefinition(room.gameKey).roundDurationMs;
    unfinishedOpponent.roundElapsedMs = gameDefinition(room.gameKey).roundDurationMs;
    unfinishedOpponent.finishedRoundIndex = room.roundIndex;
  }
  resolveRealtimeRound(room);
}

function registerRealtimeRoundLoss(room, loser, elapsedMs, reason = "wrong_answer") {
  if (!room || !loser || room.resolved) return;
  if (loser.finishedRoundIndex === room.roundIndex) return;

  const roundLimitMs = gameDefinition(room.gameKey).roundDurationMs;
  const safeElapsedMs = Math.max(1, Math.min(Number(elapsedMs || 1), roundLimitMs));
  const winner = getOpponentParticipant(room, loser.playerId);
  if (!winner) return;

  // Yanlış cevap/rota gönderen oyuncu eli o anda kaybeder. Beraberlik bozucu toplam süre
  // deterministik kalsın diye kaybedene tur limiti, kazanana olay anındaki gerçek süre yazılır.
  loser.finishedAt = Date.now();
  loser.elapsedMs = roundLimitMs;
  loser.roundElapsedMs = roundLimitMs;
  loser.finishedRoundIndex = room.roundIndex;
  clearParticipantAwayState(room, loser.playerId);

  winner.wonRoundBecauseOpponentWrongAnswer = true;
  if (winner.finishedRoundIndex !== room.roundIndex) {
    winner.finishedAt = Date.now();
    winner.elapsedMs = safeElapsedMs;
    winner.roundElapsedMs = safeElapsedMs;
    winner.finishedRoundIndex = room.roundIndex;
    clearParticipantAwayState(room, winner.playerId);
  }

  realtimeLog("realtime round loss:", room.roomId, loser.playerId, reason);
  resolveRealtimeRound(room);
}

function resolveRealtimeRound(room) {
  if (!room || room.resolved) return;
  const participants = roomParticipants(room);
  if (participants.length !== 2) return;
  if (!participants.every((item) => item.finishedRoundIndex === room.roundIndex)) return;
  if (room.deadlineHandle) {
    clearTimeout(room.deadlineHandle);
    room.deadlineHandle = null;
  }
  if (room.botFinishHandle) {
    clearTimeout(room.botFinishHandle);
    room.botFinishHandle = null;
  }

  const [first, second] = participants;
  const roundWinner = realtimeRoundWinner(room, first, second);
  roundWinner.roundWins += 1;
  participants.forEach((participant) => {
    participant.totalElapsedMs += Number(participant.roundElapsedMs || gameDefinition(room.gameKey).roundDurationMs);
  });

  participants.forEach((participant) => {
    const opponent = getOpponentParticipant(room, participant.playerId);
    emitToRoomParticipant(participant, "round_result", {
      roomId: room.roomId,
      roundIndex: room.roundIndex,
      roundCount: room.roundCount,
      myRoundWins: participant.roundWins,
      opponentRoundWins: opponent?.roundWins || 0,
      myElapsedMs: participant.roundElapsedMs,
      opponentElapsedMs: opponent?.roundElapsedMs || 0,
      wonRound: participant.playerId === roundWinner.playerId,
    });
  });

  const matchWinner = realtimeMatchWinner(room);
  if (matchWinner) {
    finishRealtimeMatch(room, matchWinner);
    return;
  }

  room.roundIndex += 1;
  scheduleRealtimeRound(room, 3_000);
  participants.forEach((participant) => {
    const opponent = getOpponentParticipant(room, participant.playerId);
    emitToRoomParticipant(participant, "next_round", {
      roomId: room.roomId,
      puzzle: room.puzzle,
      roundIndex: room.roundIndex,
      roundCount: room.roundCount,
      startsAtMillis: room.startsAtMillis,
      myRoundWins: participant.roundWins,
      opponentRoundWins: opponent?.roundWins || 0,
    });
  });
}

function createRealtimeRoom(
  socket,
  player,
  opponentSocket,
  opponentPlayer,
  gameKey,
  difficulty,
  puzzle,
  tournamentStage = null,
  opponentTournamentStage = null,
  stakePoints = 0,
  matchMode = "quick",
  prepareMs = 0,
  roundCountValue = 1,
  suppliedPuzzles = null,
  botFinishProfile = null
) {
  const roomId = typeof crypto.randomUUID === "function"
    ? crypto.randomUUID()
    : crypto.randomBytes(16).toString("hex");

  const createdAt = Date.now();
  const roundCount = String(gameKey || "").endsWith("_tournament") ? 1 : normalizeRoundCount(roundCountValue);
  const puzzles = Array.isArray(suppliedPuzzles) && suppliedPuzzles.length >= roundCount
    ? suppliedPuzzles.slice(0, roundCount)
    : [puzzle, ...Array.from({ length: Math.max(0, roundCount - 1) }, () => generatePuzzleForGame(gameKey, difficulty))];
  const room = {
    roomId,
    gameKey,
    difficulty: secureDifficulty(difficulty),
    puzzle: puzzles[0],
    puzzles,
    roundCount,
    roundIndex: 0,
    stakePoints: Math.max(0, Math.floor(Number(stakePoints || 0))),
    matchMode: safeText(matchMode, "quick", 32),
    createdAt,
    startsAtMillis: createdAt,
    resolved: false,
    resolvedReason: null,
    resolvedAt: null,
    winnerPlayerId: null,
    loserPlayerId: null,
    isFriend: false,
    awardedAt: null,
    deadlineHandle: null,
    botFinishHandle: null,
    // Hazır oda botlarında ilk 5 oyun sonrası ±4 saniye kuralı için
    // oyuncunun sunucuda tutulan ikili oyun bitirme profili odaya taşınır.
    botFinishProfile: opponentPlayer.isBot === true
      ? normalizeTwoPlayerFinishProfile(botFinishProfile || {})
      : null,

    participants: {
      [player.id]: {
        playerId: player.id,
        socketId: socket.id,
        name: player.name,
        country: player.country,
        isBot: false,
        connected: true,
        awaySince: null,
        backgrounded: false,
        reconnectDeadlineAt: null,
        timeoutHandle: null,
        finishedAt: null,
        elapsedMs: null,
        roundElapsedMs: null,
        finishedRoundIndex: null,
        roundWins: 0,
        totalElapsedMs: 0,
        tournamentStage: tournamentStage == null ? null : Math.max(1, Math.min(Number(tournamentStage || 1), 8)),
      },

      [opponentPlayer.id]: {
        playerId: opponentPlayer.id,
        socketId: opponentSocket?.id || null,
        name: opponentPlayer.name,
        country: opponentPlayer.country,
        isBot: opponentPlayer.isBot === true,
        connected: opponentPlayer.isBot === true || Boolean(opponentSocket),
        awaySince: null,
        backgrounded: false,
        reconnectDeadlineAt: null,
        timeoutHandle: null,
        finishedAt: null,
        elapsedMs: null,
        roundElapsedMs: null,
        finishedRoundIndex: null,
        roundWins: 0,
        totalElapsedMs: 0,
        tournamentStage: opponentTournamentStage == null ? null : Math.max(1, Math.min(Number(opponentTournamentStage || 1), 8)),
      },
    },
  };

  realtimeRooms.set(roomId, room);
  attachSocketToRoom(socket, room, player.id);
  if (opponentSocket) attachSocketToRoom(opponentSocket, room, opponentPlayer.id);
  scheduleRealtimeRound(room, prepareMs);
  return room;
}

function removePrivateRoomsForSocket(
  socketId,
  notify = true
) {
  for (
    const [roomCode, room]
    of privateRooms.entries()
  ) {
    if (
      room.ownerSocketId !== socketId
    ) {
      continue;
    }

    privateRooms.delete(roomCode);

    const ownerSocket =
      io.sockets.sockets.get(socketId);

    if (notify && ownerSocket) {
      ownerSocket.emit(
        "friend_room_closed",
        {
          roomCode,
          reason: "cancelled",
        }
      );
    }
  }
}

function expireOldPrivateRooms() {
  const now = Date.now();

  for (
    const [roomCode, room]
    of privateRooms.entries()
  ) {
    if (
      now - room.createdAt <=
      PRIVATE_ROOM_TTL_MS
    ) {
      continue;
    }

    privateRooms.delete(roomCode);

    const ownerSocket =
      io.sockets.sockets.get(
        room.ownerSocketId
      );

    if (ownerSocket) {
      ownerSocket.emit(
        "friend_room_closed",
        {
          roomCode,
          reason: "expired",
        }
      );
    }
  }
}

function expireResolvedRooms() {
  const now = Date.now();

  for (
    const [roomId, room]
    of realtimeRooms.entries()
  ) {
    if (
      !room.resolved ||
      !room.resolvedAt
    ) {
      continue;
    }

    if (
      now - room.resolvedAt <=
      RESOLVED_ROOM_TTL_MS
    ) {
      continue;
    }

    clearRoomTimeouts(room);
    realtimeRooms.delete(roomId);
  }
}

function removeFromAllQueues(
  socketId,
  playerId = ""
) {
  for (
    const [key, queue]
    of waitingQueues.entries()
  ) {
    const filtered = queue.filter(
      (item) => {
        if (
          item.socketId === socketId
        ) {
          return false;
        }

        if (
          playerId &&
          item.player?.id === playerId
        ) {
          return false;
        }

        return true;
      }
    );

    if (filtered.length === 0) {
      waitingQueues.delete(key);
    } else {
      waitingQueues.set(
        key,
        filtered
      );
    }
  }
}

function getRoomContextBySocket(socket) {
  const active = activeRooms.get(
    socket.id
  );

  if (!active) {
    return {};
  }

  const room = realtimeRooms.get(
    active.roomId
  );

  if (!room) {
    activeRooms.delete(socket.id);
    return {};
  }

  const participant = getParticipant(
    room,
    active.playerId
  );

  const opponent =
    getOpponentParticipant(
      room,
      active.playerId
    );

  return {
    active,
    room,
    participant,
    opponent,
  };
}

function leaveRoomAsCancel(socket) {
  const {
    active,
    room,
    participant,
    opponent,
  } = getRoomContextBySocket(socket);

  if (!active) return;

  if (room && participant) {
    if (
      !room.resolved &&
      !participant.finishedAt &&
      opponent &&
      !opponent.finishedAt
    ) {
      const isFreePreparationExit =
        !room.isFriend &&
        !String(room.gameKey || "").endsWith("_tournament") &&
        Date.now() < Number(room.startsAtMillis || 0);

      if (isFreePreparationExit) {
        const participants = roomParticipants(room);
        markRoomResolved(room, "prestart_cancelled", null, null);

        refundConsumedGameRights(participants.map((item) => item.playerId), normalizeBaseGameKey(room.gameKey))
          .then((states) => {
            participants.forEach((item) => {
              const participantSocket = item.socketId
                ? io.sockets.sockets.get(item.socketId)
                : null;
              const state = states.get(item.playerId);
              if (participantSocket && state) {
                participantSocket.emit("authoritative_reward", state);
              }
            });
          })
          .catch((error) => {
            console.error("prestart game-right refund error:", error);
          });

        const opponentSocket = opponent.socketId
          ? io.sockets.sockets.get(opponent.socketId)
          : null;
        if (opponentSocket) {
          opponentSocket.emit("opponent_left", {
            roomId: room.roomId,
            reason: "prestart_cancelled",
          });
        }
      } else {
        markRoomResolved(
          room,
          "cancelled",
          opponent.playerId,
          participant.playerId
        );

        awardRealtimeRoom(room, opponent, participant).catch((error) => {
          console.error("realtime cancel reward error:", error);
        });

        const opponentSocket =
          opponent.socketId
            ? io.sockets.sockets.get(
                opponent.socketId
              )
            : null;

        if (opponentSocket) {
          opponentSocket.emit(
            "opponent_left",
            {
              roomId: room.roomId,
              reason: "cancelled",
            }
          );
        }
      }
    }

    clearParticipantTimeout(
      participant
    );

    participant.connected = false;
    participant.awaySince = null;
    participant.backgrounded = false;
    participant.reconnectDeadlineAt =
      null;
    participant.socketId = null;
  }

  activeRooms.delete(socket.id);
  socket.leave(active.roomId);
}

function markSocketDisconnected(socket) {
  const {
    active,
    room,
    participant,
  } = getRoomContextBySocket(socket);

  if (
    !active ||
    !room ||
    !participant
  ) {
    return;
  }

  activeRooms.delete(socket.id);

  if (
    room.resolved ||
    participant.finishedAt
  ) {
    participant.connected = false;
    participant.socketId = null;
    return;
  }

  participant.connected = false;
  participant.socketId = null;

  if (!participant.awaySince) {
    participant.awaySince = Date.now();
  }

  scheduleParticipantAwayTimeout(
    room,
    participant.playerId
  );
  scheduleDigitAttackAwayFlow(room, participant.playerId);
}

app.get("/", (req, res) => {
  res.json({
    ok: true,
    service:
      "target-number-matchmaking",
    socket: "socket.io",
    socketPath: SOCKET_PATH,
    database: Boolean(pool),
    leaderboard: Boolean(pool),

    transports: [
      "websocket",
      "polling",
    ],

    waitingQueues: Array.from(
      waitingQueues.entries()
    ).map(([key, queue]) => ({
      key,
      count: queue.length,
    })),

    activeRooms: Array.from(
      realtimeRooms.values()
    ).filter(
      (room) => !room.resolved
    ).length,

    privateRooms: privateRooms.size,
  });
});

app.get("/health", (req, res) => {
  // Render liveness kontrolü PostgreSQL'e sorgu göndermesin.
  res.json({ ok: true, service: "target-number-matchmaking" });
});

app.get("/ready", async (req, res) => {
  if (!pool) {
    res.status(503).json({ ok: false, database: false });
    return;
  }
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, database: true });
  } catch (error) {
    console.error("readiness database error:", {
      message: error.message,
      code: error.code,
      detail: error.detail,
    });
    res.status(503).json({ ok: false, database: false, message: "Database bağlantısı başarısız." });
  }
});

app.get(
  "/socket-check",
  (req, res) => {
    res.json({
      ok: true,
      socketPath: SOCKET_PATH,
      androidUrlMustBe:
        "https://renderdepo-tpqh.onrender.com",
      androidUrlMustNotInclude:
        "/socket.io",
      transports: [
        "websocket",
        "polling",
      ],
    });
  }
);

io.engine.on(
  "connection_error",
  (err) => {
    realtimeLog(
      "Engine.IO connection_error:",
      {
        code: err.code,
        message: err.message,
        context: err.context,
        url:
          err.req &&
          err.req.url,
        userAgent:
          err.req &&
          err.req.headers &&
          err.req.headers[
            "user-agent"
          ],
        origin:
          err.req &&
          err.req.headers &&
          err.req.headers.origin,
      }
    );
  }
);

io.engine.on(
  "connection",
  (rawSocket) => {
    realtimeLog(
      "Engine.IO connected:",
      rawSocket.id,
      "transport:",
      rawSocket.transport.name
    );
  }
);


function authenticatedSocketPlayer(socket, payload, errorEvent = "match_error") {
  const session = verifySessionToken(payload?.authToken);
  if (!session) {
    socket.emit(errorEvent, {
      code: "AUTH_REQUIRED",
      message: "Oyuncu oturumu doğrulanamadı. Ana ekrana dönüp tekrar deneyin.",
    });
    return null;
  }

  // Yeniden bağlanmada da istemcinin gönderdiği ad/ülke/kimlik kullanılmaz.
  // Odaya erişim yalnızca imzalı oturumdaki değiştirilemez oyuncu kimliğiyle yapılır.
  return {
    id: safePlayerId(session.sub, session.sub),
    name: "",
    country: "",
  };
}

async function authenticatedSocketPlayerFromDatabase(socket, payload, errorEvent = "match_error") {
  const session = verifySessionToken(payload?.authToken);
  if (!session) {
    socket.emit(errorEvent, { code: "AUTH_REQUIRED", message: "Oyuncu oturumu doğrulanamadı. Ana ekrana dönüp tekrar deneyin." });
    return null;
  }
  const gameSessionId = normalizeGameplaySessionId(payload?.gameSessionId);
  if (!gameSessionId) {
    socket.emit(errorEvent, { code: "GAME_SESSION_REQUIRED", message: "Bu cihaz için aktif oyun oturumu bulunamadı." });
    return null;
  }
  if (!pool) {
    socket.emit(errorEvent, { code: "DATABASE_REQUIRED", message: "Sunucu veritabanı hazır değil." });
    return null;
  }
  const gameKey = normalizeBaseGameKey(payload?.gameKey);
  const client = await pool.connect();
  try {
    await ensurePlayerGameProgress(client, session.sub, gameKey);
    const result = await client.query(
      `SELECT p.username, p.country,
              gp.tournament_stage, gp.tournament_rights,
              gp.tournament_completed, gp.tournament_entry_active,
              s.general_score,
              gp.two_player_finish_count, gp.two_player_finish_total_ms
       FROM players p
       JOIN player_progress g ON g.player_id = p.player_id
       JOIN player_game_progress gp ON gp.player_id = p.player_id AND gp.game_key = $3
       JOIN player_scores s ON s.player_id = p.player_id
       JOIN player_game_sessions gs
         ON gs.player_id = p.player_id
        AND gs.session_id = $2
        AND gs.expires_at > NOW()
       WHERE p.player_id = $1`,
      [session.sub, gameSessionId, gameKey]
    );
    if (result.rowCount === 0) {
      socket.emit(errorEvent, { code: "GAME_SESSION_REPLACED", message: "Bu oyun oturumu daha yeni bir oturum tarafından geçersiz kılındı." });
      return null;
    }
    socket.data.playerId = safePlayerId(session.sub, session.sub);
    socket.data.gameSessionId = gameSessionId;
    const row = result.rows[0] || {};
    return {
      gameKey,
      player: safePlayer({ id: session.sub, name: row.username, country: row.country }, session.sub),
      tournamentStage: Math.max(1, Math.min(Number(row.tournament_stage || 1), 8)),
      tournamentRights: Math.max(0, Math.min(Number(row.tournament_rights ?? 3), 3)),
      tournamentCompleted: row.tournament_completed === true,
      tournamentEntryActive: row.tournament_entry_active === true,
      generalScore: Math.max(0, Number(row.general_score || 0)),
      twoPlayerFinishProfile: normalizeTwoPlayerFinishProfile({
        finishCount: row.two_player_finish_count,
        finishTotalMs: row.two_player_finish_total_ms,
      }),
    };
  } catch (error) {
    console.error("socket player load error:", error);
    socket.emit(errorEvent, { code: "PLAYER_STATE_ERROR", message: "Oyuncu bilgisi sunucudan alınamadı." });
    return null;
  } finally {
    client.release();
  }
}

app.get("/game/two-player/rooms", requireAuth, async (req, res) => {
  if (!requireDatabase(res)) return;
  expireOldOpenTables();
  const clientBots = String(req.query.clientBots || "") === "1";
  if (!clientBots) expireGeneratedLobbyBots();
  const difficulty = secureDifficulty(req.query.difficulty);
  const gameKey = normalizeBaseGameKey(req.query.gameKey);
  try {
    // Yeni istemcide lobi uygunluğu yalnız görsel bilgidir; gerçek oyuna girişte puan tekrar
    // authoritative DB state ile doğrulanır. Böylece her lobi refresh'inde PostgreSQL SELECT yoktur.
    let requesterScore = safeScore(req.query.score);
    if (!clientBots) {
      const scoreResult = await pool.query(
        `SELECT general_score FROM player_scores WHERE player_id = $1`,
        [req.auth.sub]
      );
      requesterScore = Math.max(0, Number(scoreResult.rows[0]?.general_score || 0));
    }
    const realTables = [...publicOpenTables.values()]
      .filter((table) => table.player.id !== req.auth.sub && table.difficulty === difficulty && normalizeBaseGameKey(table.gameKey) === gameKey)
      .sort((a, b) => a.createdAt - b.createdAt);

    const usedListings = new Set();
    const usedLobbyBotNames = new Set(realTables.map((table) => table.player.name));
    const groups = TWO_PLAYER_ROOM_GROUPS.map((group, groupIndex) => {
      const normalTargetCount = roomTargetCount(groupIndex);
      const realCandidates = realTables.filter((table) => {
        if (usedListings.has(table.listingId)) return false;
        return table.stakePoints >= group.minScore &&
          (group.maxScore == null || table.stakePoints <= group.maxScore);
      });
      // Üst salonlarda gerçek masa sayısı normal bot hedefini aşarsa bütün gerçek
      // masaları göster; ancak tek salonda görünen toplam masa sayısı 10'u geçmesin.
      const targetCount = groupIndex >= 5
        ? Math.min(10, Math.max(normalTargetCount, realCandidates.length))
        : normalTargetCount;
      const matchingReal = realCandidates.slice(0, targetCount);
      matchingReal.forEach((table) => usedListings.add(table.listingId));
      const rooms = matchingReal.map((table) => ({
        listingId: table.listingId,
        opponentName: table.player.name,
        opponentCountry: table.player.country,
        stakePoints: table.stakePoints,
        roundCount: normalizeRoundCount(table.roundCount),
        isBot: false,
      }));
      // Yeni istemci görsel bot odalarını cihazda üretir. Sunucu bu GET sırasında bot kimliği,
      // listing ve Map kaydı üretmez; bot ancak kullanıcı gerçekten o masaya bastığında yaratılır.
      while (!clientBots && rooms.length < targetCount) {
        const botIdentity = createLobbyBotIdentity(usedLobbyBotNames);
        const stakePoints = randomStakeForGroup(group, difficulty);
        const currentMultiRoomCount = rooms
          .filter((room) => normalizeRoundCount(room.roundCount) > 1)
          .length;
        const roundCount = generatedRoomRoundCount(
          groupIndex,
          currentMultiRoomCount,
          targetCount
        );
        const listingId = `bot:${group.id}:${crypto.randomBytes(8).toString("hex")}`;
        generatedLobbyBots.set(listingId, {
          listingId,
          player: {
            id: `bot_${crypto.randomBytes(12).toString("hex")}`,
            name: botIdentity.name,
            country: botIdentity.country,
            isBot: true,
          },
          gameKey,
          difficulty,
          stakePoints,
          roundCount,
          createdAt: Date.now(),
        });
        rooms.push({
          listingId,
          opponentName: botIdentity.name,
          opponentCountry: botIdentity.country,
          stakePoints,
          roundCount,
          isBot: true,
        });
      }
      return {
        ...group,
        targetCount,
        eligible: requesterScore >= group.minScore &&
          (group.maxScore == null || requesterScore <= group.maxScore),
        rooms,
      };
    });
    res.json({ ok: true, score: requesterScore, gameKey, difficulty, groups });
  } catch (error) {
    sendLeaderboardError(res, error, "Oda listesi alınamadı.", "room lobby error:");
  }
});

io.on("connection", (socket) => {
  realtimeLog(
    "Socket connected:",
    socket.id,
    "transport:",
    socket.conn.transport.name
  );

  const socketClientIp = forwardedClientIp(socket.request);
  const sensitiveSocketEvents = new Set([
    "create_open_table",
    "start_open_table_bot",
    "join_match",
    "resume_match",
    "create_friend_room",
    "join_friend_room",
    "player_finished",
  ]);

  socket.use((packet, next) => {
    const eventName = String(packet?.[0] || "unknown").slice(0, 80);
    const identity = socket.data?.playerId || socketClientIp;

    const incomingGameKey = packet?.[1]?.gameKey;
    if (incomingGameKey !== undefined && incomingGameKey !== null && String(incomingGameKey).trim() !== "") {
      try {
        normalizeBaseGameKey(incomingGameKey);
      } catch (error) {
        socket.emit("match_error", {
          code: error.publicCode || "UNSUPPORTED_GAME",
          message: error.message || "Desteklenmeyen oyun.",
        });
        return;
      }
    }

    const generalLimit = consumeSecurityRateLimit(
      "socket-packet",
      identity,
      Math.max(60, Math.min(2_000, Number(process.env.SOCKET_PACKET_RATE_LIMIT_10S || 300) || 300)),
      10_000
    );
    if (!generalLimit.allowed) {
      socket.emit("match_error", {
        code: "RATE_LIMITED",
        message: "Çok fazla gerçek zamanlı istek gönderildi. Kısa süre sonra tekrar deneyin.",
      });
      return;
    }

    if (sensitiveSocketEvents.has(eventName)) {
      const sensitiveLimit = consumeSecurityRateLimit(
        `socket-sensitive:${eventName}`,
        identity,
        Math.max(10, Math.min(300, Number(process.env.SOCKET_SENSITIVE_RATE_LIMIT_10S || 60) || 60)),
        10_000
      );
      if (!sensitiveLimit.allowed) {
        socket.emit("match_error", {
          code: "RATE_LIMITED",
          message: "Bu işlem çok sık tekrarlandı. Kısa süre sonra tekrar deneyin.",
        });
        return;
      }
    }

    next();
  });

  socket.on("client_capabilities", (payload = {}) => {
    if (payload.scopedLobbyEvents === true) {
      socket.data.supportsScopedLobbyEvents = true;
    }
  });

  socket.on("lobby_subscribe", (payload = {}) => {
    socket.data.supportsScopedLobbyEvents = true;
    const difficulty = secureDifficulty(payload.difficulty);
    const gameKey = normalizeBaseGameKey(payload.gameKey);
    const targetRoom = lobbySocketRoom(difficulty, gameKey);
    for (const roomName of socket.rooms) {
      if (roomName.startsWith("lobby:") && roomName !== targetRoom) socket.leave(roomName);
    }
    socket.join(targetRoom);
  });

  socket.on("lobby_unsubscribe", (payload = {}) => {
    const difficulty = secureDifficulty(payload.difficulty);
    socket.leave(lobbySocketRoom(difficulty, normalizeBaseGameKey(payload.gameKey)));
  });

  socket.conn.on(
    "upgrade",
    (transport) => {
      realtimeLog(
        "Socket upgraded:",
        socket.id,
        "transport:",
        transport.name
      );
    }
  );

  socket.on(
    "create_open_table",
    async (payload = {}) => {
      expireOldOpenTables();
      const identity = await authenticatedSocketPlayerFromDatabase(socket, payload, "match_error");
      if (!identity) return;
      const gameKey = normalizeBaseGameKey(payload.gameKey);
      const difficulty = secureDifficulty(payload.difficulty);
      let stakePoints;
      let roundCount;
      try {
        assertOpenTableStake(payload.stakePoints, identity.generalScore, difficulty);
        stakePoints = normalizeRequestedStake(payload.stakePoints, difficulty, identity.generalScore, false);
        roundCount = assertRoundCountEligibility(payload.roundCount, identity.generalScore, stakePoints);
      } catch (error) {
        socket.emit("match_error", { code: error.publicCode || "INVALID_WAGER", message: error.message });
        return;
      }

      removeFromAllQueues(socket.id, identity.player.id);
      removeOpenTablesForSocket(socket.id);
      leaveRoomAsCancel(socket);

      const listingId = `real:${crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(12).toString("hex")}`;
      const tablePuzzles = Array.from({ length: roundCount }, () => generatePuzzleForGame(gameKey, difficulty));
      publicOpenTables.set(listingId, {
        listingId,
        ownerSocketId: socket.id,
        player: identity.player,
        generalScore: identity.generalScore,
        gameKey,
        difficulty,
        stakePoints,
        roundCount,
        puzzles: tablePuzzles,
        puzzle: tablePuzzles[0],
        createdAt: Date.now(),
      });
      emitRoomLobbyChanged(difficulty, gameKey);
      socket.emit("open_table_created", { listingId, gameKey, stakePoints, difficulty, roundCount });
      socket.emit("waiting", { gameKey, difficulty, matchMode: "open_table", stakePoints, roundCount });
    }
  );

  socket.on(
    "start_open_table_bot",
    async (payload = {}) => {
      expireOldOpenTables();
      const identity = await authenticatedSocketPlayerFromDatabase(socket, payload, "match_error");
      if (!identity) return;

      const listingId = safeText(payload.listingId, "", 128);
      const table = publicOpenTables.get(listingId);
      if (
        !table ||
        table.ownerSocketId !== socket.id ||
        table.player.id !== identity.player.id
      ) {
        socket.emit("match_error", {
          code: "ROOM_NOT_FOUND",
          message: "Açık masa artık uygun değil.",
        });
        return;
      }

      try {
        assertRoundCountEligibility(table.roundCount, identity.generalScore, table.stakePoints);
        await consumeGameRightsForPlayers(
          [identity.player.id],
          table.difficulty,
          table.stakePoints
        );
      } catch (error) {
        socket.emit("match_error", {
          code: error.publicCode || "NO_GAME_RIGHT",
          message: error.message || "Oyun başlatılamadı.",
        });
        return;
      }

      publicOpenTables.delete(listingId);
      emitRoomLobbyChanged(table.difficulty, table.gameKey);
      await clearBotFallbackEligibilityForPlayers([identity.player.id]);

      const usedNames = new Set([identity.player.name]);
      const botIdentity = createLobbyBotIdentity(usedNames);
      const botPlayer = {
        id: `bot_${crypto.randomBytes(12).toString("hex")}`,
        name: botIdentity.name,
        country: botIdentity.country,
        isBot: true,
      };

      const room = createRealtimeRoom(
        socket,
        identity.player,
        null,
        botPlayer,
        table.gameKey,
        table.difficulty,
        table.puzzle,
        null,
        null,
        table.stakePoints,
        "open_table",
        TWO_PLAYER_PREPARE_MS,
        table.roundCount,
        table.puzzles,
        identity.twoPlayerFinishProfile
      );

      socket.emit("match_found", {
        roomId: room.roomId,
        opponent: {
          name: botPlayer.name,
          country: botPlayer.country,
          matchKey: matchmakingPlayerKey(botPlayer.id),
        },
        puzzle: room.puzzle,
        stakePoints: room.stakePoints,
        matchMode: "open_table",
        startsAtMillis: room.startsAtMillis,
        roundCount: room.roundCount,
        roundIndex: room.roundIndex,
        isBot: true,
      });
    }
  );

  socket.on(
    "join_match",
    async (payload = {}) => {
      const gameKey = normalizeMatchGameKey(payload.gameKey);
      let difficulty = String(payload.difficulty || "Medium");
      const identity = await authenticatedSocketPlayerFromDatabase(socket, payload, "match_error");
      if (!identity) return;
      const player = identity.player;
      const tournamentStage = gameKey.endsWith("_tournament") ? identity.tournamentStage : null;
      const matchMode = gameKey.endsWith("_tournament")
        ? "tournament"
        : safeText(payload.matchMode, "quick", 32);
      const listingId = safeText(payload.listingId, "", 128);
      const excludedOpponentMatchKey = safeText(payload.excludedOpponentMatchKey, "", 64);

      if (gameKey.endsWith("_tournament")) {
        if (
          identity.tournamentEntryActive !== true ||
          identity.tournamentCompleted === true ||
          identity.tournamentRights <= 0
        ) {
          socket.emit("match_error", {
            code: "TOURNAMENT_ENTRY_REQUIRED",
            message: `Turnuvaya katılmak için ${TOURNAMENT_ENTRY_TICKET_COST} biletle aktif giriş yapılmalıdır.`,
          });
          return;
        }
        difficulty = "Standard";
      } else {
        difficulty = secureDifficulty(difficulty);
      }

      removeFromAllQueues(socket.id, player.id);
      removePrivateRoomsForSocket(socket.id, false);
      removeOpenTablesForSocket(socket.id);
      leaveRoomAsCancel(socket);

      if (!gameKey.endsWith("_tournament") && listingId.startsWith("bot:")) {
        expireGeneratedLobbyBots();
        let botTable = generatedLobbyBots.get(listingId);
        if (botTable && normalizeBaseGameKey(botTable.gameKey) !== normalizeBaseGameKey(gameKey)) botTable = null;

        // Yeni istemci bot listing'ini yalnız görsel olarak kendisi üretir:
        // bot:<groupId>:<stakePoints>:<roundCount>:<nonce>. Sunucu hiçbir lobi botu saklamaz;
        // kullanıcı gerçekten seçtiğinde değerleri authoritative kurallarla doğrulayıp botu şimdi oluşturur.
        if (!botTable) {
          const parts = listingId.split(":");
          const groupId = safeText(parts[1], "", 32);
          const stakePoints = Number(parts[2]);
          const roundCount = Number(parts[3]);
          const group = TWO_PLAYER_ROOM_GROUPS.find((item) => item.id === groupId);
          const stakeValid = group && Number.isInteger(stakePoints) &&
            stakePoints >= Math.max(group.minScore, minimumTwoPlayerStake(difficulty)) &&
            (group.maxScore == null || stakePoints <= group.maxScore);
          const roundValid = Number.isInteger(roundCount) && roundCount >= 1 && roundCount <= 3;
          if (!stakeValid || !roundValid) {
            socket.emit("match_error", { code: "ROOM_NOT_FOUND", message: "Seçilen bot masası artık uygun değil." });
            return;
          }
          const usedNames = new Set([player.name]);
          const generatedIdentity = createLobbyBotIdentity(usedNames);
          const requestedBotName = safeText(payload.presetOpponentName, "", 40);
          const requestedBotCountry = safeText(payload.presetOpponentCountry, "", 3);
          botTable = {
            listingId,
            player: {
              id: `bot_${crypto.randomBytes(12).toString("hex")}`,
              // Bot adı/ülkesi puana etki etmez; istemcide görülen kimliği koru.
              name: requestedBotName || generatedIdentity.name,
              country: requestedBotCountry ? safeCountry(requestedBotCountry) : generatedIdentity.country,
              isBot: true,
            },
            gameKey: normalizeBaseGameKey(gameKey),
            difficulty,
            stakePoints,
            roundCount,
            createdAt: Date.now(),
            stateless: true,
          };
        }
        if (identity.generalScore < botTable.stakePoints) {
          socket.emit("match_error", { code: "INSUFFICIENT_SCORE", message: "Bu masaya katılmak için yeterli puanınız yok." });
          return;
        }
        try {
          assertRoundCountEligibility(botTable.roundCount, identity.generalScore, botTable.stakePoints);
          await consumeGameRightsForPlayers([player.id], botTable.difficulty, botTable.stakePoints);
        } catch (error) {
          socket.emit("match_error", { code: error.publicCode || "NO_GAME_RIGHT", message: error.message || "Oyun başlatılamadı." });
          return;
        }
        if (!botTable.stateless) generatedLobbyBots.delete(listingId);
        const botPuzzles = Array.from({ length: botTable.roundCount }, () => generatePuzzleForGame(gameKey, botTable.difficulty));
        const room = createRealtimeRoom(
          socket, player, null, botTable.player, normalizeBaseGameKey(gameKey), botTable.difficulty,
          botPuzzles[0], null, null, botTable.stakePoints, "ready_room", TWO_PLAYER_PREPARE_MS,
          botTable.roundCount, botPuzzles, identity.twoPlayerFinishProfile
        );
        socket.emit("match_found", {
          roomId: room.roomId,
          opponent: { name: botTable.player.name, country: botTable.player.country, matchKey: matchmakingPlayerKey(botTable.player.id) },
          puzzle: room.puzzle,
          stakePoints: room.stakePoints,
          matchMode: "ready_room",
          startsAtMillis: room.startsAtMillis,
          roundCount: room.roundCount,
          roundIndex: room.roundIndex,
          isBot: true,
        });
        return;
      }

      if (!gameKey.endsWith("_tournament") && listingId.startsWith("real:")) {
        expireOldOpenTables();
        const table = publicOpenTables.get(listingId);
        const ownerSocket = table ? io.sockets.sockets.get(table.ownerSocketId) : null;
        if (!table || !ownerSocket || table.player.id === player.id || normalizeBaseGameKey(table.gameKey) !== normalizeBaseGameKey(gameKey)) {
          socket.emit("match_error", { code: "ROOM_NOT_FOUND", message: "Seçilen masa artık uygun değil." });
          return;
        }
        if (identity.generalScore < table.stakePoints) {
          socket.emit("match_error", { code: "INSUFFICIENT_SCORE", message: "Bu masaya katılmak için yeterli puanınız yok." });
          return;
        }
        try {
          assertRoundCountEligibility(table.roundCount, identity.generalScore, table.stakePoints);
          await consumeGameRightsForPlayers([player.id, table.player.id], table.difficulty, table.stakePoints);
        } catch (error) {
          const message = error.message || "İki oyunculu oyun hakkı doğrulanamadı.";
          socket.emit("match_error", { code: error.publicCode || "NO_GAME_RIGHT", message });
          ownerSocket.emit("match_error", { code: error.publicCode || "NO_GAME_RIGHT", message });
          publicOpenTables.delete(listingId);
          emitRoomLobbyChanged(table.difficulty, table.gameKey);
          return;
        }
        publicOpenTables.delete(listingId);
        emitRoomLobbyChanged(table.difficulty, table.gameKey);
        await clearBotFallbackEligibilityForPlayers([player.id, table.player.id]);
        const room = createRealtimeRoom(
          socket, player, ownerSocket, table.player, table.gameKey, table.difficulty,
          table.puzzle, null, null, table.stakePoints, "ready_room", TWO_PLAYER_PREPARE_MS,
          table.roundCount, table.puzzles
        );
        socket.emit("match_found", {
          roomId: room.roomId, opponent: { name: table.player.name, country: table.player.country, matchKey: matchmakingPlayerKey(table.player.id) },
          puzzle: room.puzzle, stakePoints: table.stakePoints, matchMode: "ready_room",
          startsAtMillis: room.startsAtMillis, roundCount: room.roundCount, roundIndex: room.roundIndex, isBot: false
        });
        ownerSocket.emit("match_found", {
          roomId: room.roomId, opponent: { name: player.name, country: player.country, matchKey: matchmakingPlayerKey(player.id) },
          puzzle: room.puzzle, stakePoints: table.stakePoints, matchMode: "open_table",
          startsAtMillis: room.startsAtMillis, roundCount: room.roundCount, roundIndex: room.roundIndex, isBot: false
        });
        return;
      }

      const puzzle = generatePuzzleForGame(gameKey, difficulty);
      let requestedStake = 0;
      if (!gameKey.endsWith("_tournament")) {
        try {
          requestedStake = normalizeRequestedStake(
            payload.stakePoints, difficulty, identity.generalScore, matchMode === "quick"
          );
        } catch (error) {
          socket.emit("match_error", { code: error.publicCode || "INVALID_WAGER", message: error.message });
          return;
        }
      }

      const key = queueKey(gameKey, difficulty);
      const queue = waitingQueues.get(key) || [];
      const quickRange = !gameKey.endsWith("_tournament") && matchMode === "quick"
        ? quickStakeRange(identity.generalScore, difficulty)
        : null;
      const skippedOpponents = [];
      while (queue.length > 0) {
        const opponent = queue.shift();
        const opponentSocket = io.sockets.sockets.get(opponent.socketId);
        if (!opponentSocket || opponentSocket.id === socket.id) continue;
        if (opponent.player?.id && opponent.player.id === player.id) continue;
        if (
          excludedOpponentMatchKey &&
          matchmakingPlayerKey(opponent.player?.id) === excludedOpponentMatchKey
        ) {
          skippedOpponents.push(opponent);
          continue;
        }
        if (
          opponent.excludedOpponentMatchKey &&
          matchmakingPlayerKey(player.id) === opponent.excludedOpponentMatchKey
        ) {
          skippedOpponents.push(opponent);
          continue;
        }

        let selectedStake = 0;
        if (!gameKey.endsWith("_tournament")) {
          if (matchMode === "quick" && opponent.matchMode === "quick" && quickRange) {
            const overlapMin = Math.max(quickRange.minStake, Number(opponent.quickMinStake || 0));
            const overlapMax = Math.min(quickRange.maxStake, Number(opponent.quickMaxStake || 0));
            if (overlapMin > overlapMax) {
              skippedOpponents.push(opponent);
              continue;
            }
            selectedStake = overlapMax <= overlapMin
              ? overlapMin
              : secureRandomInt(overlapMin, overlapMax + 1);
          } else {
            selectedStake = Math.max(
              minimumTwoPlayerStake(difficulty),
              Math.min(requestedStake, opponent.stakePoints, identity.generalScore, opponent.generalScore)
            );
          }
        }
        waitingQueues.set(key, [...skippedOpponents, ...queue]);
        const selectedPuzzle = opponent.puzzle || puzzle;
        if (!gameKey.endsWith("_tournament")) {
          try {
            await consumeGameRightsForPlayers([player.id, opponent.player.id], difficulty, selectedStake);
          } catch (error) {
            const message = error.message || "İki oyunculu oyun hakkı doğrulanamadı.";
            socket.emit("match_error", { code: error.publicCode || "NO_GAME_RIGHT", message });
            opponentSocket.emit("match_error", { code: error.publicCode || "NO_GAME_RIGHT", message });
            return;
          }
        }
        await clearBotFallbackEligibilityForPlayers([player.id, opponent.player.id]);
        const room = createRealtimeRoom(
          socket, player, opponentSocket, opponent.player, gameKey, difficulty, selectedPuzzle,
          tournamentStage, opponent.tournamentStage, selectedStake, matchMode,
          gameKey.endsWith("_tournament") ? 0 : TWO_PLAYER_PREPARE_MS
        );
        socket.emit("match_found", {
          roomId: room.roomId, opponent: { name: opponent.player.name, country: opponent.player.country, matchKey: matchmakingPlayerKey(opponent.player.id) },
          puzzle: room.puzzle, stakePoints: selectedStake, matchMode,
          startsAtMillis: room.startsAtMillis, roundCount: room.roundCount, roundIndex: room.roundIndex, isBot: false
        });
        opponentSocket.emit("match_found", {
          roomId: room.roomId, opponent: { name: player.name, country: player.country, matchKey: matchmakingPlayerKey(player.id) },
          puzzle: room.puzzle, stakePoints: selectedStake, matchMode: opponent.matchMode || matchMode,
          startsAtMillis: room.startsAtMillis, roundCount: room.roundCount, roundIndex: room.roundIndex, isBot: false
        });
        realtimeLog("Match found:", room.roomId, key, "stake:", selectedStake);
        return;
      }

      queue.unshift(...skippedOpponents);
      queue.push({
        socketId: socket.id, player, puzzle, tournamentStage, joinedAt: Date.now(),
        stakePoints: requestedStake, generalScore: identity.generalScore, matchMode,
        quickMinStake: quickRange?.minStake || requestedStake,
        quickMaxStake: quickRange?.maxStake || requestedStake,
        excludedOpponentMatchKey,
      });
      waitingQueues.set(key, queue);
      await markBotFallbackEligibility(player.id, gameKey, difficulty);
      socket.emit("waiting", { gameKey, difficulty, matchMode, stakePoints: requestedStake });
    }
  );

  socket.on(
    "resume_match",
    async (payload = {}) => {
      const roomId = String(
        payload.roomId || ""
      ).trim();

      const player = authenticatedSocketPlayer(socket, payload, "resume_error");
      if (!player) return;

      const resumeGameSessionId = normalizeGameplaySessionId(payload?.gameSessionId);
      if (resumeGameSessionId) {
        socket.data.playerId = player.id;
        socket.data.gameSessionId = resumeGameSessionId;
        if (!(await socketHasActiveGameplaySession(socket, player.id, "resume_error"))) return;
      }

      const room =
        realtimeRooms.get(roomId);

      if (!roomId || !room) {
        socket.emit(
          "resume_error",
          {
            code: "ROOM_NOT_FOUND",
            message:
              "Yeniden bağlanılacak aktif oda bulunamadı.",
          }
        );

        return;
      }

      const participant =
        getParticipant(
          room,
          player.id
        );

      const opponent =
        getOpponentParticipant(
          room,
          player.id
        );

      if (!participant) {
        socket.emit(
          "resume_error",
          {
            code:
              "PLAYER_NOT_FOUND",
            message:
              "Bu oyuncu için yeniden bağlanma bilgisi bulunamadı.",
          }
        );

        return;
      }

      advanceDigitAttackAwayFlowToNow(room, participant);

      if (room.resolved) {
        socket.emit(
          "resume_error",
          {
            code:
              "MATCH_RESOLVED",
            message:
              "Bu maç bağlantı kesikken veya siz uzaktayken sonuçlandı.",
            won: room.winnerPlayerId === participant.playerId,
            opponentFinishedMs:
              Number(
                opponent?.elapsedMs ||
                  0
              ),
          }
        );

        return;
      }

      if (
        participant.awaySince &&
        Date.now() >
          participant.awaySince +
            ROOM_RECONNECT_TIMEOUT_MS
      ) {
        resolveRoomByAwayTimeout(
          room.roomId,
          participant.playerId
        );

        socket.emit(
          "resume_error",
          {
            code:
              "RECONNECT_EXPIRED",
            message:
              "1 dakikalık yeniden bağlanma süresi doldu.",
            opponentFinishedMs:
              Number(
                opponent?.elapsedMs ||
                  0
              ),
          }
        );

        return;
      }

      if (
        participant.socketId &&
        participant.socketId !==
          socket.id
      ) {
        activeRooms.delete(
          participant.socketId
        );
      }

      attachSocketToRoom(
        socket,
        room,
        participant.playerId
      );

      clearParticipantAwayState(
        room,
        participant.playerId
      );

      socket.emit(
        "resume_state",
        {
          roomId: room.roomId,

          opponent: {
            name:
              opponent?.name ||
              "Rakip",
            country:
              opponent?.country ||
              "",
            matchKey: opponent?.playerId
              ? matchmakingPlayerKey(opponent.playerId)
              : "",
          },

          puzzle: room.puzzle,
          stakePoints: room.stakePoints || 0,
          matchMode: room.matchMode || "quick",
          startsAtMillis: room.startsAtMillis || room.createdAt,
          roundCount: room.roundCount || 1,
          roundIndex: room.roundIndex || 0,
          isBot: opponent?.isBot === true,
          myRoundWins: Number(participant.roundWins || 0),
          opponentRoundWins: Number(opponent?.roundWins || 0),

          opponentFinishedMs: Number(opponent?.roundElapsedMs || 0),
          digitAttackProgressSlots: digitAttackProgressSlots(room, participant),
          digitAttackWaveStartedAtMillis: Number(
            participant.digitAttackWaveStartedAt || room.startsAtMillis || room.createdAt || 0
          ),
        }
      );

      realtimeLog(
        "Match resumed:",
        room.roomId,
        participant.playerId,
        socket.id
      );
    }
  );

  socket.on(
    "player_backgrounded",
    (payload = {}) => {
      const fallbackActive =
        activeRooms.get(socket.id);

      const roomId = String(
        payload.roomId ||
          fallbackActive?.roomId ||
          ""
      ).trim();

      const room =
        realtimeRooms.get(roomId);

      const playerId =
        fallbackActive?.playerId ||
        roomParticipants(room).find(
          (item) =>
            item.socketId ===
            socket.id
        )?.playerId;

      const participant =
        getParticipant(
          room,
          playerId
        );

      if (
        !room ||
        !participant ||
        room.resolved ||
        participant.finishedAt
      ) {
        return;
      }

      if (!participant.awaySince) {
        participant.awaySince =
          Date.now();
      }

      participant.backgrounded = true;

      scheduleParticipantAwayTimeout(
        room,
        participant.playerId
      );
      scheduleDigitAttackAwayFlow(room, participant.playerId);

      realtimeLog(
        "Player backgrounded:",
        roomId,
        participant.playerId
      );
    }
  );

  socket.on(
    "player_foregrounded",
    (payload = {}) => {
      const fallbackActive =
        activeRooms.get(socket.id);

      const roomId = String(
        payload.roomId ||
          fallbackActive?.roomId ||
          ""
      ).trim();

      const room =
        realtimeRooms.get(roomId);

      const playerId =
        fallbackActive?.playerId ||
        roomParticipants(room).find(
          (item) =>
            item.socketId ===
            socket.id
        )?.playerId;

      const participant =
        getParticipant(
          room,
          playerId
        );

      if (!room || !participant) {
        return;
      }

      if (
        room.resolved &&
        room.loserPlayerId ===
          participant.playerId
      ) {
        socket.emit(
          "resume_error",
          {
            code:
              "RECONNECT_EXPIRED",
            message:
              "1 dakika içinde oyuna dönmediğiniz için mağlup sayıldınız.",
            opponentFinishedMs:
              Number(
                getOpponentParticipant(
                  room,
                  participant.playerId
                )?.elapsedMs || 0
              ),
          }
        );

        return;
      }

      advanceDigitAttackAwayFlowToNow(room, participant);
      if (room.resolved) {
        socket.emit("resume_error", {
          code: "MATCH_RESOLVED",
          message: "Maç bağlantı kesikken sonuçlandı.",
          won: room.winnerPlayerId === participant.playerId,
          opponentFinishedMs: Number(
            getOpponentParticipant(room, participant.playerId)?.elapsedMs || 0
          ),
        });
        return;
      }

      clearParticipantAwayState(
        room,
        participant.playerId
      );
      emitDigitAttackState(room, participant);

      realtimeLog(
        "Player foregrounded:",
        roomId,
        participant.playerId
      );
    }
  );

  socket.on(
    "create_friend_room",
    async (payload = {}) => {
      expireOldPrivateRooms();

      const gameKey = normalizeBaseGameKey(payload.gameKey);

      const difficulty = String(
        payload.difficulty ||
          "Medium"
      );

      const identity = await authenticatedSocketPlayerFromDatabase(socket, payload, "friend_room_error");
      if (!identity) return;
      const player = identity.player;

      const puzzle = generatePuzzleForGame(gameKey, difficulty);

      removeFromAllQueues(
        socket.id,
        player.id
      );

      removePrivateRoomsForSocket(
        socket.id,
        false
      );
      removeOpenTablesForSocket(socket.id);

      leaveRoomAsCancel(socket);

      const roomCode =
        generateUniqueRoomCode();

      privateRooms.set(
        roomCode,
        {
          roomCode,
          ownerSocketId: socket.id,
          gameKey,
          difficulty,
          player,
          puzzle,
          createdAt: Date.now(),
        }
      );

      socket.emit(
        "friend_room_created",
        {
          roomCode,
          gameKey,
          difficulty,
        }
      );

      realtimeLog(
        "Friend room created:",
        roomCode,
        socket.id,
        queueKey(
          gameKey,
          difficulty
        )
      );
    }
  );

  socket.on(
    "join_friend_room",
    async (payload = {}) => {
      expireOldPrivateRooms();

      const roomCode =
        normalizeRoomCode(
          payload.roomCode
        );

      const room =
        privateRooms.get(roomCode);

      if (
        !roomCode ||
        roomCode.length !== 6
      ) {
        socket.emit(
          "friend_room_error",
          {
            message:
              "Geçerli 6 haneli oda kodu gir.",
          }
        );

        return;
      }

      if (!room) {
        socket.emit(
          "friend_room_error",
          {
            message:
              "Oda bulunamadı. Kodu kontrol edip tekrar deneyin.",
          }
        );

        return;
      }

      if (
        room.ownerSocketId ===
        socket.id
      ) {
        socket.emit(
          "friend_room_error",
          {
            message:
              "Kendi oluşturduğun odaya aynı cihazdan katılamazsın.",
          }
        );

        return;
      }

      const ownerSocket =
        io.sockets.sockets.get(
          room.ownerSocketId
        );

      if (!ownerSocket) {
        privateRooms.delete(
          roomCode
        );

        socket.emit(
          "friend_room_error",
          {
            message:
              "Oda sahibi bağlantıdan ayrılmış.",
          }
        );

        return;
      }

      const identity = await authenticatedSocketPlayerFromDatabase(socket, payload, "friend_room_error");
      if (!identity) return;
      const player = identity.player;

      removeFromAllQueues(
        socket.id,
        player.id
      );

      removePrivateRoomsForSocket(
        socket.id,
        false
      );
      removeOpenTablesForSocket(socket.id);

      leaveRoomAsCancel(socket);

      try {
        await consumeGameRightsForPlayers([player.id, room.player.id], room.difficulty);
      } catch (error) {
        const message = error.message || "İki oyunculu oyun hakkı doğrulanamadı.";
        socket.emit("friend_room_error", { code: error.publicCode || "NO_GAME_RIGHT", message });
        ownerSocket.emit("friend_room_error", { code: error.publicCode || "NO_GAME_RIGHT", message });
        return;
      }

      privateRooms.delete(roomCode);

      const realtimeRoom =
        createRealtimeRoom(
          socket,
          player,
          ownerSocket,
          room.player,
          room.gameKey,
          room.difficulty,
          room.puzzle
        );

      realtimeRoom.isFriend = true;

      socket.emit(
        "match_found",
        {
          roomId:
            realtimeRoom.roomId,
          roomCode,

          opponent: {
            name:
              room.player.name,
            country:
              room.player.country,
            matchKey: matchmakingPlayerKey(room.player.id),
          },

          puzzle: room.puzzle,
        }
      );

      ownerSocket.emit(
        "match_found",
        {
          roomId:
            realtimeRoom.roomId,
          roomCode,

          opponent: {
            name: player.name,
            country:
              player.country,
            matchKey: matchmakingPlayerKey(player.id),
          },

          puzzle: room.puzzle,
        }
      );

      realtimeLog(
        "Friend match found:",
        roomCode,
        realtimeRoom.roomId,
        queueKey(
          room.gameKey,
          room.difficulty
        )
      );
    }
  );

  socket.on(
    "digit_attack_lane",
    (payload = {}) => {
      const roomId = String(payload.roomId || "").trim();
      const room = realtimeRooms.get(roomId);
      const active = activeRooms.get(socket.id);
      if (!room || !active || active.roomId !== roomId || room.resolved || !isDigitAttackRealtimeRoom(room)) return;
      const participant = getParticipant(room, active.playerId);
      const state = ensureDigitAttackParticipantFlow(room, participant);
      if (!state || participant.isBot || participant.finishedRoundIndex === room.roundIndex) return;
      if (Number(payload.roundIndex ?? room.roundIndex) !== room.roundIndex) return;
      state.digitAttackLane = Math.max(0, Math.min(2, Math.floor(Number(payload.lane) || 0)));
    }
  );

  socket.on(
    "digit_attack_choice",
    async (payload = {}) => {
      const roomId = String(payload.roomId || "").trim();
      const room = realtimeRooms.get(roomId);
      const active = activeRooms.get(socket.id);
      if (!room || !active || active.roomId !== roomId || room.resolved || !isDigitAttackRealtimeRoom(room)) return;
      const participant = getParticipant(room, active.playerId);
      if (!participant || participant.isBot || participant.finishedRoundIndex === room.roundIndex) return;
      if (!(await socketHasActiveGameplaySession(socket, participant.playerId, "match_error"))) return;
      if (Number(payload.roundIndex ?? room.roundIndex) !== room.roundIndex) return;
      applyRealtimeDigitAttackChoice(
        room,
        participant,
        payload.lane,
        Number(payload.waveIndex),
        "player"
      );
    }
  );

  socket.on(
    "player_finished",
    async (payload = {}) => {
      const roomId = String(payload.roomId || "").trim();
      const room = realtimeRooms.get(roomId);
      const active = activeRooms.get(socket.id);
      const playerId = active?.playerId || roomParticipants(room).find((item) => item.socketId === socket.id)?.playerId;
      const participant = getParticipant(room, playerId);

      if (!room || !participant || room.resolved || participant.isBot) return;
      if (!(await socketHasActiveGameplaySession(socket, participant.playerId, "match_error"))) return;
      if (Number(payload.roundIndex ?? room.roundIndex) !== room.roundIndex) return;
      if (Date.now() < Number(room.startsAtMillis || room.createdAt || 0)) {
        socket.emit("match_error", { code: "MATCH_NOT_STARTED", message: "Hazırlık geri sayımı henüz tamamlanmadı." });
        return;
      }
      if (!validateChallengeAnswer(room.puzzle, payload.numberSlots, payload.operators, payload.answer)) {
        socket.emit("match_error", { code: "INVALID_SOLUTION", message: "Gönderilen cevap sunucuda doğrulanamadı." });
        return;
      }

      const elapsedMs = Math.max(1, Date.now() - Number(room.startsAtMillis || room.createdAt));
      if (challengeAnswerIsWinning(room.puzzle, payload.numberSlots, payload.operators, payload.answer)) {
        registerRealtimeRoundFinish(room, participant, elapsedMs);
      } else {
        registerRealtimeRoundLoss(
          room,
          participant,
          elapsedMs,
          normalizeBaseGameKey(room.gameKey) === "shortest_path" ? "wrong_route" :
            normalizeBaseGameKey(room.gameKey) === "digit_attack" ? "three_mistakes" : "wrong_answer"
        );
      }
    }
  );

  socket.on(
    "cancel_match",
    () => {
      removeFromAllQueues(socket.id);

      removePrivateRoomsForSocket(
        socket.id,
        false
      );
      removeOpenTablesForSocket(socket.id);

      leaveRoomAsCancel(socket);
    }
  );

  socket.on(
    "disconnect",
    (reason) => {
      realtimeLog(
        "Socket disconnected:",
        socket.id,
        reason
      );

      removeFromAllQueues(socket.id);

      removePrivateRoomsForSocket(
        socket.id,
        false
      );
      removeOpenTablesForSocket(socket.id);

      markSocketDisconnected(socket);
    }
  );
});

async function migrateAndDropLegacyTaskEvents() {
  if (!pool) return;

  const exists = await pool.query(
    `SELECT to_regclass('public.player_task_events') AS table_name`
  );
  if (!exists.rows[0]?.table_name) return;

  const players = await pool.query(
    `SELECT DISTINCT player_id FROM player_task_events ORDER BY player_id`
  );

  for (const row of players.rows) {
    const playerId = String(row.player_id || "").trim();
    if (!playerId) continue;
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await ensureAuthenticatedPlayer(client, playerId);
      const current = await client.query(
        `SELECT daily_key, daily_state, weekly_key, weekly_state,
                monthly_key, monthly_state, game_totals, recent_sources
         FROM player_task_state
         WHERE player_id = $1
         FOR UPDATE`,
        [playerId]
      );
      const legacy = await client.query(
        `SELECT source_key, event_type, game_key, multiplayer, won, occurred_at
         FROM player_task_events
         WHERE player_id = $1
         ORDER BY occurred_at ASC`,
        [playerId]
      );

      if (legacy.rowCount > 0 && current.rowCount === 0) {
        const aggregate = aggregateLegacyTaskEvents(legacy.rows, new Date());
        await persistTaskAggregateState(client, playerId, aggregate);
      } else if (legacy.rowCount > 0 && current.rowCount > 0) {
        // Normal eski akış aggregate oluşturduktan sonra ham eventleri siliyordu.
        // İkisi birden kalmışsa çifte sayım/ödül üretmemek için mevcut aggregate'i authoritative kabul et.
        console.warn(`Legacy task events already have aggregate state; dropping stale rows for ${playerId}.`);
      }

      await client.query(`DELETE FROM player_task_events WHERE player_id = $1`, [playerId]);
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  await pool.query(`DROP TABLE IF EXISTS player_task_events`);
  await pool.query(
    `INSERT INTO schema_migrations (migration_id)
     VALUES ('task_events_removed_v1_20260813')
     ON CONFLICT (migration_id) DO NOTHING`
  );
}

async function migrateAndDropLegacyTaskClaims() {
  if (!pool) return;
  const exists = await pool.query(
    `SELECT to_regclass('public.player_task_claims') AS table_name`
  );
  if (!exists.rows[0]?.table_name) return;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Eski ayrı claim satırlarından yalnız hâlen aktif olan günlük/haftalık/aylık dönemi taşı.
    // Geçmiş dönem claim'leri artık hiçbir kararı etkilemediği için tarihsel satırları kopyalamak gerekmez.
    for (const { periodType, keyColumn, stateColumn } of [
      { periodType: 'daily', keyColumn: 'daily_key', stateColumn: 'daily_state' },
      { periodType: 'weekly', keyColumn: 'weekly_key', stateColumn: 'weekly_state' },
      { periodType: 'monthly', keyColumn: 'monthly_key', stateColumn: 'monthly_state' },
    ]) {
      await client.query(
        `UPDATE player_task_state AS pts
         SET ${stateColumn} = jsonb_set(
               COALESCE(pts.${stateColumn}, '{}'::jsonb),
               '{claimed}',
               COALESCE((
                 SELECT jsonb_object_agg(c.task_code, to_jsonb(TRUE))
                 FROM player_task_claims c
                 WHERE c.player_id = pts.player_id
                   AND c.period_type = $1
                   AND c.period_key = pts.${keyColumn}
               ), '{}'::jsonb),
               true
             ),
             updated_at = NOW()
         WHERE EXISTS (
           SELECT 1 FROM player_task_claims c
           WHERE c.player_id = pts.player_id
             AND c.period_type = $1
             AND c.period_key = pts.${keyColumn}
         )`,
        [periodType]
      );
    }

    await client.query(`DROP TABLE IF EXISTS player_task_claims`);
    await client.query(
      `INSERT INTO schema_migrations (migration_id)
       VALUES ('task_claims_embedded_v1_20260813')
       ON CONFLICT (migration_id) DO NOTHING`
    );
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

// Kullanıcı isteği: 90 gün boyunca hiçbir sunucu işlemi/etkinliği olmayan unlinked guest silinir.
const GUEST_RETENTION_DAYS = 90;
const GUEST_ACTIVITY_TOUCH_DAYS = Math.max(
  1,
  Math.min(30, Number(process.env.GUEST_ACTIVITY_TOUCH_DAYS || 7) || 7)
);
const GUEST_ACTIVITY_TOUCH_MS = GUEST_ACTIVITY_TOUCH_DAYS * 24 * 60 * 60_000;

const CHALLENGE_RESULT_RETENTION_MS = Math.max(
  60 * 60_000,
  Math.min(7 * 24 * 60 * 60_000, Number(process.env.CHALLENGE_RESULT_RETENTION_MS || 6 * 60 * 60_000) || 6 * 60 * 60_000)
);
const CHALLENGE_EXPIRED_GRACE_MS = 6 * 60 * 60_000;

async function runDatabaseMaintenanceTask(taskKey, minIntervalMs, work) {
  if (!pool) return { ran: false, value: null };
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      `INSERT INTO maintenance_state (task_key, last_run_at)
       VALUES ($1, TO_TIMESTAMP(0))
       ON CONFLICT (task_key) DO NOTHING`,
      [taskKey]
    );
    const gate = await client.query(
      `SELECT last_run_at FROM maintenance_state WHERE task_key = $1 FOR UPDATE`,
      [taskKey]
    );
    const lastRunMillis = new Date(gate.rows[0]?.last_run_at || 0).getTime();
    if (Number.isFinite(lastRunMillis) && Date.now() - lastRunMillis < minIntervalMs) {
      await client.query('COMMIT');
      return { ran: false, value: null };
    }
    const value = await work(client);
    await client.query(
      `UPDATE maintenance_state SET last_run_at = NOW() WHERE task_key = $1`,
      [taskKey]
    );
    await client.query('COMMIT');
    return { ran: true, value };
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

async function cleanupPersistentEphemeralData() {
  if (!pool) return;
  try {
    await runDatabaseMaintenanceTask('secure_challenge_cleanup', 2 * 60 * 60_000, (client) =>
      client.query(
        `DELETE FROM secure_game_challenges
         WHERE (completed_at IS NOT NULL AND completed_at < NOW() - ($1 * INTERVAL '1 millisecond'))
            OR (completed_at IS NULL AND expires_at < NOW() - ($2 * INTERVAL '1 millisecond'))`,
        [CHALLENGE_RESULT_RETENTION_MS, CHALLENGE_EXPIRED_GRACE_MS]
      )
    );
  } catch (error) {
    console.error("ephemeral PostgreSQL cleanup error:", error);
  }
}

async function cleanupStaleGuestAccounts() {
  if (!pool) return;
  try {
    // Yalnız PGS'ye bağlanmamış guest hesapları silinir. Son etkinlik; credential coarse-touch,
    // profil/skor/progress/görev/challenge ve gameplay session zamanlarının en yenisidir.
    // maintenance_state kapısı nedeniyle restart veya çoklu instance ağır sorguyu tekrar çalıştırmaz.
    const maintenance = await runDatabaseMaintenanceTask('stale_guest_cleanup', 24 * 60 * 60_000, (client) => client.query(
      `WITH stale AS (
         SELECT gc.guest_id
         FROM guest_credentials gc
         JOIN players pl ON pl.player_id = gc.guest_id
         JOIN player_scores ps ON ps.player_id = gc.guest_id
         JOIN player_progress pp ON pp.player_id = gc.guest_id
         LEFT JOIN player_task_state pts ON pts.player_id = gc.guest_id
         WHERE gc.linked_player_id IS NULL
           AND gc.guest_id LIKE 'guest_%'
           -- Partial index bu ilk koşulla 90 günden yeni guest'leri pahalı alt sorgulara sokmaz.
           AND gc.updated_at < NOW() - ($1::integer * INTERVAL '1 day')
           AND GREATEST(
             gc.updated_at,
             pl.updated_at,
             ps.updated_at,
             pp.updated_at,
             COALESCE(pts.updated_at, '1970-01-01'::timestamptz),
             COALESCE((
               SELECT MAX(GREATEST(ch.created_at, COALESCE(ch.completed_at, ch.created_at)))
               FROM secure_game_challenges ch
               WHERE ch.player_id = gc.guest_id
             ), '1970-01-01'::timestamptz),
             COALESCE((
               SELECT MAX(gs.expires_at)
               FROM player_game_sessions gs
               WHERE gs.player_id = gc.guest_id
             ), '1970-01-01'::timestamptz)
           ) < NOW() - ($1::integer * INTERVAL '1 day')
           AND NOT EXISTS (
             SELECT 1 FROM player_game_sessions active_gs
             WHERE active_gs.player_id = gc.guest_id AND active_gs.expires_at > NOW()
           )
           AND NOT EXISTS (
             SELECT 1 FROM secure_game_challenges active_ch
             WHERE active_ch.player_id = gc.guest_id
               AND active_ch.completed_at IS NULL
               AND active_ch.expires_at > NOW()
           )
         FOR UPDATE OF gc SKIP LOCKED
       ), deleted_players AS (
         DELETE FROM players p
         USING stale s
         WHERE p.player_id = s.guest_id
         RETURNING p.player_id
       )
       DELETE FROM guest_credentials gc
       USING stale s
       WHERE gc.guest_id = s.guest_id
       RETURNING gc.guest_id`,
      [GUEST_RETENTION_DAYS]
    ));
    const result = maintenance.value;
    if (maintenance.ran && result?.rowCount > 0) {
      console.log(`Stale guest cleanup: ${result.rowCount} hesap silindi (${GUEST_RETENTION_DAYS}+ gün).`);
    }
  } catch (error) {
    console.error('stale guest cleanup error:', error);
  }
}

setInterval(() => {
  expireOldPrivateRooms();
  expireOldOpenTables();
  expireResolvedRooms();
  cleanupBotFallbackEligibility();
}, 60_000).unref();

setInterval(() => {
  cleanupLeaderboardResponseCache();
}, LEADERBOARD_SERVER_CACHE_CLEANUP_INTERVAL_MS).unref();

setInterval(() => {
  cleanupPersistentEphemeralData();
}, 2 * 60 * 60_000).unref();

setInterval(() => {
  cleanupStaleGuestAccounts();
}, 24 * 60 * 60_000).unref();


const PORT = Number(
  process.env.PORT || 10000
);

assertSecurityEnvironment();

initDatabase()
  .then(async () => {
    await migrateAndDropLegacyTaskEvents();
    await migrateAndDropLegacyTaskClaims();
    server.listen(
      PORT,
      "0.0.0.0",
      () => {
        console.log(`Target number matchmaking server running on port ${PORT}`);
        // Ağır bakım sorguları servis açılışını geciktirmez. DB'deki zaman kapısı aynı işi
        // restart/çoklu instance durumunda yeniden çalıştırmayı engeller.
        cleanupPersistentEphemeralData();
        cleanupStaleGuestAccounts();
      }
    );
  })
  .catch((error) => {
    console.error("Database init failed; service will not start:", {
      message: error.message,
      code: error.code,
      detail: error.detail,
      stack: error.stack,
    });
    process.exitCode = 1;
  });