const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "geolocation=(), camera=(), microphone=()");
  res.setHeader("Cache-Control", "no-store");
  next();
});

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

app.use(express.json({ limit: "64kb" }));
app.use(rateLimit({ prefix: "global", limit: 240, windowMs: 60_000 }));

const server = http.createServer(app);

const SOCKET_PATH = "/socket.io/";
const DATABASE_URL = process.env.DATABASE_URL;

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
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS player_scores (
      player_id TEXT PRIMARY KEY REFERENCES players(player_id) ON DELETE CASCADE,
      general_score INTEGER NOT NULL DEFAULT 0 CHECK (general_score >= 0),
      infinite_score INTEGER NOT NULL DEFAULT 0 CHECK (infinite_score >= 0),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS player_monthly_scores (
      player_id TEXT NOT NULL REFERENCES players(player_id) ON DELETE CASCADE,
      month_key TEXT NOT NULL,
      general_score INTEGER NOT NULL DEFAULT 0 CHECK (general_score >= 0),
      infinite_score INTEGER NOT NULL DEFAULT 0 CHECK (infinite_score >= 0),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (player_id, month_key)
    );

    CREATE TABLE IF NOT EXISTS player_game_rights (
      player_id TEXT PRIMARY KEY REFERENCES players(player_id) ON DELETE CASCADE,
      remaining_rights INTEGER NOT NULL DEFAULT 10 CHECK (remaining_rights >= 0),
      last_refill_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS player_xp (
      player_id TEXT PRIMARY KEY REFERENCES players(player_id) ON DELETE CASCADE,
      total_xp INTEGER NOT NULL DEFAULT 0 CHECK (total_xp >= 0),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    ALTER TABLE players
      ADD COLUMN IF NOT EXISTS username_changed_at TIMESTAMPTZ;

    ALTER TABLE players
      ADD COLUMN IF NOT EXISTS username_change_count INTEGER NOT NULL DEFAULT 0;

    CREATE TABLE IF NOT EXISTS player_runs (
      run_id TEXT PRIMARY KEY,
      player_id TEXT NOT NULL REFERENCES players(player_id) ON DELETE CASCADE,
      mode TEXT NOT NULL,
      expected_stage INTEGER NOT NULL DEFAULT 1 CHECK (expected_stage >= 1),
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    ALTER TABLE player_runs
      ADD COLUMN IF NOT EXISTS accumulated_score INTEGER NOT NULL DEFAULT 0;

    ALTER TABLE player_runs
      ADD COLUMN IF NOT EXISTS remaining_rights INTEGER NOT NULL DEFAULT 3;

    CREATE TABLE IF NOT EXISTS target_challenges (
      challenge_id TEXT PRIMARY KEY,
      run_id TEXT NOT NULL REFERENCES player_runs(run_id) ON DELETE CASCADE,
      player_id TEXT NOT NULL REFERENCES players(player_id) ON DELETE CASCADE,
      mode TEXT NOT NULL,
      difficulty TEXT NOT NULL,
      stage INTEGER NOT NULL CHECK (stage >= 1),
      puzzle JSONB NOT NULL,
      bot_finish_ms BIGINT,
      bot_leave_ms BIGINT,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ NOT NULL,
      consumed_at TIMESTAMPTZ,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS reward_events (
      event_id TEXT PRIMARY KEY,
      player_id TEXT NOT NULL REFERENCES players(player_id) ON DELETE CASCADE,
      general_delta INTEGER NOT NULL DEFAULT 0,
      infinite_delta INTEGER NOT NULL DEFAULT 0,
      xp_delta INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_target_challenges_player
      ON target_challenges (player_id, created_at DESC);

    CREATE INDEX IF NOT EXISTS idx_target_challenges_run_stage
      ON target_challenges (run_id, stage, status);

    CREATE INDEX IF NOT EXISTS idx_player_runs_player_mode
      ON player_runs (player_id, mode, active);

    CREATE INDEX IF NOT EXISTS idx_player_scores_general
      ON player_scores (general_score DESC);

    CREATE INDEX IF NOT EXISTS idx_player_scores_infinite
      ON player_scores (infinite_score DESC);

    CREATE INDEX IF NOT EXISTS idx_monthly_scores_month_general
      ON player_monthly_scores (month_key, general_score DESC);

    CREATE INDEX IF NOT EXISTS idx_monthly_scores_month_infinite
      ON player_monthly_scores (month_key, infinite_score DESC);

    CREATE INDEX IF NOT EXISTS idx_players_country
      ON players (country);

    CREATE INDEX IF NOT EXISTS idx_players_username_lower
      ON players (LOWER(username));
  `);

  console.log("PostgreSQL leaderboard tabloları hazır.");
}

function currentMonthKey() {
  return new Date().toISOString().slice(0, 7);
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
  const username = safeText(value, "", 20);
  return username || "Oyuncu";
}

function validateUsername(value) {
  const username = String(value || "").trim();
  if (username.length < 3 || username.length > 20) {
    return "Kullanıcı adı 3-20 karakter arasında olmalı.";
  }
  if (/\s/u.test(username)) {
    return "Kullanıcı adında boşluk olamaz.";
  }
  if (!/^[\p{L}\p{N}][\p{L}\p{N}._-]*$/u.test(username)) {
    return "Kullanıcı adı harf veya rakamla başlamalı; yalnızca harf, rakam, nokta, alt çizgi ve tire içermelidir.";
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


const SESSION_SECRET = process.env.SESSION_SECRET || "";
const GOOGLE_WEB_CLIENT_ID = process.env.GOOGLE_WEB_CLIENT_ID || "";
const GOOGLE_WEB_CLIENT_SECRET = process.env.GOOGLE_WEB_CLIENT_SECRET || "";
const GOOGLE_OAUTH_REDIRECT_URI = process.env.GOOGLE_OAUTH_REDIRECT_URI || "";
const PLAY_GAMES_APP_ID = process.env.PLAY_GAMES_APP_ID || "";
const SESSION_TTL_SECONDS = Number(process.env.SESSION_TTL_SECONDS || 6 * 60 * 60);
const USERNAME_CHANGE_COOLDOWN_MS = Number(
  process.env.USERNAME_CHANGE_COOLDOWN_MS || 30 * 24 * 60 * 60 * 1000
);
const CHALLENGE_TTL_MS = Number(process.env.CHALLENGE_TTL_MS || 5 * 60 * 1000);

const rateLimitBuckets = new Map();

function requestIp(req) {
  return String(req.ip || req.socket?.remoteAddress || "unknown").slice(0, 96);
}

function consumeRateLimit(key, limit, windowMs) {
  const now = Date.now();
  const current = rateLimitBuckets.get(key);
  if (!current || current.resetAt <= now) {
    rateLimitBuckets.set(key, { count: 1, resetAt: now + windowMs });
    return { allowed: true, remaining: Math.max(0, limit - 1), resetAt: now + windowMs };
  }
  current.count += 1;
  return {
    allowed: current.count <= limit,
    remaining: Math.max(0, limit - current.count),
    resetAt: current.resetAt,
  };
}

function rateLimit(options = {}) {
  const limit = Number(options.limit || 60);
  const windowMs = Number(options.windowMs || 60_000);
  const prefix = options.prefix || "http";
  return (req, res, next) => {
    const player = req.auth?.playerId || "anonymous";
    const key = `${prefix}:${requestIp(req)}:${player}`;
    const result = consumeRateLimit(key, limit, windowMs);
    res.setHeader("X-RateLimit-Limit", String(limit));
    res.setHeader("X-RateLimit-Remaining", String(result.remaining));
    res.setHeader("X-RateLimit-Reset", String(Math.ceil(result.resetAt / 1000)));
    if (!result.allowed) {
      res.setHeader("Retry-After", String(Math.max(1, Math.ceil((result.resetAt - Date.now()) / 1000))));
      res.status(429).json({ ok: false, code: "RATE_LIMITED", message: "Çok fazla istek gönderildi. Lütfen kısa süre sonra tekrar deneyin." });
      return;
    }
    next();
  };
}

setInterval(() => {
  const now = Date.now();
  for (const [key, value] of rateLimitBuckets.entries()) {
    if (value.resetAt <= now) rateLimitBuckets.delete(key);
  }
}, 60_000).unref();

function base64UrlJson(value) {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function issueSessionToken(playerId) {
  if (!SESSION_SECRET) throw new Error("SESSION_SECRET tanımlı değil.");
  const now = Math.floor(Date.now() / 1000);
  const payload = base64UrlJson({ sub: playerId, iat: now, exp: now + SESSION_TTL_SECONDS, nonce: crypto.randomBytes(12).toString("hex") });
  const signature = crypto.createHmac("sha256", SESSION_SECRET).update(payload).digest("base64url");
  return `${payload}.${signature}`;
}

function verifySessionToken(token) {
  if (!SESSION_SECRET || !token) return null;
  const [payloadPart, signaturePart] = String(token).split(".");
  if (!payloadPart || !signaturePart) return null;
  const expected = crypto.createHmac("sha256", SESSION_SECRET).update(payloadPart).digest();
  const supplied = Buffer.from(signaturePart, "base64url");
  if (expected.length !== supplied.length || !crypto.timingSafeEqual(expected, supplied)) return null;
  let payload;
  try { payload = JSON.parse(Buffer.from(payloadPart, "base64url").toString("utf8")); } catch { return null; }
  if (!payload?.sub || Number(payload.exp || 0) <= Math.floor(Date.now() / 1000)) return null;
  return { playerId: safeLeaderboardPlayerId(payload.sub), expiresAt: Number(payload.exp) };
}

function requireAuth(req, res, next) {
  const header = String(req.headers.authorization || "");
  const token = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
  const auth = verifySessionToken(token);
  if (!auth?.playerId) {
    res.status(401).json({ ok: false, code: "UNAUTHORIZED", message: "Güvenli oyuncu oturumu gerekli." });
    return;
  }
  req.auth = auth;
  next();
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, options);
  const text = await response.text();
  let json = {};
  try { json = text ? JSON.parse(text) : {}; } catch { json = {}; }
  if (!response.ok) {
    const error = new Error(json.error_description || json.error?.message || json.message || `HTTP ${response.status}`);
    error.statusCode = response.status >= 400 && response.status < 500 ? 401 : 502;
    throw error;
  }
  return json;
}

async function exchangePlayGamesAuthCode(authCode) {
  if (!GOOGLE_WEB_CLIENT_ID || !GOOGLE_WEB_CLIENT_SECRET || !PLAY_GAMES_APP_ID || !SESSION_SECRET) {
    const error = new Error("Sunucu Google Play Games kimlik doğrulaması için yapılandırılmamış.");
    error.statusCode = 503;
    throw error;
  }
  const form = new URLSearchParams({
    client_id: GOOGLE_WEB_CLIENT_ID,
    client_secret: GOOGLE_WEB_CLIENT_SECRET,
    code: authCode,
    grant_type: "authorization_code",
  });
  if (GOOGLE_OAUTH_REDIRECT_URI) form.set("redirect_uri", GOOGLE_OAUTH_REDIRECT_URI);
  const tokens = await fetchJson("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form.toString(),
  });
  const accessToken = String(tokens.access_token || "");
  if (!accessToken) throw new Error("Google erişim jetonu alınamadı.");
  const verification = await fetchJson(
    `https://games.googleapis.com/games/v1/applications/${encodeURIComponent(PLAY_GAMES_APP_ID)}/verify`,
    { headers: { Authorization: `Bearer ${accessToken}` } }
  );
  const verifiedPlayerId = safeLeaderboardPlayerId(verification.player_id);
  if (!verifiedPlayerId) throw new Error("Play Games oyuncu kimliği doğrulanamadı.");
  return `pg_${verifiedPlayerId}`;
}

function authenticatedPlayer(req) {
  return req.auth.playerId;
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

function isStablePlayGamesLeaderboardId(playerId) {
  return String(playerId || "").startsWith("pg_");
}

function isLegacyLocalLeaderboardId(playerId) {
  return String(playerId || "").startsWith("local_");
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
 * Eski local_ kimliğine bağlı skorları kalıcı pg_ kimliğine taşır.
 * Aynı hesabın iki farklı kurulumda iki satıra bölünmesini engeller.
 */
async function mergeLegacyPlayerIntoStablePlayer(
  client,
  legacyPlayerId,
  stablePlayerId,
  username,
  country
) {
  if (legacyPlayerId === stablePlayerId) return;

  const temporaryUsername =
    `__migration_${crypto.randomBytes(12).toString("hex")}`;

  // Hedef oyuncu satırı yoksa geçici, benzersiz bir adla oluşturulur.
  await client.query(
    `INSERT INTO players (
       player_id,
       username,
       country,
       created_at,
       updated_at
     )
     VALUES ($1, $2, $3, NOW(), NOW())
     ON CONFLICT (player_id)
     DO UPDATE SET
       country = EXCLUDED.country,
       updated_at = NOW()`,
    [stablePlayerId, temporaryUsername, country]
  );

  // Toplam skorlar aynı hesabın kopyaları kabul edildiği için toplanmaz;
  // en yüksek olan korunur. Böylece çift sayım yapılmaz.
  await client.query(
    `INSERT INTO player_scores
       (
         player_id,
         general_score,
         infinite_score,
         updated_at
       )
     SELECT
       $2,
       general_score,
       infinite_score,
       updated_at
     FROM player_scores
     WHERE player_id = $1
     ON CONFLICT (player_id)
     DO UPDATE SET
       general_score = GREATEST(
         player_scores.general_score,
         EXCLUDED.general_score
       ),
       infinite_score = GREATEST(
         player_scores.infinite_score,
         EXCLUDED.infinite_score
       ),
       updated_at = GREATEST(
         player_scores.updated_at,
         EXCLUDED.updated_at
       )`,
    [legacyPlayerId, stablePlayerId]
  );

  await client.query(
    `INSERT INTO player_monthly_scores
       (
         player_id,
         month_key,
         general_score,
         infinite_score,
         updated_at
       )
     SELECT
       $2,
       month_key,
       general_score,
       infinite_score,
       updated_at
     FROM player_monthly_scores
     WHERE player_id = $1
     ON CONFLICT (player_id, month_key)
     DO UPDATE SET
       general_score = GREATEST(
         player_monthly_scores.general_score,
         EXCLUDED.general_score
       ),
       infinite_score = GREATEST(
         player_monthly_scores.infinite_score,
         EXCLUDED.infinite_score
       ),
       updated_at = GREATEST(
         player_monthly_scores.updated_at,
         EXCLUDED.updated_at
       )`,
    [legacyPlayerId, stablePlayerId]
  );

  // Eski oyuncu silinince ona bağlı eski skor satırları
  // CASCADE ile temizlenir.
  await client.query(
    `DELETE FROM players
     WHERE player_id = $1`,
    [legacyPlayerId]
  );

  await client.query(
    `UPDATE players
     SET
       username = $2,
       country = $3,
       updated_at = NOW()
     WHERE player_id = $1`,
    [stablePlayerId, username, country]
  );

  await ensurePlayerScoreRow(client, stablePlayerId);

  console.log("Leaderboard identity migrated:", {
    legacyPlayerId,
    stablePlayerId,
    username,
  });
}

/**
 * Kullanıcı adı yalnızca kullanıcı adı kaydetme/değiştirme sırasında
 * sahiplenilir.
 *
 * Yeni pg_ kimliğine geçişte aynı ada bağlı eski local_ satırı
 * otomatik birleştirilir.
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

  const foreignOwners = ownersResult.rows.map(
    (row) => String(row.player_id)
  );

  const migratableLegacyOwners = foreignOwners.filter(
    (ownerPlayerId) =>
      isStablePlayGamesLeaderboardId(playerId) &&
      isLegacyLocalLeaderboardId(ownerPlayerId)
  );

  const blockingOwners = foreignOwners.filter(
    (ownerPlayerId) =>
      !migratableLegacyOwners.includes(ownerPlayerId)
  );

  if (blockingOwners.length > 0) {
    throw usernameTakenError();
  }

  for (const legacyPlayerId of migratableLegacyOwners) {
    await mergeLegacyPlayerIntoStablePlayer(
      client,
      legacyPlayerId,
      playerId,
      username,
      country
    );
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
 * Oyuncu kimliği henüz sunucuda yoksa ilk kayıt veya
 * legacy -> pg_ geçişi yapılır.
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


app.post(
  "/auth/play-games",
  rateLimit({ prefix: "auth", limit: 8, windowMs: 10 * 60_000 }),
  async (req, res) => {
    try {
      const authCode = safeText(req.body.authCode, "", 4096);
      if (!authCode) {
        res.status(400).json({ ok: false, message: "authCode zorunlu." });
        return;
      }
      const playerId = await exchangePlayGamesAuthCode(authCode);
      if (pool) {
        await pool.query(
          `INSERT INTO players (player_id, username, country, updated_at)
           VALUES ($1, $2, 'TR', NOW())
           ON CONFLICT (player_id) DO NOTHING`,
          [playerId, `Oyuncu_${crypto.createHash("sha256").update(playerId).digest("hex").slice(0, 8)}`]
        );
      }
      res.json({ ok: true, sessionToken: issueSessionToken(playerId), expiresInSeconds: SESSION_TTL_SECONDS });
    } catch (error) {
      sendLeaderboardError(res, error, "Play Games hesabı doğrulanamadı.", "play games auth error:");
    }
  }
);

// Eski istemci-yetkili puan uçları bilerek kapatılmıştır.
app.post(
  ["/leaderboard/scores/sync", "/leaderboard/scores/add", "/target/solution/verify", "/target/puzzle"],
  (req, res) => res.status(410).json({
    ok: false,
    code: "ENDPOINT_RETIRED",
    message: "Bu endpoint güvenlik nedeniyle kapatıldı. Tek kullanımlık challenge akışını kullanın.",
  })
);

app.use(
  [
    "/leaderboard/username/claim",
    "/leaderboard",
    "/game-rights/status",
    "/game-rights/consume",
    "/player/state",
    "/target/run/prepare",
    "/target/challenge/start",
    "/target/challenge/finish",
    "/target/challenge/forfeit",
  ],
  requireAuth
);

app.post(
  "/leaderboard/username/claim",
  rateLimit({ prefix: "username", limit: 6, windowMs: 60 * 60_000 }),
  async (req, res) => {
    if (!requireDatabase(res)) return;

    const playerId = authenticatedPlayer(req);
    const rawUsername = String(req.body.username || "").trim();
    const usernameError = validateUsername(rawUsername);
    if (usernameError) {
      res.status(400).json({ ok: false, code: "INVALID_USERNAME", message: usernameError });
      return;
    }
    const username = safeUsername(rawUsername);
    const country = safeCountry(req.body.country);

    if (!playerId) {
      res.status(400).json({
        ok: false,
        message: "playerId zorunlu.",
      });

      return;
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const existingName = await client.query(
        `SELECT username, username_changed_at, username_change_count
         FROM players WHERE player_id = $1 FOR UPDATE`,
        [playerId]
      );
      const current = existingName.rows[0];
      const changedAt = current?.username_changed_at ? new Date(current.username_changed_at).getTime() : 0;
      const currentUsername = String(current?.username || "");
      const sameName = current && currentUsername.toLowerCase() === username.toLowerCase();
      const placeholderName = /^Oyuncu_[0-9a-f]{8}$/i.test(currentUsername);
      if (current && !placeholderName && !sameName && Number(current.username_change_count || 0) > 0 && Date.now() - changedAt < USERNAME_CHANGE_COOLDOWN_MS) {
        const error = new Error("Kullanıcı adını tekrar değiştirmek için 1 ay beklemelisin.");
        error.statusCode = 429;
        error.publicCode = "USERNAME_COOLDOWN";
        throw error;
      }

      await claimOrCreatePlayer(
        client,
        playerId,
        username,
        country
      );

      if (!sameName) {
        await client.query(
          `UPDATE players SET
             username_changed_at = CASE WHEN $2 THEN username_changed_at ELSE NOW() END,
             username_change_count = username_change_count + CASE WHEN $2 THEN 0 ELSE 1 END,
             updated_at = NOW()
           WHERE player_id = $1`,
          [playerId, !current || placeholderName]
        );
      }

      await client.query("COMMIT");

      res.json({
        ok: true,
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
  async (req, res) => {
    if (!requireDatabase(res)) return;

    const playerId = authenticatedPlayer(req);
    const username = safeUsername(req.body.username);
    const country = safeCountry(req.body.country);
    const generalScore = safeScore(
      req.body.generalScore
    );
    const infiniteScore = safeScore(
      req.body.infiniteScore
    );

    if (!playerId) {
      res.status(400).json({
        ok: false,
        message: "playerId zorunlu.",
      });

      return;
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      await ensurePlayerForScore(
        client,
        playerId,
        username,
        country
      );

      await client.query(
        `UPDATE player_scores
         SET
           general_score = $2,
           infinite_score = GREATEST(
             infinite_score,
             $3
           ),
           updated_at = NOW()
         WHERE player_id = $1`,
        [
          playerId,
          generalScore,
          infiniteScore,
        ]
      );

      await client.query("COMMIT");

      res.json({
        ok: true,
      });
    } catch (error) {
      await client.query("ROLLBACK");

      sendLeaderboardError(
        res,
        error,
        "Skor senkronize edilemedi.",
        "leaderboard sync error:"
      );
    } finally {
      client.release();
    }
  }
);

app.post(
  "/leaderboard/scores/add",
  async (req, res) => {
    if (!requireDatabase(res)) return;

    const playerId = authenticatedPlayer(req);
    const username = safeUsername(req.body.username);
    const country = safeCountry(req.body.country);

    const generalDelta = safeSignedDelta(
      req.body.generalScoreDelta
    );

    const infiniteDelta = safeDelta(
      req.body.infiniteScoreDelta
    );

    const monthKey = currentMonthKey();

    if (!playerId) {
      res.status(400).json({
        ok: false,
        message: "playerId zorunlu.",
      });

      return;
    }

    if (
      generalDelta === 0 &&
      infiniteDelta <= 0
    ) {
      res.json({
        ok: true,
        skipped: true,
      });

      return;
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      await ensurePlayerForScore(
        client,
        playerId,
        username,
        country
      );

      await client.query(
        `UPDATE player_scores
         SET
           general_score = GREATEST(
             0,
             LEAST(
               general_score + $2,
               2000000000
             )
           ),
           infinite_score = LEAST(
             infinite_score + $3,
             2000000000
           ),
           updated_at = NOW()
         WHERE player_id = $1`,
        [
          playerId,
          generalDelta,
          infiniteDelta,
        ]
      );

      await client.query(
        `INSERT INTO player_monthly_scores
           (
             player_id,
             month_key,
             general_score,
             infinite_score,
             updated_at
           )
         VALUES
           (
             $1,
             $2,
             GREATEST($3, 0),
             $4,
             NOW()
           )
         ON CONFLICT (player_id, month_key)
         DO UPDATE SET
           general_score = GREATEST(
             0,
             LEAST(
               player_monthly_scores.general_score + $3,
               2000000000
             )
           ),
           infinite_score = LEAST(
             player_monthly_scores.infinite_score +
               EXCLUDED.infinite_score,
             2000000000
           ),
           updated_at = NOW()`,
        [
          playerId,
          monthKey,
          generalDelta,
          infiniteDelta,
        ]
      );

      await client.query("COMMIT");

      res.json({
        ok: true,
      });
    } catch (error) {
      await client.query("ROLLBACK");

      sendLeaderboardError(
        res,
        error,
        "Skor kaydedilemedi.",
        "leaderboard add error:"
      );
    } finally {
      client.release();
    }
  }
);

app.get("/leaderboard", async (req, res) => {
  if (!requireDatabase(res)) return;

  const scoreType =
    req.query.scoreType === "infinite"
      ? "infinite"
      : "general";

  const period =
    req.query.period === "month"
      ? "month"
      : "all";

  const scope =
    req.query.scope === "country"
      ? "country"
      : "world";

  const country = safeCountry(req.query.country);

  const playerId = authenticatedPlayer(req);

  const monthKey = currentMonthKey();

  const scoreColumn =
    scoreType === "infinite"
      ? "infinite_score"
      : "general_score";

  const tableName =
    period === "month"
      ? "player_monthly_scores"
      : "player_scores";

  function buildWhere(includeCountry) {
    const values = [];

    const conditions = [
      `s.${scoreColumn} > 0`,
    ];

    if (period === "month") {
      values.push(monthKey);

      conditions.push(
        `s.month_key = $${values.length}`
      );
    }

    if (includeCountry) {
      values.push(country);

      conditions.push(
        `p.country = $${values.length}`
      );
    }

    return {
      values,
      whereSql: conditions.join(" AND "),
    };
  }

  async function getMyRank(includeCountry) {
    if (!playerId) return null;

    const built = buildWhere(includeCountry);

    const values = [
      ...built.values,
      playerId,
    ];

    const playerParamIndex = values.length;

    const sql = `
      WITH ranked AS (
        SELECT
          p.player_id,
          p.username,
          p.country,
          s.${scoreColumn} AS score,
          ROW_NUMBER() OVER (
            ORDER BY
              s.${scoreColumn} DESC,
              s.updated_at ASC,
              p.username ASC
          ) AS position
        FROM ${tableName} s
        JOIN players p
          ON p.player_id = s.player_id
        WHERE ${built.whereSql}
      )
      SELECT
        position,
        score
      FROM ranked
      WHERE player_id = $${playerParamIndex}
      LIMIT 1
    `;

    const result = await pool.query(
      sql,
      values
    );

    const row = result.rows[0];

    if (!row) return null;

    return {
      rank: Number(row.position),
      score: Number(row.score),
    };
  }

  try {
    const listBuilt = buildWhere(
      scope === "country"
    );

    const listSql = `
      WITH ranked AS (
        SELECT
          p.player_id,
          p.username,
          p.country,
          s.${scoreColumn} AS score,
          ROW_NUMBER() OVER (
            ORDER BY
              s.${scoreColumn} DESC,
              s.updated_at ASC,
              p.username ASC
          ) AS position
        FROM ${tableName} s
        JOIN players p
          ON p.player_id = s.player_id
        WHERE ${listBuilt.whereSql}
      )
      SELECT
        position,
        username,
        country,
        score
      FROM ranked
      ORDER BY position ASC
      LIMIT 50
    `;

    const listResult = await pool.query(
      listSql,
      listBuilt.values
    );

    const myWorld = await getMyRank(false);
    const myCountry = await getMyRank(true);

    res.json({
      ok: true,
      scoreType,
      period,
      scope,
      country,
      monthKey,
      myWorldRank: myWorld
        ? myWorld.rank
        : null,
      myCountryRank: myCountry
        ? myCountry.rank
        : null,
      myScore: myWorld
        ? myWorld.score
        : 0,
      rows: listResult.rows.map((row) => ({
        rank: Number(row.position),
        username: row.username,
        country: row.country,
        score: Number(row.score),
      })),
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
    console.log(
      "Socket.IO handshake request:",
      req.url,
      "origin:",
      req.headers.origin || "-"
    );

    callback(null, true);
  },
});

const waitingQueues = new Map();
const activeRooms = new Map();
const realtimeRooms = new Map();
const privateRooms = new Map();

const PRIVATE_ROOM_TTL_MS = Number(
  process.env.PRIVATE_ROOM_TTL_MS ||
    15 * 60 * 1000
);

const ROOM_RECONNECT_TIMEOUT_MS = Number(
  process.env.ROOM_RECONNECT_TIMEOUT_MS ||
    60 * 1000
);

const RESOLVED_ROOM_TTL_MS = Number(
  process.env.RESOLVED_ROOM_TTL_MS ||
    10 * 60 * 1000
);

function normalizeMatchGameKey(value) {
  const gameKey = String(value || "target_number")
    .trim()
    .replace(/[^a-zA-Z0-9_:-]/g, "")
    .slice(0, 96);
  return gameKey || "target_number";
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

function normalizeDifficulty(value) {
  return String(value || "Medium") === "Hard"
    ? "Hard"
    : "Medium";
}

function safePuzzle(
  rawPuzzle,
  difficulty
) {
  const normalizedDifficulty = normalizeDifficulty(
    rawPuzzle?.difficulty || difficulty
  );

  const expectedCount =
    normalizedDifficulty === "Hard" ? 4 : 3;

  const numbers = Array.isArray(
    rawPuzzle?.numbers
  )
    ? rawPuzzle.numbers
        .map((n) => Number(n))
        .filter((n) => Number.isFinite(n))
        .map((n) => Math.floor(n))
        .slice(0, expectedCount)
    : [];

  const target = Number(rawPuzzle?.target);

  if (
    !Number.isFinite(target) ||
    target <= 0 ||
    numbers.length !== expectedCount
  ) {
    return null;
  }

  return {
    difficulty: normalizedDifficulty,
    target: Math.floor(target),
    numbers,
  };
}

function evaluateWithOperatorPrecedence(
  orderedNumbers,
  operators
) {
  if (
    !Array.isArray(orderedNumbers) ||
    !Array.isArray(operators) ||
    orderedNumbers.length === 0 ||
    operators.length !== orderedNumbers.length - 1
  ) {
    return null;
  }

  let values = orderedNumbers.map((value) => Number(value));
  let ops = operators.map((op) =>
    String(op || "")
      .replace("-", "−")
      .replace("*", "×")
      .replace("/", "÷")
  );

  if (values.some((value) => !Number.isFinite(value))) {
    return null;
  }

  for (let index = 0; index < ops.length; ) {
    const op = ops[index];

    if (op !== "×" && op !== "÷") {
      index += 1;
      continue;
    }

    const left = values[index];
    const right = values[index + 1];
    const result = op === "×" ? left * right : right === 0 ? null : left / right;

    if (result === null || !Number.isFinite(result)) {
      return null;
    }

    values.splice(index, 2, result);
    ops.splice(index, 1);
  }

  let result = values[0];
  for (let index = 0; index < ops.length; index += 1) {
    const op = ops[index];
    const next = values[index + 1];

    if (op === "+") {
      result += next;
    } else if (op === "−") {
      result -= next;
    } else {
      return null;
    }
  }

  return Number.isFinite(result) ? result : null;
}

function buildSolvableTarget(
  numbers,
  targetMin,
  targetMax,
  requireMultiplyOrDivide
) {
  const operators = ["+", "−", "×", "÷"];

  for (let attempt = 0; attempt < 240; attempt += 1) {
    const orderedNumbers = [...numbers].sort(
      () => crypto.randomInt(0, 3) - 1
    );

    const selectedOperators = Array.from(
      { length: numbers.length - 1 },
      () => operators[crypto.randomInt(0, operators.length)]
    );

    const usesMultiplyOrDivide = selectedOperators.some(
      (op) => op === "×" || op === "÷"
    );

    if (requireMultiplyOrDivide && !usesMultiplyOrDivide) {
      continue;
    }

    const result = evaluateWithOperatorPrecedence(
      orderedNumbers,
      selectedOperators
    );

    if (result === null) continue;

    const rounded = Math.round(result);
    if (
      Math.abs(result - rounded) < 0.0001 &&
      rounded >= targetMin &&
      rounded <= targetMax
    ) {
      return rounded;
    }
  }

  return null;
}

function generateNumberPool(
  count,
  minInclusive,
  maxInclusive
) {
  const numbers = [];
  let oneUsed = false;

  while (numbers.length < count) {
    const number = crypto.randomInt(
      minInclusive,
      maxInclusive + 1
    );

    if (number === 1 && oneUsed) continue;
    if (number === 1) oneUsed = true;
    numbers.push(number);
  }

  return numbers.sort(() => crypto.randomInt(0, 3) - 1);
}

function generateTargetNumberPuzzle(difficulty) {
  const normalizedDifficulty = normalizeDifficulty(difficulty);
  const count = normalizedDifficulty === "Hard" ? 4 : 3;
  const minInclusive = normalizedDifficulty === "Hard" ? 2 : 1;
  const maxInclusive = normalizedDifficulty === "Hard" ? 20 : 9;
  const targetMin = normalizedDifficulty === "Hard" ? 21 : 1;
  const targetMax = normalizedDifficulty === "Hard" ? 199 : 49;
  const requireMultiplyOrDivide = normalizedDifficulty === "Hard";

  for (let attempt = 0; attempt < 5000; attempt += 1) {
    const numbers = generateNumberPool(
      count,
      minInclusive,
      maxInclusive
    );

    const target = buildSolvableTarget(
      numbers,
      targetMin,
      targetMax,
      requireMultiplyOrDivide
    );

    if (target !== null) {
      return {
        difficulty: normalizedDifficulty,
        target,
        numbers,
      };
    }
  }

  const fallbackNumbers =
    normalizedDifficulty === "Hard"
      ? [10, 10, 5, 4]
      : [3, 5, 7];

  return {
    difficulty: normalizedDifficulty,
    target: normalizedDifficulty === "Hard" ? 24 : 15,
    numbers: fallbackNumbers.sort(() => crypto.randomInt(0, 3) - 1),
  };
}

function validateTargetNumberSolution(
  puzzle,
  numberSlots,
  operatorSlots
) {
  const cleanPuzzle = safePuzzle(puzzle, puzzle?.difficulty);
  if (!cleanPuzzle) return false;

  if (
    !Array.isArray(numberSlots) ||
    !Array.isArray(operatorSlots) ||
    numberSlots.length !== cleanPuzzle.numbers.length ||
    operatorSlots.length !== cleanPuzzle.numbers.length - 1
  ) {
    return false;
  }

  const used = new Set();
  const orderedNumbers = [];

  for (const rawIndex of numberSlots) {
    const index = Number(rawIndex);

    if (
      !Number.isInteger(index) ||
      index < 0 ||
      index >= cleanPuzzle.numbers.length ||
      used.has(index)
    ) {
      return false;
    }

    used.add(index);
    orderedNumbers.push(cleanPuzzle.numbers[index]);
  }

  const normalizedOperators = operatorSlots.map((op) =>
    String(op || "")
      .replace("-", "−")
      .replace("*", "×")
      .replace("/", "÷")
  );

  if (
    normalizedOperators.some(
      (op) => !["+", "−", "×", "÷"].includes(op)
    )
  ) {
    return false;
  }

  const result = evaluateWithOperatorPrecedence(
    orderedNumbers,
    normalizedOperators
  );

  return (
    result !== null &&
    Math.abs(result - cleanPuzzle.target) < 0.0001
  );
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
}

function clearRoomTimeouts(room) {
  roomParticipants(room).forEach(
    clearParticipantTimeout
  );
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
  void settleRealtimeRoom(room);

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

  console.log(
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


function realtimeModeForGameKey(gameKey) {
  const key = String(gameKey || "");
  if (key.startsWith("target_number_tournament")) return "tournament";
  if (key.startsWith("target_number_friend")) return "friend";
  return "two_player";
}

function realtimeStageForGameKey(gameKey) {
  const match = String(gameKey || "").match(/stage_(\d+)/i);
  return match ? Math.max(1, Math.min(12, Number(match[1]))) : 1;
}

function realtimeReward(mode, difficulty, stage, won) {
  if (mode === "friend") return { generalDelta: 0, infiniteDelta: 0, xp: 0 };
  if (mode === "tournament") return won ? challengeReward("tournament", difficulty, stage, "solved") : { generalDelta: 0, infiniteDelta: 0, xp: 0 };
  if (won) return { generalDelta: difficulty === "Hard" ? 15 : 10, infiniteDelta: 0, xp: difficulty === "Hard" ? 30 : 20 };
  return { generalDelta: -(difficulty === "Hard" ? 15 : 10), infiniteDelta: 0, xp: 0 };
}

async function settleRealtimeTournamentParticipant(client, playerId, stage, won) {
  const runResult = await client.query(
    `SELECT run_id, expected_stage, accumulated_score, remaining_rights
     FROM player_runs
     WHERE player_id = $1 AND mode = 'tournament' AND active = TRUE
     ORDER BY updated_at DESC
     LIMIT 1
     FOR UPDATE`,
    [playerId]
  );
  if (runResult.rowCount === 0 || Number(runResult.rows[0].expected_stage) !== stage) {
    return { reward: { generalDelta: 0, infiniteDelta: 0, xp: 0 }, accepted: false };
  }
  const run = runResult.rows[0];
  const stageReward = stage >= 12 ? 480 : stage * 20;
  const accumulated = Math.max(0, Number(run.accumulated_score || 0));
  const rights = Math.max(0, Number(run.remaining_rights || 0));
  if (won) {
    const updatedAccumulated = accumulated + stageReward;
    const completed = stage >= 12;
    await client.query(
      `UPDATE player_runs SET expected_stage = expected_stage + 1, accumulated_score = $2,
         active = CASE WHEN $3 THEN FALSE ELSE active END, updated_at = NOW() WHERE run_id = $1`,
      [run.run_id, updatedAccumulated, completed]
    );
    return {
      accepted: true,
      reward: { generalDelta: completed ? updatedAccumulated : 0, infiniteDelta: 0, xp: stageReward },
    };
  }
  const remainingRights = Math.max(0, rights - 1);
  const ended = remainingRights <= 0;
  await client.query(
    `UPDATE player_runs SET remaining_rights = $2,
       active = CASE WHEN $3 THEN FALSE ELSE active END, updated_at = NOW() WHERE run_id = $1`,
    [run.run_id, remainingRights, ended]
  );
  return {
    accepted: true,
    reward: { generalDelta: ended ? accumulated : 0, infiniteDelta: 0, xp: 0 },
  };
}

async function settleRealtimeRoom(room) {
  if (!pool || !room || room.rewardsSettled || !room.resolved) return;
  room.rewardsSettled = true;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const mode = realtimeModeForGameKey(room.gameKey);
    const stage = realtimeStageForGameKey(room.gameKey);
    const notifications = [];
    for (const participant of roomParticipants(room)) {
      const won = participant.playerId === room.winnerPlayerId;
      await ensurePlayerForScore(client, participant.playerId, participant.name, participant.country || "TR");
      const settlement = mode === "tournament"
        ? await settleRealtimeTournamentParticipant(client, participant.playerId, stage, won)
        : { accepted: true, reward: realtimeReward(mode, room.difficulty, stage, won) };
      const reward = settlement.reward;
      const state = await applyRewardTransaction(client, participant.playerId, reward, `room:${room.roomId}:${participant.playerId}`);
      notifications.push({ participant, won, reward, state, accepted: settlement.accepted });
    }
    await client.query("COMMIT");
    for (const item of notifications) {
      const targetSocket = item.participant.socketId
        ? io.sockets.sockets.get(item.participant.socketId)
        : null;
      if (targetSocket) {
        targetSocket.emit("reward_granted", {
          ok: item.accepted,
          won: item.won,
          reward: item.reward,
          state: item.state,
        });
      }
    }
  } catch (error) {
    await client.query("ROLLBACK");
    room.rewardsSettled = false;
    console.error("realtime reward settlement error:", error);
  } finally { client.release(); }
}

function createRealtimeRoom(
  socket,
  player,
  opponentSocket,
  opponentPlayer,
  gameKey,
  difficulty,
  puzzle
) {
  const roomId =
    typeof crypto.randomUUID ===
    "function"
      ? crypto.randomUUID()
      : crypto
          .randomBytes(16)
          .toString("hex");

  const room = {
    roomId,
    gameKey,
    difficulty,
    puzzle,
    createdAt: Date.now(),
    // Güvenlik için gerçek süreyi istemciden değil sunucu saatinden hesaplıyoruz.
    startedAt: Date.now(),
    resolved: false,
    resolvedReason: null,
    resolvedAt: null,
    winnerPlayerId: null,
    loserPlayerId: null,
    rewardsSettled: false,

    participants: {
      [player.id]: {
        playerId: player.id,
        socketId: socket.id,
        name: player.name,
        country: player.country,
        connected: true,
        awaySince: null,
        backgrounded: false,
        reconnectDeadlineAt: null,
        timeoutHandle: null,
        finishedAt: null,
        elapsedMs: null,
      },

      [opponentPlayer.id]: {
        playerId: opponentPlayer.id,
        socketId: opponentSocket.id,
        name: opponentPlayer.name,
        country: opponentPlayer.country,
        connected: true,
        awaySince: null,
        backgrounded: false,
        reconnectDeadlineAt: null,
        timeoutHandle: null,
        finishedAt: null,
        elapsedMs: null,
      },
    },
  };

  realtimeRooms.set(roomId, room);

  attachSocketToRoom(
    socket,
    room,
    player.id
  );

  attachSocketToRoom(
    opponentSocket,
    room,
    opponentPlayer.id
  );

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
      markRoomResolved(
        room,
        "cancelled",
        opponent.playerId,
        participant.playerId
      );
      void settleRealtimeRoom(room);

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

    status: "ok",
  });
});

app.get("/health", async (req, res) => {
  if (!pool) {
    res.json({
      ok: true,
      database: false,
    });

    return;
  }

  try {
    await pool.query("SELECT 1");

    res.json({
      ok: true,
      database: true,
    });
  } catch (error) {
    console.error(
      "health database error:",
      {
        message: error.message,
        code: error.code,
        detail: error.detail,
      }
    );

    res.status(500).json({
      ok: false,
      database: false,
      message:
        "Database bağlantısı başarısız.",
    });
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
    console.log(
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
    console.log(
      "Engine.IO connected:",
      rawSocket.id,
      "transport:",
      rawSocket.transport.name
    );
  }
);



async function readPlayerState(client, playerId) {
  await ensurePlayerProgressRows(client, playerId);
  const rights = await readAndRefillRights(client, playerId);
  const result = await client.query(
    `SELECT ps.general_score, ps.infinite_score, px.total_xp
     FROM player_scores ps
     JOIN player_xp px ON px.player_id = ps.player_id
     WHERE ps.player_id = $1`,
    [playerId]
  );
  const row = result.rows[0] || {};
  return {
    totalScore: Number(row.general_score || 0),
    infiniteScore: Number(row.infinite_score || 0),
    totalXp: Number(row.total_xp || 0),
    ...rights,
  };
}

async function applyRewardTransaction(client, playerId, reward, eventId) {
  await ensurePlayerProgressRows(client, playerId);
  const inserted = await client.query(
    `INSERT INTO reward_events (event_id, player_id, general_delta, infinite_delta, xp_delta)
     VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (event_id) DO NOTHING
     RETURNING event_id`,
    [eventId, playerId, reward.generalDelta, reward.infiniteDelta, reward.xp]
  );
  if (inserted.rowCount > 0) {
    await client.query(
      `UPDATE player_scores SET
         general_score = GREATEST(0, LEAST(2000000000, general_score + $2)),
         infinite_score = GREATEST(0, LEAST(2000000000, infinite_score + $3)),
         updated_at = NOW()
       WHERE player_id = $1`,
      [playerId, reward.generalDelta, reward.infiniteDelta]
    );
    await client.query(
      `INSERT INTO player_monthly_scores (player_id, month_key, general_score, infinite_score, updated_at)
       VALUES ($1, $2, GREATEST(0, $3), GREATEST(0, $4), NOW())
       ON CONFLICT (player_id, month_key) DO UPDATE SET
         general_score = GREATEST(0, LEAST(2000000000, player_monthly_scores.general_score + $3)),
         infinite_score = GREATEST(0, LEAST(2000000000, player_monthly_scores.infinite_score + $4)),
         updated_at = NOW()`,
      [playerId, currentMonthKey(), reward.generalDelta, reward.infiniteDelta]
    );
    await client.query(
      `UPDATE player_xp SET total_xp = LEAST(2000000000, total_xp + $2), updated_at = NOW()
       WHERE player_id = $1`,
      [playerId, Math.max(0, reward.xp)]
    );
  }
  return readPlayerState(client, playerId);
}

function normalizedChallengeMode(value) {
  const mode = String(value || "single").toLowerCase();
  return ["single", "infinite", "tournament", "hundred", "two_player_bot"].includes(mode)
    ? mode
    : "single";
}

function expectedDifficultyForMode(mode, stage, requested) {
  if (mode === "infinite") return stage <= 5 ? "Medium" : "Hard";
  if (mode === "tournament") return stage <= 4 ? "Medium" : "Hard";
  if (mode === "hundred") return stage <= 4 ? "Medium" : "Hard";
  return normalizeDifficulty(requested);
}

function challengeReward(mode, difficulty, stage, outcome = "solved") {
  if (outcome !== "solved") {
    if (mode === "hundred") return { generalDelta: stage * 10, infiniteDelta: 0, xp: stage * 20 };
    if (mode === "two_player_bot") return { generalDelta: -(difficulty === "Hard" ? 15 : 10), infiniteDelta: 0, xp: 0 };
    return { generalDelta: 0, infiniteDelta: 0, xp: 0 };
  }
  if (mode === "infinite") {
    const points = Math.min(2000000000, stage * 5);
    const xp = Math.min(2000000000, Math.floor(stage * (stage + 1) / 2) * 5);
    return { generalDelta: points, infiniteDelta: points, xp };
  }
  if (mode === "tournament") {
    const points = stage >= 12 ? 480 : stage * 20;
    return { generalDelta: points, infiniteDelta: 0, xp: points };
  }
  if (mode === "hundred") {
    return stage >= 12
      ? { generalDelta: 240, infiniteDelta: 0, xp: 480 }
      : { generalDelta: 0, infiniteDelta: 0, xp: 0 };
  }
  if (mode === "two_player_bot") {
    return { generalDelta: difficulty === "Hard" ? 15 : 10, infiniteDelta: 0, xp: difficulty === "Hard" ? 30 : 20 };
  }
  return { generalDelta: difficulty === "Hard" ? 15 : 10, infiniteDelta: 0, xp: difficulty === "Hard" ? 15 : 10 };
}

function createBotPlan(difficulty) {
  const leaveRoll = crypto.randomInt(0, 10000);
  if (leaveRoll < 560) return { finishMs: null, leaveMs: crypto.randomInt(0, 120) * 1000 };
  const noFinishThreshold = difficulty === "Hard" ? 3090 : 1630;
  if (leaveRoll < noFinishThreshold) return { finishMs: null, leaveMs: null };
  const min = difficulty === "Hard" ? 8000 : 6000;
  return { finishMs: crypto.randomInt(min, 117000), leaveMs: null };
}

app.post(
  "/player/state",
  rateLimit({ prefix: "state", limit: 60, windowMs: 60_000 }),
  async (req, res) => {
    if (!requireDatabase(res)) return;
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const playerId = authenticatedPlayer(req);
      await ensurePlayerForScore(client, playerId, "Oyuncu", "TR");
      const state = await readPlayerState(client, playerId);
      await client.query("COMMIT");
      res.json({ ok: true, ...state });
    } catch (error) {
      await client.query("ROLLBACK");
      sendLeaderboardError(res, error, "Oyuncu durumu alınamadı.", "player state error:");
    } finally { client.release(); }
  }
);

app.post(
  "/target/run/prepare",
  rateLimit({ prefix: "run-prepare", limit: 30, windowMs: 60_000 }),
  async (req, res) => {
    if (!requireDatabase(res)) return;
    const playerId = authenticatedPlayer(req);
    const mode = normalizedChallengeMode(req.body.mode);
    const stage = Math.max(1, Math.min(12_000, Math.floor(Number(req.body.stage || 1))));
    const requestedRunId = safeText(req.body.runId, "", 96);
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await ensurePlayerForScore(client, playerId, "Oyuncu", "TR");
      let row = null;
      if (requestedRunId) {
        const result = await client.query(
          `SELECT run_id, expected_stage, active FROM player_runs
           WHERE run_id = $1 AND player_id = $2 AND mode = $3 FOR UPDATE`,
          [requestedRunId, playerId, mode]
        );
        row = result.rows[0] || null;
      } else if (stage > 1) {
        const result = await client.query(
          `SELECT run_id, expected_stage, active FROM player_runs
           WHERE player_id = $1 AND mode = $2 AND active = TRUE
           ORDER BY updated_at DESC LIMIT 1 FOR UPDATE`,
          [playerId, mode]
        );
        row = result.rows[0] || null;
      }
      if (stage === 1 && !requestedRunId) {
        await client.query(
          `UPDATE player_runs SET active = FALSE, updated_at = NOW()
           WHERE player_id = $1 AND mode = $2 AND active = TRUE`,
          [playerId, mode]
        );
        const runId = crypto.randomUUID();
        await client.query(
          `INSERT INTO player_runs
             (run_id, player_id, mode, expected_stage, accumulated_score, remaining_rights)
           VALUES ($1, $2, $3, 1, 0, $4)`,
          [runId, playerId, mode, mode === "tournament" ? 3 : 1]
        );
        row = { run_id: runId, expected_stage: 1, active: true };
      }
      if (!row || !row.active || Number(row.expected_stage) !== stage) {
        const error = new Error(`Beklenen güvenli aşama bulunamadı: ${stage}.`);
        error.statusCode = 409;
        throw error;
      }
      await client.query("COMMIT");
      res.json({ ok: true, runId: row.run_id, mode, stage });
    } catch (error) {
      await client.query("ROLLBACK");
      sendLeaderboardError(res, error, "Oyun serisi hazırlanamadı.", "run prepare error:");
    } finally { client.release(); }
  }
);

app.post(
  "/target/challenge/start",
  rateLimit({ prefix: "challenge-start", limit: 30, windowMs: 60_000 }),
  async (req, res) => {
    if (!requireDatabase(res)) return;
    const playerId = authenticatedPlayer(req);
    const mode = normalizedChallengeMode(req.body.mode);
    const requestedStage = Math.max(1, Math.min(12_000, Math.floor(Number(req.body.stage || 1))));
    const requestedRunId = safeText(req.body.runId, "", 96);
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await ensurePlayerForScore(client, playerId, "Oyuncu", "TR");
      if (mode === "two_player_bot") {
        await ensurePlayerProgressRows(client, playerId);
        const rights = await readAndRefillRights(client, playerId);
        if (rights.remainingRights <= 0) {
          const error = new Error("Oyun hakkınız kalmadı.");
          error.statusCode = 409;
          error.publicCode = "NO_GAME_RIGHT";
          throw error;
        }
        await client.query(
          `UPDATE player_game_rights SET remaining_rights = remaining_rights - 1,
             last_refill_at = CASE WHEN remaining_rights >= $2 THEN NOW() ELSE last_refill_at END,
             updated_at = NOW() WHERE player_id = $1`,
          [playerId, MAX_GAME_RIGHTS]
        );
      }
      let runId = requestedRunId;
      let expectedStage = 1;
      if (runId) {
        const runResult = await client.query(
          `SELECT run_id, expected_stage, active, accumulated_score, remaining_rights FROM player_runs
           WHERE run_id = $1 AND player_id = $2 AND mode = $3 FOR UPDATE`,
          [runId, playerId, mode]
        );
        if (runResult.rowCount === 0 || !runResult.rows[0].active) {
          const error = new Error("Geçerli oyun serisi bulunamadı."); error.statusCode = 409; throw error;
        }
        expectedStage = Number(runResult.rows[0].expected_stage || 1);
        if (requestedStage !== expectedStage) {
          const error = new Error(`Beklenen aşama ${expectedStage}.`); error.statusCode = 409; throw error;
        }
      } else {
        if (requestedStage !== 1) {
          const error = new Error("Yeni oyun serisi 1. aşamadan başlamalıdır."); error.statusCode = 409; throw error;
        }
        runId = crypto.randomUUID();
        await client.query(
          `INSERT INTO player_runs
             (run_id, player_id, mode, expected_stage, accumulated_score, remaining_rights)
           VALUES ($1, $2, $3, 1, 0, $4)`,
          [runId, playerId, mode, mode === "tournament" ? 3 : 1]
        );
      }
      await client.query(
        `UPDATE target_challenges SET status = 'replaced', updated_at = NOW()
         WHERE run_id = $1 AND player_id = $2 AND stage = $3 AND status = 'active'`,
        [runId, playerId, expectedStage]
      );
      const difficulty = expectedDifficultyForMode(mode, expectedStage, req.body.difficulty);
      const puzzle = generateTargetNumberPuzzle(difficulty);
      const challengeId = crypto.randomUUID();
      const botPlan = mode === "two_player_bot" || mode === "tournament" ? createBotPlan(difficulty) : { finishMs: null, leaveMs: null };
      await client.query(
        `INSERT INTO target_challenges
           (challenge_id, run_id, player_id, mode, difficulty, stage, puzzle, bot_finish_ms, bot_leave_ms, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, NOW() + ($10 * INTERVAL '1 millisecond'))`,
        [challengeId, runId, playerId, mode, difficulty, expectedStage, JSON.stringify(puzzle), botPlan.finishMs, botPlan.leaveMs, CHALLENGE_TTL_MS]
      );
      await client.query("COMMIT");
      res.json({ ok: true, challengeId, runId, mode, stage: expectedStage, puzzle, botFinishMs: botPlan.finishMs, botLeaveMs: botPlan.leaveMs });
    } catch (error) {
      await client.query("ROLLBACK");
      sendLeaderboardError(res, error, "Güvenli bulmaca başlatılamadı.", "challenge start error:");
    } finally { client.release(); }
  }
);

app.post(
  "/target/challenge/finish",
  rateLimit({ prefix: "challenge-finish", limit: 40, windowMs: 60_000 }),
  async (req, res) => {
    if (!requireDatabase(res)) return;
    const playerId = authenticatedPlayer(req);
    const challengeId = safeText(req.body.challengeId, "", 96);
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const result = await client.query(
        `SELECT * FROM target_challenges WHERE challenge_id = $1 AND player_id = $2 FOR UPDATE`,
        [challengeId, playerId]
      );
      const challenge = result.rows[0];
      if (!challenge || challenge.status !== "active") {
        const error = new Error("Challenge geçersiz veya daha önce kullanılmış."); error.statusCode = 409; throw error;
      }
      if (new Date(challenge.expires_at).getTime() < Date.now()) {
        await client.query(`UPDATE target_challenges SET status = 'expired', updated_at = NOW() WHERE challenge_id = $1`, [challengeId]);
        const error = new Error("Challenge süresi dolmuş."); error.statusCode = 410; throw error;
      }
      const valid = validateTargetNumberSolution(challenge.puzzle, req.body.numberSlots, req.body.operatorSlots);
      if (!valid) { const error = new Error("Çözüm sunucu tarafından doğrulanamadı."); error.statusCode = 400; throw error; }
      const run = await client.query(
        `SELECT expected_stage, accumulated_score, remaining_rights, active
         FROM player_runs WHERE run_id = $1 AND player_id = $2 FOR UPDATE`,
        [challenge.run_id, playerId]
      );
      if (run.rowCount === 0 || !run.rows[0].active || Number(run.rows[0].expected_stage) !== Number(challenge.stage)) {
        const error = new Error("Bu aşama artık ödül almaya uygun değil."); error.statusCode = 409; throw error;
      }

      const elapsedMs = Math.max(0, Date.now() - new Date(challenge.created_at).getTime());
      const botFinishedFirst =
        (challenge.mode === "two_player_bot" || challenge.mode === "tournament") &&
        challenge.bot_finish_ms !== null &&
        elapsedMs >= Number(challenge.bot_finish_ms) &&
        (challenge.bot_leave_ms === null || Number(challenge.bot_finish_ms) <= Number(challenge.bot_leave_ms));

      const won = !botFinishedFirst;
      let reward;
      let nextStage = Number(challenge.stage);
      const stageReward = Number(challenge.stage) >= 12 ? 480 : Number(challenge.stage) * 20;
      const currentAccumulated = Math.max(0, Number(run.rows[0].accumulated_score || 0));
      const currentRights = Math.max(0, Number(run.rows[0].remaining_rights || 0));

      if (challenge.mode === "tournament") {
        if (won) {
          const updatedAccumulated = currentAccumulated + stageReward;
          const completed = Number(challenge.stage) >= 12;
          reward = { generalDelta: completed ? updatedAccumulated : 0, infiniteDelta: 0, xp: stageReward };
          nextStage = Number(challenge.stage) + 1;
          await client.query(
            `UPDATE player_runs SET expected_stage = expected_stage + 1, accumulated_score = $2,
               active = CASE WHEN $3 THEN FALSE ELSE active END, updated_at = NOW()
             WHERE run_id = $1`,
            [challenge.run_id, updatedAccumulated, completed]
          );
        } else {
          const remainingRights = Math.max(0, currentRights - 1);
          const ended = remainingRights <= 0;
          reward = { generalDelta: ended ? currentAccumulated : 0, infiniteDelta: 0, xp: 0 };
          await client.query(
            `UPDATE player_runs SET remaining_rights = $2, active = CASE WHEN $3 THEN FALSE ELSE active END, updated_at = NOW()
             WHERE run_id = $1`,
            [challenge.run_id, remainingRights, ended]
          );
        }
      } else {
        reward = challengeReward(challenge.mode, challenge.difficulty, Number(challenge.stage), won ? "solved" : "forfeit");
        if (won) {
          nextStage = Number(challenge.stage) + 1;
          const completed = challenge.mode === "single" || challenge.mode === "two_player_bot" ||
            (challenge.mode === "hundred" && Number(challenge.stage) >= 12);
          await client.query(
            `UPDATE player_runs SET expected_stage = expected_stage + 1,
               active = CASE WHEN $2 THEN FALSE ELSE active END, updated_at = NOW() WHERE run_id = $1`,
            [challenge.run_id, completed]
          );
        } else {
          await client.query(`UPDATE player_runs SET active = FALSE, updated_at = NOW() WHERE run_id = $1`, [challenge.run_id]);
        }
      }

      await client.query(
        `UPDATE target_challenges SET status = $2, consumed_at = NOW(), updated_at = NOW() WHERE challenge_id = $1`,
        [challengeId, won ? "consumed" : "lost"]
      );
      const state = await applyRewardTransaction(
        client, playerId, reward, `challenge:${challengeId}:${won ? "solved" : "bot-finished"}`
      );
      await client.query("COMMIT");
      res.json({ ok: true, won, reward, state, nextStage, runId: challenge.run_id });
    } catch (error) {
      await client.query("ROLLBACK");
      sendLeaderboardError(res, error, "Ödül doğrulanamadı.", "challenge finish error:");
    } finally { client.release(); }
  }
);

app.post(
  "/target/challenge/forfeit",
  rateLimit({ prefix: "challenge-forfeit", limit: 30, windowMs: 60_000 }),
  async (req, res) => {
    if (!requireDatabase(res)) return;
    const playerId = authenticatedPlayer(req);
    const challengeId = safeText(req.body.challengeId, "", 96);
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const result = await client.query(`SELECT * FROM target_challenges WHERE challenge_id = $1 AND player_id = $2 FOR UPDATE`, [challengeId, playerId]);
      const challenge = result.rows[0];
      if (!challenge || challenge.status !== "active") {
        const state = await readPlayerState(client, playerId);
        await client.query("COMMIT");
        res.json({ ok: true, won: false, reward: { generalDelta: 0, infiniteDelta: 0, xp: 0 }, state });
        return;
      }
      const reason = safeText(req.body.reason, "forfeit", 32);
      const elapsedMs = Math.max(0, Date.now() - new Date(challenge.created_at).getTime());
      const verifiedBotLeft =
        reason === "bot_left" &&
        challenge.bot_leave_ms !== null &&
        elapsedMs >= Number(challenge.bot_leave_ms) &&
        (challenge.bot_finish_ms === null || Number(challenge.bot_leave_ms) < Number(challenge.bot_finish_ms));
      const won = Boolean(verifiedBotLeft);
      const runResult = await client.query(
        `SELECT expected_stage, accumulated_score, remaining_rights, active
         FROM player_runs WHERE run_id = $1 AND player_id = $2 FOR UPDATE`,
        [challenge.run_id, playerId]
      );
      if (runResult.rowCount === 0 || !runResult.rows[0].active ||
          Number(runResult.rows[0].expected_stage) !== Number(challenge.stage)) {
        const error = new Error("Bu aşama artık sonuçlandırılamaz."); error.statusCode = 409; throw error;
      }

      let reward;
      if (challenge.mode === "tournament" && reason === "tournament_timeout") {
        reward = { generalDelta: 0, infiniteDelta: 0, xp: 0 };
      } else if (challenge.mode === "tournament") {
        const stageReward = Number(challenge.stage) >= 12 ? 480 : Number(challenge.stage) * 20;
        const accumulated = Math.max(0, Number(runResult.rows[0].accumulated_score || 0));
        const rights = Math.max(0, Number(runResult.rows[0].remaining_rights || 0));
        if (won) {
          const updatedAccumulated = accumulated + stageReward;
          const completed = Number(challenge.stage) >= 12;
          reward = { generalDelta: completed ? updatedAccumulated : 0, infiniteDelta: 0, xp: stageReward };
          await client.query(
            `UPDATE player_runs SET expected_stage = expected_stage + 1, accumulated_score = $2,
               active = CASE WHEN $3 THEN FALSE ELSE active END, updated_at = NOW() WHERE run_id = $1`,
            [challenge.run_id, updatedAccumulated, completed]
          );
        } else {
          const remainingRights = Math.max(0, rights - 1);
          const ended = remainingRights <= 0;
          reward = { generalDelta: ended ? accumulated : 0, infiniteDelta: 0, xp: 0 };
          await client.query(
            `UPDATE player_runs SET remaining_rights = $2, active = CASE WHEN $3 THEN FALSE ELSE active END, updated_at = NOW() WHERE run_id = $1`,
            [challenge.run_id, remainingRights, ended]
          );
        }
      } else if (reason === "draw_timeout") {
        reward = { generalDelta: 0, infiniteDelta: 0, xp: 0 };
        await client.query(`UPDATE player_runs SET active = FALSE, updated_at = NOW() WHERE run_id = $1`, [challenge.run_id]);
      } else {
        reward = won
          ? challengeReward(challenge.mode, challenge.difficulty, Number(challenge.stage), "solved")
          : challengeReward(challenge.mode, challenge.difficulty, Number(challenge.stage), "forfeit");
        if (won) {
          const completed = challenge.mode === "single" || challenge.mode === "two_player_bot" ||
            (challenge.mode === "hundred" && Number(challenge.stage) >= 12);
          await client.query(
            `UPDATE player_runs SET expected_stage = expected_stage + 1,
               active = CASE WHEN $2 THEN FALSE ELSE active END, updated_at = NOW() WHERE run_id = $1`,
            [challenge.run_id, completed]
          );
        } else {
          await client.query(`UPDATE player_runs SET active = FALSE, updated_at = NOW() WHERE run_id = $1`, [challenge.run_id]);
        }
      }

      await client.query(
        `UPDATE target_challenges SET status = $2, consumed_at = NOW(), updated_at = NOW() WHERE challenge_id = $1`,
        [challengeId, won ? "consumed" : "forfeited"]
      );
      const state = await applyRewardTransaction(client, playerId, reward, `challenge:${challengeId}:${won ? "bot-left" : reason}`);
      await client.query("COMMIT");
      res.json({ ok: true, won, reward, state, runId: challenge.run_id });
    } catch (error) {
      await client.query("ROLLBACK");
      sendLeaderboardError(res, error, "Mağlubiyet sonucu kaydedilemedi.", "challenge forfeit error:");
    } finally { client.release(); }
  }
);

const MAX_GAME_RIGHTS = Number(process.env.MAX_GAME_RIGHTS || 10);
const GAME_RIGHT_REFILL_MS = Number(
  process.env.GAME_RIGHT_REFILL_MS || 10 * 60 * 1000
);

function targetNumberRewardForMode(payload) {
  const mode = String(payload.mode || "single");
  const difficulty = normalizeDifficulty(payload.difficulty);
  const stage = Math.max(1, Math.floor(Number(payload.stage || 1)));

  if (mode === "infinite") {
    return {
      generalDelta: Math.min(250, 5 + stage * 2),
      infiniteDelta: Math.min(250, 5 + stage * 2),
      xp: Math.min(500, 5 + stage * 3),
    };
  }

  if (mode === "tournament") {
    return {
      generalDelta: stage >= 12 ? 300 : 0,
      infiniteDelta: 0,
      xp: difficulty === "Hard" ? 30 : 20,
    };
  }

  if (mode === "hundred") {
    return {
      generalDelta: stage >= 12 ? 480 : stage * 10,
      infiniteDelta: 0,
      xp: stage >= 12 ? 480 : stage * 20,
    };
  }

  return {
    generalDelta: difficulty === "Hard" ? 15 : 10,
    infiniteDelta: 0,
    xp: difficulty === "Hard" ? 15 : 10,
  };
}

async function ensurePlayerProgressRows(client, playerId) {
  await ensurePlayerScoreRow(client, playerId);
  await client.query(
    `INSERT INTO player_game_rights (player_id)
     VALUES ($1)
     ON CONFLICT (player_id) DO NOTHING`,
    [playerId]
  );
  await client.query(
    `INSERT INTO player_xp (player_id)
     VALUES ($1)
     ON CONFLICT (player_id) DO NOTHING`,
    [playerId]
  );
}

async function readAndRefillRights(client, playerId) {
  await client.query(
    `INSERT INTO player_game_rights (
       player_id,
       remaining_rights,
       last_refill_at,
       updated_at
     )
     VALUES ($1, $2, NOW(), NOW())
     ON CONFLICT (player_id) DO NOTHING`,
    [playerId, MAX_GAME_RIGHTS]
  );

  const result = await client.query(
    `SELECT
       remaining_rights,
       last_refill_at,
       updated_at
     FROM player_game_rights
     WHERE player_id = $1
     FOR UPDATE`,
    [playerId]
  );

  const row = result.rows[0];
  const lastRefillAt = new Date(row.last_refill_at).getTime();
  const now = Date.now();
  const elapsedMs = Math.max(0, now - lastRefillAt);
  const refillCount = Math.floor(elapsedMs / GAME_RIGHT_REFILL_MS);

  let remainingRights = Math.max(
    0,
    Math.min(Number(row.remaining_rights || 0), MAX_GAME_RIGHTS)
  );
  let nextRefillAtMillis =
    remainingRights >= MAX_GAME_RIGHTS
      ? 0
      : lastRefillAt + GAME_RIGHT_REFILL_MS;

  if (refillCount > 0 && remainingRights < MAX_GAME_RIGHTS) {
    remainingRights = Math.min(
      MAX_GAME_RIGHTS,
      remainingRights + refillCount
    );

    const updatedLastRefillAt =
      remainingRights >= MAX_GAME_RIGHTS
        ? now
        : lastRefillAt + refillCount * GAME_RIGHT_REFILL_MS;

    await client.query(
      `UPDATE player_game_rights
       SET
         remaining_rights = $2,
         last_refill_at = TO_TIMESTAMP($3 / 1000.0),
         updated_at = NOW()
       WHERE player_id = $1`,
      [playerId, remainingRights, updatedLastRefillAt]
    );

    nextRefillAtMillis =
      remainingRights >= MAX_GAME_RIGHTS
        ? 0
        : updatedLastRefillAt + GAME_RIGHT_REFILL_MS;
  }

  return {
    remainingRights,
    maxRights: MAX_GAME_RIGHTS,
    millisUntilNextRight:
      nextRefillAtMillis > 0
        ? Math.max(0, nextRefillAtMillis - now)
        : 0,
  };
}

app.post("/target/puzzle", (req, res) => {
  const difficulty = normalizeDifficulty(req.body.difficulty);
  res.json({
    ok: true,
    puzzle: generateTargetNumberPuzzle(difficulty),
  });
});

app.post("/target/solution/verify", async (req, res) => {
  if (!requireDatabase(res)) return;

  const playerId = authenticatedPlayer(req);
  const username = safeUsername(req.body.username);
  const country = safeCountry(req.body.country);
  const puzzle = safePuzzle(req.body.puzzle, req.body.difficulty);

  if (!playerId || !puzzle) {
    res.status(400).json({
      ok: false,
      message: "playerId ve geçerli puzzle zorunlu.",
    });
    return;
  }

  const valid = validateTargetNumberSolution(
    puzzle,
    req.body.numberSlots,
    req.body.operatorSlots
  );

  if (!valid) {
    res.status(400).json({
      ok: false,
      message: "Çözüm doğrulanamadı.",
    });
    return;
  }

  const reward = targetNumberRewardForMode({
    mode: req.body.mode,
    difficulty: puzzle.difficulty,
    stage: req.body.stage,
  });

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await ensurePlayerForScore(client, playerId, username, country);
    await ensurePlayerProgressRows(client, playerId);

    await client.query(
      `UPDATE player_scores
       SET
         general_score = LEAST(general_score + $2, 2000000000),
         infinite_score = LEAST(infinite_score + $3, 2000000000),
         updated_at = NOW()
       WHERE player_id = $1`,
      [playerId, reward.generalDelta, reward.infiniteDelta]
    );

    await client.query(
      `INSERT INTO player_monthly_scores
         (player_id, month_key, general_score, infinite_score, updated_at)
       VALUES ($1, $2, $3, $4, NOW())
       ON CONFLICT (player_id, month_key)
       DO UPDATE SET
         general_score = LEAST(player_monthly_scores.general_score + $3, 2000000000),
         infinite_score = LEAST(player_monthly_scores.infinite_score + $4, 2000000000),
         updated_at = NOW()`,
      [
        playerId,
        currentMonthKey(),
        reward.generalDelta,
        reward.infiniteDelta,
      ]
    );

    await client.query(
      `UPDATE player_xp
       SET
         total_xp = LEAST(total_xp + $2, 2000000000),
         updated_at = NOW()
       WHERE player_id = $1`,
      [playerId, reward.xp]
    );

    await client.query("COMMIT");
    res.json({
      ok: true,
      reward,
    });
  } catch (error) {
    await client.query("ROLLBACK");
    sendLeaderboardError(
      res,
      error,
      "Ödül doğrulanamadı.",
      "target solution verify error:"
    );
  } finally {
    client.release();
  }
});

app.post("/game-rights/status", rateLimit({ prefix: "rights-status", limit: 60, windowMs: 60_000 }), async (req, res) => {
  if (!requireDatabase(res)) return;

  const playerId = authenticatedPlayer(req);
  const username = safeUsername(req.body.username);
  const country = safeCountry(req.body.country);

  if (!playerId) {
    res.status(400).json({ ok: false, message: "playerId zorunlu." });
    return;
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await ensurePlayerForScore(client, playerId, username, country);
    await ensurePlayerProgressRows(client, playerId);
    await readAndRefillRights(client, playerId);
    const state = await readPlayerState(client, playerId);
    await client.query("COMMIT");
    res.json({ ok: true, ...state });
  } catch (error) {
    await client.query("ROLLBACK");
    sendLeaderboardError(res, error, "Oyun hakkı okunamadı.", "game rights status error:");
  } finally {
    client.release();
  }
});

app.post("/game-rights/consume", rateLimit({ prefix: "rights-consume", limit: 20, windowMs: 60_000 }), async (req, res) => {
  if (!requireDatabase(res)) return;

  const playerId = authenticatedPlayer(req);
  const username = safeUsername(req.body.username);
  const country = safeCountry(req.body.country);

  if (!playerId) {
    res.status(400).json({ ok: false, message: "playerId zorunlu." });
    return;
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await ensurePlayerForScore(client, playerId, username, country);
    await ensurePlayerProgressRows(client, playerId);
    const state = await readAndRefillRights(client, playerId);

    if (state.remainingRights <= 0) {
      await client.query("COMMIT");
      res.status(409).json({
        ok: false,
        consumed: false,
        message: "Oyun hakkınız kalmadı.",
        ...state,
      });
      return;
    }

    const updatedRights = state.remainingRights - 1;
    await client.query(
      `UPDATE player_game_rights
       SET
         remaining_rights = $2,
         last_refill_at = CASE
           WHEN $3 THEN NOW()
           ELSE last_refill_at
         END,
         updated_at = NOW()
       WHERE player_id = $1`,
      [playerId, updatedRights, state.remainingRights >= MAX_GAME_RIGHTS]
    );

    const fullState = await readPlayerState(client, playerId);
    await client.query("COMMIT");
    res.json({ ok: true, consumed: true, ...fullState });
  } catch (error) {
    await client.query("ROLLBACK");
    sendLeaderboardError(res, error, "Oyun hakkı tüketilemedi.", "game rights consume error:");
  } finally {
    client.release();
  }
});


async function consumeRealtimeGameRights(players) {
  if (!pool) return { ok: false, message: "Veritabanı kullanılamıyor." };
  const uniquePlayers = Array.from(
    new Map(players.map((item) => [item.id, item])).values()
  );
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    for (const player of uniquePlayers) {
      await ensurePlayerForScore(client, player.id, player.name || "Oyuncu", player.country || "TR");
      await ensurePlayerProgressRows(client, player.id);
      const rights = await readAndRefillRights(client, player.id);
      if (rights.remainingRights <= 0) {
        await client.query("ROLLBACK");
        return { ok: false, playerId: player.id, message: "Oyun hakkı kalmadı." };
      }
    }
    for (const player of uniquePlayers) {
      await client.query(
        `UPDATE player_game_rights SET remaining_rights = remaining_rights - 1,
           last_refill_at = CASE WHEN remaining_rights >= $2 THEN NOW() ELSE last_refill_at END,
           updated_at = NOW() WHERE player_id = $1`,
        [player.id, MAX_GAME_RIGHTS]
      );
    }
    await client.query("COMMIT");
    return { ok: true };
  } catch (error) {
    await client.query("ROLLBACK");
    console.error("realtime rights consume error:", error);
    return { ok: false, message: "Oyun hakkı doğrulanamadı." };
  } finally {
    client.release();
  }
}

io.use((socket, next) => {
  const authorization = String(socket.handshake.headers?.authorization || "");
  const bearerToken = authorization.startsWith("Bearer ")
    ? authorization.slice(7).trim()
    : "";
  const token = String(socket.handshake.auth?.token || bearerToken);
  const auth = verifySessionToken(token);
  if (!auth?.playerId) {
    next(new Error("UNAUTHORIZED"));
    return;
  }
  socket.data.playerId = auth.playerId;
  next();
});

function socketEventAllowed(socket, eventName, limit = 30, windowMs = 60_000) {
  const key = `socket:${eventName}:${socket.handshake.address || "unknown"}:${socket.data.playerId}`;
  const result = consumeRateLimit(key, limit, windowMs);
  if (!result.allowed) socket.emit("match_error", { message: "Çok fazla işlem yapıldı. Lütfen kısa süre sonra tekrar deneyin." });
  return result.allowed;
}

io.on("connection", (socket) => {
  console.log(
    "Socket connected:",
    socket.id,
    "transport:",
    socket.conn.transport.name
  );

  socket.conn.on(
    "upgrade",
    (transport) => {
      console.log(
        "Socket upgraded:",
        socket.id,
        "transport:",
        transport.name
      );
    }
  );

  socket.on(
    "join_match",
    async (payload = {}) => {
      const gameKey =
        normalizeMatchGameKey(
          payload.gameKey
        );

      const difficulty = String(
        payload.difficulty ||
          "Medium"
      );

      if (!socketEventAllowed(socket, "join_match", 20, 60_000)) return;
      const player = {
        ...safePlayer(payload.player, socket.data.playerId),
        id: socket.data.playerId,
      };

      removeFromAllQueues(
        socket.id,
        player.id
      );

      removePrivateRoomsForSocket(
        socket.id,
        false
      );

      leaveRoomAsCancel(socket);

      const key = queueKey(
        gameKey,
        difficulty
      );

      const queue =
        waitingQueues.get(key) || [];

      while (queue.length > 0) {
        const opponent =
          queue.shift();

        const opponentSocket =
          io.sockets.sockets.get(
            opponent.socketId
          );

        if (
          !opponentSocket ||
          opponentSocket.id === socket.id
        ) {
          continue;
        }

        if (
          opponent.player?.id &&
          opponent.player.id === player.id
        ) {
          continue;
        }

        waitingQueues.set(
          key,
          queue
        );

        if (realtimeModeForGameKey(gameKey) === "two_player") {
          const rightsResult = await consumeRealtimeGameRights([player, opponent.player]);
          if (!rightsResult.ok) {
            const message = rightsResult.message || "Oyun hakkı doğrulanamadı.";
            socket.emit("match_error", { code: "NO_GAME_RIGHT", message });
            opponentSocket.emit("match_error", { code: "NO_GAME_RIGHT", message });
            return;
          }
        }

        // Puzzle artık istemciden alınmaz; oda oluştuğu anda sunucu üretir.
        const selectedPuzzle =
          generateTargetNumberPuzzle(difficulty);

        const room =
          createRealtimeRoom(
            socket,
            player,
            opponentSocket,
            opponent.player,
            gameKey,
            difficulty,
            selectedPuzzle
          );

        socket.emit(
          "match_found",
          {
            roomId: room.roomId,
            opponent: {
              name:
                opponent.player.name,
              country:
                opponent.player.country,
            },
            puzzle: selectedPuzzle,
          }
        );

        opponentSocket.emit(
          "match_found",
          {
            roomId: room.roomId,
            opponent: {
              name: player.name,
              country:
                player.country,
            },
            puzzle: selectedPuzzle,
          }
        );

        console.log(
          "Match found:",
          room.roomId,
          key
        );

        return;
      }

      queue.push({
        socketId: socket.id,
        player,
        joinedAt: Date.now(),
      });

      waitingQueues.set(
        key,
        queue
      );

      socket.emit("waiting", {
        gameKey,
        difficulty,
      });

      console.log(
        "Player waiting:",
        socket.id,
        key,
        player.id
      );
    }
  );

  socket.on(
    "resume_match",
    (payload = {}) => {
      const roomId = String(
        payload.roomId || ""
      ).trim();

      if (!socketEventAllowed(socket, "resume_match", 20, 60_000)) return;
      const player = {
        ...safePlayer(payload.player, socket.data.playerId),
        id: socket.data.playerId,
      };

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

      if (room.resolved) {
        socket.emit(
          "resume_error",
          {
            code:
              "MATCH_RESOLVED",
            message:
              "Bu maç zaten sona ermiş.",
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
          },

          puzzle: room.puzzle,

          opponentFinishedMs:
            Number(
              opponent?.elapsedMs ||
                0
            ),
        }
      );

      console.log(
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

      console.log(
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

      clearParticipantAwayState(
        room,
        participant.playerId
      );

      console.log(
        "Player foregrounded:",
        roomId,
        participant.playerId
      );
    }
  );

  socket.on(
    "create_friend_room",
    (payload = {}) => {
      expireOldPrivateRooms();

      const gameKey = String(
        payload.gameKey ||
          "target_number"
      );

      const difficulty = String(
        payload.difficulty ||
          "Medium"
      );

      if (!socketEventAllowed(socket, "create_friend_room", 10, 60_000)) return;
      const player = {
        ...safePlayer(payload.player, socket.data.playerId),
        id: socket.data.playerId,
      };

      // Arkadaş odasının puzzle'ı da istemciden alınmaz; oda sahibi sadece zorluk seçer.
      const puzzle = generateTargetNumberPuzzle(difficulty);

      removeFromAllQueues(
        socket.id,
        player.id
      );

      removePrivateRoomsForSocket(
        socket.id,
        false
      );

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

      console.log(
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

      if (!socketEventAllowed(socket, "join_friend_room", 20, 60_000)) return;
      const player = {
        ...safePlayer(payload.player, socket.data.playerId),
        id: socket.data.playerId,
      };

      removeFromAllQueues(
        socket.id,
        player.id
      );

      removePrivateRoomsForSocket(
        socket.id,
        false
      );

      leaveRoomAsCancel(socket);

      const rightsResult = await consumeRealtimeGameRights([player, room.player]);
      if (!rightsResult.ok) {
        const message = rightsResult.message || "Oyun hakkı doğrulanamadı.";
        socket.emit("friend_room_error", { code: "NO_GAME_RIGHT", message });
        ownerSocket.emit("friend_room_error", { code: "NO_GAME_RIGHT", message });
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
          },

          puzzle: room.puzzle,
        }
      );

      console.log(
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
    "player_finished",
    async (payload = {}) => {
      if (!socketEventAllowed(socket, "player_finished", 12, 60_000)) return;
      const roomId = String(
        payload.roomId || ""
      ).trim();

      const room =
        realtimeRooms.get(roomId);

      const active =
        activeRooms.get(socket.id);

      const playerId =
        active?.playerId ||
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

      const opponent =
        getOpponentParticipant(
          room,
          playerId
        );

      if (
        !room ||
        !participant ||
        room.resolved
      ) {
        return;
      }

      const solution =
        payload.solution || {};

      const validSolution =
        validateTargetNumberSolution(
          room.puzzle,
          solution.numberSlots,
          solution.operatorSlots
        );

      if (!validSolution) {
        socket.emit(
          "match_error",
          {
            message:
              "Çözüm sunucu tarafından doğrulanamadı.",
          }
        );

        return;
      }

      const now = Date.now();
      const startedAt = Number(
        room.startedAt || room.createdAt || now
      );
      const serverElapsedMs = Math.max(
        1,
        Math.min(
          now - startedAt,
          Number(
            process.env.COMPETITIVE_MATCH_LIMIT_MS ||
              2 * 60 * 1000
          )
        )
      );

      participant.finishedAt = now;
      participant.elapsedMs = Math.floor(
        serverElapsedMs
      );

      clearParticipantAwayState(
        room,
        participant.playerId
      );

      markRoomResolved(
        room,
        "finished",
        participant.playerId,
        opponent?.playerId
      );
      await settleRealtimeRoom(room);

      const opponentSocket =
        opponent?.socketId
          ? io.sockets.sockets.get(
              opponent.socketId
            )
          : null;

      if (opponentSocket) {
        opponentSocket.emit(
          "opponent_finished",
          {
            roomId,
            elapsedMs:
              participant.elapsedMs,
          }
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

      leaveRoomAsCancel(socket);
    }
  );

  socket.on(
    "disconnect",
    (reason) => {
      console.log(
        "Socket disconnected:",
        socket.id,
        reason
      );

      removeFromAllQueues(socket.id);

      removePrivateRoomsForSocket(
        socket.id,
        false
      );

      markSocketDisconnected(socket);
    }
  );
});

setInterval(() => {
  expireOldPrivateRooms();
  expireResolvedRooms();
}, 60_000).unref();

const PORT = Number(
  process.env.PORT || 10000
);

initDatabase()
  .catch((error) => {
    console.error(
      "Database init failed:",
      {
        message: error.message,
        code: error.code,
        detail: error.detail,
        stack: error.stack,
      }
    );
  })
  .finally(() => {
    server.listen(
      PORT,
      "0.0.0.0",
      () => {
        console.log(
          `Target number matchmaking server running on port ${PORT}`
        );
      }
    );
  });