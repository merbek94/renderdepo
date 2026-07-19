"use strict";

const express = require("express");
const http = require("http");
const crypto = require("crypto");
const { Pool } = require("pg");
const { Server } = require("socket.io");

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(express.json({ limit: "64kb" }));

const server = http.createServer(app);

const PORT = positiveInt(process.env.PORT, 10000);
const DATABASE_URL = String(process.env.DATABASE_URL || "").trim();
const SESSION_SECRET = String(process.env.SESSION_SECRET || "").trim();
const GOOGLE_SERVER_CLIENT_ID = String(
  process.env.GOOGLE_SERVER_CLIENT_ID || ""
).trim();
const GOOGLE_SERVER_CLIENT_SECRET = String(
  process.env.GOOGLE_SERVER_CLIENT_SECRET || ""
).trim();
const GOOGLE_REDIRECT_URI = String(process.env.GOOGLE_REDIRECT_URI || "");

const SOCKET_PATH = "/socket.io/";
const SESSION_TTL_MS = positiveInt(
  process.env.SESSION_TTL_MS,
  12 * 60 * 60 * 1000
);
const MAX_RIGHTS = positiveInt(process.env.MAX_GAME_RIGHTS, 10);
const RIGHT_REFILL_MS = positiveInt(
  process.env.GAME_RIGHT_REFILL_MS,
  10 * 60 * 1000
);
const SINGLE_LIMIT_MS = positiveInt(
  process.env.TARGET_SINGLE_LIMIT_MS,
  5 * 60 * 1000
);
const COMPETITIVE_LIMIT_MS = positiveInt(
  process.env.TARGET_COMPETITIVE_LIMIT_MS,
  2 * 60 * 1000
);
const INFINITE_LIMIT_MS = positiveInt(
  process.env.TARGET_INFINITE_LIMIT_MS,
  2 * 60 * 1000
);
const RECONNECT_TIMEOUT_MS = positiveInt(
  process.env.ROOM_RECONNECT_TIMEOUT_MS,
  60 * 1000
);
const RESOLVED_ROOM_TTL_MS = positiveInt(
  process.env.RESOLVED_ROOM_TTL_MS,
  10 * 60 * 1000
);
const FRIEND_ROOM_TTL_MS = positiveInt(
  process.env.PRIVATE_ROOM_TTL_MS,
  15 * 60 * 1000
);
const BOT_MATCH_DELAY_MIN_MS = positiveInt(
  process.env.BOT_MATCH_DELAY_MIN_MS,
  20 * 1000
);
const BOT_MATCH_DELAY_MAX_MS = Math.max(
  BOT_MATCH_DELAY_MIN_MS,
  positiveInt(process.env.BOT_MATCH_DELAY_MAX_MS, 36 * 1000)
);
const USERNAME_CHANGE_MS = positiveInt(
  process.env.USERNAME_CHANGE_MS,
  30 * 24 * 60 * 60 * 1000
);

const HUNDRED_TOTAL_STAGES = 12;
const TOURNAMENT_TOTAL_STAGES = 12;
const TOURNAMENT_INITIAL_RIGHTS = 3;
const MAX_SCORE = 2_000_000_000;
const MIN_SOLUTION_MS = positiveInt(process.env.MIN_SOLUTION_MS, 1_000);

if (!DATABASE_URL) {
  console.warn(
    "DATABASE_URL tanımlı değil. Kalıcı oyun verileri çalışmayacak."
  );
}

if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  console.warn("SESSION_SECRET en az 32 karakter olmalıdır.");
}

if (!GOOGLE_SERVER_CLIENT_ID || !GOOGLE_SERVER_CLIENT_SECRET) {
  console.warn("Google OAuth sunucu kimlik bilgileri eksik.");
}

const pool = DATABASE_URL
  ? new Pool({
      connectionString: DATABASE_URL,
      ssl:
        DATABASE_URL.includes("localhost") ||
        DATABASE_URL.includes("127.0.0.1")
          ? false
          : { rejectUnauthorized: false },
      max: positiveInt(process.env.PG_POOL_MAX, 10),
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 10_000,
    })
  : null;

app.use((req, _res, next) => {
  console.log(
    "HTTP",
    req.method,
    req.path,
    "ua:",
    req.headers["user-agent"] || "-"
  );
  next();
});

const rateLimitBuckets = new Map();

function rateLimit(windowMs, maxRequests, namespace) {
  return (req, res, next) => {
    const now = nowMs();
    const key = `${namespace}:${
      req.ip || req.socket?.remoteAddress || "unknown"
    }`;

    const current = rateLimitBuckets.get(key);

    if (!current || current.resetAt <= now) {
      rateLimitBuckets.set(key, {
        count: 1,
        resetAt: now + windowMs,
      });

      next();
      return;
    }

    if (current.count >= maxRequests) {
      res.setHeader(
        "Retry-After",
        String(
          Math.max(
            1,
            Math.ceil((current.resetAt - now) / 1000)
          )
        )
      );

      res.status(429).json({
        ok: false,
        code: "RATE_LIMITED",
        message:
          "Çok fazla istek gönderildi. Lütfen kısa süre sonra tekrar dene.",
      });

      return;
    }

    current.count += 1;
    next();
  };
}

const globalHttpRateLimit = rateLimit(
  60_000,
  positiveInt(process.env.HTTP_RATE_LIMIT_PER_MINUTE, 300),
  "http"
);

const authHttpRateLimit = rateLimit(
  10 * 60_000,
  positiveInt(process.env.AUTH_RATE_LIMIT_PER_10_MINUTES, 20),
  "auth"
);

app.use(globalHttpRateLimit);

setInterval(() => {
  const now = nowMs();

  for (const [key, value] of rateLimitBuckets.entries()) {
    if (value.resetAt <= now) {
      rateLimitBuckets.delete(key);
    }
  }
}, 10 * 60_000).unref?.();

function positiveInt(value, fallback) {
  const parsed = Number(value);

  return Number.isFinite(parsed) && parsed > 0
    ? Math.floor(parsed)
    : fallback;
}

function nowMs() {
  return Date.now();
}

function clampInt(value, min, max, fallback = min) {
  const number = Number(value);

  if (!Number.isFinite(number)) {
    return fallback;
  }

  return Math.max(min, Math.min(max, Math.trunc(number)));
}

function safeText(value, fallback = "", maxLength = 100) {
  const text = String(value ?? fallback).trim();

  return (text || fallback).slice(0, maxLength);
}

function safeCountry(value) {
  return (
    safeText(value, "TR", 3)
      .toUpperCase()
      .replace(/[^A-Z]/g, "")
      .slice(0, 3) || "TR"
  );
}

function normalizeUsername(value) {
  return safeText(value, "", 20);
}

function validateUsername(value) {
  const username = normalizeUsername(value);

  if (!username) {
    return "Kullanıcı adı boş olamaz.";
  }

  if (
    username !== String(value || "").trim() ||
    /\s/.test(username)
  ) {
    return "Kullanıcı adında boşluk olamaz.";
  }

  if (username.length < 3 || username.length > 20) {
    return "Kullanıcı adı 3-20 karakter arasında olmalı.";
  }

  if (!/^[\p{L}\p{N}]/u.test(username)) {
    return "İlk karakter yalnızca harf veya rakam olabilir.";
  }

  if (!/^[\p{L}\p{N}_.-]+$/u.test(username)) {
    return "Kullanıcı adında yalnızca harf, rakam, nokta, alt çizgi ve tire kullanılabilir.";
  }

  return null;
}

function normalizeDifficulty(value) {
  return String(value || "Medium") === "Hard"
    ? "Hard"
    : "Medium";
}

function normalizeMode(value) {
  const mode = String(value || "single").toLowerCase();

  return ["single", "infinite", "hundred"].includes(mode)
    ? mode
    : "single";
}

function normalizeGameKey(value) {
  const key = safeText(
    value,
    "target_number_two_player",
    64
  ).toLowerCase();

  if (key.includes("tournament")) {
    return "target_number_tournament";
  }

  if (key.includes("friend")) {
    return "target_number_friend";
  }

  return "target_number_two_player";
}

function currentMonthKey() {
  return new Date().toISOString().slice(0, 7);
}

function base64url(input) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function fromBase64url(input) {
  const normalized = String(input)
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  const padded =
    normalized +
    "=".repeat((4 - (normalized.length % 4)) % 4);

  return Buffer.from(padded, "base64").toString("utf8");
}

function createSessionToken(playerId) {
  if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
    throw new Error("SESSION_SECRET yapılandırılmamış.");
  }

  const issuedAt = nowMs();

  const payload = {
    sub: playerId,
    iat: issuedAt,
    exp: issuedAt + SESSION_TTL_MS,
    nonce: crypto.randomBytes(12).toString("hex"),
  };

  const encoded = base64url(JSON.stringify(payload));

  const signature = base64url(
    crypto
      .createHmac("sha256", SESSION_SECRET)
      .update(encoded)
      .digest()
  );

  return `${encoded}.${signature}`;
}

function verifySessionToken(token) {
  if (!token || !SESSION_SECRET) {
    return null;
  }

  const parts = String(token).split(".");

  if (parts.length !== 2) {
    return null;
  }

  const [encoded, signature] = parts;

  const expected = base64url(
    crypto
      .createHmac("sha256", SESSION_SECRET)
      .update(encoded)
      .digest()
  );

  const a = Buffer.from(signature);
  const b = Buffer.from(expected);

  if (
    a.length !== b.length ||
    !crypto.timingSafeEqual(a, b)
  ) {
    return null;
  }

  try {
    const payload = JSON.parse(fromBase64url(encoded));

    if (
      !payload.sub ||
      !Number.isFinite(payload.exp) ||
      payload.exp <= nowMs()
    ) {
      return null;
    }

    return payload;
  } catch (_error) {
    return null;
  }
}

function bearerTokenFromHeaders(headers = {}) {
  const header = String(
    headers.authorization ||
      headers.Authorization ||
      ""
  );

  const match = /^Bearer\s+(.+)$/i.exec(header.trim());

  return match ? match[1].trim() : "";
}

function requireDatabase(res) {
  if (pool) {
    return true;
  }

  res.status(503).json({
    ok: false,
    code: "DATABASE_UNAVAILABLE",
    message: "Veritabanı kullanılamıyor.",
  });

  return false;
}

function publicError(status, code, message) {
  const error = new Error(message);
  error.statusCode = status;
  error.publicCode = code;

  return error;
}

function sendError(
  res,
  error,
  fallbackMessage = "İşlem tamamlanamadı."
) {
  const status = clampInt(
    error?.statusCode,
    400,
    599,
    500
  );

  if (status >= 500) {
    console.error("server error", {
      message: error?.message,
      code: error?.code,
      detail: error?.detail,
      stack: error?.stack,
    });
  }

  res.status(status).json({
    ok: false,
    code: error?.publicCode || "SERVER_ERROR",
    message:
      status < 500
        ? error.message
        : fallbackMessage,
  });
}

async function authMiddleware(req, res, next) {
  const payload = verifySessionToken(
    bearerTokenFromHeaders(req.headers)
  );

  if (!payload) {
    res.status(401).json({
      ok: false,
      code: "UNAUTHORIZED",
      message:
        "Oturum geçersiz veya süresi dolmuş.",
    });

    return;
  }

  req.auth = {
    playerId: payload.sub,
  };

  next();
}

async function initDatabase() {
  if (!pool) {
    return;
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS players (
      player_id TEXT PRIMARY KEY,
      google_display_name TEXT NOT NULL DEFAULT '',
      username TEXT NOT NULL DEFAULT '',
      country TEXT NOT NULL DEFAULT 'TR',
      username_change_count INTEGER NOT NULL DEFAULT 0
        CHECK (username_change_count >= 0),
      last_username_change_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    ALTER TABLE players
      ADD COLUMN IF NOT EXISTS google_display_name
      TEXT NOT NULL DEFAULT '';

    ALTER TABLE players
      ADD COLUMN IF NOT EXISTS username
      TEXT NOT NULL DEFAULT '';

    ALTER TABLE players
      ADD COLUMN IF NOT EXISTS country
      TEXT NOT NULL DEFAULT 'TR';

    ALTER TABLE players
      ADD COLUMN IF NOT EXISTS username_change_count
      INTEGER NOT NULL DEFAULT 0;

    ALTER TABLE players
      ADD COLUMN IF NOT EXISTS last_username_change_at
      TIMESTAMPTZ;

    ALTER TABLE players
      ALTER COLUMN username SET DEFAULT '';

    ALTER TABLE players
      ALTER COLUMN country SET DEFAULT 'TR';

    WITH duplicate_usernames AS (
      SELECT
        player_id,
        ROW_NUMBER() OVER (
          PARTITION BY LOWER(username)
          ORDER BY
            updated_at DESC,
            created_at ASC,
            player_id ASC
        ) AS duplicate_order
      FROM players
      WHERE username <> ''
    )
    UPDATE players p
    SET
      username = '',
      updated_at = NOW()
    FROM duplicate_usernames d
    WHERE
      p.player_id = d.player_id
      AND d.duplicate_order > 1;

    CREATE UNIQUE INDEX IF NOT EXISTS
      idx_players_username_lower_unique
      ON players (LOWER(username))
      WHERE username <> '';

    CREATE TABLE IF NOT EXISTS player_state (
      player_id TEXT PRIMARY KEY
        REFERENCES players(player_id)
        ON DELETE CASCADE,

      general_score INTEGER NOT NULL DEFAULT 0
        CHECK (general_score >= 0),

      infinite_high_score INTEGER NOT NULL DEFAULT 0
        CHECK (infinite_high_score >= 0),

      total_xp INTEGER NOT NULL DEFAULT 0
        CHECK (total_xp >= 0),

      game_rights INTEGER NOT NULL DEFAULT ${MAX_RIGHTS}
        CHECK (
          game_rights >= 0
          AND game_rights <= ${MAX_RIGHTS}
        ),

      rights_anchor_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW(),

      updated_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS player_monthly_scores (
      player_id TEXT NOT NULL
        REFERENCES players(player_id)
        ON DELETE CASCADE,

      month_key TEXT NOT NULL,

      general_score INTEGER NOT NULL DEFAULT 0
        CHECK (general_score >= 0),

      infinite_score INTEGER NOT NULL DEFAULT 0
        CHECK (infinite_score >= 0),

      updated_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW(),

      PRIMARY KEY (player_id, month_key)
    );

    CREATE TABLE IF NOT EXISTS target_number_progress (
      player_id TEXT PRIMARY KEY
        REFERENCES players(player_id)
        ON DELETE CASCADE,

      infinite_session_id UUID,
      infinite_stage INTEGER NOT NULL DEFAULT 1,
      infinite_score INTEGER NOT NULL DEFAULT 0,
      infinite_puzzle JSONB,
      infinite_number_slots JSONB,
      infinite_operator_slots JSONB,
      infinite_remaining_ms BIGINT,

      hundred_current_stage INTEGER
        NOT NULL DEFAULT 1,

      hundred_total_elapsed_ms BIGINT
        NOT NULL DEFAULT 0,

      hundred_active BOOLEAN
        NOT NULL DEFAULT FALSE,

      tournament_current_stage INTEGER
        NOT NULL DEFAULT 1,

      tournament_remaining_rights INTEGER
        NOT NULL DEFAULT ${TOURNAMENT_INITIAL_RIGHTS},

      tournament_total_score INTEGER
        NOT NULL DEFAULT 0,

      tournament_completed BOOLEAN
        NOT NULL DEFAULT FALSE,

      statistics JSONB
        NOT NULL DEFAULT '{}'::jsonb,

      updated_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW()
    );

    ALTER TABLE target_number_progress
      ADD COLUMN IF NOT EXISTS hundred_current_stage
      INTEGER NOT NULL DEFAULT 1;

    ALTER TABLE target_number_progress
      ADD COLUMN IF NOT EXISTS hundred_total_elapsed_ms
      BIGINT NOT NULL DEFAULT 0;

    ALTER TABLE target_number_progress
      ADD COLUMN IF NOT EXISTS hundred_active
      BOOLEAN NOT NULL DEFAULT FALSE;

    CREATE TABLE IF NOT EXISTS target_number_sessions (
      session_id UUID PRIMARY KEY,

      player_id TEXT NOT NULL
        REFERENCES players(player_id)
        ON DELETE CASCADE,

      mode TEXT NOT NULL,
      difficulty TEXT NOT NULL,
      stage INTEGER NOT NULL DEFAULT 1,
      puzzle JSONB NOT NULL,
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb,

      started_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW(),

      deadline_at TIMESTAMPTZ NOT NULL,

      elapsed_active_ms BIGINT
        NOT NULL DEFAULT 0,

      paused_remaining_ms BIGINT,

      status TEXT
        NOT NULL DEFAULT 'active',

      finished_at TIMESTAMPTZ,
      result JSONB,

      updated_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW()
    );

    ALTER TABLE target_number_sessions
      ADD COLUMN IF NOT EXISTS elapsed_active_ms
      BIGINT NOT NULL DEFAULT 0;

    ALTER TABLE target_number_sessions
      ADD COLUMN IF NOT EXISTS paused_remaining_ms
      BIGINT;

    CREATE INDEX IF NOT EXISTS
      idx_target_sessions_player_status
      ON target_number_sessions(
        player_id,
        status,
        updated_at DESC
      );

    CREATE TABLE IF NOT EXISTS match_rooms (
      room_id UUID PRIMARY KEY,
      game_key TEXT NOT NULL,
      difficulty TEXT NOT NULL,
      puzzle JSONB NOT NULL,

      started_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW(),

      deadline_at TIMESTAMPTZ NOT NULL,

      status TEXT
        NOT NULL DEFAULT 'active',

      winner_player_id TEXT,
      loser_player_id TEXT,
      result_reason TEXT,
      bot_finish_at TIMESTAMPTZ,

      created_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW(),

      updated_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS match_participants (
      room_id UUID NOT NULL
        REFERENCES match_rooms(room_id)
        ON DELETE CASCADE,

      player_id TEXT NOT NULL,
      is_bot BOOLEAN NOT NULL DEFAULT FALSE,
      display_name TEXT NOT NULL,
      country TEXT NOT NULL DEFAULT 'TR',
      socket_id TEXT,
      finished_at TIMESTAMPTZ,
      elapsed_ms BIGINT,
      away_since TIMESTAMPTZ,

      PRIMARY KEY (room_id, player_id)
    );

    CREATE INDEX IF NOT EXISTS
      idx_match_participants_player
      ON match_participants(player_id, room_id);

    CREATE TABLE IF NOT EXISTS friend_rooms (
      room_code TEXT PRIMARY KEY,

      owner_player_id TEXT NOT NULL
        REFERENCES players(player_id)
        ON DELETE CASCADE,

      owner_socket_id TEXT NOT NULL,
      game_key TEXT NOT NULL,
      difficulty TEXT NOT NULL,

      created_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS
      idx_player_state_general
      ON player_state(general_score DESC);

    CREATE INDEX IF NOT EXISTS
      idx_player_state_infinite
      ON player_state(infinite_high_score DESC);

    CREATE INDEX IF NOT EXISTS
      idx_monthly_general
      ON player_monthly_scores(
        month_key,
        general_score DESC
      );

    CREATE INDEX IF NOT EXISTS
      idx_monthly_infinite
      ON player_monthly_scores(
        month_key,
        infinite_score DESC
      );

    CREATE INDEX IF NOT EXISTS
      idx_players_country
      ON players(country);
  `);

  /*
   * Eski server.js sürümündeki player_scores
   * tablosu varsa toplamları yeni tabloya taşır.
   */
  await pool.query(`
    DO $$
    BEGIN
      IF to_regclass('public.player_scores') IS NOT NULL THEN
        INSERT INTO player_state (
          player_id,
          general_score,
          infinite_high_score,
          total_xp,
          game_rights,
          rights_anchor_at,
          updated_at
        )
        SELECT
          ps.player_id,
          GREATEST(ps.general_score, 0),
          GREATEST(ps.infinite_score, 0),
          0,
          ${MAX_RIGHTS},
          NOW(),
          NOW()
        FROM player_scores ps
        JOIN players p
          ON p.player_id = ps.player_id
        ON CONFLICT (player_id)
        DO UPDATE SET
          general_score = GREATEST(
            player_state.general_score,
            EXCLUDED.general_score
          ),
          infinite_high_score = GREATEST(
            player_state.infinite_high_score,
            EXCLUDED.infinite_high_score
          ),
          updated_at = NOW();
      END IF;
    END $$;
  `);

  console.log(
    "PostgreSQL tabloları ve güvenli veri geçişi hazır."
  );
}

async function exchangePlayGamesAuthCode(authCode) {
  if (
    !GOOGLE_SERVER_CLIENT_ID ||
    !GOOGLE_SERVER_CLIENT_SECRET
  ) {
    throw publicError(
      503,
      "GOOGLE_AUTH_NOT_CONFIGURED",
      "Sunucu Play Games doğrulaması için yapılandırılmamış."
    );
  }

  const code = safeText(authCode, "", 4096);

  if (!code) {
    throw publicError(
      400,
      "AUTH_CODE_REQUIRED",
      "Play Games yetkilendirme kodu zorunlu."
    );
  }

  const form = new URLSearchParams();

  form.set("code", code);
  form.set("client_id", GOOGLE_SERVER_CLIENT_ID);
  form.set(
    "client_secret",
    GOOGLE_SERVER_CLIENT_SECRET
  );
  form.set("grant_type", "authorization_code");
  form.set("redirect_uri", GOOGLE_REDIRECT_URI);

  const tokenResponse = await fetch(
    "https://oauth2.googleapis.com/token",
    {
      method: "POST",
      headers: {
        "Content-Type":
          "application/x-www-form-urlencoded",
      },
      body: form,
    }
  );

  const tokenJson = await tokenResponse
    .json()
    .catch(() => ({}));

  if (
    !tokenResponse.ok ||
    !tokenJson.access_token
  ) {
    console.warn(
      "Google token exchange failed",
      tokenJson.error || tokenResponse.status
    );

    throw publicError(
      401,
      "PLAY_GAMES_AUTH_FAILED",
      "Play Games hesabı doğrulanamadı."
    );
  }

  const playerResponse = await fetch(
    "https://games.googleapis.com/games/v1/players/me",
    {
      headers: {
        Authorization:
          `Bearer ${tokenJson.access_token}`,
      },
    }
  );

  const playerJson = await playerResponse
    .json()
    .catch(() => ({}));

  if (
    !playerResponse.ok ||
    !playerJson.playerId
  ) {
    console.warn(
      "Google player lookup failed",
      playerJson.error || playerResponse.status
    );

    throw publicError(
      401,
      "PLAY_GAMES_PLAYER_FAILED",
      "Play Games oyuncu kimliği doğrulanamadı."
    );
  }

  return {
    playerId:
      `pg_${safeText(
        playerJson.playerId,
        "",
        128
      )}`,
    displayName: safeText(
      playerJson.displayName,
      "Oyuncu",
      80
    ),
  };
}

async function ensurePlayer(
  client,
  identity,
  requestedCountry = "TR"
) {
  const country = safeCountry(requestedCountry);

  await client.query(
    `INSERT INTO players (
       player_id,
       google_display_name,
       country,
       created_at,
       updated_at
     )
     VALUES ($1, $2, $3, NOW(), NOW())
     ON CONFLICT (player_id)
     DO UPDATE SET
       google_display_name =
         EXCLUDED.google_display_name,
       country =
         CASE
           WHEN players.country = ''
           THEN EXCLUDED.country
           ELSE players.country
         END,
       updated_at = NOW()`,
    [
      identity.playerId,
      identity.displayName,
      country,
    ]
  );

  await client.query(
    `INSERT INTO player_state (
       player_id,
       game_rights,
       rights_anchor_at
     )
     VALUES ($1, $2, NOW())
     ON CONFLICT (player_id)
     DO NOTHING`,
    [
      identity.playerId,
      MAX_RIGHTS,
    ]
  );

  await client.query(
    `INSERT INTO target_number_progress (
       player_id
     )
     VALUES ($1)
     ON CONFLICT (player_id)
     DO NOTHING`,
    [identity.playerId]
  );
}

async function refreshRights(
  client,
  playerId,
  lock = false
) {
  const result = await client.query(
    `SELECT
       game_rights,
       rights_anchor_at
     FROM player_state
     WHERE player_id = $1
     ${lock ? "FOR UPDATE" : ""}`,
    [playerId]
  );

  if (!result.rows[0]) {
    throw publicError(
      404,
      "PLAYER_STATE_NOT_FOUND",
      "Oyuncu durumu bulunamadı."
    );
  }

  let rights = clampInt(
    result.rows[0].game_rights,
    0,
    MAX_RIGHTS,
    MAX_RIGHTS
  );

  let anchorMs = new Date(
    result.rows[0].rights_anchor_at
  ).getTime();

  const now = nowMs();

  if (!Number.isFinite(anchorMs)) {
    anchorMs = now;
  }

  if (rights < MAX_RIGHTS) {
    const refillCount = Math.floor(
      Math.max(0, now - anchorMs) /
        RIGHT_REFILL_MS
    );

    if (refillCount > 0) {
      rights = Math.min(
        MAX_RIGHTS,
        rights + refillCount
      );

      anchorMs =
        rights >= MAX_RIGHTS
          ? now
          : anchorMs +
            refillCount * RIGHT_REFILL_MS;

      await client.query(
        `UPDATE player_state
         SET
           game_rights = $2,
           rights_anchor_at =
             TO_TIMESTAMP($3 / 1000.0),
           updated_at = NOW()
         WHERE player_id = $1`,
        [
          playerId,
          rights,
          anchorMs,
        ]
      );
    }
  } else {
    anchorMs = now;
  }

  return {
    remainingRights: rights,
    maxRights: MAX_RIGHTS,
    millisUntilNextRight:
      rights >= MAX_RIGHTS
        ? 0
        : Math.max(
            0,
            anchorMs +
              RIGHT_REFILL_MS -
              now
          ),
  };
}

async function consumeGameRight(
  client,
  playerId
) {
  const rights = await refreshRights(
    client,
    playerId,
    true
  );

  if (rights.remainingRights <= 0) {
    throw publicError(
      409,
      "NO_GAME_RIGHT",
      "İki kişilik oyun hakkın kalmadı."
    );
  }

  const wasFull =
    rights.remainingRights >= MAX_RIGHTS;

  const next = rights.remainingRights - 1;

  await client.query(
    `UPDATE player_state
     SET
       game_rights = $2,
       rights_anchor_at =
         CASE
           WHEN $3 THEN NOW()
           ELSE rights_anchor_at
         END,
       updated_at = NOW()
     WHERE player_id = $1`,
    [
      playerId,
      next,
      wasFull,
    ]
  );

  return next;
}

function levelForXp(totalXp) {
  const safe = clampInt(
    totalXp,
    0,
    MAX_SCORE,
    0
  );

  let remaining = safe;
  let level = 1;

  while (level < 1000) {
    const required = level * 2;

    if (remaining < required) {
      break;
    }

    remaining -= required;
    level += 1;
  }

  return {
    totalXp: safe,
    level,
    xpInCurrentLevel:
      level < 1000 ? remaining : 0,
    xpRequiredForNextLevel:
      level < 1000 ? level * 2 : 0,
  };
}

function emptyStatistics() {
  return {
    singleMedium: {
      completedGames: 0,
      wonGames: 0,
      bestFinishMs: 0,
      totalFinishMs: 0,
      timedFinishCount: 0,
    },
    singleHard: {
      completedGames: 0,
      wonGames: 0,
      bestFinishMs: 0,
      totalFinishMs: 0,
      timedFinishCount: 0,
    },
    twoPlayerMedium: {
      completedGames: 0,
      wonGames: 0,
      bestFinishMs: 0,
      totalFinishMs: 0,
      timedFinishCount: 0,
    },
    twoPlayerHard: {
      completedGames: 0,
      wonGames: 0,
      bestFinishMs: 0,
      totalFinishMs: 0,
      timedFinishCount: 0,
    },
    infinite: {
      completedStages: 0,
      highestScore: 0,
      maxStage: 0,
      totalStage: 0,
      totalScore: 0,
      totalStageFinishMs: 0,
      timedStageCount: 0,
    },
  };
}

function normalizedStatistics(value) {
  const base = emptyStatistics();

  const source =
    value &&
    typeof value === "object"
      ? value
      : {};

  for (const key of Object.keys(base)) {
    if (
      source[key] &&
      typeof source[key] === "object"
    ) {
      for (
        const field of Object.keys(base[key])
      ) {
        base[key][field] = clampInt(
          source[key][field],
          0,
          MAX_SCORE,
          0
        );
      }
    }
  }

  return base;
}

function updateClassicStats(
  stats,
  key,
  won,
  elapsedMs
) {
  const item =
    stats[key] ||
    emptyStatistics()[key];

  item.completedGames += 1;

  if (won) {
    item.wonGames += 1;
  }

  if (
    won &&
    Number.isFinite(elapsedMs) &&
    elapsedMs > 0
  ) {
    const elapsed = Math.floor(elapsedMs);

    item.bestFinishMs =
      item.bestFinishMs > 0
        ? Math.min(
            item.bestFinishMs,
            elapsed
          )
        : elapsed;

    item.totalFinishMs = Math.min(
      MAX_SCORE,
      item.totalFinishMs + elapsed
    );

    item.timedFinishCount += 1;
  }

  stats[key] = item;
}

function updateInfiniteStats(
  stats,
  stage,
  totalScore,
  elapsedMs
) {
  const item =
    stats.infinite ||
    emptyStatistics().infinite;

  item.completedStages += 1;

  item.highestScore = Math.max(
    item.highestScore,
    totalScore
  );

  item.maxStage = Math.max(
    item.maxStage,
    stage
  );

  item.totalStage = Math.min(
    MAX_SCORE,
    item.totalStage +
      Math.max(0, stage)
  );

  item.totalScore = Math.min(
    MAX_SCORE,
    item.totalScore +
      Math.max(0, totalScore)
  );

  if (elapsedMs > 0) {
    item.totalStageFinishMs = Math.min(
      MAX_SCORE,
      item.totalStageFinishMs +
        elapsedMs
    );

    item.timedStageCount += 1;
  }

  stats.infinite = item;
}

async function loadPlayerSnapshot(
  client,
  playerId
) {
  const rights = await refreshRights(
    client,
    playerId,
    false
  );

  const result = await client.query(
    `SELECT
       p.username,
       p.google_display_name,
       p.country,
       p.username_change_count,
       p.last_username_change_at,
       s.general_score,
       s.infinite_high_score,
       s.total_xp,
       t.infinite_session_id,
       t.infinite_stage,
       t.infinite_score,
       t.tournament_current_stage,
       t.tournament_remaining_rights,
       t.tournament_total_score,
       t.tournament_completed,
       t.statistics
     FROM players p
     JOIN player_state s
       ON s.player_id = p.player_id
     JOIN target_number_progress t
       ON t.player_id = p.player_id
     WHERE p.player_id = $1`,
    [playerId]
  );

  const row = result.rows[0];

  if (!row) {
    throw publicError(
      404,
      "PLAYER_NOT_FOUND",
      "Oyuncu bulunamadı."
    );
  }

  const lastChangeMs =
    row.last_username_change_at
      ? new Date(
          row.last_username_change_at
        ).getTime()
      : 0;

  const nextChangeAt =
    lastChangeMs > 0
      ? lastChangeMs +
        USERNAME_CHANGE_MS
      : 0;

  const now = nowMs();
  const level = levelForXp(row.total_xp);

  return {
    playerId,
    username: row.username || "",
    googleDisplayName:
      row.google_display_name || "Oyuncu",
    country: safeCountry(row.country),
    usernameChangeCount: Number(
      row.username_change_count || 0
    ),
    lastUsernameChangeAtMillis:
      lastChangeMs,
    usernameNextChangeAtMillis:
      nextChangeAt,
    usernameMillisUntilNextChange:
      Math.max(0, nextChangeAt - now),
    totalScore: Number(
      row.general_score || 0
    ),
    infiniteHighScore: Number(
      row.infinite_high_score || 0
    ),
    level,
    gameRights: rights,
    hasInfiniteProgress: Boolean(
      row.infinite_session_id
    ),
    infiniteStage: Number(
      row.infinite_stage || 1
    ),
    infiniteScore: Number(
      row.infinite_score || 0
    ),
    tournament: {
      currentStage: Number(
        row.tournament_current_stage || 1
      ),
      remainingRights: Number(
        row.tournament_remaining_rights ||
          TOURNAMENT_INITIAL_RIGHTS
      ),
      totalScore: Number(
        row.tournament_total_score || 0
      ),
      completed: Boolean(
        row.tournament_completed
      ),
    },
    statistics: normalizedStatistics(
      row.statistics
    ),
    serverTimeMillis: now,
  };
}

async function applyRewards(
  client,
  playerId,
  generalDelta,
  infiniteHighCandidate,
  xpDelta
) {
  const safeGeneral = clampInt(
    generalDelta,
    -100_000,
    100_000,
    0
  );

  const safeHigh = clampInt(
    infiniteHighCandidate,
    0,
    MAX_SCORE,
    0
  );

  const safeXp = clampInt(
    xpDelta,
    0,
    1_000_000,
    0
  );

  await client.query(
    `UPDATE player_state
     SET
       general_score = GREATEST(
         0,
         LEAST(
           $2,
           general_score + $3
         )
       ),
       infinite_high_score =
         GREATEST(
           infinite_high_score,
           $4
         ),
       total_xp = LEAST(
         $2,
         total_xp + $5
       ),
       updated_at = NOW()
     WHERE player_id = $1`,
    [
      playerId,
      MAX_SCORE,
      safeGeneral,
      safeHigh,
      safeXp,
    ]
  );

  if (
    safeGeneral !== 0 ||
    safeHigh > 0
  ) {
    await client.query(
      `INSERT INTO player_monthly_scores (
         player_id,
         month_key,
         general_score,
         infinite_score,
         updated_at
       )
       VALUES (
         $1,
         $2,
         GREATEST($3, 0),
         GREATEST($4, 0),
         NOW()
       )
       ON CONFLICT (
         player_id,
         month_key
       )
       DO UPDATE SET
         general_score =
           GREATEST(
             0,
             LEAST(
               $5,
               player_monthly_scores.general_score
                 + $3
             )
           ),
         infinite_score =
           GREATEST(
             player_monthly_scores.infinite_score,
             $4
           ),
         updated_at = NOW()`,
      [
        playerId,
        currentMonthKey(),
        safeGeneral,
        safeHigh,
        MAX_SCORE,
      ]
    );
  }
}

function rewardForDifficulty(difficulty) {
  return normalizeDifficulty(difficulty) ===
    "Hard"
    ? 15
    : 10;
}

function twoPlayerXp(difficulty) {
  return normalizeDifficulty(difficulty) ===
    "Hard"
    ? 30
    : 20;
}

function tournamentDifficulty(stage) {
  return clampInt(
    stage,
    1,
    TOURNAMENT_TOTAL_STAGES,
    1
  ) <= 4
    ? "Medium"
    : "Hard";
}

function tournamentStageReward(stage) {
  const safe = clampInt(
    stage,
    1,
    TOURNAMENT_TOTAL_STAGES,
    1
  );

  return safe >= TOURNAMENT_TOTAL_STAGES
    ? 480
    : safe * 20;
}

function infiniteDifficulty(stage) {
  return clampInt(
    stage,
    1,
    1_000_000,
    1
  ) <= 5
    ? "Medium"
    : "Hard";
}

function infiniteStageReward(stage) {
  return (
    clampInt(
      stage,
      1,
      1_000_000,
      1
    ) * 5
  );
}

function infiniteXpReward(stage) {
  const safe = BigInt(
    clampInt(
      stage,
      1,
      100_000,
      1
    )
  );

  const value =
    (safe * (safe + 1n) * 5n) /
    2n;

  return Number(
    value > BigInt(MAX_SCORE)
      ? BigInt(MAX_SCORE)
      : value
  );
}

function hundredDifficulty(stage) {
  return clampInt(
    stage,
    1,
    HUNDRED_TOTAL_STAGES,
    1
  ) <= 4
    ? "Medium"
    : "Hard";
}

function hundredStageLimitMs(_stage) {
  return 90_000;
}

function randomInt(
  minInclusive,
  maxInclusive
) {
  return crypto.randomInt(
    minInclusive,
    maxInclusive + 1
  );
}

function shuffle(values) {
  const result = [...values];

  for (
    let index = result.length - 1;
    index > 0;
    index -= 1
  ) {
    const swapIndex = crypto.randomInt(
      0,
      index + 1
    );

    [
      result[index],
      result[swapIndex],
    ] = [
      result[swapIndex],
      result[index],
    ];
  }

  return result;
}

function buildOrders(values) {
  if (!values.length) {
    return [[]];
  }

  const output = [];

  values.forEach((value, index) => {
    const rest = values
      .slice(0, index)
      .concat(values.slice(index + 1));

    for (const order of buildOrders(rest)) {
      output.push([value, ...order]);
    }
  });

  return output;
}

function buildOperatorOrders(
  operators,
  count
) {
  if (count <= 0) {
    return [[]];
  }

  const output = [];

  for (const operator of operators) {
    for (
      const rest of buildOperatorOrders(
        operators,
        count - 1
      )
    ) {
      output.push([operator, ...rest]);
    }
  }

  return output;
}

function evaluateExpression(
  numbers,
  operators
) {
  if (
    !Array.isArray(numbers) ||
    !numbers.length ||
    !Array.isArray(operators) ||
    operators.length !==
      numbers.length - 1
  ) {
    return null;
  }

  const additiveNumbers = [
    Number(numbers[0]),
  ];

  const additiveOperators = [];

  for (
    let index = 0;
    index < operators.length;
    index += 1
  ) {
    const operator = operators[index];

    const next = Number(
      numbers[index + 1]
    );

    if (!Number.isFinite(next)) {
      return null;
    }

    if (operator === "×") {
      additiveNumbers[
        additiveNumbers.length - 1
      ] *= next;
    } else if (operator === "÷") {
      if (Math.abs(next) < 0.0001) {
        return null;
      }

      additiveNumbers[
        additiveNumbers.length - 1
      ] /= next;
    } else if (
      operator === "+" ||
      operator === "−"
    ) {
      additiveOperators.push(operator);
      additiveNumbers.push(next);
    } else {
      return null;
    }
  }

  let result = additiveNumbers[0];

  additiveOperators.forEach(
    (operator, index) => {
      result =
        operator === "+"
          ? result +
            additiveNumbers[index + 1]
          : result -
            additiveNumbers[index + 1];
    }
  );

  return Number.isFinite(result)
    ? result
    : null;
}

function buildAddSubtractTargets(numbers) {
  const targets = new Set();

  for (const order of buildOrders(numbers)) {
    for (
      const operators of buildOperatorOrders(
        ["+", "−"],
        numbers.length - 1
      )
    ) {
      const result = evaluateExpression(
        order,
        operators
      );

      if (
        result !== null &&
        Math.abs(
          result - Math.round(result)
        ) < 0.0001
      ) {
        targets.add(Math.round(result));
      }
    }
  }

  return targets;
}

function buildSolvableTarget(
  numbers,
  minTarget,
  maxTarget,
  requireMultiplyOrDivide
) {
  const allOperators = [
    "+",
    "−",
    "×",
    "÷",
  ];

  const addOnly =
    requireMultiplyOrDivide
      ? buildAddSubtractTargets(numbers)
      : new Set();

  const numberOrders = shuffle(
    buildOrders(numbers)
  );

  const operatorOrders = shuffle(
    buildOperatorOrders(
      allOperators,
      numbers.length - 1
    )
  );

  for (const ordered of numberOrders) {
    for (
      const operators of operatorOrders
    ) {
      if (
        requireMultiplyOrDivide &&
        !operators.some(
          (item) =>
            item === "×" ||
            item === "÷"
        )
      ) {
        continue;
      }

      const result = evaluateExpression(
        ordered,
        operators
      );

      if (result === null) {
        continue;
      }

      const rounded = Math.round(result);

      if (
        Math.abs(result - rounded) <
          0.0001 &&
        rounded >= minTarget &&
        rounded <= maxTarget &&
        !addOnly.has(rounded)
      ) {
        return rounded;
      }
    }
  }

  return null;
}

function generatePuzzle(difficultyValue) {
  const difficulty =
    normalizeDifficulty(
      difficultyValue
    );

  const count =
    difficulty === "Hard" ? 4 : 3;

  const min =
    difficulty === "Hard" ? 2 : 1;

  const max =
    difficulty === "Hard" ? 20 : 9;

  const targetMin =
    difficulty === "Hard" ? 21 : 1;

  const targetMax =
    difficulty === "Hard" ? 199 : 49;

  for (
    let attempt = 0;
    attempt < 500;
    attempt += 1
  ) {
    const numbers = [];
    let oneUsed = false;

    while (numbers.length < count) {
      const number = randomInt(
        min,
        max
      );

      if (
        number === 1 &&
        oneUsed
      ) {
        continue;
      }

      if (number === 1) {
        oneUsed = true;
      }

      numbers.push(number);
    }

    const shuffled =
      shuffle(numbers);

    const target =
      buildSolvableTarget(
        shuffled,
        targetMin,
        targetMax,
        difficulty === "Hard"
      );

    if (target !== null) {
      return {
        difficulty,
        target,
        numbers: shuffled,
      };
    }
  }

  return difficulty === "Hard"
    ? {
        difficulty,
        target: 24,
        numbers: shuffle([
          10,
          10,
          5,
          4,
        ]),
      }
    : {
        difficulty,
        target: 15,
        numbers: shuffle([
          3,
          5,
          7,
        ]),
      };
}

function validateSolution(
  puzzle,
  numberSlots,
  operatorSlots
) {
  if (
    !puzzle ||
    !Array.isArray(puzzle.numbers)
  ) {
    return false;
  }

  const count =
    puzzle.numbers.length;

  if (
    !Array.isArray(numberSlots) ||
    numberSlots.length !== count
  ) {
    return false;
  }

  if (
    !Array.isArray(operatorSlots) ||
    operatorSlots.length !== count - 1
  ) {
    return false;
  }

  const indices = numberSlots.map(
    (value) => Number(value)
  );

  if (
    indices.some(
      (value) =>
        !Number.isInteger(value) ||
        value < 0 ||
        value >= count
    )
  ) {
    return false;
  }

  if (
    new Set(indices).size !== count
  ) {
    return false;
  }

  const operators =
    operatorSlots.map(
      (value) => String(value)
    );

  if (
    operators.some(
      (value) =>
        ![
          "+",
          "−",
          "×",
          "÷",
        ].includes(value)
    )
  ) {
    return false;
  }

  const orderedNumbers =
    indices.map(
      (index) =>
        Number(
          puzzle.numbers[index]
        )
    );

  const result = evaluateExpression(
    orderedNumbers,
    operators
  );

  return (
    result !== null &&
    Math.abs(
      result -
        Number(puzzle.target)
    ) < 0.0001
  );
}

function sessionRemainingMs(row) {
  if (!row) {
    return 0;
  }

  if (row.status === "paused") {
    return Math.max(
      0,
      Number(
        row.paused_remaining_ms || 0
      )
    );
  }

  return Math.max(
    0,
    new Date(
      row.deadline_at
    ).getTime() - nowMs()
  );
}

function sessionElapsedMs(row) {
  if (!row) {
    return 0;
  }

  const stored = Math.max(
    0,
    Number(
      row.elapsed_active_ms || 0
    )
  );

  if (row.status !== "active") {
    return stored;
  }

  return (
    stored +
    Math.max(
      0,
      nowMs() -
        new Date(
          row.started_at
        ).getTime()
    )
  );
}

function sanitizePartialSolution(
  puzzle,
  numberSlotsValue,
  operatorSlotsValue
) {
  const count = Array.isArray(
    puzzle?.numbers
  )
    ? puzzle.numbers.length
    : 0;

  const rawNumbers =
    Array.isArray(numberSlotsValue)
      ? numberSlotsValue.slice(0, count)
      : [];

  const rawOperators =
    Array.isArray(operatorSlotsValue)
      ? operatorSlotsValue.slice(
          0,
          Math.max(0, count - 1)
        )
      : [];

  const numberSlots = Array.from(
    { length: count },
    (_unused, index) => {
      const value =
        rawNumbers[index];

      if (
        value === null ||
        value === undefined
      ) {
        return null;
      }

      const parsed = Number(value);

      return (
        Number.isInteger(parsed) &&
        parsed >= 0 &&
        parsed < count
      )
        ? parsed
        : null;
    }
  );

  const seen = new Set();

  for (
    let index = 0;
    index < numberSlots.length;
    index += 1
  ) {
    const value =
      numberSlots[index];

    if (value === null) {
      continue;
    }

    if (seen.has(value)) {
      numberSlots[index] = null;
    } else {
      seen.add(value);
    }
  }

  const operatorSlots = Array.from(
    {
      length: Math.max(
        0,
        count - 1
      ),
    },
    (_unused, index) => {
      const value =
        rawOperators[index];

      if (
        value === null ||
        value === undefined
      ) {
        return null;
      }

      const operator =
        String(value);

      return [
        "+",
        "−",
        "×",
        "÷",
      ].includes(operator)
        ? operator
        : null;
    }
  );

  return {
    numberSlots,
    operatorSlots,
  };
}

function sessionPublic(
  row,
  progress = null
) {
  if (!row) {
    return null;
  }

  const remainingMs =
    sessionRemainingMs(row);

  return {
    sessionId: row.session_id,
    mode: row.mode,
    difficulty: row.difficulty,
    stage: Number(row.stage || 1),
    puzzle: row.puzzle,
    startedAtMillis: new Date(
      row.started_at
    ).getTime(),
    deadlineAtMillis:
      row.status === "paused"
        ? nowMs() + remainingMs
        : new Date(
            row.deadline_at
          ).getTime(),
    numberSlots:
      progress?.infinite_number_slots ||
      undefined,
    operatorSlots:
      progress?.infinite_operator_slots ||
      undefined,
    remainingMs,
    paused:
      row.status === "paused",
    metadata: row.metadata || {},
  };
}

async function createTargetSession(
  client,
  playerId,
  mode,
  difficulty,
  stage,
  metadata = {},
  customLimitMs = null
) {
  const puzzle =
    generatePuzzle(difficulty);

  const sessionId =
    crypto.randomUUID();

  const limitMs =
    customLimitMs ||
    (
      mode === "single"
        ? SINGLE_LIMIT_MS
        : mode === "infinite"
          ? INFINITE_LIMIT_MS
          : hundredStageLimitMs(stage)
    );

  const result = await client.query(
    `INSERT INTO target_number_sessions (
       session_id,
       player_id,
       mode,
       difficulty,
       stage,
       puzzle,
       metadata,
       started_at,
       deadline_at,
       status,
       updated_at
     )
     VALUES (
       $1,
       $2,
       $3,
       $4,
       $5,
       $6::jsonb,
       $7::jsonb,
       NOW(),
       NOW() + (
         $8 * INTERVAL '1 millisecond'
       ),
       'active',
       NOW()
     )
     RETURNING *`,
    [
      sessionId,
      playerId,
      mode,
      normalizeDifficulty(difficulty),
      stage,
      JSON.stringify(puzzle),
      JSON.stringify(metadata),
      limitMs,
    ]
  );

  return result.rows[0];
}

async function closeOtherActiveSessions(
  client,
  playerId,
  mode
) {
  await client.query(
    `UPDATE target_number_sessions
     SET
       status = 'abandoned',
       finished_at = NOW(),
       updated_at = NOW()
     WHERE
       player_id = $1
       AND mode = $2
       AND status IN (
         'active',
         'paused'
       )`,
    [
      playerId,
      mode,
    ]
  );
}

app.get("/", (_req, res) => {
  res.json({
    ok: true,
    service:
      "target-number-secure-server",
    serverTimeMillis: nowMs(),
  });
});

app.get(
  "/health",
  async (_req, res) => {
    if (!pool) {
      res.status(503).json({
        ok: false,
        database: false,
      });

      return;
    }

    try {
      await pool.query("SELECT 1");

      res.json({
        ok: true,
        database: true,
        serverTimeMillis: nowMs(),
      });
    } catch (error) {
      sendError(
        res,
        error,
        "Veritabanı bağlantısı başarısız."
      );
    }
  }
);

app.post(
  "/auth/play-games",
  authHttpRateLimit,
  async (req, res) => {
    if (!requireDatabase(res)) {
      return;
    }

    try {
      const identity =
        await exchangePlayGamesAuthCode(
          req.body?.authCode
        );

      const client =
        await pool.connect();

      try {
        await client.query("BEGIN");

        await ensurePlayer(
          client,
          identity,
          req.body?.country
        );

        const state =
          await loadPlayerSnapshot(
            client,
            identity.playerId
          );

        await client.query("COMMIT");

        res.json({
          ok: true,
          token: createSessionToken(
            identity.playerId
          ),
          state,
        });
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        client.release();
      }
    } catch (error) {
      sendError(
        res,
        error,
        "Play Games doğrulaması tamamlanamadı."
      );
    }
  }
);

app.get(
  "/player/state",
  authMiddleware,
  async (req, res) => {
    if (!requireDatabase(res)) {
      return;
    }

    try {
      const client =
        await pool.connect();

      try {
        const state =
          await loadPlayerSnapshot(
            client,
            req.auth.playerId
          );

        res.json({
          ok: true,
          state,
        });
      } finally {
        client.release();
      }
    } catch (error) {
      sendError(
        res,
        error,
        "Oyuncu bilgileri alınamadı."
      );
    }
  }
);

app.post(
  "/player/username",
  authMiddleware,
  async (req, res) => {
    if (!requireDatabase(res)) {
      return;
    }

    const username =
      normalizeUsername(
        req.body?.username
      );

    const validationError =
      validateUsername(
        req.body?.username
      );

    if (validationError) {
      res.status(400).json({
        ok: false,
        code: "INVALID_USERNAME",
        message: validationError,
      });

      return;
    }

    const client =
      await pool.connect();

    try {
      await client.query("BEGIN");

      const currentResult =
        await client.query(
          `SELECT
             username,
             username_change_count,
             last_username_change_at
           FROM players
           WHERE player_id = $1
           FOR UPDATE`,
          [req.auth.playerId]
        );

      const current =
        currentResult.rows[0];

      if (!current) {
        throw publicError(
          404,
          "PLAYER_NOT_FOUND",
          "Oyuncu bulunamadı."
        );
      }

      if (
        String(
          current.username || ""
        ).toLowerCase() ===
        username.toLowerCase()
      ) {
        throw publicError(
          409,
          "USERNAME_UNCHANGED",
          "Yeni kullanıcı adı mevcut adınla aynı olamaz."
        );
      }

      const hasUsername =
        Boolean(current.username);

      const lastChangeMs =
        current.last_username_change_at
          ? new Date(
              current.last_username_change_at
            ).getTime()
          : 0;

      if (
        hasUsername &&
        lastChangeMs +
          USERNAME_CHANGE_MS >
          nowMs()
      ) {
        throw publicError(
          429,
          "USERNAME_COOLDOWN",
          "Kullanıcı adını tekrar değiştirmek için 1 ay beklemelisin."
        );
      }

      const taken =
        await client.query(
          `SELECT 1
           FROM players
           WHERE
             LOWER(username) =
               LOWER($1)
             AND player_id <> $2
           LIMIT 1`,
          [
            username,
            req.auth.playerId,
          ]
        );

      if (taken.rowCount > 0) {
        throw publicError(
          409,
          "USERNAME_TAKEN",
          "Bu kullanıcı adı zaten alınmış."
        );
      }

      await client.query(
        `UPDATE players
         SET
           username = $2,
           username_change_count =
             username_change_count +
             CASE
               WHEN username = ''
               THEN 0
               ELSE 1
             END,
           last_username_change_at =
             CASE
               WHEN username = ''
               THEN NULL
               ELSE NOW()
             END,
           updated_at = NOW()
         WHERE player_id = $1`,
        [
          req.auth.playerId,
          username,
        ]
      );

      const state =
        await loadPlayerSnapshot(
          client,
          req.auth.playerId
        );

      await client.query("COMMIT");

      res.json({
        ok: true,
        state,
      });
    } catch (error) {
      await client.query("ROLLBACK");

      sendError(
        res,
        error,
        "Kullanıcı adı kaydedilemedi."
      );
    } finally {
      client.release();
    }
  }
);

app.get(
  "/leaderboard",
  authMiddleware,
  async (req, res) => {
    if (!requireDatabase(res)) {
      return;
    }

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

    const country =
      safeCountry(req.query.country);

    const scoreColumn =
      scoreType === "infinite"
        ? (
            period === "month"
              ? "infinite_score"
              : "infinite_high_score"
          )
        : "general_score";

    const table =
      period === "month"
        ? "player_monthly_scores"
        : "player_state";

    const monthKey =
      currentMonthKey();

    try {
      const baseConditions = [
        `s.${scoreColumn} > 0`,
      ];

      const baseValues = [];

      if (period === "month") {
        baseValues.push(monthKey);

        baseConditions.push(
          `s.month_key = $${baseValues.length}`
        );
      }

      const buildQuery = (
        countryFilter
      ) => {
        const values = [
          ...baseValues,
        ];

        const conditions = [
          ...baseConditions,
        ];

        if (countryFilter) {
          values.push(country);

          conditions.push(
            `p.country = $${values.length}`
          );
        }

        return {
          values,
          where:
            conditions.join(" AND "),
        };
      };

      const listBuilt =
        buildQuery(
          scope === "country"
        );

      const list =
        await pool.query(
          `WITH ranked AS (
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
             FROM ${table} s
             JOIN players p
               ON p.player_id =
                  s.player_id
             WHERE ${listBuilt.where}
           )
           SELECT
             position,
             username,
             country,
             score
           FROM ranked
           ORDER BY position
           LIMIT 50`,
          listBuilt.values
        );

      async function myRank(
        countryFilter
      ) {
        const built =
          buildQuery(countryFilter);

        built.values.push(
          req.auth.playerId
        );

        const playerParam =
          built.values.length;

        const result =
          await pool.query(
            `WITH ranked AS (
               SELECT
                 p.player_id,
                 s.${scoreColumn}
                   AS score,
                 ROW_NUMBER() OVER (
                   ORDER BY
                     s.${scoreColumn}
                       DESC,
                     s.updated_at ASC,
                     p.username ASC
                 ) AS position
               FROM ${table} s
               JOIN players p
                 ON p.player_id =
                    s.player_id
               WHERE ${built.where}
             )
             SELECT
               position,
               score
             FROM ranked
             WHERE
               player_id =
                 $${playerParam}
             LIMIT 1`,
            built.values
          );

        return (
          result.rows[0] || null
        );
      }

      const world =
        await myRank(false);

      const local =
        await myRank(true);

      res.json({
        ok: true,
        scoreType,
        period,
        scope,
        country,
        myWorldRank:
          world
            ? Number(world.position)
            : null,
        myCountryRank:
          local
            ? Number(local.position)
            : null,
        myScore:
          world
            ? Number(world.score)
            : 0,
        rows: list.rows.map(
          (row) => ({
            rank: Number(
              row.position
            ),
            username:
              row.username ||
              "Oyuncu",
            country: safeCountry(
              row.country
            ),
            score: Number(
              row.score || 0
            ),
          })
        ),
      });
    } catch (error) {
      sendError(
        res,
        error,
        "Skor tablosu alınamadı."
      );
    }
  }
);

app.post(
  "/target-number/session/start",
  authMiddleware,
  async (req, res) => {
    if (!requireDatabase(res)) {
      return;
    }

    const mode =
      normalizeMode(req.body?.mode);

    const requestedDifficulty =
      normalizeDifficulty(
        req.body?.difficulty
      );

    const fresh =
      Boolean(req.body?.fresh);

    const client =
      await pool.connect();

    try {
      await client.query("BEGIN");

      let session;
      let responseProgress = null;

      if (mode === "infinite") {
        const progressResult =
          await client.query(
            `SELECT *
             FROM target_number_progress
             WHERE player_id = $1
             FOR UPDATE`,
            [req.auth.playerId]
          );

        let progress =
          progressResult.rows[0];

        if (fresh) {
          await closeOtherActiveSessions(
            client,
            req.auth.playerId,
            "infinite"
          );

          session =
            await createTargetSession(
              client,
              req.auth.playerId,
              "infinite",
              infiniteDifficulty(1),
              1
            );

          await client.query(
            `UPDATE target_number_progress
             SET
               infinite_session_id = $2,
               infinite_stage = 1,
               infinite_score = 0,
               infinite_puzzle = $3::jsonb,
               infinite_number_slots =
                 $4::jsonb,
               infinite_operator_slots =
                 $5::jsonb,
               infinite_remaining_ms = $6,
               updated_at = NOW()
             WHERE player_id = $1`,
            [
              req.auth.playerId,
              session.session_id,
              JSON.stringify(
                session.puzzle
              ),
              JSON.stringify(
                Array(
                  session.puzzle
                    .numbers.length
                ).fill(null)
              ),
              JSON.stringify(
                Array(
                  session.puzzle
                    .numbers.length - 1
                ).fill(null)
              ),
              INFINITE_LIMIT_MS,
            ]
          );
        } else if (
          progress?.infinite_session_id
        ) {
          const existing =
            await client.query(
              `SELECT *
               FROM target_number_sessions
               WHERE
                 session_id = $1
                 AND player_id = $2
                 AND status IN (
                   'active',
                   'paused'
                 )
               FOR UPDATE`,
              [
                progress
                  .infinite_session_id,
                req.auth.playerId,
              ]
            );

          session =
            existing.rows[0];

          if (
            session?.status ===
              "active" &&
            sessionRemainingMs(
              session
            ) <= 0
          ) {
            await client.query(
              `UPDATE target_number_sessions
               SET
                 status = 'expired',
                 finished_at = NOW(),
                 updated_at = NOW()
               WHERE session_id = $1`,
              [session.session_id]
            );

            session = null;

            progress = {
              ...progress,
              infinite_session_id:
                null,
              infinite_stage: 1,
              infinite_score: 0,
            };

            await client.query(
              `UPDATE target_number_progress
               SET
                 infinite_session_id =
                   NULL,
                 infinite_stage = 1,
                 infinite_score = 0,
                 infinite_puzzle = NULL,
                 infinite_number_slots =
                   NULL,
                 infinite_operator_slots =
                   NULL,
                 infinite_remaining_ms =
                   NULL,
                 updated_at = NOW()
               WHERE player_id = $1`,
              [req.auth.playerId]
            );
          } else if (
            session?.status ===
            "paused"
          ) {
            const remainingMs =
              sessionRemainingMs(
                session
              );

            if (remainingMs <= 0) {
              await client.query(
                `UPDATE target_number_sessions
                 SET
                   status = 'expired',
                   finished_at = NOW(),
                   updated_at = NOW()
                 WHERE session_id = $1`,
                [session.session_id]
              );

              await client.query(
                `UPDATE target_number_progress
                 SET
                   infinite_session_id =
                     NULL,
                   infinite_stage = 1,
                   infinite_score = 0,
                   infinite_puzzle = NULL,
                   infinite_number_slots =
                     NULL,
                   infinite_operator_slots =
                     NULL,
                   infinite_remaining_ms =
                     NULL,
                   updated_at = NOW()
                 WHERE player_id = $1`,
                [req.auth.playerId]
              );

              session = null;

              progress = {
                ...progress,
                infinite_session_id:
                  null,
                infinite_stage: 1,
                infinite_score: 0,
              };
            } else {
              const resumed =
                await client.query(
                  `UPDATE target_number_sessions
                   SET
                     status = 'active',
                     started_at = NOW(),
                     deadline_at =
                       NOW() + (
                         $2 *
                         INTERVAL
                           '1 millisecond'
                       ),
                     paused_remaining_ms =
                       NULL,
                     updated_at = NOW()
                   WHERE session_id = $1
                   RETURNING *`,
                  [
                    session.session_id,
                    remainingMs,
                  ]
                );

              session =
                resumed.rows[0];
            }
          }
        }

        if (!session) {
          const stage =
            progress?.infinite_stage > 0
              ? Number(
                  progress.infinite_stage
                )
              : 1;

          const score =
            progress?.infinite_score > 0
              ? Number(
                  progress.infinite_score
                )
              : 0;

          session =
            await createTargetSession(
              client,
              req.auth.playerId,
              "infinite",
              infiniteDifficulty(stage),
              stage
            );

          await client.query(
            `UPDATE target_number_progress
             SET
               infinite_session_id = $2,
               infinite_stage = $3,
               infinite_score = $4,
               infinite_puzzle = $5::jsonb,
               infinite_number_slots =
                 $6::jsonb,
               infinite_operator_slots =
                 $7::jsonb,
               infinite_remaining_ms = $8,
               updated_at = NOW()
             WHERE player_id = $1`,
            [
              req.auth.playerId,
              session.session_id,
              stage,
              score,
              JSON.stringify(
                session.puzzle
              ),
              JSON.stringify(
                Array(
                  session.puzzle
                    .numbers.length
                ).fill(null)
              ),
              JSON.stringify(
                Array(
                  session.puzzle
                    .numbers.length - 1
                ).fill(null)
              ),
              INFINITE_LIMIT_MS,
            ]
          );
        }

        const refreshedProgress =
          await client.query(
            `SELECT *
             FROM target_number_progress
             WHERE player_id = $1`,
            [req.auth.playerId]
          );

        responseProgress =
          refreshedProgress.rows[0] ||
          null;
      } else if (
        mode === "hundred"
      ) {
        await closeOtherActiveSessions(
          client,
          req.auth.playerId,
          "hundred"
        );

        const progressResult =
          await client.query(
            `SELECT *
             FROM target_number_progress
             WHERE player_id = $1
             FOR UPDATE`,
            [req.auth.playerId]
          );

        const progress =
          progressResult.rows[0];

        const stage =
          fresh ||
          !progress?.hundred_active
            ? 1
            : clampInt(
                progress
                  .hundred_current_stage,
                1,
                HUNDRED_TOTAL_STAGES,
                1
              );

        if (
          fresh ||
          !progress?.hundred_active
        ) {
          await client.query(
            `UPDATE target_number_progress
             SET
               hundred_current_stage = 1,
               hundred_total_elapsed_ms =
                 0,
               hundred_active = TRUE,
               updated_at = NOW()
             WHERE player_id = $1`,
            [req.auth.playerId]
          );
        }

        const cutoff = Math.floor(
          hundredStageLimitMs(stage) *
            (
              0.60 +
              Math.random() * 0.35
            )
        );

        const rankSeed =
          crypto.randomInt(1, 101);

        session =
          await createTargetSession(
            client,
            req.auth.playerId,
            "hundred",
            hundredDifficulty(stage),
            stage,
            {
              qualifyingCutoffMs:
                cutoff,
              rankSeed,
              totalStages:
                HUNDRED_TOTAL_STAGES,
            },
            hundredStageLimitMs(
              stage
            )
          );
      } else {
        await closeOtherActiveSessions(
          client,
          req.auth.playerId,
          "single"
        );

        session =
          await createTargetSession(
            client,
            req.auth.playerId,
            "single",
            requestedDifficulty,
            1
          );
      }

      const state =
        await loadPlayerSnapshot(
          client,
          req.auth.playerId
        );

      await client.query("COMMIT");

      res.json({
        ok: true,
        session: sessionPublic(
          session,
          responseProgress
        ),
        state,
      });
    } catch (error) {
      await client.query("ROLLBACK");

      sendError(
        res,
        error,
        "Oyun oturumu başlatılamadı."
      );
    } finally {
      client.release();
    }
  }
);

app.post(
  "/target-number/session/progress",
  authMiddleware,
  async (req, res) => {
    if (!requireDatabase(res)) {
      return;
    }

    const sessionId = safeText(
      req.body?.sessionId,
      "",
      64
    );

    const pause =
      Boolean(req.body?.pause);

    const client =
      await pool.connect();

    try {
      await client.query("BEGIN");

      const result =
        await client.query(
          `SELECT *
           FROM target_number_sessions
           WHERE
             session_id = $1
             AND player_id = $2
             AND status IN (
               'active',
               'paused'
             )
           FOR UPDATE`,
          [
            sessionId,
            req.auth.playerId,
          ]
        );

      let session =
        result.rows[0];

      if (!session) {
        throw publicError(
          404,
          "SESSION_NOT_FOUND",
          "Aktif oyun oturumu bulunamadı."
        );
      }

      if (
        session.mode !== "infinite"
      ) {
        throw publicError(
          409,
          "PROGRESS_NOT_ALLOWED",
          "Bu oyun türünde ilerleme kaydı desteklenmiyor."
        );
      }

      const partial =
        sanitizePartialSolution(
          session.puzzle,
          req.body?.numberSlots,
          req.body?.operatorSlots
        );

      let remainingMs =
        sessionRemainingMs(session);

      if (remainingMs <= 0) {
        await client.query(
          `UPDATE target_number_sessions
           SET
             status = 'expired',
             finished_at = NOW(),
             updated_at = NOW()
           WHERE session_id = $1`,
          [session.session_id]
        );

        await client.query(
          `UPDATE target_number_progress
           SET
             infinite_session_id = NULL,
             infinite_stage = 1,
             infinite_score = 0,
             infinite_puzzle = NULL,
             infinite_number_slots = NULL,
             infinite_operator_slots =
               NULL,
             infinite_remaining_ms = NULL,
             updated_at = NOW()
           WHERE player_id = $1`,
          [req.auth.playerId]
        );

        await client.query("COMMIT");

        res.status(409).json({
          ok: false,
          code: "SESSION_EXPIRED",
          message:
            "Oyun süresi dolmuş.",
        });

        return;
      }

      if (
        session.status === "active" &&
        pause
      ) {
        const elapsedActiveMs =
          sessionElapsedMs(session);

        const paused =
          await client.query(
            `UPDATE target_number_sessions
             SET
               status = 'paused',
               elapsed_active_ms = $2,
               paused_remaining_ms = $3,
               updated_at = NOW()
             WHERE session_id = $1
             RETURNING *`,
            [
              session.session_id,
              elapsedActiveMs,
              remainingMs,
            ]
          );

        session = paused.rows[0];
      } else if (
        session.status === "paused" &&
        !pause
      ) {
        const resumed =
          await client.query(
            `UPDATE target_number_sessions
             SET
               status = 'active',
               started_at = NOW(),
               deadline_at =
                 NOW() + (
                   $2 *
                   INTERVAL
                     '1 millisecond'
                 ),
               paused_remaining_ms = NULL,
               updated_at = NOW()
             WHERE session_id = $1
             RETURNING *`,
            [
              session.session_id,
              remainingMs,
            ]
          );

        session = resumed.rows[0];
      }

      remainingMs =
        sessionRemainingMs(session);

      await client.query(
        `UPDATE target_number_progress
         SET
           infinite_number_slots =
             $2::jsonb,
           infinite_operator_slots =
             $3::jsonb,
           infinite_remaining_ms = $4,
           updated_at = NOW()
         WHERE player_id = $1`,
        [
          req.auth.playerId,
          JSON.stringify(
            partial.numberSlots
          ),
          JSON.stringify(
            partial.operatorSlots
          ),
          remainingMs,
        ]
      );

      const progressResult =
        await client.query(
          `SELECT *
           FROM target_number_progress
           WHERE player_id = $1`,
          [req.auth.playerId]
        );

      await client.query("COMMIT");

      res.json({
        ok: true,
        session: sessionPublic(
          session,
          progressResult.rows[0] ||
            null
        ),
      });
    } catch (error) {
      await client
        .query("ROLLBACK")
        .catch(() => {});

      sendError(
        res,
        error,
        "İlerleme kaydedilemedi."
      );
    } finally {
      client.release();
    }
  }
);

app.post(
  "/target-number/session/finish",
  authMiddleware,
  async (req, res) => {
    if (!requireDatabase(res)) {
      return;
    }

    const sessionId = safeText(
      req.body?.sessionId,
      "",
      64
    );

    const client =
      await pool.connect();

    try {
      await client.query("BEGIN");

      const result =
        await client.query(
          `SELECT *
           FROM target_number_sessions
           WHERE
             session_id = $1
             AND player_id = $2
           FOR UPDATE`,
          [
            sessionId,
            req.auth.playerId,
          ]
        );

      const session =
        result.rows[0];

      if (!session) {
        throw publicError(
          404,
          "SESSION_NOT_FOUND",
          "Oyun oturumu bulunamadı."
        );
      }

      if (
        session.status !== "active"
      ) {
        throw publicError(
          409,
          "SESSION_FINISHED",
          "Bu oyun oturumu zaten tamamlanmış."
        );
      }

      const deadlineMs =
        new Date(
          session.deadline_at
        ).getTime();

      if (
        nowMs() >
        deadlineMs + 2_000
      ) {
        throw publicError(
          409,
          "SESSION_EXPIRED",
          "Oyun süresi dolmuş."
        );
      }

      const elapsedMs = Math.max(
        1,
        sessionElapsedMs(session)
      );

      if (
        elapsedMs < MIN_SOLUTION_MS
      ) {
        throw publicError(
          409,
          "SOLUTION_TOO_FAST",
          "Çözüm olağan dışı derecede hızlı gönderildi."
        );
      }

      if (
        !validateSolution(
          session.puzzle,
          req.body?.numberSlots,
          req.body?.operatorSlots
        )
      ) {
        throw publicError(
          422,
          "INVALID_SOLUTION",
          "Gönderilen çözüm hedef sayıyı doğrulamıyor."
        );
      }

      let generalAward = 0;
      let infiniteAward = 0;
      let xpAward = 0;
      let nextSession = null;
      let modeResult = {};

      const progressResult =
        await client.query(
          `SELECT *
           FROM target_number_progress
           WHERE player_id = $1
           FOR UPDATE`,
          [req.auth.playerId]
        );

      const progress =
        progressResult.rows[0];

      const stats =
        normalizedStatistics(
          progress?.statistics
        );

      if (
        session.mode === "single"
      ) {
        generalAward =
          rewardForDifficulty(
            session.difficulty
          );

        xpAward = generalAward;

        updateClassicStats(
          stats,
          session.difficulty === "Hard"
            ? "singleHard"
            : "singleMedium",
          true,
          elapsedMs
        );
      } else if (
        session.mode === "infinite"
      ) {
        const stage = Number(
          session.stage || 1
        );

        infiniteAward =
          infiniteStageReward(stage);

        xpAward =
          infiniteXpReward(stage);

        const currentRunScore =
          Number(
            progress?.infinite_score ||
              0
          ) + infiniteAward;

        updateInfiniteStats(
          stats,
          stage,
          currentRunScore,
          elapsedMs
        );

        nextSession =
          await createTargetSession(
            client,
            req.auth.playerId,
            "infinite",
            infiniteDifficulty(
              stage + 1
            ),
            stage + 1
          );

        await client.query(
          `UPDATE target_number_progress
           SET
             infinite_session_id = $2,
             infinite_stage = $3,
             infinite_score = $4,
             infinite_puzzle = $5::jsonb,
             infinite_number_slots =
               $6::jsonb,
             infinite_operator_slots =
               $7::jsonb,
             infinite_remaining_ms = $8,
             statistics = $9::jsonb,
             updated_at = NOW()
           WHERE player_id = $1`,
          [
            req.auth.playerId,
            nextSession.session_id,
            stage + 1,
            currentRunScore,
            JSON.stringify(
              nextSession.puzzle
            ),
            JSON.stringify(
              Array(
                nextSession.puzzle
                  .numbers.length
              ).fill(null)
            ),
            JSON.stringify(
              Array(
                nextSession.puzzle
                  .numbers.length - 1
              ).fill(null)
            ),
            INFINITE_LIMIT_MS,
            JSON.stringify(stats),
          ]
        );

        modeResult = {
          runScore:
            currentRunScore,
          completedStage: stage,
        };

        await applyRewards(
          client,
          req.auth.playerId,
          0,
          currentRunScore,
          xpAward
        );
      } else if (
        session.mode === "hundred"
      ) {
        const stage = Number(
          session.stage || 1
        );

        const cutoff = Number(
          session.metadata
            ?.qualifyingCutoffMs ||
            hundredStageLimitMs(
              stage
            )
        );

        const qualified =
          elapsedMs <= cutoff ||
          stage ===
            HUNDRED_TOTAL_STAGES;

        const rank = qualified
          ? Math.max(
              1,
              Math.min(
                100,
                Math.round(
                  (
                    elapsedMs /
                    Math.max(
                      1,
                      cutoff
                    )
                  ) * 35
                )
              )
            )
          : Math.max(
              2,
              Math.min(
                100,
                Number(
                  session.metadata
                    ?.rankSeed || 50
                )
              )
            );

        const totalElapsedMs =
          Math.max(
            0,
            Number(
              progress
                ?.hundred_total_elapsed_ms ||
                0
            )
          ) + elapsedMs;

        if (
          qualified &&
          stage <
            HUNDRED_TOTAL_STAGES
        ) {
          nextSession =
            await createTargetSession(
              client,
              req.auth.playerId,
              "hundred",
              hundredDifficulty(
                stage + 1
              ),
              stage + 1,
              {
                qualifyingCutoffMs:
                  Math.floor(
                    hundredStageLimitMs(
                      stage + 1
                    ) *
                      (
                        0.60 +
                        Math.random() *
                          0.35
                      )
                  ),
                rankSeed:
                  crypto.randomInt(
                    1,
                    101
                  ),
                totalStages:
                  HUNDRED_TOTAL_STAGES,
              },
              hundredStageLimitMs(
                stage + 1
              )
            );

          await client.query(
            `UPDATE target_number_progress
             SET
               hundred_current_stage = $2,
               hundred_total_elapsed_ms =
                 $3,
               hundred_active = TRUE,
               updated_at = NOW()
             WHERE player_id = $1`,
            [
              req.auth.playerId,
              stage + 1,
              totalElapsedMs,
            ]
          );

          modeResult = {
            qualified: true,
            won: false,
            rank,
            reachedStage: stage,
            totalElapsedMs,
            earnedPoints: 0,
          };
        } else {
          const won =
            qualified &&
            stage >=
              HUNDRED_TOTAL_STAGES;

          generalAward =
            won ? 240 : stage * 10;

          xpAward =
            won ? 480 : stage * 20;

          await client.query(
            `UPDATE target_number_progress
             SET
               hundred_current_stage = 1,
               hundred_total_elapsed_ms =
                 0,
               hundred_active = FALSE,
               updated_at = NOW()
             WHERE player_id = $1`,
            [req.auth.playerId]
          );

          modeResult = {
            qualified: false,
            won,
            rank,
            reachedStage: stage,
            totalElapsedMs,
            earnedPoints:
              generalAward,
          };
        }
      }

      if (
        session.mode !== "infinite"
      ) {
        await client.query(
          `UPDATE target_number_progress
           SET
             statistics = $2::jsonb,
             updated_at = NOW()
           WHERE player_id = $1`,
          [
            req.auth.playerId,
            JSON.stringify(stats),
          ]
        );

        await applyRewards(
          client,
          req.auth.playerId,
          generalAward,
          0,
          xpAward
        );
      }

      await client.query(
        `UPDATE target_number_sessions
         SET
           status = 'completed',
           finished_at = NOW(),
           elapsed_active_ms = $2,
           paused_remaining_ms = NULL,
           result = $3::jsonb,
           updated_at = NOW()
         WHERE session_id = $1`,
        [
          session.session_id,
          elapsedMs,
          JSON.stringify({
            elapsedMs,
            generalAward,
            infiniteAward,
            xpAward,
            ...modeResult,
          }),
        ]
      );

      const state =
        await loadPlayerSnapshot(
          client,
          req.auth.playerId
        );

      await client.query("COMMIT");

      res.json({
        ok: true,
        accepted: true,
        elapsedMs,
        generalAward,
        infiniteAward,
        xpAward,
        result: modeResult,
        nextSession:
          sessionPublic(nextSession),
        state,
      });
    } catch (error) {
      await client.query("ROLLBACK");

      sendError(
        res,
        error,
        "Çözüm doğrulanamadı."
      );
    } finally {
      client.release();
    }
  }
);

app.post(
  "/target-number/session/forfeit",
  authMiddleware,
  async (req, res) => {
    if (!requireDatabase(res)) {
      return;
    }

    const sessionId = safeText(
      req.body?.sessionId,
      "",
      64
    );

    const client =
      await pool.connect();

    try {
      await client.query("BEGIN");

      const result =
        await client.query(
          `SELECT *
           FROM target_number_sessions
           WHERE
             session_id = $1
             AND player_id = $2
           FOR UPDATE`,
          [
            sessionId,
            req.auth.playerId,
          ]
        );

      const session =
        result.rows[0];

      if (
        !session ||
        ![
          "active",
          "paused",
        ].includes(session.status)
      ) {
        const state =
          await loadPlayerSnapshot(
            client,
            req.auth.playerId
          );

        await client.query("COMMIT");

        res.json({
          ok: true,
          state,
        });

        return;
      }

      let generalAward = 0;
      let xpAward = 0;

      const progressResult =
        await client.query(
          `SELECT *
           FROM target_number_progress
           WHERE player_id = $1
           FOR UPDATE`,
          [req.auth.playerId]
        );

      const progress =
        progressResult.rows[0];

      const stats =
        normalizedStatistics(
          progress?.statistics
        );

      if (
        session.mode === "single"
      ) {
        updateClassicStats(
          stats,
          session.difficulty === "Hard"
            ? "singleHard"
            : "singleMedium",
          false,
          0
        );
      } else if (
        session.mode === "infinite"
      ) {
        await client.query(
          `UPDATE target_number_progress
           SET
             infinite_session_id = NULL,
             infinite_stage = 1,
             infinite_score = 0,
             infinite_puzzle = NULL,
             infinite_number_slots = NULL,
             infinite_operator_slots =
               NULL,
             infinite_remaining_ms = NULL,
             updated_at = NOW()
           WHERE player_id = $1`,
          [req.auth.playerId]
        );
      } else if (
        session.mode === "hundred"
      ) {
        const stage = clampInt(
          session.stage,
          1,
          HUNDRED_TOTAL_STAGES,
          1
        );

        const completedStages =
          Math.max(0, stage - 1);

        generalAward =
          completedStages * 10;

        xpAward =
          completedStages * 20;

        await client.query(
          `UPDATE target_number_progress
           SET
             hundred_current_stage = 1,
             hundred_total_elapsed_ms =
               0,
             hundred_active = FALSE,
             updated_at = NOW()
           WHERE player_id = $1`,
          [req.auth.playerId]
        );

        await applyRewards(
          client,
          req.auth.playerId,
          generalAward,
          0,
          xpAward
        );
      }

      await client.query(
        `UPDATE target_number_progress
         SET
           statistics = $2::jsonb,
           updated_at = NOW()
         WHERE player_id = $1`,
        [
          req.auth.playerId,
          JSON.stringify(stats),
        ]
      );

      const elapsedMs = Math.max(
        0,
        sessionElapsedMs(session)
      );

      await client.query(
        `UPDATE target_number_sessions
         SET
           status = 'forfeit',
           finished_at = NOW(),
           elapsed_active_ms = $2,
           paused_remaining_ms = NULL,
           result = $3::jsonb,
           updated_at = NOW()
         WHERE session_id = $1`,
        [
          session.session_id,
          elapsedMs,
          JSON.stringify({
            generalAward,
            xpAward,
          }),
        ]
      );

      const state =
        await loadPlayerSnapshot(
          client,
          req.auth.playerId
        );

      await client.query("COMMIT");

      res.json({
        ok: true,
        generalAward,
        xpAward,
        state,
      });
    } catch (error) {
      await client.query("ROLLBACK");

      sendError(
        res,
        error,
        "Oyun sonlandırılamadı."
      );
    } finally {
      client.release();
    }
  }
);

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
});

io.use(async (socket, next) => {
  try {
    const token =
      bearerTokenFromHeaders(
        socket.handshake.headers
      );

    const payload =
      verifySessionToken(token);

    if (!payload) {
      return next(
        new Error("UNAUTHORIZED")
      );
    }

    socket.data.playerId =
      payload.sub;

    if (!pool) {
      return next(
        new Error(
          "DATABASE_UNAVAILABLE"
        )
      );
    }

    const result = await pool.query(
      `SELECT
         player_id,
         username,
         google_display_name,
         country
       FROM players
       WHERE player_id = $1`,
      [payload.sub]
    );

    const row = result.rows[0];

    if (!row) {
      return next(
        new Error("PLAYER_NOT_FOUND")
      );
    }

    socket.data.player = {
      id: row.player_id,
      name:
        row.username ||
        row.google_display_name ||
        "Oyuncu",
      country: safeCountry(
        row.country
      ),
    };

    next();
  } catch (error) {
    next(error);
  }
});

const waitingQueues = new Map();
const queueTimers = new Map();
const socketActiveRoom = new Map();
const botTimers = new Map();
const roomDeadlineTimers = new Map();

function queueKey(
  gameKey,
  difficulty
) {
  return `${
    normalizeGameKey(gameKey)
  }::${
    normalizeDifficulty(difficulty)
  }`;
}

function clearQueueTimer(socketId) {
  const timer =
    queueTimers.get(socketId);

  if (timer) {
    clearTimeout(timer);
  }

  queueTimers.delete(socketId);
}

function removeFromQueues(
  socketId,
  playerId
) {
  clearQueueTimer(socketId);

  for (
    const [key, entries]
    of waitingQueues.entries()
  ) {
    const filtered =
      entries.filter(
        (entry) =>
          entry.socketId !== socketId &&
          (
            !playerId ||
            entry.playerId !== playerId
          )
      );

    if (filtered.length) {
      waitingQueues.set(
        key,
        filtered
      );
    } else {
      waitingQueues.delete(key);
    }
  }
}

async function getTournamentProgress(
  client,
  playerId,
  lock = false
) {
  const result = await client.query(
    `SELECT
       tournament_current_stage,
       tournament_remaining_rights,
       tournament_total_score,
       tournament_completed
     FROM target_number_progress
     WHERE player_id = $1
     ${lock ? "FOR UPDATE" : ""}`,
    [playerId]
  );

  const row = result.rows[0];

  return {
    currentStage: Number(
      row?.tournament_current_stage ||
        1
    ),
    remainingRights: Number(
      row?.tournament_remaining_rights ||
        TOURNAMENT_INITIAL_RIGHTS
    ),
    totalScore: Number(
      row?.tournament_total_score ||
        0
    ),
    completed: Boolean(
      row?.tournament_completed
    ),
  };
}

async function authorizeMatchEntry(
  playerId,
  gameKey,
  difficulty
) {
  const client =
    await pool.connect();

  try {
    await client.query("BEGIN");

    let progress = null;

    if (
      gameKey ===
        "target_number_two_player" ||
      gameKey ===
        "target_number_friend"
    ) {
      const rights =
        await refreshRights(
          client,
          playerId,
          true
        );

      if (
        rights.remainingRights <= 0
      ) {
        throw publicError(
          409,
          "NO_GAME_RIGHT",
          "İki kişilik oyun hakkın kalmadı."
        );
      }
    } else if (
      gameKey ===
      "target_number_tournament"
    ) {
      progress =
        await getTournamentProgress(
          client,
          playerId,
          true
        );

      if (progress.completed) {
        throw publicError(
          409,
          "TOURNAMENT_COMPLETED",
          "Turnuva tamamlanmış."
        );
      }

      if (
        progress.remainingRights <= 0
      ) {
        throw publicError(
          409,
          "NO_TOURNAMENT_RIGHT",
          "Turnuva hakkın kalmadı."
        );
      }

      if (
        normalizeDifficulty(
          difficulty
        ) !==
        tournamentDifficulty(
          progress.currentStage
        )
      ) {
        throw publicError(
          409,
          "INVALID_TOURNAMENT_STAGE",
          "Turnuva aşaması güncel değil."
        );
      }
    }

    await client.query("COMMIT");
    return progress;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

async function createMatchRoom(
  playerA,
  playerB,
  gameKey,
  difficulty,
  socketA,
  socketB = null,
  isBot = false
) {
  const roomId =
    crypto.randomUUID();

  const puzzle =
    generatePuzzle(difficulty);

  const botFinishMs =
    isBot
      ? estimateBotFinishMs(
          difficulty
        )
      : null;

  const client =
    await pool.connect();

  try {
    await client.query("BEGIN");

    if (
      gameKey ===
        "target_number_two_player" ||
      gameKey ===
        "target_number_friend"
    ) {
      const realPlayerIds = [
        playerA.id,
        ...(
          isBot
            ? []
            : [playerB.id]
        ),
      ]
        .filter(
          (
            value,
            index,
            array
          ) =>
            value &&
            array.indexOf(value) ===
              index
        )
        .sort();

      for (
        const realPlayerId
        of realPlayerIds
      ) {
        await consumeGameRight(
          client,
          realPlayerId
        );
      }
    }

    await client.query(
      `INSERT INTO match_rooms (
         room_id,
         game_key,
         difficulty,
         puzzle,
         started_at,
         deadline_at,
         status,
         bot_finish_at
       )
       VALUES (
         $1,
         $2,
         $3,
         $4::jsonb,
         NOW(),
         NOW() + (
           $5 *
           INTERVAL '1 millisecond'
         ),
         'active',
         CASE
           WHEN $6::bigint IS NULL
           THEN NULL
           ELSE NOW() + (
             $6 *
             INTERVAL '1 millisecond'
           )
         END
       )`,
      [
        roomId,
        gameKey,
        difficulty,
        JSON.stringify(puzzle),
        COMPETITIVE_LIMIT_MS,
        botFinishMs,
      ]
    );

    await client.query(
      `INSERT INTO match_participants (
         room_id,
         player_id,
         is_bot,
         display_name,
         country,
         socket_id
       )
       VALUES (
         $1,
         $2,
         FALSE,
         $3,
         $4,
         $5
       )`,
      [
        roomId,
        playerA.id,
        playerA.name,
        playerA.country,
        socketA.id,
      ]
    );

    await client.query(
      `INSERT INTO match_participants (
         room_id,
         player_id,
         is_bot,
         display_name,
         country,
         socket_id
       )
       VALUES (
         $1,
         $2,
         $3,
         $4,
         $5,
         $6
       )`,
      [
        roomId,
        playerB.id,
        isBot,
        playerB.name,
        playerB.country,
        socketB?.id || null,
      ]
    );

    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }

  socketA.join(roomId);

  socketActiveRoom.set(
    socketA.id,
    {
      roomId,
      playerId: playerA.id,
    }
  );

  if (socketB) {
    socketB.join(roomId);

    socketActiveRoom.set(
      socketB.id,
      {
        roomId,
        playerId: playerB.id,
      }
    );
  }

  if (
    isBot &&
    botFinishMs
  ) {
    scheduleBotFinish(
      roomId,
      playerB.id,
      botFinishMs
    );
  }

  scheduleRoomDeadline(
    roomId,
    COMPETITIVE_LIMIT_MS + 2_000
  );

  return {
    roomId,
    puzzle,
    botFinishMs,
  };
}

function clearRoomTimers(roomId) {
  const botTimer =
    botTimers.get(roomId);

  if (botTimer) {
    clearTimeout(botTimer);
  }

  botTimers.delete(roomId);

  const deadlineTimer =
    roomDeadlineTimers.get(roomId);

  if (deadlineTimer) {
    clearTimeout(deadlineTimer);
  }

  roomDeadlineTimers.delete(roomId);
}

function scheduleRoomDeadline(
  roomId,
  delayMs
) {
  const old =
    roomDeadlineTimers.get(roomId);

  if (old) {
    clearTimeout(old);
  }

  const timer = setTimeout(
    () => {
      roomDeadlineTimers.delete(
        roomId
      );

      resolveMatchTimeout(roomId)
        .catch((error) => {
          console.error(
            "room timeout error",
            error
          );
        });
    },
    Math.max(1, delayMs)
  );

  timer.unref?.();

  roomDeadlineTimers.set(
    roomId,
    timer
  );
}

function estimateBotFinishMs(
  difficulty
) {
  if (
    normalizeDifficulty(difficulty) ===
    "Hard"
  ) {
    const cannotFinish =
      Math.random() < 0.253;

    if (cannotFinish) {
      return null;
    }

    return randomInt(
      35_000,
      115_000
    );
  }

  const cannotFinish =
    Math.random() < 0.107;

  if (cannotFinish) {
    return null;
  }

  return randomInt(
    18_000,
    100_000
  );
}

function randomBot() {
  const names = [
    "SayıUstası",
    "HızlıZihin",
    "Matematikçi",
    "HedefAvcısı",
    "AkılKüpü",
    "RakamPilot",
    "İşlemci",
    "ZihinKoçu",
  ];

  const countries = [
    "TR",
    "DE",
    "US",
    "GB",
    "FR",
    "IT",
    "ES",
    "JP",
    "KR",
    "BR",
  ];

  return {
    id:
      `bot_${
        crypto
          .randomBytes(12)
          .toString("hex")
      }`,
    name:
      `${
        names[
          crypto.randomInt(
            0,
            names.length
          )
        ]
      }${
        crypto.randomInt(
          10,
          999
        )
      }`,
    country:
      countries[
        crypto.randomInt(
          0,
          countries.length
        )
      ],
  };
}

function scheduleBotFinish(
  roomId,
  botPlayerId,
  delayMs
) {
  const old =
    botTimers.get(roomId);

  if (old) {
    clearTimeout(old);
  }

  const timer = setTimeout(
    async () => {
      botTimers.delete(roomId);

      try {
        await resolveMatchByFinisher(
          roomId,
          botPlayerId,
          "bot_finished"
        );
      } catch (error) {
        console.error(
          "bot finish error",
          error
        );
      }
    },
    Math.max(1, delayMs)
  );

  timer.unref?.();

  botTimers.set(roomId, timer);
}

async function loadRoom(
  client,
  roomId,
  lock = false
) {
  const roomResult =
    await client.query(
      `SELECT *
       FROM match_rooms
       WHERE room_id = $1
       ${lock ? "FOR UPDATE" : ""}`,
      [roomId]
    );

  const room =
    roomResult.rows[0];

  if (!room) {
    return null;
  }

  const participants =
    await client.query(
      `SELECT *
       FROM match_participants
       WHERE room_id = $1
       ORDER BY
         is_bot ASC,
         player_id ASC`,
      [roomId]
    );

  return {
    room,
    participants:
      participants.rows,
  };
}

async function updateTournamentAfterResult(
  client,
  playerId,
  won
) {
  const progress =
    await getTournamentProgress(
      client,
      playerId,
      true
    );

  if (progress.completed) {
    return progress;
  }

  const stage = clampInt(
    progress.currentStage,
    1,
    TOURNAMENT_TOTAL_STAGES,
    1
  );

  if (won) {
    const accumulated =
      progress.totalScore +
      tournamentStageReward(stage);

    const completed =
      stage >=
      TOURNAMENT_TOTAL_STAGES;

    await applyRewards(
      client,
      playerId,
      completed ? accumulated : 0,
      0,
      tournamentStageReward(stage)
    );

    const updated = {
      currentStage:
        completed
          ? TOURNAMENT_TOTAL_STAGES
          : stage + 1,
      remainingRights:
        progress.remainingRights,
      totalScore: accumulated,
      completed,
    };

    await client.query(
      `UPDATE target_number_progress
       SET
         tournament_current_stage =
           $2,
         tournament_remaining_rights =
           $3,
         tournament_total_score = $4,
         tournament_completed = $5,
         updated_at = NOW()
       WHERE player_id = $1`,
      [
        playerId,
        updated.currentStage,
        updated.remainingRights,
        updated.totalScore,
        updated.completed,
      ]
    );

    return updated;
  }

  const rights = Math.max(
    0,
    progress.remainingRights - 1
  );

  if (rights === 0) {
    if (progress.totalScore > 0) {
      await applyRewards(
        client,
        playerId,
        progress.totalScore,
        0,
        0
      );
    }

    await client.query(
      `UPDATE target_number_progress
       SET
         tournament_current_stage = 1,
         tournament_remaining_rights =
           $2,
         tournament_total_score = 0,
         tournament_completed = FALSE,
         updated_at = NOW()
       WHERE player_id = $1`,
      [
        playerId,
        TOURNAMENT_INITIAL_RIGHTS,
      ]
    );

    return {
      currentStage: 1,
      remainingRights:
        TOURNAMENT_INITIAL_RIGHTS,
      totalScore: 0,
      completed: false,
    };
  }

  await client.query(
    `UPDATE target_number_progress
     SET
       tournament_remaining_rights =
         $2,
       updated_at = NOW()
     WHERE player_id = $1`,
    [
      playerId,
      rights,
    ]
  );

  return {
    ...progress,
    remainingRights: rights,
  };
}

async function updateTwoPlayerStatistics(
  client,
  playerId,
  difficulty,
  won,
  elapsedMs
) {
  const result =
    await client.query(
      `SELECT statistics
       FROM target_number_progress
       WHERE player_id = $1
       FOR UPDATE`,
      [playerId]
    );

  const stats =
    normalizedStatistics(
      result.rows[0]?.statistics
    );

  const key =
    normalizeDifficulty(
      difficulty
    ) === "Hard"
      ? "twoPlayerHard"
      : "twoPlayerMedium";

  updateClassicStats(
    stats,
    key,
    won,
    won ? elapsedMs : null
  );

  await client.query(
    `UPDATE target_number_progress
     SET
       statistics = $2::jsonb,
       updated_at = NOW()
     WHERE player_id = $1`,
    [
      playerId,
      JSON.stringify(stats),
    ]
  );
}

async function applyCompetitiveOutcome(
  client,
  room,
  winner,
  loser,
  elapsedMs = null
) {
  const gameKey = room.game_key;
  const difficulty =
    room.difficulty;

  const winnerBot =
    Boolean(winner?.is_bot);

  const loserBot =
    Boolean(loser?.is_bot);

  let winnerTournament = null;
  let loserTournament = null;

  if (
    gameKey ===
    "target_number_two_player"
  ) {
    if (
      winner &&
      !winnerBot
    ) {
      await updateTwoPlayerStatistics(
        client,
        winner.player_id,
        difficulty,
        true,
        elapsedMs
      );

      await applyRewards(
        client,
        winner.player_id,
        rewardForDifficulty(
          difficulty
        ),
        0,
        twoPlayerXp(difficulty)
      );
    }

    if (
      loser &&
      !loserBot
    ) {
      await updateTwoPlayerStatistics(
        client,
        loser.player_id,
        difficulty,
        false,
        null
      );

      await applyRewards(
        client,
        loser.player_id,
        -rewardForDifficulty(
          difficulty
        ),
        0,
        0
      );
    }
  } else if (
    gameKey ===
    "target_number_tournament"
  ) {
    if (
      winner &&
      !winnerBot
    ) {
      winnerTournament =
        await updateTournamentAfterResult(
          client,
          winner.player_id,
          true
        );
    }

    if (
      loser &&
      !loserBot
    ) {
      loserTournament =
        await updateTournamentAfterResult(
          client,
          loser.player_id,
          false
        );
    }
  }

  return {
    winnerTournament,
    loserTournament,
  };
}

async function resolveMatchByFinisher(
  roomId,
  finisherPlayerId,
  reason
) {
  const client =
    await pool.connect();

  let emitted = null;

  try {
    await client.query("BEGIN");

    const loaded =
      await loadRoom(
        client,
        roomId,
        true
      );

    if (
      !loaded ||
      loaded.room.status !== "active"
    ) {
      await client.query("COMMIT");
      return null;
    }

    const winner =
      loaded.participants.find(
        (item) =>
          item.player_id ===
          finisherPlayerId
      );

    const loser =
      loaded.participants.find(
        (item) =>
          item.player_id !==
          finisherPlayerId
      );

    if (!winner || !loser) {
      throw publicError(
        409,
        "ROOM_PARTICIPANTS_INVALID",
        "Maç oyuncuları bulunamadı."
      );
    }

    const elapsedMs = Math.max(
      1,
      nowMs() -
        new Date(
          loaded.room.started_at
        ).getTime()
    );

    await client.query(
      `UPDATE match_participants
       SET
         finished_at = NOW(),
         elapsed_ms = $3
       WHERE
         room_id = $1
         AND player_id = $2`,
      [
        roomId,
        winner.player_id,
        elapsedMs,
      ]
    );

    await client.query(
      `UPDATE match_rooms
       SET
         status = 'resolved',
         winner_player_id = $2,
         loser_player_id = $3,
         result_reason = $4,
         updated_at = NOW()
       WHERE room_id = $1`,
      [
        roomId,
        winner.player_id,
        loser.player_id,
        reason,
      ]
    );

    const progress =
      await applyCompetitiveOutcome(
        client,
        loaded.room,
        winner,
        loser,
        elapsedMs
      );

    const winnerState =
      winner.is_bot
        ? null
        : await loadPlayerSnapshot(
            client,
            winner.player_id
          );

    const loserState =
      loser.is_bot
        ? null
        : await loadPlayerSnapshot(
            client,
            loser.player_id
          );

    await client.query("COMMIT");

    emitted = {
      room: loaded.room,
      winner,
      loser,
      elapsedMs,
      winnerState,
      loserState,
      progress,
      reason,
    };
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }

  if (emitted) {
    clearRoomTimers(roomId);
    emitMatchResult(emitted);
  }

  return emitted;
}

function emitMatchResult(result) {
  const winnerPayload = {
    roomId:
      result.room.room_id,
    won: true,
    elapsedMs:
      result.elapsedMs,
    opponentElapsedMs: null,
    state:
      result.winnerState,
    tournament:
      result.progress
        .winnerTournament,
    reason:
      result.reason ||
      result.room.result_reason ||
      "finished",
  };

  const loserPayload = {
    roomId:
      result.room.room_id,
    won: false,
    elapsedMs: null,
    opponentElapsedMs:
      result.elapsedMs,
    state:
      result.loserState,
    tournament:
      result.progress
        .loserTournament,
    reason:
      result.reason ||
      result.room.result_reason ||
      "finished",
  };

  if (
    !result.winner.is_bot &&
    result.winner.socket_id
  ) {
    io.to(
      result.winner.socket_id
    ).emit(
      "match_result",
      winnerPayload
    );

    socketActiveRoom.delete(
      result.winner.socket_id
    );
  }

  if (
    !result.loser.is_bot &&
    result.loser.socket_id
  ) {
    io.to(
      result.loser.socket_id
    ).emit(
      "opponent_finished",
      {
        roomId:
          result.room.room_id,
        elapsedMs:
          result.elapsedMs,
      }
    );

    io.to(
      result.loser.socket_id
    ).emit(
      "match_result",
      loserPayload
    );

    socketActiveRoom.delete(
      result.loser.socket_id
    );
  }
}

async function resolveMatchTimeout(
  roomId
) {
  const client =
    await pool.connect();

  let payloads = [];

  try {
    await client.query("BEGIN");

    const loaded =
      await loadRoom(
        client,
        roomId,
        true
      );

    if (
      !loaded ||
      loaded.room.status !== "active"
    ) {
      await client.query("COMMIT");
      return;
    }

    await client.query(
      `UPDATE match_rooms
       SET
         status = 'resolved',
         winner_player_id = NULL,
         loser_player_id = NULL,
         result_reason = 'timeout',
         updated_at = NOW()
       WHERE room_id = $1`,
      [roomId]
    );

    for (
      const participant
      of loaded.participants
    ) {
      if (participant.is_bot) {
        continue;
      }

      let tournament = null;

      if (
        loaded.room.game_key ===
        "target_number_tournament"
      ) {
        tournament =
          await updateTournamentAfterResult(
            client,
            participant.player_id,
            false
          );
      } else if (
        loaded.room.game_key ===
        "target_number_two_player"
      ) {
        await updateTwoPlayerStatistics(
          client,
          participant.player_id,
          loaded.room.difficulty,
          false,
          null
        );
      }

      const state =
        await loadPlayerSnapshot(
          client,
          participant.player_id
        );

      payloads.push({
        participant,
        state,
        tournament,
      });
    }

    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }

  clearRoomTimers(roomId);

  for (
    const {
      participant,
      state,
      tournament,
    } of payloads
  ) {
    if (participant.socket_id) {
      io.to(
        participant.socket_id
      ).emit(
        "match_result",
        {
          roomId,
          won: null,
          elapsedMs: null,
          opponentElapsedMs: null,
          state,
          tournament,
          reason: "timeout",
        }
      );

      socketActiveRoom.delete(
        participant.socket_id
      );
    }
  }
}

async function forfeitActiveRoom(
  socket,
  reason = "cancelled"
) {
  const active =
    socketActiveRoom.get(socket.id);

  if (!active) {
    return;
  }

  socketActiveRoom.delete(socket.id);

  const client =
    await pool.connect();

  let emitted = null;

  try {
    await client.query("BEGIN");

    const loaded =
      await loadRoom(
        client,
        active.roomId,
        true
      );

    if (
      !loaded ||
      loaded.room.status !== "active"
    ) {
      await client.query("COMMIT");
      return;
    }

    const loser =
      loaded.participants.find(
        (item) =>
          item.player_id ===
          socket.data.playerId
      );

    const winner =
      loaded.participants.find(
        (item) =>
          item.player_id !==
          socket.data.playerId
      );

    if (!loser || !winner) {
      await client.query("COMMIT");
      return;
    }

    await client.query(
      `UPDATE match_rooms
       SET
         status = 'resolved',
         winner_player_id = $2,
         loser_player_id = $3,
         result_reason = $4,
         updated_at = NOW()
       WHERE room_id = $1`,
      [
        active.roomId,
        winner.player_id,
        loser.player_id,
        reason,
      ]
    );

    const progress =
      await applyCompetitiveOutcome(
        client,
        loaded.room,
        winner,
        loser,
        null
      );

    const winnerState =
      winner.is_bot
        ? null
        : await loadPlayerSnapshot(
            client,
            winner.player_id
          );

    const loserState =
      loser.is_bot
        ? null
        : await loadPlayerSnapshot(
            client,
            loser.player_id
          );

    await client.query("COMMIT");

    emitted = {
      room: loaded.room,
      winner,
      loser,
      elapsedMs: null,
      winnerState,
      loserState,
      progress,
      reason,
    };
  } catch (error) {
    await client.query("ROLLBACK");

    console.error(
      "forfeit error",
      error
    );
  } finally {
    client.release();
  }

  if (emitted) {
    clearRoomTimers(
      active.roomId
    );

    if (
      !emitted.winner.is_bot &&
      emitted.winner.socket_id
    ) {
      io.to(
        emitted.winner.socket_id
      ).emit(
        "opponent_left",
        {
          roomId: active.roomId,
        }
      );

      io.to(
        emitted.winner.socket_id
      ).emit(
        "match_result",
        {
          roomId: active.roomId,
          won: true,
          elapsedMs: null,
          opponentElapsedMs: null,
          state:
            emitted.winnerState,
          tournament:
            emitted.progress
              .winnerTournament,
          reason,
        }
      );

      socketActiveRoom.delete(
        emitted.winner.socket_id
      );
    }

    if (
      !emitted.loser.is_bot &&
      emitted.loser.socket_id
    ) {
      socketActiveRoom.delete(
        emitted.loser.socket_id
      );
    }
  }
}

async function createBotMatchForWaiting(
  entry
) {
  const socket =
    io.sockets.sockets.get(
      entry.socketId
    );

  if (
    !socket ||
    socket.data.playerId !==
      entry.playerId
  ) {
    return;
  }

  const key = queueKey(
    entry.gameKey,
    entry.difficulty
  );

  const queue =
    waitingQueues.get(key) || [];

  const stillWaiting =
    queue.find(
      (item) =>
        item.socketId ===
        entry.socketId
    );

  if (!stillWaiting) {
    return;
  }

  waitingQueues.set(
    key,
    queue.filter(
      (item) =>
        item.socketId !==
        entry.socketId
    )
  );

  const bot = randomBot();

  const room =
    await createMatchRoom(
      socket.data.player,
      bot,
      entry.gameKey,
      entry.difficulty,
      socket,
      null,
      true
    );

  socket.emit(
    "match_found",
    {
      roomId: room.roomId,
      isBot: true,
      opponent: {
        name: bot.name,
        country: bot.country,
      },
      puzzle: room.puzzle,
      startedAtMillis: nowMs(),
      deadlineAtMillis:
        nowMs() +
        COMPETITIVE_LIMIT_MS,
    }
  );
}

io.on(
  "connection",
  (socket) => {
    console.log(
      "Socket connected",
      socket.id,
      socket.data.playerId
    );

    socket.on(
      "join_match",
      async (
        payload = {},
        ack
      ) => {
        try {
          const gameKey =
            normalizeGameKey(
              payload.gameKey
            );

          const difficulty =
            normalizeDifficulty(
              payload.difficulty
            );

          removeFromQueues(
            socket.id,
            socket.data.playerId
          );

          await forfeitActiveRoom(
            socket,
            "new_match"
          );

          await authorizeMatchEntry(
            socket.data.playerId,
            gameKey,
            difficulty
          );

          const key = queueKey(
            gameKey,
            difficulty
          );

          const queue =
            waitingQueues.get(key) ||
            [];

          while (queue.length) {
            const opponentEntry =
              queue.shift();

            const opponentSocket =
              io.sockets.sockets.get(
                opponentEntry.socketId
              );

            if (
              !opponentSocket ||
              opponentSocket.data
                .playerId ===
                socket.data.playerId
            ) {
              continue;
            }

            clearQueueTimer(
              opponentSocket.id
            );

            waitingQueues.set(
              key,
              queue
            );

            const room =
              await createMatchRoom(
                socket.data.player,
                opponentSocket.data
                  .player,
                gameKey,
                difficulty,
                socket,
                opponentSocket,
                false
              );

            const common = {
              roomId: room.roomId,
              isBot: false,
              puzzle: room.puzzle,
              startedAtMillis:
                nowMs(),
              deadlineAtMillis:
                nowMs() +
                COMPETITIVE_LIMIT_MS,
            };

            socket.emit(
              "match_found",
              {
                ...common,
                opponent: {
                  name:
                    opponentSocket
                      .data.player.name,
                  country:
                    opponentSocket
                      .data.player
                      .country,
                },
              }
            );

            opponentSocket.emit(
              "match_found",
              {
                ...common,
                opponent: {
                  name:
                    socket.data
                      .player.name,
                  country:
                    socket.data
                      .player.country,
                },
              }
            );

            ack?.({
              ok: true,
              matched: true,
            });

            return;
          }

          const entry = {
            socketId: socket.id,
            playerId:
              socket.data.playerId,
            gameKey,
            difficulty,
            joinedAt: nowMs(),
          };

          queue.push(entry);

          waitingQueues.set(
            key,
            queue
          );

          const delay = randomInt(
            BOT_MATCH_DELAY_MIN_MS,
            BOT_MATCH_DELAY_MAX_MS
          );

          const timer = setTimeout(
            () => {
              createBotMatchForWaiting(
                entry
              ).catch((error) => {
                socket.emit(
                  "match_error",
                  {
                    message:
                      error.message,
                  }
                );
              });
            },
            delay
          );

          timer.unref?.();

          queueTimers.set(
            socket.id,
            timer
          );

          socket.emit(
            "waiting",
            {
              gameKey,
              difficulty,
            }
          );

          ack?.({
            ok: true,
            matched: false,
          });
        } catch (error) {
          const payloadError = {
            ok: false,
            code:
              error.publicCode ||
              "MATCH_ERROR",
            message:
              error.message ||
              "Eşleşme başlatılamadı.",
          };

          socket.emit(
            "match_error",
            payloadError
          );

          ack?.(payloadError);
        }
      }
    );

    socket.on(
      "submit_solution",
      async (
        payload = {},
        ack
      ) => {
        try {
          const roomId = safeText(
            payload.roomId,
            "",
            64
          );

          const active =
            socketActiveRoom.get(
              socket.id
            );

          if (
            !active ||
            active.roomId !== roomId ||
            active.playerId !==
              socket.data.playerId
          ) {
            throw publicError(
              409,
              "ROOM_NOT_ACTIVE",
              "Aktif maç bulunamadı."
            );
          }

          const client =
            await pool.connect();

          try {
            const loaded =
              await loadRoom(
                client,
                roomId,
                false
              );

            if (
              !loaded ||
              loaded.room.status !==
                "active"
            ) {
              throw publicError(
                409,
                "MATCH_RESOLVED",
                "Maç zaten sona ermiş."
              );
            }

            if (
              nowMs() >
              new Date(
                loaded.room.deadline_at
              ).getTime() +
                2_000
            ) {
              throw publicError(
                409,
                "MATCH_EXPIRED",
                "Maç süresi dolmuş."
              );
            }

            const elapsedMs =
              Math.max(
                1,
                nowMs() -
                  new Date(
                    loaded.room
                      .started_at
                  ).getTime()
              );

            if (
              elapsedMs <
              MIN_SOLUTION_MS
            ) {
              throw publicError(
                409,
                "SOLUTION_TOO_FAST",
                "Çözüm olağan dışı derecede hızlı gönderildi."
              );
            }

            if (
              !validateSolution(
                loaded.room.puzzle,
                payload.numberSlots,
                payload.operatorSlots
              )
            ) {
              throw publicError(
                422,
                "INVALID_SOLUTION",
                "Gönderilen çözüm geçerli değil."
              );
            }
          } finally {
            client.release();
          }

          const resolved =
            await resolveMatchByFinisher(
              roomId,
              socket.data.playerId,
              "finished"
            );

          ack?.({
            ok: true,
            accepted: true,
            elapsedMs:
              resolved?.elapsedMs ||
              null,
          });
        } catch (error) {
          ack?.({
            ok: false,
            code:
              error.publicCode ||
              "SOLUTION_ERROR",
            message:
              error.message ||
              "Çözüm doğrulanamadı.",
          });
        }
      }
    );

    socket.on(
      "resume_match",
      async (
        payload = {},
        ack
      ) => {
        try {
          const roomId = safeText(
            payload.roomId,
            "",
            64
          );

          const client =
            await pool.connect();

          try {
            await client.query(
              "BEGIN"
            );

            const loaded =
              await loadRoom(
                client,
                roomId,
                true
              );

            if (!loaded) {
              throw publicError(
                404,
                "ROOM_NOT_FOUND",
                "Yeniden bağlanılacak oda bulunamadı."
              );
            }

            const participant =
              loaded.participants.find(
                (item) =>
                  item.player_id ===
                  socket.data.playerId
              );

            const opponent =
              loaded.participants.find(
                (item) =>
                  item.player_id !==
                  socket.data.playerId
              );

            if (!participant) {
              throw publicError(
                403,
                "PLAYER_NOT_IN_ROOM",
                "Bu oyuncu odada değil."
              );
            }

            if (
              loaded.room.status !==
              "active"
            ) {
              const won =
                loaded.room
                  .winner_player_id
                  ? loaded.room
                      .winner_player_id ===
                    socket.data.playerId
                  : null;

              const state =
                await loadPlayerSnapshot(
                  client,
                  socket.data.playerId
                );

              await client.query(
                "COMMIT"
              );

              socket.emit(
                "match_result",
                {
                  roomId,
                  won,
                  elapsedMs: won
                    ? Number(
                        participant
                          .elapsed_ms || 0
                      )
                    : null,
                  opponentElapsedMs:
                    won
                      ? null
                      : Number(
                          opponent
                            ?.elapsed_ms ||
                            0
                        ),
                  state,
                  reason:
                    loaded.room
                      .result_reason ||
                    "resolved",
                }
              );

              ack?.({
                ok: true,
                resolved: true,
              });

              return;
            }

            const awayMs =
              participant.away_since
                ? nowMs() -
                  new Date(
                    participant.away_since
                  ).getTime()
                : 0;

            if (
              awayMs >
              RECONNECT_TIMEOUT_MS
            ) {
              throw publicError(
                409,
                "RECONNECT_EXPIRED",
                "Yeniden bağlanma süresi doldu."
              );
            }

            await client.query(
              `UPDATE match_participants
               SET
                 socket_id = $3,
                 away_since = NULL
               WHERE
                 room_id = $1
                 AND player_id = $2`,
              [
                roomId,
                socket.data.playerId,
                socket.id,
              ]
            );

            await client.query(
              "COMMIT"
            );

            socket.join(roomId);

            socketActiveRoom.set(
              socket.id,
              {
                roomId,
                playerId:
                  socket.data.playerId,
              }
            );

            socket.emit(
              "resume_state",
              {
                roomId,
                isBot: Boolean(
                  opponent?.is_bot
                ),
                opponent: {
                  name:
                    opponent
                      ?.display_name ||
                    "Rakip",
                  country:
                    opponent?.country ||
                    "",
                },
                puzzle:
                  loaded.room.puzzle,
                opponentFinishedMs:
                  opponent?.elapsed_ms
                    ? Number(
                        opponent.elapsed_ms
                      )
                    : null,
                startedAtMillis:
                  new Date(
                    loaded.room
                      .started_at
                  ).getTime(),
                deadlineAtMillis:
                  new Date(
                    loaded.room
                      .deadline_at
                  ).getTime(),
              }
            );

            if (
              opponent?.is_bot &&
              loaded.room.bot_finish_at
            ) {
              const remaining =
                new Date(
                  loaded.room
                    .bot_finish_at
                ).getTime() -
                nowMs();

              if (remaining > 0) {
                scheduleBotFinish(
                  roomId,
                  opponent.player_id,
                  remaining
                );
              } else {
                resolveMatchByFinisher(
                  roomId,
                  opponent.player_id,
                  "bot_finished"
                ).catch(console.error);
              }
            }

            ack?.({
              ok: true,
              resolved: false,
            });
          } catch (error) {
            await client
              .query("ROLLBACK")
              .catch(() => {});

            throw error;
          } finally {
            client.release();
          }
        } catch (error) {
          const response = {
            ok: false,
            code:
              error.publicCode ||
              "RESUME_ERROR",
            message:
              error.message ||
              "Maça dönülemedi.",
          };

          socket.emit(
            "resume_error",
            response
          );

          ack?.(response);
        }
      }
    );

    socket.on(
      "player_backgrounded",
      async () => {
        const active =
          socketActiveRoom.get(
            socket.id
          );

        if (!active) {
          return;
        }

        await pool
          .query(
            `UPDATE match_participants
             SET
               away_since =
                 COALESCE(
                   away_since,
                   NOW()
                 )
             WHERE
               room_id = $1
               AND player_id = $2`,
            [
              active.roomId,
              socket.data.playerId,
            ]
          )
          .catch(console.error);
      }
    );

    socket.on(
      "player_foregrounded",
      async () => {
        const active =
          socketActiveRoom.get(
            socket.id
          );

        if (!active) {
          return;
        }

        await pool
          .query(
            `UPDATE match_participants
             SET
               away_since = NULL,
               socket_id = $3
             WHERE
               room_id = $1
               AND player_id = $2`,
            [
              active.roomId,
              socket.data.playerId,
              socket.id,
            ]
          )
          .catch(console.error);
      }
    );

    socket.on(
      "create_friend_room",
      async (
        payload = {},
        ack
      ) => {
        try {
          const difficulty =
            normalizeDifficulty(
              payload.difficulty
            );

          removeFromQueues(
            socket.id,
            socket.data.playerId
          );

          await forfeitActiveRoom(
            socket,
            "new_friend_room"
          );

          await authorizeMatchEntry(
            socket.data.playerId,
            "target_number_friend",
            difficulty
          );

          await pool.query(
            `DELETE FROM friend_rooms
             WHERE
               owner_player_id = $1
               OR owner_socket_id = $2`,
            [
              socket.data.playerId,
              socket.id,
            ]
          );

          let roomCode = "";

          for (
            let attempt = 0;
            attempt < 20;
            attempt += 1
          ) {
            roomCode = crypto
              .randomBytes(4)
              .toString("hex")
              .slice(0, 6)
              .toUpperCase();

            try {
              await pool.query(
                `INSERT INTO friend_rooms (
                   room_code,
                   owner_player_id,
                   owner_socket_id,
                   game_key,
                   difficulty,
                   created_at
                 )
                 VALUES (
                   $1,
                   $2,
                   $3,
                   'target_number_friend',
                   $4,
                   NOW()
                 )`,
                [
                  roomCode,
                  socket.data.playerId,
                  socket.id,
                  difficulty,
                ]
              );

              break;
            } catch (error) {
              if (
                error.code !== "23505"
              ) {
                throw error;
              }

              roomCode = "";
            }
          }

          if (!roomCode) {
            throw publicError(
              503,
              "ROOM_CODE_FAILED",
              "Oda kodu oluşturulamadı."
            );
          }

          socket.emit(
            "friend_room_created",
            { roomCode }
          );

          ack?.({
            ok: true,
            roomCode,
          });
        } catch (error) {
          const response = {
            ok: false,
            code:
              error.publicCode ||
              "FRIEND_ROOM_ERROR",
            message:
              error.message ||
              "Oda oluşturulamadı.",
          };

          socket.emit(
            "friend_room_error",
            response
          );

          ack?.(response);
        }
      }
    );

    socket.on(
      "join_friend_room",
      async (
        payload = {},
        ack
      ) => {
        try {
          const roomCode =
            safeText(
              payload.roomCode,
              "",
              6
            )
              .toUpperCase()
              .replace(
                /[^A-Z0-9]/g,
                ""
              );

          if (
            roomCode.length !== 6
          ) {
            throw publicError(
              400,
              "INVALID_ROOM_CODE",
              "Geçerli 6 haneli oda kodu gir."
            );
          }

          const client =
            await pool.connect();

          try {
            await client.query(
              "BEGIN"
            );

            const result =
              await client.query(
                `SELECT *
                 FROM friend_rooms
                 WHERE room_code = $1
                 FOR UPDATE`,
                [roomCode]
              );

            const friend =
              result.rows[0];

            if (!friend) {
              throw publicError(
                404,
                "ROOM_NOT_FOUND",
                "Oda bulunamadı."
              );
            }

            if (
              nowMs() -
                new Date(
                  friend.created_at
                ).getTime() >
              FRIEND_ROOM_TTL_MS
            ) {
              await client.query(
                `DELETE FROM friend_rooms
                 WHERE room_code = $1`,
                [roomCode]
              );

              throw publicError(
                410,
                "ROOM_EXPIRED",
                "Odanın süresi dolmuş."
              );
            }

            if (
              friend.owner_player_id ===
              socket.data.playerId
            ) {
              throw publicError(
                409,
                "SAME_PLAYER",
                "Kendi odana katılamazsın."
              );
            }

            const ownerSocket =
              io.sockets.sockets.get(
                friend.owner_socket_id
              );

            if (!ownerSocket) {
              throw publicError(
                410,
                "OWNER_LEFT",
                "Oda sahibi bağlantıdan ayrılmış."
              );
            }

            await client.query(
              `DELETE FROM friend_rooms
               WHERE room_code = $1`,
              [roomCode]
            );

            await client.query(
              "COMMIT"
            );

            const room =
              await createMatchRoom(
                socket.data.player,
                ownerSocket.data.player,
                "target_number_friend",
                friend.difficulty,
                socket,
                ownerSocket,
                false
              );

            const common = {
              roomId: room.roomId,
              roomCode,
              isBot: false,
              puzzle: room.puzzle,
              startedAtMillis:
                nowMs(),
              deadlineAtMillis:
                nowMs() +
                COMPETITIVE_LIMIT_MS,
            };

            socket.emit(
              "match_found",
              {
                ...common,
                opponent: {
                  name:
                    ownerSocket.data
                      .player.name,
                  country:
                    ownerSocket.data
                      .player.country,
                },
              }
            );

            ownerSocket.emit(
              "match_found",
              {
                ...common,
                opponent: {
                  name:
                    socket.data
                      .player.name,
                  country:
                    socket.data
                      .player.country,
                },
              }
            );

            ack?.({ ok: true });
          } catch (error) {
            await client
              .query("ROLLBACK")
              .catch(() => {});

            throw error;
          } finally {
            client.release();
          }
        } catch (error) {
          const response = {
            ok: false,
            code:
              error.publicCode ||
              "FRIEND_JOIN_ERROR",
            message:
              error.message ||
              "Odaya katılınamadı.",
          };

          socket.emit(
            "friend_room_error",
            response
          );

          ack?.(response);
        }
      }
    );

    socket.on(
      "cancel_match",
      async (_payload, ack) => {
        removeFromQueues(
          socket.id,
          socket.data.playerId
        );

        await forfeitActiveRoom(
          socket,
          "cancelled"
        );

        await pool
          .query(
            `DELETE FROM friend_rooms
             WHERE
               owner_player_id = $1
               OR owner_socket_id = $2`,
            [
              socket.data.playerId,
              socket.id,
            ]
          )
          .catch(console.error);

        ack?.({ ok: true });
      }
    );

    socket.on(
      "disconnect",
      async () => {
        console.log(
          "Socket disconnected",
          socket.id,
          socket.data.playerId
        );

        removeFromQueues(
          socket.id,
          socket.data.playerId
        );

        const active =
          socketActiveRoom.get(
            socket.id
          );

        socketActiveRoom.delete(
          socket.id
        );

        if (active) {
          await pool
            .query(
              `UPDATE match_participants
               SET
                 away_since =
                   COALESCE(
                     away_since,
                     NOW()
                   ),
                 socket_id = NULL
               WHERE
                 room_id = $1
                 AND player_id = $2`,
              [
                active.roomId,
                socket.data.playerId,
              ]
            )
            .catch(console.error);

          const timer = setTimeout(
            async () => {
              try {
                const client =
                  await pool.connect();

                let shouldForfeit =
                  false;

                try {
                  const loaded =
                    await loadRoom(
                      client,
                      active.roomId,
                      false
                    );

                  const participant =
                    loaded?.participants.find(
                      (item) =>
                        item.player_id ===
                        socket.data
                          .playerId
                    );

                  shouldForfeit =
                    Boolean(
                      loaded &&
                      loaded.room.status ===
                        "active" &&
                      participant
                        ?.away_since &&
                      nowMs() -
                        new Date(
                          participant.away_since
                        ).getTime() >=
                        RECONNECT_TIMEOUT_MS
                    );
                } finally {
                  client.release();
                }

                if (shouldForfeit) {
                  const fakeSocket = {
                    id: socket.id,
                    data: {
                      playerId:
                        socket.data
                          .playerId,
                    },
                  };

                  socketActiveRoom.set(
                    socket.id,
                    active
                  );

                  await forfeitActiveRoom(
                    fakeSocket,
                    "reconnect_timeout"
                  );
                }
              } catch (error) {
                console.error(
                  "disconnect forfeit error",
                  error
                );
              }
            },
            RECONNECT_TIMEOUT_MS +
              500
          );

          timer.unref?.();
        }

        await pool
          .query(
            `DELETE FROM friend_rooms
             WHERE owner_socket_id = $1`,
            [socket.id]
          )
          .catch(console.error);
      }
    );
  }
);

setInterval(async () => {
  if (!pool) {
    return;
  }

  try {
    await pool.query(
      `DELETE FROM friend_rooms
       WHERE
         created_at <
         NOW() - (
           $1 *
           INTERVAL '1 millisecond'
         )`,
      [FRIEND_ROOM_TTL_MS]
    );

    await pool.query(
      `DELETE FROM match_rooms
       WHERE
         status <> 'active'
         AND updated_at <
           NOW() - (
             $1 *
             INTERVAL '1 millisecond'
           )`,
      [RESOLVED_ROOM_TTL_MS]
    );
  } catch (error) {
    console.error(
      "cleanup error",
      error
    );
  }
}, 60_000).unref();

initDatabase()
  .then(() => {
    server.listen(
      PORT,
      "0.0.0.0",
      () => {
        console.log(
          `Secure target-number server listening on ${PORT}`
        );
      }
    );
  })
  .catch((error) => {
    console.error(
      "Database initialization failed",
      error
    );

    process.exitCode = 1;
  });