"use strict";

const express = require("express");
const http = require("http");
const crypto = require("crypto");
const { Server } = require("socket.io");
const { Pool } = require("pg");

const app = express();
const server = http.createServer(app);

const PORT = intEnv("PORT", 10000, 1, 65535);
const SOCKET_PATH = "/socket.io/";
const DATABASE_URL = process.env.DATABASE_URL || "";
const AUTH_JWT_SECRET = process.env.AUTH_JWT_SECRET || "";
const GOOGLE_WEB_CLIENT_ID = process.env.GOOGLE_WEB_CLIENT_ID || "";
const GOOGLE_WEB_CLIENT_SECRET = process.env.GOOGLE_WEB_CLIENT_SECRET || "";
const PLAY_GAMES_APPLICATION_ID = process.env.PLAY_GAMES_APPLICATION_ID || "";
const ALLOW_INSECURE_DEV_AUTH = boolEnv("ALLOW_INSECURE_DEV_AUTH", false);
const LOG_HTTP = boolEnv("LOG_HTTP", false);

const AUTH_TOKEN_TTL_MS = intEnv(
  "AUTH_TOKEN_TTL_MS",
  12 * 60 * 60 * 1000,
  5 * 60 * 1000,
  7 * 24 * 60 * 60 * 1000
);
const MAX_RIGHTS = 10;
const RIGHT_REFILL_MS = 10 * 60 * 1000;
const TOURNAMENT_TOTAL_STAGES = 12;
const TOURNAMENT_INITIAL_RIGHTS = 3;
const SINGLE_LIMIT_MS = 5 * 60 * 1000;
const COMPETITIVE_LIMIT_MS = 2 * 60 * 1000;
const INFINITE_LIMIT_MS = 2 * 60 * 1000;
const HUNDRED_STAGE_LIMIT_MS = 90 * 1000;
const MIN_VALID_SOLVE_MS = intEnv(
  "MIN_VALID_SOLVE_MS",
  750,
  0,
  10_000
);
const ROOM_RECONNECT_TIMEOUT_MS = intEnv(
  "ROOM_RECONNECT_TIMEOUT_MS",
  60 * 1000,
  10_000,
  10 * 60 * 1000
);
const PRIVATE_ROOM_TTL_MS = intEnv(
  "PRIVATE_ROOM_TTL_MS",
  15 * 60 * 1000,
  60_000,
  24 * 60 * 60 * 1000
);
const RESOLVED_ROOM_TTL_MS = intEnv(
  "RESOLVED_ROOM_TTL_MS",
  10 * 60 * 1000,
  60_000,
  24 * 60 * 60 * 1000
);
const BOT_FALLBACK_MIN_WAIT_MS = intEnv(
  "BOT_FALLBACK_MIN_WAIT_MS",
  18_000,
  0,
  5 * 60 * 1000
);
const LEADERBOARD_CACHE_MS = intEnv(
  "LEADERBOARD_CACHE_MS",
  15_000,
  0,
  5 * 60 * 1000
);
const MAX_JSON_BYTES = "48kb";

if (!AUTH_JWT_SECRET || AUTH_JWT_SECRET.length < 32) {
  console.warn(
    "AUTH_JWT_SECRET en az 32 karakter olmalıdır. " +
      "Korunan endpointler yapılandırma tamamlanana kadar 503 döndürür."
  );
}

const pool = DATABASE_URL
  ? new Pool({
      connectionString: DATABASE_URL,
      ssl:
        DATABASE_URL.includes("localhost") ||
        DATABASE_URL.includes("127.0.0.1")
          ? false
          : { rejectUnauthorized: false },
      max: intEnv("PG_POOL_MAX", 3, 1, 20),
      idleTimeoutMillis: 20_000,
      connectionTimeoutMillis: 10_000,
      allowExitOnIdle: true,
    })
  : null;

app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(express.json({ limit: MAX_JSON_BYTES, strict: true }));

if (LOG_HTTP) {
  app.use((req, _res, next) => {
    console.log("HTTP", req.method, req.path, req.ip);
    next();
  });
}

function intEnv(name, fallback, min, max) {
  const parsed = Number.parseInt(process.env[name] || "", 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(min, Math.min(max, parsed));
}

function boolEnv(name, fallback) {
  const raw = String(process.env[name] || "")
    .trim()
    .toLowerCase();

  if (!raw) return fallback;
  return raw === "1" || raw === "true" || raw === "yes";
}

function nowMs() {
  return Date.now();
}

function safeText(value, fallback = "", maxLength = 96) {
  const text = String(value ?? fallback).trim();
  return (text || fallback).slice(0, maxLength);
}

function safePlayerId(value) {
  return safeText(value, "", 128)
    .replace(/[^a-zA-Z0-9_.:-]/g, "")
    .slice(0, 128);
}

function safeUsername(value) {
  return safeText(value, "", 20).replace(/\s+/g, "");
}

function usernameKey(value) {
  return safeUsername(value).toLocaleLowerCase("en-US");
}

function validateUsername(value) {
  const username = safeUsername(value);

  if (username.length < 3 || username.length > 20) {
    return "Kullanıcı adı 3-20 karakter arasında olmalı.";
  }

  if (!/^[\p{L}\p{N}][\p{L}\p{N}_.-]*$/u.test(username)) {
    return (
      "Kullanıcı adı harf veya rakamla başlamalı; " +
      "yalnızca harf, rakam, _, . ve - içerebilir."
    );
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

function safeDifficulty(value) {
  return String(value || "Medium").toLowerCase() === "hard"
    ? "Hard"
    : "Medium";
}

function safeMode(value) {
  const mode = String(value || "single")
    .trim()
    .toLowerCase();

  return [
    "single",
    "infinite",
    "two_player",
    "friend",
    "tournament",
    "hundred",
  ].includes(mode)
    ? mode
    : "single";
}

function safeInt(
  value,
  fallback = 0,
  min = 0,
  max = 2_000_000_000
) {
  const number = Number(value);

  if (!Number.isFinite(number)) return fallback;

  return Math.max(
    min,
    Math.min(max, Math.trunc(number))
  );
}

function base64url(input) {
  return Buffer.from(input).toString("base64url");
}

function signAuthToken(playerId) {
  const issuedAt = nowMs();

  const payload = base64url(
    JSON.stringify({
      sub: playerId,
      iat: issuedAt,
      exp: issuedAt + AUTH_TOKEN_TTL_MS,
      v: 1,
    })
  );

  const signature = crypto
    .createHmac("sha256", AUTH_JWT_SECRET)
    .update(payload)
    .digest("base64url");

  return `${payload}.${signature}`;
}

function verifyAuthToken(token) {
  if (!AUTH_JWT_SECRET || AUTH_JWT_SECRET.length < 32) {
    return null;
  }

  const parts = String(token || "").split(".");

  if (parts.length !== 2) return null;

  const [payload, signature] = parts;

  const expected = crypto
    .createHmac("sha256", AUTH_JWT_SECRET)
    .update(payload)
    .digest("base64url");

  const a = Buffer.from(signature);
  const b = Buffer.from(expected);

  if (
    a.length !== b.length ||
    !crypto.timingSafeEqual(a, b)
  ) {
    return null;
  }

  try {
    const parsed = JSON.parse(
      Buffer.from(payload, "base64url").toString("utf8")
    );

    if (
      !parsed.sub ||
      Number(parsed.exp || 0) <= nowMs()
    ) {
      return null;
    }

    return safePlayerId(parsed.sub) || null;
  } catch (_error) {
    return null;
  }
}

function bearerToken(req) {
  const header = String(req.headers.authorization || "");

  return header.startsWith("Bearer ")
    ? header.slice(7).trim()
    : "";
}

function requireConfig(res) {
  if (!pool) {
    res.status(503).json({
      ok: false,
      code: "DATABASE_NOT_CONFIGURED",
      message: "DATABASE_URL tanımlı değil.",
    });

    return false;
  }

  if (
    !AUTH_JWT_SECRET ||
    AUTH_JWT_SECRET.length < 32
  ) {
    res.status(503).json({
      ok: false,
      code: "AUTH_NOT_CONFIGURED",
      message:
        "Sunucu kimlik doğrulaması yapılandırılmadı.",
    });

    return false;
  }

  return true;
}

function authMiddleware(req, res, next) {
  if (!requireConfig(res)) return;

  const playerId = verifyAuthToken(
    bearerToken(req)
  );

  if (!playerId) {
    res.status(401).json({
      ok: false,
      code: "AUTH_REQUIRED",
      message:
        "Oturum geçersiz veya süresi dolmuş.",
    });

    return;
  }

  req.playerId = playerId;
  next();
}

const rateBuckets = new Map();

function rateLimit({
  windowMs,
  max,
  key = (req) => req.playerId || req.ip,
}) {
  return (req, res, next) => {
    const bucketKey = `${req.path}:${key(req)}`;
    const now = nowMs();
    const current = rateBuckets.get(bucketKey);

    if (!current || current.resetAt <= now) {
      rateBuckets.set(bucketKey, {
        count: 1,
        resetAt: now + windowMs,
      });

      next();
      return;
    }

    current.count += 1;

    if (current.count > max) {
      res.status(429).json({
        ok: false,
        code: "RATE_LIMIT",
        message:
          "Çok fazla istek gönderildi. " +
          "Kısa süre sonra tekrar deneyin.",
      });

      return;
    }

    next();
  };
}

async function initDatabase() {
  if (!pool) {
    console.warn("DATABASE_URL tanımlı değil.");
    return;
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS players (
      player_id TEXT PRIMARY KEY,
      username TEXT NOT NULL DEFAULT '',
      username_key TEXT,
      country TEXT NOT NULL DEFAULT 'TR',
      username_change_count INTEGER NOT NULL DEFAULT 0
        CHECK (username_change_count >= 0),
      username_changed_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    ALTER TABLE players
      ADD COLUMN IF NOT EXISTS username_key TEXT;

    ALTER TABLE players
      ADD COLUMN IF NOT EXISTS username_change_count
        INTEGER NOT NULL DEFAULT 0;

    ALTER TABLE players
      ADD COLUMN IF NOT EXISTS username_changed_at
        TIMESTAMPTZ;

    ALTER TABLE players
      ALTER COLUMN username SET DEFAULT '';

    WITH ranked_names AS (
      SELECT
        player_id,
        username,
        ROW_NUMBER() OVER (
          PARTITION BY LOWER(username)
          ORDER BY created_at, player_id
        ) AS rn
      FROM players
      WHERE username IS NOT NULL
        AND username <> ''
    )
    UPDATE players p
    SET username_key = CASE
      WHEN r.rn = 1 THEN LOWER(r.username)
      ELSE
        LOWER(r.username) || '_' ||
        SUBSTRING(MD5(p.player_id), 1, 8)
    END
    FROM ranked_names r
    WHERE p.player_id = r.player_id
      AND (
        p.username_key IS NULL OR
        p.username_key = ''
      );

    CREATE UNIQUE INDEX IF NOT EXISTS
      uq_players_username_key
      ON players (username_key)
      WHERE username_key IS NOT NULL
        AND username_key <> '';

    CREATE INDEX IF NOT EXISTS
      idx_players_country
      ON players (country);

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
          game_rights BETWEEN 0 AND ${MAX_RIGHTS}
        ),

      rights_anchor_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW(),

      tournament_stage INTEGER NOT NULL DEFAULT 1
        CHECK (
          tournament_stage BETWEEN 1
          AND ${TOURNAMENT_TOTAL_STAGES}
        ),

      tournament_rights INTEGER NOT NULL
        DEFAULT ${TOURNAMENT_INITIAL_RIGHTS}
        CHECK (
          tournament_rights BETWEEN 0
          AND ${TOURNAMENT_INITIAL_RIGHTS}
        ),

      tournament_score INTEGER NOT NULL DEFAULT 0
        CHECK (tournament_score >= 0),

      tournament_completed BOOLEAN
        NOT NULL DEFAULT FALSE,

      infinite_state JSONB,
      hundred_state JSONB,

      updated_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW()
    );

    INSERT INTO player_state (player_id)
    SELECT player_id
    FROM players
    ON CONFLICT (player_id) DO NOTHING;

    DO $$
    BEGIN
      IF to_regclass('public.player_scores')
         IS NOT NULL
      THEN
        INSERT INTO player_state (
          player_id,
          general_score,
          infinite_high_score,
          updated_at
        )
        SELECT
          player_id,
          general_score,
          infinite_score,
          updated_at
        FROM player_scores
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
          updated_at = GREATEST(
            player_state.updated_at,
            EXCLUDED.updated_at
          );
      END IF;
    END $$;

    CREATE TABLE IF NOT EXISTS
      player_monthly_scores (
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

    CREATE INDEX IF NOT EXISTS
      idx_player_state_general
      ON player_state (
        general_score DESC,
        updated_at ASC
      );

    CREATE INDEX IF NOT EXISTS
      idx_player_state_infinite
      ON player_state (
        infinite_high_score DESC,
        updated_at ASC
      );

    CREATE INDEX IF NOT EXISTS
      idx_monthly_general
      ON player_monthly_scores (
        month_key,
        general_score DESC,
        updated_at ASC
      );

    CREATE INDEX IF NOT EXISTS
      idx_monthly_infinite
      ON player_monthly_scores (
        month_key,
        infinite_score DESC,
        updated_at ASC
      );

    CREATE TABLE IF NOT EXISTS game_sessions (
      session_id TEXT PRIMARY KEY,

      player_id TEXT NOT NULL
        REFERENCES players(player_id)
        ON DELETE CASCADE,

      room_id TEXT,
      mode TEXT NOT NULL,
      difficulty TEXT NOT NULL,
      stage INTEGER NOT NULL DEFAULT 1,
      puzzle JSONB NOT NULL,
      state JSONB NOT NULL DEFAULT '{}'::jsonb,
      status TEXT NOT NULL DEFAULT 'active',
      result TEXT,

      started_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW(),

      deadline_at TIMESTAMPTZ NOT NULL,
      completed_at TIMESTAMPTZ,

      updated_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW()
    );

    UPDATE game_sessions
    SET
      status = 'abandoned',
      result = COALESCE(
        result,
        'server_restart'
      ),
      completed_at = NOW(),
      updated_at = NOW()
    WHERE status = 'active'
      AND mode IN (
        'two_player',
        'friend',
        'tournament'
      );

    WITH duplicate_active AS (
      SELECT
        session_id,
        ROW_NUMBER() OVER (
          PARTITION BY player_id
          ORDER BY
            updated_at DESC,
            started_at DESC,
            session_id DESC
        ) AS rn
      FROM game_sessions
      WHERE status = 'active'
    )
    UPDATE game_sessions g
    SET
      status = 'abandoned',
      result = COALESCE(
        g.result,
        'migration_duplicate'
      ),
      completed_at = NOW(),
      updated_at = NOW()
    FROM duplicate_active d
    WHERE g.session_id = d.session_id
      AND d.rn > 1;

    CREATE INDEX IF NOT EXISTS
      idx_game_sessions_player_active
      ON game_sessions (
        player_id,
        mode,
        status,
        updated_at DESC
      );

    CREATE UNIQUE INDEX IF NOT EXISTS
      uq_game_sessions_one_active_per_player
      ON game_sessions (player_id)
      WHERE status = 'active';

    CREATE INDEX IF NOT EXISTS
      idx_game_sessions_room
      ON game_sessions (room_id)
      WHERE room_id IS NOT NULL;

    CREATE INDEX IF NOT EXISTS
      idx_game_sessions_cleanup
      ON game_sessions (
        status,
        updated_at
      );
  `);

  console.log("PostgreSQL şeması hazır.");
}

async function ensurePlayer(
  client,
  playerId,
  country = "TR"
) {
  await client.query(
    `INSERT INTO players (
       player_id,
       country,
       updated_at
     )
     VALUES ($1, $2, NOW())
     ON CONFLICT (player_id)
     DO UPDATE SET
       country = EXCLUDED.country,
       updated_at = NOW()`,
    [playerId, safeCountry(country)]
  );

  await client.query(
    `INSERT INTO player_state (player_id)
     VALUES ($1)
     ON CONFLICT (player_id) DO NOTHING`,
    [playerId]
  );
}

function levelState(totalXp) {
  const safeXp = safeInt(totalXp, 0, 0);
  let remaining = safeXp;
  let level = 1;

  while (level < 1000) {
    const required = level * 2;

    if (remaining < required) break;

    remaining -= required;
    level += 1;
  }

  return {
    totalXp: safeXp,
    level,
    xpInCurrentLevel:
      level < 1000 ? remaining : 0,
    xpRequiredForNextLevel:
      level < 1000 ? level * 2 : 0,
  };
}

function refillRightsFromRow(
  row,
  at = nowMs()
) {
  let rights = safeInt(
    row.game_rights,
    MAX_RIGHTS,
    0,
    MAX_RIGHTS
  );

  let anchor = new Date(
    row.rights_anchor_at || at
  ).getTime();

  if (!Number.isFinite(anchor)) {
    anchor = at;
  }

  if (rights >= MAX_RIGHTS) {
    return {
      rights: MAX_RIGHTS,
      anchorMs: at,
      changed: anchor !== at,
    };
  }

  const refillCount = Math.floor(
    Math.max(0, at - anchor) /
      RIGHT_REFILL_MS
  );

  if (refillCount <= 0) {
    return {
      rights,
      anchorMs: anchor,
      changed: false,
    };
  }

  rights = Math.min(
    MAX_RIGHTS,
    rights + refillCount
  );

  const anchorMs =
    rights >= MAX_RIGHTS
      ? at
      : anchor +
        refillCount * RIGHT_REFILL_MS;

  return {
    rights,
    anchorMs,
    changed: true,
  };
}

async function normalizeRights(
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

  const row = result.rows[0];

  if (!row) {
    throw new Error(
      "PLAYER_STATE_NOT_FOUND"
    );
  }

  const normalized =
    refillRightsFromRow(row);

  if (normalized.changed) {
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
        normalized.rights,
        normalized.anchorMs,
      ]
    );
  }

  return normalized;
}

async function consumeRight(
  client,
  playerId
) {
  const normalized = await normalizeRights(
    client,
    playerId,
    true
  );

  if (normalized.rights <= 0) {
    const error = new Error(
      "Oyun hakkınız bulunmuyor."
    );

    error.code = "NO_GAME_RIGHT";
    error.status = 409;
    throw error;
  }

  const next = normalized.rights - 1;

  const anchorMs =
    normalized.rights >= MAX_RIGHTS
      ? nowMs()
      : normalized.anchorMs;

  await client.query(
    `UPDATE player_state
     SET
       game_rights = $2,
       rights_anchor_at =
         TO_TIMESTAMP($3 / 1000.0),
       updated_at = NOW()
     WHERE player_id = $1`,
    [playerId, next, anchorMs]
  );

  return next;
}

async function profileForPlayer(
  clientOrPool,
  playerId,
  { lock = false } = {}
) {
  await normalizeRights(
    clientOrPool,
    playerId,
    lock
  );

  const result = await clientOrPool.query(
    `SELECT
       p.player_id,
       p.username,
       p.country,
       p.username_change_count,

       EXTRACT(
         EPOCH FROM p.username_changed_at
       ) * 1000
         AS username_changed_at_ms,

       EXTRACT(
         EPOCH FROM p.updated_at
       ) * 1000
         AS username_updated_at_ms,

       s.general_score,
       s.infinite_high_score,
       s.total_xp,
       s.game_rights,

       EXTRACT(
         EPOCH FROM s.rights_anchor_at
       ) * 1000
         AS rights_anchor_at_ms,

       s.tournament_stage,
       s.tournament_rights,
       s.tournament_score,
       s.tournament_completed,
       s.infinite_state,
       s.hundred_state

     FROM players p

     JOIN player_state s
       ON s.player_id = p.player_id

     WHERE p.player_id = $1

     ${
       lock
         ? "FOR UPDATE OF p, s"
         : ""
     }`,
    [playerId]
  );

  const row = result.rows[0];

  if (!row) return null;

  const rightState = refillRightsFromRow({
    game_rights: row.game_rights,
    rights_anchor_at: Number(
      row.rights_anchor_at_ms || nowMs()
    ),
  });

  const millisUntilNextRight =
    rightState.rights >= MAX_RIGHTS
      ? 0
      : Math.max(
          0,
          RIGHT_REFILL_MS -
            (nowMs() - rightState.anchorMs)
        );

  const lastChangeMs = Number(
    row.username_changed_at_ms || 0
  );

  const nextChangeMs =
    lastChangeMs > 0
      ? addOneCalendarMonthUtc(
          lastChangeMs
        )
      : 0;

  const level = levelState(row.total_xp);
  const infiniteState =
    row.infinite_state || null;

  return {
    playerId: row.player_id,
    username: row.username || "",
    country: row.country || "TR",

    usernameChangeCount: Number(
      row.username_change_count || 0
    ),

    usernameChangedAtMillis:
      lastChangeMs,

    usernameUpdatedAtMillis: Number(
      row.username_updated_at_ms || 0
    ),

    usernameNextChangeAtMillis:
      nextChangeMs,

    usernameMillisUntilNextChange:
      Math.max(
        0,
        nextChangeMs - nowMs()
      ),

    generalScore: Number(
      row.general_score || 0
    ),

    infiniteHighScore: Number(
      row.infinite_high_score || 0
    ),

    ...level,

    gameRights: rightState.rights,
    maxGameRights: MAX_RIGHTS,
    millisUntilNextRight,

    tournament: {
      currentStage: Number(
        row.tournament_stage || 1
      ),

      remainingRights: Number(
        row.tournament_rights ||
          TOURNAMENT_INITIAL_RIGHTS
      ),

      totalScore: Number(
        row.tournament_score || 0
      ),

      completed: Boolean(
        row.tournament_completed
      ),
    },

    hasInfiniteProgress: Boolean(
      infiniteState &&
        infiniteState.sessionId
    ),

    infiniteState,
  };
}

function addOneCalendarMonthUtc(
  timestampMs
) {
  const d = new Date(timestampMs);

  const next = new Date(
    Date.UTC(
      d.getUTCFullYear(),
      d.getUTCMonth() + 1,
      d.getUTCDate(),
      d.getUTCHours(),
      d.getUTCMinutes(),
      d.getUTCSeconds(),
      d.getUTCMilliseconds()
    )
  );

  return next.getTime();
}

function currentMonthKey() {
  return new Date()
    .toISOString()
    .slice(0, 7);
}

const leaderboardCache = new Map();

function invalidateLeaderboardCache() {
  leaderboardCache.clear();
}

async function applyRewards(
  client,
  playerId,
  {
    general = 0,
    infinite = 0,
    xp = 0,
  }
) {
  const generalDelta = safeInt(
    general,
    0,
    -100_000,
    100_000
  );

  const infiniteDelta = safeInt(
    infinite,
    0,
    0,
    100_000
  );

  const xpDelta = safeInt(
    xp,
    0,
    0,
    1_000_000
  );

  if (
    generalDelta === 0 &&
    infiniteDelta === 0 &&
    xpDelta === 0
  ) {
    return;
  }

  await client.query(
    `UPDATE player_state
     SET
       general_score = GREATEST(
         0,
         LEAST(
           2000000000,
           general_score + $2
         )
       ),

       infinite_high_score = GREATEST(
         infinite_high_score,
         LEAST(
           2000000000,
           $3
         )
       ),

       total_xp = LEAST(
         2000000000,
         total_xp + $4
       ),

       updated_at = NOW()

     WHERE player_id = $1`,
    [
      playerId,
      generalDelta,
      infiniteDelta,
      xpDelta,
    ]
  );

  if (
    generalDelta !== 0 ||
    infiniteDelta > 0
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
         general_score = GREATEST(
           0,
           LEAST(
             2000000000,
             player_monthly_scores.general_score +
               $3
           )
         ),

         infinite_score = GREATEST(
           player_monthly_scores.infinite_score,
           EXCLUDED.infinite_score
         ),

         updated_at = NOW()`,
      [
        playerId,
        currentMonthKey(),
        generalDelta,
        infiniteDelta,
      ]
    );

    invalidateLeaderboardCache();
  }
}

async function exchangePlayGamesAuthCode(
  authCode
) {
  if (
    !GOOGLE_WEB_CLIENT_ID ||
    !GOOGLE_WEB_CLIENT_SECRET ||
    !PLAY_GAMES_APPLICATION_ID
  ) {
    const error = new Error(
      "Google Play Games sunucu kimlik bilgileri eksik."
    );

    error.code =
      "GOOGLE_AUTH_NOT_CONFIGURED";

    error.status = 503;
    throw error;
  }

  const tokenResponse = await fetch(
    "https://oauth2.googleapis.com/token",
    {
      method: "POST",

      headers: {
        "Content-Type":
          "application/x-www-form-urlencoded",
      },

      body: new URLSearchParams({
        code: safeText(
          authCode,
          "",
          4096
        ),

        client_id:
          GOOGLE_WEB_CLIENT_ID,

        client_secret:
          GOOGLE_WEB_CLIENT_SECRET,

        redirect_uri: "",

        grant_type:
          "authorization_code",
      }),
    }
  );

  const tokenJson =
    await tokenResponse
      .json()
      .catch(() => ({}));

  if (
    !tokenResponse.ok ||
    !tokenJson.access_token
  ) {
    const error = new Error(
      "Play Games yetkilendirme kodu doğrulanamadı."
    );

    error.code =
      "GOOGLE_CODE_EXCHANGE_FAILED";

    error.status = 401;
    throw error;
  }

  const verifyResponse = await fetch(
    "https://games.googleapis.com/" +
      "games/v1/applications/" +
      encodeURIComponent(
        PLAY_GAMES_APPLICATION_ID
      ) +
      "/verify",
    {
      headers: {
        Authorization:
          `Bearer ${tokenJson.access_token}`,
      },
    }
  );

  const verifyJson =
    await verifyResponse
      .json()
      .catch(() => ({}));

  const verifiedGooglePlayerId =
    safePlayerId(
      verifyJson.player_id ||
        verifyJson.playerId
    );

  const playerId =
    verifiedGooglePlayerId
      ? verifiedGooglePlayerId.startsWith(
          "pg_"
        )
        ? verifiedGooglePlayerId
        : `pg_${verifiedGooglePlayerId}`
      : "";

  if (
    !verifyResponse.ok ||
    !playerId
  ) {
    const error = new Error(
      "Play Games oyuncu kimliği doğrulanamadı."
    );

    error.code =
      "GOOGLE_PLAYER_VERIFY_FAILED";

    error.status = 401;
    throw error;
  }

  return playerId;
}

function sendError(
  res,
  error,
  fallback = "İşlem tamamlanamadı."
) {
  const status = Number(
    error.status || 500
  );

  if (status >= 500) {
    console.error(
      error.code || "SERVER_ERROR",
      error.message,
      error.stack
    );
  }

  res.status(
    status >= 400 && status < 600
      ? status
      : 500
  ).json({
    ok: false,

    code:
      error.code || "SERVER_ERROR",

    message:
      status >= 500
        ? fallback
        : error.message,
  });
}

app.post(
  "/auth/play-games",
  rateLimit({
    windowMs: 60_000,
    max: 12,
  }),
  async (req, res) => {
    if (!requireConfig(res)) return;

    try {
      let playerId;

      if (
        ALLOW_INSECURE_DEV_AUTH &&
        req.body.devPlayerId
      ) {
        playerId = safePlayerId(
          `dev_${req.body.devPlayerId}`
        );
      } else {
        playerId =
          await exchangePlayGamesAuthCode(
            req.body.serverAuthCode
          );
      }

      if (!playerId) {
        res.status(401).json({
          ok: false,
          code: "AUTH_FAILED",
          message:
            "Oyuncu doğrulanamadı.",
        });

        return;
      }

      const client =
        await pool.connect();

      try {
        await client.query("BEGIN");

        await ensurePlayer(
          client,
          playerId,
          req.body.country
        );

        const profile =
          await profileForPlayer(
            client,
            playerId,
            { lock: true }
          );

        await client.query("COMMIT");

        res.json({
          ok: true,

          token:
            signAuthToken(playerId),

          expiresInMillis:
            AUTH_TOKEN_TTL_MS,

          profile,
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
        "Play Games oturumu açılamadı."
      );
    }
  }
);

app.get(
  "/profile",
  authMiddleware,
  rateLimit({
    windowMs: 10_000,
    max: 20,
  }),
  async (req, res) => {
    try {
      const profile =
        await profileForPlayer(
          pool,
          req.playerId
        );

      if (!profile) {
        res.status(404).json({
          ok: false,

          code:
            "PLAYER_NOT_FOUND",

          message:
            "Oyuncu kaydı bulunamadı.",
        });

        return;
      }

      res.json({
        ok: true,
        profile,
      });
    } catch (error) {
      sendError(
        res,
        error,
        "Profil yüklenemedi."
      );
    }
  }
);

app.post(
  "/profile/username",
  authMiddleware,
  rateLimit({
    windowMs: 60_000,
    max: 8,
  }),
  async (req, res) => {
    const username =
      safeUsername(
        req.body.username
      );

    const validationError =
      validateUsername(username);

    if (validationError) {
      res.status(400).json({
        ok: false,

        code:
          "INVALID_USERNAME",

        message:
          validationError,
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

             EXTRACT(
               EPOCH FROM
                 username_changed_at
             ) * 1000
               AS changed_at_ms

           FROM players

           WHERE player_id = $1

           FOR UPDATE`,
          [req.playerId]
        );

      const current =
        currentResult.rows[0];

      if (!current) {
        const error = new Error(
          "Oyuncu kaydı bulunamadı."
        );

        error.status = 404;
        error.code =
          "PLAYER_NOT_FOUND";

        throw error;
      }

      if (
        current.username === username
      ) {
        const error = new Error(
          "Yeni kullanıcı adı mevcut adınızla aynı olamaz."
        );

        error.status = 409;
        error.code =
          "SAME_USERNAME";

        throw error;
      }

      const isInitial =
        !current.username;

      const changedAtMs = Number(
        current.changed_at_ms || 0
      );

      if (
        !isInitial &&
        changedAtMs > 0 &&
        addOneCalendarMonthUtc(
          changedAtMs
        ) > nowMs()
      ) {
        const error = new Error(
          "Kullanıcı adını tekrar değiştirmek için bir ay beklemelisiniz."
        );

        error.status = 409;
        error.code =
          "USERNAME_COOLDOWN";

        throw error;
      }

      try {
        await client.query(
          `UPDATE players
           SET
             username = $2,
             username_key = $3,

             username_change_count =
               username_change_count +
               CASE
                 WHEN username = ''
                   THEN 0
                 ELSE 1
               END,

             username_changed_at =
               CASE
                 WHEN username = ''
                   THEN NULL
                 ELSE NOW()
               END,

             updated_at = NOW()

           WHERE player_id = $1`,
          [
            req.playerId,
            username,
            usernameKey(username),
          ]
        );
      } catch (error) {
        if (error.code === "23505") {
          error.status = 409;
          error.code =
            "USERNAME_TAKEN";
          error.message =
            "Bu kullanıcı adı zaten alınmış.";
        }

        throw error;
      }

      const profile =
        await profileForPlayer(
          client,
          req.playerId,
          { lock: true }
        );

      await client.query("COMMIT");

      res.json({
        ok: true,
        profile,
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

app.post(
  "/leaderboard/scores/sync",
  (_req, res) => {
    res.status(410).json({
      ok: false,

      code:
        "CLIENT_SCORE_DISABLED",

      message:
        "İstemci tarafından toplam skor gönderme kapatıldı.",
    });
  }
);

app.post(
  "/leaderboard/scores/add",
  (_req, res) => {
    res.status(410).json({
      ok: false,

      code:
        "CLIENT_SCORE_DISABLED",

      message:
        "İstemci tarafından skor farkı gönderme kapatıldı.",
    });
  }
);

app.post(
  "/leaderboard/username/claim",
  (_req, res) => {
    res.status(410).json({
      ok: false,

      code:
        "OLD_ENDPOINT_DISABLED",

      message:
        "Yeni /profile/username endpointini kullanın.",
    });
  }
);

app.get(
  "/leaderboard",
  authMiddleware,
  rateLimit({
    windowMs: 10_000,
    max: 20,
  }),
  async (req, res) => {
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

    const countryResult =
      await pool
        .query(
          `SELECT country
           FROM players
           WHERE player_id = $1`,
          [req.playerId]
        )
        .catch(() => ({
          rows: [],
        }));

    const country = safeCountry(
      countryResult.rows[0]?.country
    );

    const scopeCountryKey =
      scope === "country"
        ? country
        : "*";

    const cacheKey =
      `response:${scoreType}:` +
      `${period}:${scope}:` +
      `${scopeCountryKey}:` +
      `${req.playerId}`;

    const cached =
      leaderboardCache.get(cacheKey);

    if (
      cached &&
      cached.expiresAt > nowMs()
    ) {
      res.json(cached.value);
      return;
    }

    try {
      const monthKey =
        currentMonthKey();

      const tableName =
        period === "month"
          ? "player_monthly_scores"
          : "player_state";

      const scoreColumn =
        scoreType === "infinite"
          ? period === "month"
            ? "infinite_score"
            : "infinite_high_score"
          : "general_score";

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

      if (scope === "country") {
        values.push(country);

        conditions.push(
          `p.country = $${values.length}`
        );
      }

      const where =
        conditions.join(" AND ");

      const rankingBase = `
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

        WHERE ${where}`;

      const rowsCacheKey =
        `rows:${scoreType}:` +
        `${period}:${scope}:` +
        `${scopeCountryKey}`;

      const cachedRows =
        leaderboardCache.get(
          rowsCacheKey
        );

      let rows;

      if (
        cachedRows &&
        cachedRows.expiresAt >
          nowMs()
      ) {
        rows = cachedRows.value;
      } else {
        const listResult =
          await pool.query(
            `WITH ranked AS (
               ${rankingBase}
             )

             SELECT
               position,
               username,
               country,
               score

             FROM ranked

             ORDER BY position
             LIMIT 50`,
            values
          );

        rows = listResult.rows.map(
          (row) => ({
            rank: Number(
              row.position
            ),

            username:
              row.username,

            country:
              row.country,

            score: Number(
              row.score
            ),
          })
        );

        leaderboardCache.set(
          rowsCacheKey,
          {
            expiresAt:
              nowMs() +
              LEADERBOARD_CACHE_MS,

            value: rows,
          }
        );
      }

      async function myRank(
        includeCountry
      ) {
        const rankValues = [];

        const rankConditions = [
          `s.${scoreColumn} > 0`,
        ];

        if (period === "month") {
          rankValues.push(monthKey);

          rankConditions.push(
            `s.month_key = ` +
              `$${rankValues.length}`
          );
        }

        if (includeCountry) {
          rankValues.push(country);

          rankConditions.push(
            `p.country = ` +
              `$${rankValues.length}`
          );
        }

        rankValues.push(req.playerId);

        const playerParam =
          rankValues.length;

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

               FROM ${tableName} s

               JOIN players p
                 ON p.player_id =
                    s.player_id

               WHERE ${
                 rankConditions.join(
                   " AND "
                 )
               }
             )

             SELECT
               position,
               score

             FROM ranked

             WHERE player_id =
               $${playerParam}

             LIMIT 1`,
            rankValues
          );

        return result.rows[0] || null;
      }

      const [world, local] =
        await Promise.all([
          myRank(false),
          myRank(true),
        ]);

      const value = {
        ok: true,
        scoreType,
        period,
        scope,
        country,
        monthKey,

        myWorldRank: world
          ? Number(world.position)
          : null,

        myCountryRank: local
          ? Number(local.position)
          : null,

        myScore: world
          ? Number(world.score)
          : 0,

        rows,
      };

      leaderboardCache.set(
        cacheKey,
        {
          expiresAt:
            nowMs() +
            LEADERBOARD_CACHE_MS,

          value,
        }
      );

      res.json(value);
    } catch (error) {
      sendError(
        res,
        error,
        "Skor tablosu yüklenemedi."
      );
    }
  }
);

app.post(
  "/tournament/reset",
  authMiddleware,
  rateLimit({
    windowMs: 60_000,
    max: 6,
  }),
  async (req, res) => {
    const client =
      await pool.connect();

    try {
      await client.query("BEGIN");

      await client.query(
        `SELECT pg_advisory_xact_lock(
           hashtext($1)
         )`,
        [req.playerId]
      );

      await expireStaleActiveSessions(
        client,
        req.playerId
      );

      const active =
        await client.query(
          `SELECT 1
           FROM game_sessions
           WHERE player_id = $1
             AND status = 'active'
           LIMIT 1`,
          [req.playerId]
        );

      if (active.rows[0]) {
        const error = new Error(
          "Aktif oyun bitmeden turnuva sıfırlanamaz."
        );

        error.status = 409;
        error.code =
          "ACTIVE_SESSION_EXISTS";

        throw error;
      }

      await client.query(
        `UPDATE player_state
         SET
           tournament_stage = 1,

           tournament_rights = $2,

           tournament_score = 0,

           tournament_completed =
             FALSE,

           updated_at = NOW()

         WHERE player_id = $1`,
        [
          req.playerId,
          TOURNAMENT_INITIAL_RIGHTS,
        ]
      );

      const profile =
        await profileForPlayer(
          client,
          req.playerId,
          { lock: true }
        );

      await client.query("COMMIT");

      res.json({
        ok: true,
        profile,
      });
    } catch (error) {
      await client.query("ROLLBACK");

      sendError(
        res,
        error,
        "Turnuva sıfırlanamadı."
      );
    } finally {
      client.release();
    }
  }
);

const OPERATORS = [
  "+",
  "−",
  "×",
  "÷",
];

function permutations(items) {
  if (items.length <= 1) {
    return [items.slice()];
  }

  const result = [];

  items.forEach((item, index) => {
    const rest = items
      .slice(0, index)
      .concat(
        items.slice(index + 1)
      );

    for (
      const tail of permutations(rest)
    ) {
      result.push([
        item,
        ...tail,
      ]);
    }
  });

  return result;
}

function operatorProducts(length) {
  let rows = [[]];

  for (
    let index = 0;
    index < length;
    index += 1
  ) {
    rows = rows.flatMap((row) =>
      OPERATORS.map((operator) => [
        ...row,
        operator,
      ])
    );
  }

  return rows;
}

function evaluateExpression(
  values,
  operators
) {
  if (
    !Array.isArray(values) ||
    operators.length !==
      values.length - 1
  ) {
    return null;
  }

  const additiveValues = [
    Number(values[0]),
  ];

  const additiveOps = [];

  for (
    let index = 0;
    index < operators.length;
    index += 1
  ) {
    const next = Number(
      values[index + 1]
    );

    const operator =
      operators[index];

    if (operator === "×") {
      additiveValues[
        additiveValues.length - 1
      ] *= next;
    } else if (operator === "÷") {
      if (Math.abs(next) < 1e-9) {
        return null;
      }

      additiveValues[
        additiveValues.length - 1
      ] /= next;
    } else if (
      operator === "+" ||
      operator === "−"
    ) {
      additiveOps.push(operator);
      additiveValues.push(next);
    } else {
      return null;
    }
  }

  let result = additiveValues[0];

  additiveOps.forEach(
    (operator, index) => {
      result =
        operator === "+"
          ? result +
            additiveValues[index + 1]
          : result -
            additiveValues[index + 1];
    }
  );

  return result;
}

function randomInt(
  min,
  maxInclusive
) {
  return crypto.randomInt(
    min,
    maxInclusive + 1
  );
}

function generatePuzzle(difficulty) {
  const hard =
    difficulty === "Hard";

  const count = hard ? 4 : 3;

  for (
    let attempt = 0;
    attempt < 100;
    attempt += 1
  ) {
    const numbers = Array.from(
      { length: count },
      () =>
        hard
          ? randomInt(2, 20)
          : randomInt(1, 9)
    );

    const candidates = [];

    for (
      const ordered of
        permutations(numbers)
    ) {
      for (
        const operators of
          operatorProducts(count - 1)
      ) {
        if (
          hard &&
          !operators.some(
            (operator) =>
              operator === "×" ||
              operator === "÷"
          )
        ) {
          continue;
        }

        const value =
          evaluateExpression(
            ordered,
            operators
          );

        if (
          !Number.isFinite(value) ||
          Math.abs(
            value -
              Math.round(value)
          ) > 1e-9
        ) {
          continue;
        }

        const target =
          Math.round(value);

        const valid = hard
          ? target > 20 &&
            target < 200
          : target > 0 &&
            target < 50;

        if (valid) {
          candidates.push(target);
        }
      }
    }

    if (candidates.length > 0) {
      return {
        difficulty,

        target:
          candidates[
            randomInt(
              0,
              candidates.length - 1
            )
          ],

        numbers,
      };
    }
  }

  return hard
    ? {
        difficulty: "Hard",
        target: 60,
        numbers: [3, 4, 5, 10],
      }
    : {
        difficulty: "Medium",
        target: 24,
        numbers: [3, 8, 1],
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

  if (
    !Array.isArray(numberSlots) ||
    !Array.isArray(operatorSlots)
  ) {
    return false;
  }

  if (
    numberSlots.length !==
      puzzle.numbers.length ||
    operatorSlots.length !==
      puzzle.numbers.length - 1
  ) {
    return false;
  }

  const indices = numberSlots.map(
    (value) =>
      safeInt(
        value,
        -1,
        -1,
        puzzle.numbers.length - 1
      )
  );

  if (
    new Set(indices).size !==
      puzzle.numbers.length ||
    indices.some(
      (index) => index < 0
    )
  ) {
    return false;
  }

  const operators =
    operatorSlots.map(
      (operator) =>
        String(operator || "")
    );

  if (
    operators.some(
      (operator) =>
        !OPERATORS.includes(operator)
    )
  ) {
    return false;
  }

  const ordered = indices.map(
    (index) =>
      Number(puzzle.numbers[index])
  );

  const result =
    evaluateExpression(
      ordered,
      operators
    );

  return (
    Number.isFinite(result) &&
    Math.abs(
      result -
        Number(puzzle.target)
    ) < 0.0001
  );
}

function sessionId() {
  return typeof crypto.randomUUID ===
    "function"
    ? crypto.randomUUID()
    : crypto
        .randomBytes(16)
        .toString("hex");
}

function stageDifficulty(
  stage,
  mode
) {
  if (mode === "infinite") {
    return stage <= 5
      ? "Medium"
      : "Hard";
  }

  if (
    mode === "tournament" ||
    mode === "hundred"
  ) {
    return stage <= 4
      ? "Medium"
      : "Hard";
  }

  return "Medium";
}

function stageReward(
  mode,
  difficulty,
  stage
) {
  if (mode === "single") {
    return difficulty === "Hard"
      ? 15
      : 10;
  }

  if (
    mode === "two_player" ||
    mode === "friend"
  ) {
    return difficulty === "Hard"
      ? 15
      : 10;
  }

  if (mode === "infinite") {
    return stage * 5;
  }

  if (mode === "tournament") {
    return stage >=
      TOURNAMENT_TOTAL_STAGES
      ? 480
      : stage * 20;
  }

  return 0;
}

function xpReward(
  mode,
  difficulty,
  stage,
  won = true
) {
  if (!won) {
    return mode === "hundred"
      ? stage * 20
      : 0;
  }

  if (mode === "single") {
    return difficulty === "Hard"
      ? 15
      : 10;
  }

  if (
    mode === "two_player" ||
    mode === "friend"
  ) {
    return difficulty === "Hard"
      ? 30
      : 20;
  }

  if (mode === "infinite") {
    return Math.min(
      2_000_000_000,
      (stage * (stage + 1) * 5) /
        2
    );
  }

  if (mode === "tournament") {
    return stageReward(
      mode,
      difficulty,
      stage
    );
  }

  if (mode === "hundred") {
    return 480;
  }

  return 0;
}

async function expireStaleActiveSessions(
  client,
  playerId
) {
  await client.query(
    `UPDATE game_sessions
     SET
       status = 'expired',

       result = COALESCE(
         result,
         'expired'
       ),

       completed_at = NOW(),
       updated_at = NOW()

     WHERE player_id = $1
       AND status = 'active'
       AND deadline_at <= NOW()`,
    [playerId]
  );
}

async function preparePlayerForNewSession(
  client,
  playerId,
  mode,
  { replaceSameMode = false } = {}
) {
  await client.query(
    `SELECT pg_advisory_xact_lock(
       hashtext($1)
     )`,
    [playerId]
  );

  await expireStaleActiveSessions(
    client,
    playerId
  );

  if (replaceSameMode) {
    await client.query(
      `UPDATE game_sessions
       SET
         status = 'abandoned',

         result = COALESCE(
           result,
           'replaced'
         ),

         completed_at = NOW(),
         updated_at = NOW()

       WHERE player_id = $1
         AND mode = $2
         AND status = 'active'`,
      [playerId, mode]
    );
  }

  const active = await client.query(
    `SELECT mode
     FROM game_sessions
     WHERE player_id = $1
       AND status = 'active'
     LIMIT 1`,
    [playerId]
  );

  if (active.rows[0]) {
    const error = new Error(
      "Başka bir aktif oyununuz bulunuyor."
    );

    error.status = 409;
    error.code =
      "ACTIVE_SESSION_EXISTS";

    throw error;
  }
}

async function createGameSession(
  client,
  {
    playerId,
    mode,
    difficulty,
    stage = 1,
    roomId = null,
    deadlineMs,
    state = {},
  }
) {
  const puzzle =
    generatePuzzle(difficulty);

  const id = sessionId();

  const deadlineAt =
    nowMs() + deadlineMs;

  await client.query(
    `INSERT INTO game_sessions (
       session_id,
       player_id,
       room_id,
       mode,
       difficulty,
       stage,
       puzzle,
       state,
       deadline_at
     )
     VALUES (
       $1,
       $2,
       $3,
       $4,
       $5,
       $6,
       $7::jsonb,
       $8::jsonb,
       TO_TIMESTAMP($9 / 1000.0)
     )`,
    [
      id,
      playerId,
      roomId,
      mode,
      difficulty,
      stage,
      JSON.stringify(puzzle),
      JSON.stringify(state),
      deadlineAt,
    ]
  );

  return {
    sessionId: id,
    mode,
    difficulty,
    stage,
    puzzle,
    deadlineAtMillis: deadlineAt,
    numberSlots: [],
    operatorSlots: [],
    remainingMs: deadlineMs,
  };
}

async function readActiveSession(
  clientOrPool,
  playerId,
  sessionIdValue,
  lock = false
) {
  const result =
    await clientOrPool.query(
      `SELECT
         session_id,
         player_id,
         room_id,
         mode,
         difficulty,
         stage,
         puzzle,
         state,
         status,
         result,

         EXTRACT(
           EPOCH FROM started_at
         ) * 1000
           AS started_at_ms,

         EXTRACT(
           EPOCH FROM deadline_at
         ) * 1000
           AS deadline_at_ms

       FROM game_sessions

       WHERE session_id = $1
         AND player_id = $2

       ${
         lock
           ? "FOR UPDATE"
           : ""
       }`,
      [
        safeText(
          sessionIdValue,
          "",
          128
        ),

        playerId,
      ]
    );

  return result.rows[0] || null;
}

function serializeSession(row) {
  if (!row) return null;

  const state = row.state || {};

  return {
    sessionId: row.session_id,
    mode: row.mode,
    difficulty: row.difficulty,

    stage: Number(
      row.stage || 1
    ),

    puzzle: row.puzzle,

    deadlineAtMillis: Number(
      row.deadline_at_ms || 0
    ),

    numberSlots:
      Array.isArray(
        state.numberSlots
      )
        ? state.numberSlots
        : [],

    operatorSlots:
      Array.isArray(
        state.operatorSlots
      )
        ? state.operatorSlots
        : [],

    remainingMs: Math.max(
      1,
      Number(
        row.deadline_at_ms || 0
      ) - nowMs()
    ),

    score: safeInt(
      state.score,
      0
    ),
  };
}

app.post(
  "/game/session/start",
  authMiddleware,
  rateLimit({
    windowMs: 10_000,
    max: 12,
  }),
  async (req, res) => {
    const mode =
      safeMode(req.body.mode);

    const requestedDifficulty =
      safeDifficulty(
        req.body.difficulty
      );

    const fresh =
      Boolean(req.body.fresh);

    if (
      ![
        "single",
        "infinite",
        "hundred",
      ].includes(mode)
    ) {
      res.status(400).json({
        ok: false,

        code:
          "INVALID_MODE",

        message:
          "Bu mod HTTP oturumu ile başlatılamaz.",
      });

      return;
    }

    const client =
      await pool.connect();

    try {
      await client.query("BEGIN");

      const profile =
        await profileForPlayer(
          client,
          req.playerId,
          { lock: true }
        );

      let gameSession;

      if (mode === "single") {
        await preparePlayerForNewSession(
          client,
          req.playerId,
          mode,
          {
            replaceSameMode: true,
          }
        );

        gameSession =
          await createGameSession(
            client,
            {
              playerId:
                req.playerId,

              mode,

              difficulty:
                requestedDifficulty,

              deadlineMs:
                SINGLE_LIMIT_MS,
            }
          );
      } else if (
        mode === "infinite"
      ) {
        const state =
          profile.infiniteState;

        if (
          !fresh &&
          state?.sessionId
        ) {
          const existing =
            await readActiveSession(
              client,
              req.playerId,
              state.sessionId,
              true
            );

          if (
            existing &&
            existing.status ===
              "active" &&
            Number(
              existing.deadline_at_ms
            ) > nowMs()
          ) {
            gameSession =
              serializeSession(
                existing
              );
          }
        }

        if (!gameSession) {
          await preparePlayerForNewSession(
            client,
            req.playerId,
            mode,
            {
              replaceSameMode:
                fresh,
            }
          );

          const stage = fresh
            ? 1
            : safeInt(
                state?.stage,
                1,
                1,
                100000
              );

          const score = fresh
            ? 0
            : safeInt(
                state?.score,
                0
              );

          const difficulty =
            stageDifficulty(
              stage,
              mode
            );

          gameSession =
            await createGameSession(
              client,
              {
                playerId:
                  req.playerId,

                mode,
                difficulty,
                stage,

                deadlineMs:
                  INFINITE_LIMIT_MS,

                state: {
                  score,
                  numberSlots: [],
                  operatorSlots: [],
                },
              }
            );

          gameSession.score = score;

          await client.query(
            `UPDATE player_state
             SET
               infinite_state =
                 $2::jsonb,

               updated_at = NOW()

             WHERE player_id = $1`,
            [
              req.playerId,

              JSON.stringify({
                sessionId:
                  gameSession.sessionId,

                stage,
                score,
              }),
            ]
          );
        }
      } else {
        await preparePlayerForNewSession(
          client,
          req.playerId,
          mode,
          {
            replaceSameMode: true,
          }
        );

        const difficulty =
          stageDifficulty(1, mode);

        const botPlan =
          buildHundredPlan();

        const runStartedAt =
          nowMs();

        gameSession =
          await createGameSession(
            client,
            {
              playerId:
                req.playerId,

              mode,
              difficulty,
              stage: 1,

              deadlineMs:
                HUNDRED_STAGE_LIMIT_MS,

              state: {
                runStartedAt,
                botPlan,
                numberSlots: [],
                operatorSlots: [],
              },
            }
          );

        gameSession.botPlan =
          botPlan;

        await client.query(
          `UPDATE player_state
           SET
             hundred_state =
               $2::jsonb,

             updated_at = NOW()

           WHERE player_id = $1`,
          [
            req.playerId,

            JSON.stringify({
              sessionId:
                gameSession.sessionId,

              stage: 1,
              runStartedAt,
              botPlan,
            }),
          ]
        );
      }

      const finalProfile =
        await profileForPlayer(
          client,
          req.playerId,
          { lock: true }
        );

      await client.query("COMMIT");

      res.json({
        ok: true,
        session: gameSession,
        profile: finalProfile,
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

function buildHundredPlan() {
  const eliminations = [];

  for (
    let stage = 1;
    stage <=
      TOURNAMENT_TOTAL_STAGES;
    stage += 1
  ) {
    const count =
      stage < 10
        ? randomInt(5, 12)
        : randomInt(2, 5);

    eliminations.push({
      stage,
      count,

      offsetMs:
        randomInt(
          8_000,
          70_000
        ),
    });
  }

  return {
    eliminations,

    leaderboardFinishMs:
      Array.from(
        { length: 20 },
        () =>
          randomInt(
            35_000,
            10 * 60_000
          )
      ),
  };
}

app.post(
  "/game/session/progress",
  authMiddleware,
  rateLimit({
    windowMs: 10_000,
    max: 12,
  }),
  async (req, res) => {
    try {
      const session =
        await readActiveSession(
          pool,
          req.playerId,
          req.body.sessionId,
          false
        );

      if (
        !session ||
        session.status !== "active"
      ) {
        res.status(404).json({
          ok: false,

          code:
            "SESSION_NOT_FOUND",

          message:
            "Aktif oyun oturumu bulunamadı.",
        });

        return;
      }

      if (
        session.mode !== "infinite" &&
        session.mode !== "hundred"
      ) {
        res.json({
          ok: true,
          skipped: true,
        });

        return;
      }

      const numberSlots =
        Array.isArray(
          req.body.numberSlots
        )
          ? req.body.numberSlots.slice(
              0,
              8
            )
          : [];

      const operatorSlots =
        Array.isArray(
          req.body.operatorSlots
        )
          ? req.body.operatorSlots.slice(
              0,
              7
            )
          : [];

      await pool.query(
        `UPDATE game_sessions
         SET
           state =
             state || $3::jsonb,

           updated_at = NOW()

         WHERE session_id = $1
           AND player_id = $2
           AND status = 'active'`,
        [
          session.session_id,
          req.playerId,

          JSON.stringify({
            numberSlots,
            operatorSlots,
          }),
        ]
      );

      res.json({ ok: true });
    } catch (error) {
      sendError(
        res,
        error,
        "İlerleme kaydedilemedi."
      );
    }
  }
);

app.post(
  "/game/session/complete",
  authMiddleware,
  rateLimit({
    windowMs: 10_000,
    max: 20,
  }),
  async (req, res) => {
    const client =
      await pool.connect();

    try {
      await client.query("BEGIN");

      const row =
        await readActiveSession(
          client,
          req.playerId,
          req.body.sessionId,
          true
        );

      if (!row) {
        const error = new Error(
          "Oyun oturumu bulunamadı."
        );

        error.status = 404;
        error.code =
          "SESSION_NOT_FOUND";

        throw error;
      }

      if (row.status !== "active") {
        const profile =
          await profileForPlayer(
            client,
            req.playerId,
            { lock: true }
          );

        await client.query("COMMIT");

        res.json({
          ok: true,
          duplicate: true,
          profile,
          result: row.result,
        });

        return;
      }

      if (
        Number(
          row.deadline_at_ms
        ) < nowMs()
      ) {
        const error = new Error(
          "Oyun süresi doldu."
        );

        error.status = 409;
        error.code =
          "SESSION_EXPIRED";

        throw error;
      }

      if (
        nowMs() -
          Number(
            row.started_at_ms || 0
          ) <
        MIN_VALID_SOLVE_MS
      ) {
        const error = new Error(
          "Çözüm olağan dışı hızda gönderildi."
        );

        error.status = 422;
        error.code =
          "SOLUTION_TOO_FAST";

        throw error;
      }

      if (
        !validateSolution(
          row.puzzle,
          req.body.numberSlots,
          req.body.operatorSlots
        )
      ) {
        const error = new Error(
          "Çözüm sunucu doğrulamasından geçmedi."
        );

        error.status = 422;
        error.code =
          "INVALID_SOLUTION";

        throw error;
      }

      const mode = row.mode;

      const difficulty =
        row.difficulty;

      const stage = Number(
        row.stage || 1
      );

      const state =
        row.state || {};

      let rewards = {
        general: 0,
        infinite: 0,
        xp: 0,
      };

      let nextSession = null;
      let result = "completed";

      if (mode === "single") {
        const reward =
          stageReward(
            mode,
            difficulty,
            stage
          );

        rewards = {
          general: reward,
          infinite: 0,

          xp: xpReward(
            mode,
            difficulty,
            stage
          ),
        };

        await applyRewards(
          client,
          req.playerId,
          rewards
        );
      } else if (
        mode === "infinite"
      ) {
        const earned =
          stageReward(
            mode,
            difficulty,
            stage
          );

        const newScore =
          safeInt(
            state.score,
            0
          ) + earned;

        rewards = {
          general: 0,
          infinite: newScore,

          xp: xpReward(
            mode,
            difficulty,
            stage
          ),
        };

        await applyRewards(
          client,
          req.playerId,
          rewards
        );

        await client.query(
          `UPDATE game_sessions
           SET
             status = 'completed',
             result = 'completed',
             completed_at = NOW(),
             updated_at = NOW()

           WHERE session_id = $1
             AND player_id = $2
             AND status = 'active'`,
          [
            row.session_id,
            req.playerId,
          ]
        );

        const nextStage =
          stage + 1;

        nextSession =
          await createGameSession(
            client,
            {
              playerId:
                req.playerId,

              mode,

              difficulty:
                stageDifficulty(
                  nextStage,
                  mode
                ),

              stage: nextStage,

              deadlineMs:
                INFINITE_LIMIT_MS,

              state: {
                score: newScore,
                numberSlots: [],
                operatorSlots: [],
              },
            }
          );

        nextSession.score =
          newScore;

        await client.query(
          `UPDATE player_state
           SET
             infinite_state =
               $2::jsonb,

             infinite_high_score =
               GREATEST(
                 infinite_high_score,
                 $3
               ),

             updated_at = NOW()

           WHERE player_id = $1`,
          [
            req.playerId,

            JSON.stringify({
              sessionId:
                nextSession.sessionId,

              stage: nextStage,
              score: newScore,
            }),

            newScore,
          ]
        );
      } else if (
        mode === "hundred"
      ) {
        if (
          stage >=
          TOURNAMENT_TOTAL_STAGES
        ) {
          rewards = {
            general: 240,
            infinite: 0,
            xp: 480,
          };

          await applyRewards(
            client,
            req.playerId,
            rewards
          );

          await client.query(
            `UPDATE player_state
             SET
               hundred_state = NULL,
               updated_at = NOW()
             WHERE player_id = $1`,
            [req.playerId]
          );

          result = "won";
        } else {
          await client.query(
            `UPDATE game_sessions
             SET
               status = 'completed',
               result = 'completed',
               completed_at = NOW(),
               updated_at = NOW()

             WHERE session_id = $1
               AND player_id = $2
               AND status = 'active'`,
            [
              row.session_id,
              req.playerId,
            ]
          );

          const nextStage =
            stage + 1;

          const botPlan =
            state.botPlan ||
            buildHundredPlan();

          const runStartedAt =
            state.runStartedAt ||
            nowMs();

          nextSession =
            await createGameSession(
              client,
              {
                playerId:
                  req.playerId,

                mode,

                difficulty:
                  stageDifficulty(
                    nextStage,
                    mode
                  ),

                stage:
                  nextStage,

                deadlineMs:
                  HUNDRED_STAGE_LIMIT_MS,

                state: {
                  runStartedAt,
                  botPlan,
                  numberSlots: [],
                  operatorSlots: [],
                },
              }
            );

          nextSession.botPlan =
            botPlan;

          await client.query(
            `UPDATE player_state
             SET
               hundred_state =
                 $2::jsonb,

               updated_at = NOW()

             WHERE player_id = $1`,
            [
              req.playerId,

              JSON.stringify({
                sessionId:
                  nextSession.sessionId,

                stage: nextStage,
                runStartedAt,
                botPlan,
              }),
            ]
          );
        }
      } else {
        const error = new Error(
          "Bu oturum Socket.IO üzerinden tamamlanmalıdır."
        );

        error.status = 409;

        error.code =
          "SOCKET_SESSION_REQUIRED";

        throw error;
      }

      await client.query(
        `UPDATE game_sessions
         SET
           status = 'completed',
           result = $3,
           completed_at = NOW(),
           updated_at = NOW()

         WHERE session_id = $1
           AND player_id = $2`,
        [
          row.session_id,
          req.playerId,
          result,
        ]
      );

      const profile =
        await profileForPlayer(
          client,
          req.playerId,
          { lock: true }
        );

      await client.query("COMMIT");

      res.json({
        ok: true,
        accepted: true,
        result,
        rewards,
        nextSession,
        profile,
      });
    } catch (error) {
      await client.query("ROLLBACK");

      sendError(
        res,
        error,
        "Çözüm kaydedilemedi."
      );
    } finally {
      client.release();
    }
  }
);

app.post(
  "/game/session/abandon",
  authMiddleware,
  rateLimit({
    windowMs: 10_000,
    max: 20,
  }),
  async (req, res) => {
    const client =
      await pool.connect();

    try {
      await client.query("BEGIN");

      const row =
        await readActiveSession(
          client,
          req.playerId,
          req.body.sessionId,
          true
        );

      if (
        !row ||
        row.status !== "active"
      ) {
        const profile =
          await profileForPlayer(
            client,
            req.playerId,
            { lock: true }
          );

        await client.query("COMMIT");

        res.json({
          ok: true,
          duplicate: true,
          profile,
        });

        return;
      }

      let rewards = {
        general: 0,
        infinite: 0,
        xp: 0,
      };

      if (row.mode === "infinite") {
        await client.query(
          `UPDATE player_state
           SET
             infinite_state = NULL,
             updated_at = NOW()
           WHERE player_id = $1`,
          [req.playerId]
        );
      } else if (
        row.mode === "hundred"
      ) {
        const expiredOnServer =
          Number(
            row.deadline_at_ms || 0
          ) <= nowMs();

        if (expiredOnServer) {
          const stage = Number(
            row.stage || 1
          );

          rewards = {
            general: stage * 10,
            infinite: 0,
            xp: stage * 20,
          };

          await applyRewards(
            client,
            req.playerId,
            rewards
          );
        }

        await client.query(
          `UPDATE player_state
           SET
             hundred_state = NULL,
             updated_at = NOW()
           WHERE player_id = $1`,
          [req.playerId]
        );
      }

      await client.query(
        `UPDATE game_sessions
         SET
           status = 'abandoned',
           result = 'lost',
           completed_at = NOW(),
           updated_at = NOW()

         WHERE session_id = $1
           AND player_id = $2`,
        [
          row.session_id,
          req.playerId,
        ]
      );

      const profile =
        await profileForPlayer(
          client,
          req.playerId,
          { lock: true }
        );

      await client.query("COMMIT");

      res.json({
        ok: true,
        result: "lost",
        rewards,
        profile,
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

  transports: [
    "websocket",
    "polling",
  ],

  allowEIO3: true,
  pingInterval: 25_000,
  pingTimeout: 20_000,

  maxHttpBufferSize:
    48 * 1024,

  cors: {
    origin: true,
    methods: ["GET", "POST"],
    credentials: false,
  },
});

const waitingQueues = new Map();
const activeRooms = new Map();
const realtimeRooms = new Map();
const privateRooms = new Map();
const botFallbackTickets =
  new Map();

function socketAuthPlayer(payload) {
  return verifyAuthToken(
    payload?.authToken
  );
}

function normalizeGameKey(value) {
  const key = safeText(
    value,
    "target_number",
    96
  ).toLowerCase();

  if (
    key ===
    "target_number_tournament"
  ) {
    return key;
  }

  if (
    key ===
    "target_number_friend"
  ) {
    return key;
  }

  return "target_number";
}

function matchMode(gameKey) {
  if (
    gameKey ===
    "target_number_tournament"
  ) {
    return "tournament";
  }

  if (
    gameKey ===
    "target_number_friend"
  ) {
    return "friend";
  }

  return "two_player";
}

function queueKey(
  gameKey,
  difficulty,
  stage = 0
) {
  return (
    `${gameKey}::` +
    `${difficulty}::` +
    `${stage}`
  );
}

function safePlayerCosmetic(
  raw,
  playerId
) {
  return {
    id: playerId,

    name: safeText(
      raw?.name,
      "Oyuncu",
      24
    ),

    country: safeCountry(
      raw?.country
    ),
  };
}

function roomParticipants(room) {
  return Object.values(
    room?.participants || {}
  );
}

function participant(
  room,
  playerId
) {
  return (
    room?.participants?.[
      playerId
    ] || null
  );
}

function opponent(
  room,
  playerId
) {
  return (
    roomParticipants(room).find(
      (item) =>
        item.playerId !== playerId
    ) || null
  );
}

function clearParticipantTimer(item) {
  if (item?.timeoutHandle) {
    clearTimeout(
      item.timeoutHandle
    );
  }

  if (item) {
    item.timeoutHandle = null;
  }
}

function attachSocket(
  socket,
  room,
  playerId
) {
  const item =
    participant(room, playerId);

  if (!item) return;

  if (
    item.socketId &&
    item.socketId !== socket.id
  ) {
    activeRooms.delete(
      item.socketId
    );
  }

  item.socketId = socket.id;
  item.connected = true;
  item.awaySince = null;

  clearParticipantTimer(item);

  socket.join(room.roomId);

  activeRooms.set(socket.id, {
    roomId: room.roomId,
    playerId,
  });
}

async function playerMatchEligibility(
  client,
  playerId,
  mode,
  difficulty
) {
  const profile =
    await profileForPlayer(
      client,
      playerId,
      { lock: true }
    );

  if (!profile?.username) {
    const error = new Error(
      "Önce kullanıcı adı belirlemelisiniz."
    );

    error.status = 409;
    error.code =
      "USERNAME_REQUIRED";

    throw error;
  }

  if (
    mode === "two_player" ||
    mode === "friend"
  ) {
    const required = stageReward(
      mode,
      difficulty,
      1
    );

    if (
      profile.generalScore <
      required
    ) {
      const error = new Error(
        "Bu eşleşme için yeterli puanınız yok."
      );

      error.status = 409;
      error.code =
        "INSUFFICIENT_SCORE";

      throw error;
    }

    await consumeRight(
      client,
      playerId
    );

    return {
      profile,
      stage: 1,
    };
  }

  if (mode === "tournament") {
    if (
      profile.tournament.completed
    ) {
      const error = new Error(
        "Turnuva tamamlandı."
      );

      error.status = 409;
      error.code =
        "TOURNAMENT_COMPLETED";

      throw error;
    }

    if (
      profile.tournament
        .remainingRights <= 0
    ) {
      const error = new Error(
        "Turnuva hakkınız kalmadı."
      );

      error.status = 409;
      error.code =
        "NO_TOURNAMENT_RIGHT";

      throw error;
    }

    return {
      profile,

      stage:
        profile.tournament
          .currentStage,
    };
  }

  return {
    profile,
    stage: 1,
  };
}

async function createRealtimeRoom({
  socketA,
  playerA,
  socketB,
  playerB,
  gameKey,
  difficulty,
  botPlan = null,
}) {
  const mode =
    matchMode(gameKey);

  const roomId = sessionId();

  const client =
    await pool.connect();

  try {
    await client.query("BEGIN");

    const lockIds = [
      playerA.id,

      ...(
        playerB.isBot
          ? []
          : [playerB.id]
      ),
    ].sort();

    for (
      const playerId of lockIds
    ) {
      await client.query(
        `SELECT pg_advisory_xact_lock(
           hashtext($1)
         )`,
        [playerId]
      );

      await expireStaleActiveSessions(
        client,
        playerId
      );

      const active =
        await client.query(
          `SELECT 1
           FROM game_sessions
           WHERE player_id = $1
             AND status = 'active'
           LIMIT 1`,
          [playerId]
        );

      if (active.rows[0]) {
        const error = new Error(
          "Başka bir aktif oyununuz bulunuyor."
        );

        error.status = 409;
        error.code =
          "ACTIVE_SESSION_EXISTS";

        throw error;
      }
    }

    const eligibleA =
      await playerMatchEligibility(
        client,
        playerA.id,
        mode,
        difficulty
      );

    const eligibleB =
      playerB.isBot
        ? {
            stage:
              eligibleA.stage,

            profile: null,
          }
        : await playerMatchEligibility(
            client,
            playerB.id,
            mode,
            difficulty
          );

    const verifiedPlayerA = {
      ...playerA,

      name:
        eligibleA.profile.username,

      country:
        eligibleA.profile.country,
    };

    const verifiedPlayerB =
      playerB.isBot
        ? playerB
        : {
            ...playerB,

            name:
              eligibleB.profile
                .username,

            country:
              eligibleB.profile
                .country,
          };

    const stage =
      mode === "tournament"
        ? Math.min(
            eligibleA.stage,
            eligibleB.stage
          )
        : 1;

    const resolvedDifficulty =
      mode === "tournament"
        ? stageDifficulty(
            stage,
            mode
          )
        : difficulty;

    const sharedPuzzle =
      generatePuzzle(
        resolvedDifficulty
      );

    const sessionA = sessionId();

    const sessionB =
      playerB.isBot
        ? null
        : sessionId();

    const deadlineAt =
      nowMs() +
      COMPETITIVE_LIMIT_MS;

    await client.query(
      `INSERT INTO game_sessions (
         session_id,
         player_id,
         room_id,
         mode,
         difficulty,
         stage,
         puzzle,
         state,
         deadline_at
       )
       VALUES (
         $1,
         $2,
         $3,
         $4,
         $5,
         $6,
         $7::jsonb,
         $8::jsonb,
         TO_TIMESTAMP($9 / 1000.0)
       )`,
      [
        sessionA,
        playerA.id,
        roomId,
        mode,
        resolvedDifficulty,
        stage,
        JSON.stringify(
          sharedPuzzle
        ),

        JSON.stringify({
          opponentPlayerId:
            playerB.id,

          botPlan,
        }),

        deadlineAt,
      ]
    );

    if (!playerB.isBot) {
      await client.query(
        `INSERT INTO game_sessions (
           session_id,
           player_id,
           room_id,
           mode,
           difficulty,
           stage,
           puzzle,
           state,
           deadline_at
         )
         VALUES (
           $1,
           $2,
           $3,
           $4,
           $5,
           $6,
           $7::jsonb,
           $8::jsonb,
           TO_TIMESTAMP($9 / 1000.0)
         )`,
        [
          sessionB,
          playerB.id,
          roomId,
          mode,
          resolvedDifficulty,
          stage,

          JSON.stringify(
            sharedPuzzle
          ),

          JSON.stringify({
            opponentPlayerId:
              playerA.id,
          }),

          deadlineAt,
        ]
      );
    }

    await client.query("COMMIT");

    const room = {
      roomId,
      gameKey,
      mode,

      difficulty:
        resolvedDifficulty,

      stage,
      puzzle: sharedPuzzle,
      createdAt: nowMs(),
      deadlineAt,

      resolved: false,
      resolvedAt: null,
      resultReason: null,
      deadlineHandle: null,
      botPlan,

      participants: {
        [verifiedPlayerA.id]: {
          playerId:
            verifiedPlayerA.id,

          sessionId: sessionA,

          name:
            verifiedPlayerA.name,

          country:
            verifiedPlayerA.country,

          socketId: socketA.id,
          connected: true,
          isBot: false,
          awaySince: null,
          timeoutHandle: null,
          finishedAt: null,
          elapsedMs: null,
        },

        [verifiedPlayerB.id]: {
          playerId:
            verifiedPlayerB.id,

          sessionId: sessionB,

          name:
            verifiedPlayerB.name,

          country:
            verifiedPlayerB.country,

          socketId:
            socketB?.id || null,

          connected:
            Boolean(socketB),

          isBot:
            Boolean(playerB.isBot),

          awaySince: null,
          timeoutHandle: null,
          finishedAt: null,
          elapsedMs: null,
        },
      },
    };

    realtimeRooms.set(
      roomId,
      room
    );

    attachSocket(
      socketA,
      room,
      playerA.id
    );

    if (socketB) {
      attachSocket(
        socketB,
        room,
        playerB.id
      );
    }

    room.deadlineHandle =
      setTimeout(() => {
        expireRealtimeRoom(room)
          .catch((error) =>
            console.error(
              "room deadline",
              error.message
            )
          );
      }, Math.max(
        1,
        deadlineAt - nowMs()
      ));

    if (
      typeof room.deadlineHandle
        .unref === "function"
    ) {
      room.deadlineHandle.unref();
    }

    if (playerB.isBot) {
      scheduleBotRoom(room);
    }

    return room;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

function matchFoundPayload(
  room,
  ownPlayerId,
  extra = {}
) {
  const me = participant(
    room,
    ownPlayerId
  );

  const other = opponent(
    room,
    ownPlayerId
  );

  return {
    roomId: room.roomId,

    sessionId:
      me?.sessionId,

    isBot:
      Boolean(other?.isBot),

    opponent: other?.isBot
      ? {
          country:
            other.country,
        }
      : {
          name:
            other?.name ||
            "Rakip",

          country:
            other?.country || "",
        },

    puzzle: room.puzzle,
    stage: room.stage,

    startedAtMillis:
      room.createdAt,

    deadlineAtMillis:
      room.deadlineAt,

    botFinishMs:
      room.botPlan?.finishMs ??
      null,

    botLeaveMs:
      room.botPlan?.leaveMs ??
      null,

    ...extra,
  };
}

function scheduleBotRoom(room) {
  const bot =
    roomParticipants(room).find(
      (item) => item.isBot
    );

  const human =
    roomParticipants(room).find(
      (item) => !item.isBot
    );

  if (
    !bot ||
    !human ||
    !room.botPlan
  ) {
    return;
  }

  const {
    finishMs,
    leaveMs,
  } = room.botPlan;

  if (leaveMs != null) {
    const timer = setTimeout(
      () =>
        resolveRealtimeRoom(
          room,
          human.playerId,
          bot.playerId,
          "bot_left"
        ).catch(console.error),

      Math.max(1, leaveMs)
    );

    if (
      typeof timer.unref ===
      "function"
    ) {
      timer.unref();
    }
  } else if (
    finishMs != null
  ) {
    const timer = setTimeout(
      () =>
        resolveRealtimeRoom(
          room,
          bot.playerId,
          human.playerId,
          "bot_finished",
          finishMs
        ).catch(console.error),

      Math.max(1, finishMs)
    );

    if (
      typeof timer.unref ===
      "function"
    ) {
      timer.unref();
    }
  }
}

async function expireRealtimeRoom(
  room
) {
  if (
    !room ||
    room.resolved
  ) {
    return;
  }

  room.resolved = true;
  room.resolvedAt = nowMs();
  room.resultReason =
    "timeout_draw";

  if (room.deadlineHandle) {
    clearTimeout(
      room.deadlineHandle
    );
  }

  for (
    const item of
      roomParticipants(room)
  ) {
    clearParticipantTimer(item);
  }

  const client =
    await pool.connect();

  try {
    await client.query("BEGIN");

    for (
      const item of
        roomParticipants(room)
    ) {
      if (
        item.isBot ||
        !item.sessionId
      ) {
        continue;
      }

      await client.query(
        `UPDATE game_sessions
         SET
           status = 'completed',
           result = 'draw',
           completed_at = NOW(),
           updated_at = NOW()

         WHERE session_id = $1
           AND player_id = $2
           AND status = 'active'`,
        [
          item.sessionId,
          item.playerId,
        ]
      );
    }

    await client.query("COMMIT");

    for (
      const item of
        roomParticipants(room)
    ) {
      if (
        item.isBot ||
        !item.socketId
      ) {
        continue;
      }

      const targetSocket =
        io.sockets.sockets.get(
          item.socketId
        );

      targetSocket?.emit(
        "match_expired",
        {
          roomId: room.roomId,
          reason: "timeout_draw",
        }
      );
    }
  } catch (error) {
    await client.query("ROLLBACK");
    room.resolved = false;
    throw error;
  } finally {
    client.release();
  }
}

async function applyMatchOutcome(
  client,
  room,
  winnerId,
  loserId
) {
  const mode = room.mode;

  const reward = stageReward(
    mode,
    room.difficulty,
    room.stage
  );

  const winnerRewards = {
    general: 0,
    infinite: 0,
    xp: 0,
  };

  const loserRewards = {
    general: 0,
    infinite: 0,
    xp: 0,
  };

  const winnerIsBot =
    String(winnerId || "")
      .startsWith("bot:");

  const loserIsBot =
    String(loserId || "")
      .startsWith("bot:");

  if (
    mode === "two_player" ||
    mode === "friend"
  ) {
    winnerRewards.general =
      reward;

    winnerRewards.xp =
      xpReward(
        mode,
        room.difficulty,
        room.stage,
        true
      );

    loserRewards.general =
      -reward;

    if (!winnerIsBot) {
      await applyRewards(
        client,
        winnerId,
        winnerRewards
      );
    }

    if (
      loserId &&
      !loserIsBot
    ) {
      await applyRewards(
        client,
        loserId,
        loserRewards
      );
    }
  } else if (
    mode === "tournament"
  ) {
    if (!winnerIsBot) {
      const winnerState =
        await profileForPlayer(
          client,
          winnerId,
          { lock: true }
        );

      const completed =
        room.stage >=
        TOURNAMENT_TOTAL_STAGES;

      const newTournamentScore =
        winnerState.tournament
          .totalScore + reward;

      winnerRewards.xp =
        xpReward(
          mode,
          room.difficulty,
          room.stage,
          true
        );

      await applyRewards(
        client,
        winnerId,
        winnerRewards
      );

      if (completed) {
        winnerRewards.general =
          newTournamentScore;

        await applyRewards(
          client,
          winnerId,
          {
            general:
              newTournamentScore,

            infinite: 0,
            xp: 0,
          }
        );
      }

      await client.query(
        `UPDATE player_state
         SET
           tournament_stage = $2,
           tournament_score = $3,
           tournament_completed = $4,
           updated_at = NOW()

         WHERE player_id = $1`,
        [
          winnerId,

          completed
            ? TOURNAMENT_TOTAL_STAGES
            : room.stage + 1,

          newTournamentScore,
          completed,
        ]
      );
    }

    if (
      loserId &&
      !loserIsBot
    ) {
      const loserState =
        await profileForPlayer(
          client,
          loserId,
          { lock: true }
        );

      const nextRights =
        Math.max(
          0,
          loserState.tournament
            .remainingRights - 1
        );

      if (nextRights === 0) {
        loserRewards.general =
          loserState.tournament
            .totalScore;

        if (
          loserRewards.general > 0
        ) {
          await applyRewards(
            client,
            loserId,
            {
              general:
                loserRewards.general,

              infinite: 0,
              xp: 0,
            }
          );
        }

        await client.query(
          `UPDATE player_state
           SET
             tournament_stage = 1,

             tournament_rights = $2,

             tournament_score = 0,

             tournament_completed =
               FALSE,

             updated_at = NOW()

           WHERE player_id = $1`,
          [
            loserId,
            TOURNAMENT_INITIAL_RIGHTS,
          ]
        );
      } else {
        await client.query(
          `UPDATE player_state
           SET
             tournament_rights = $2,
             updated_at = NOW()
           WHERE player_id = $1`,
          [
            loserId,
            nextRights,
          ]
        );
      }
    }
  }

  return {
    winnerRewards,
    loserRewards,
  };
}

async function resolveRealtimeRoom(
  room,
  winnerId,
  loserId,
  reason,
  winnerElapsedMs = null
) {
  if (
    !room ||
    room.resolved
  ) {
    return;
  }

  room.resolved = true;
  room.resolvedAt = nowMs();
  room.resultReason = reason;

  if (room.deadlineHandle) {
    clearTimeout(
      room.deadlineHandle
    );
  }

  room.deadlineHandle = null;

  const winner =
    participant(room, winnerId);

  if (
    winner &&
    winnerElapsedMs != null
  ) {
    winner.elapsedMs = Math.max(
      1,
      Math.trunc(winnerElapsedMs)
    );
  }

  const client =
    await pool.connect();

  try {
    await client.query("BEGIN");

    const rewards =
      await applyMatchOutcome(
        client,
        room,
        winnerId,
        loserId
      );

    for (
      const item of
        roomParticipants(room)
    ) {
      if (
        item.isBot ||
        !item.sessionId
      ) {
        continue;
      }

      const won =
        item.playerId === winnerId;

      await client.query(
        `UPDATE game_sessions
         SET
           status = 'completed',
           result = $3,
           completed_at = NOW(),
           updated_at = NOW()

         WHERE session_id = $1
           AND player_id = $2
           AND status = 'active'`,
        [
          item.sessionId,
          item.playerId,

          won
            ? "won"
            : "lost",
        ]
      );
    }

    const winnerProfile =
      String(winnerId)
        .startsWith("bot:")
        ? null
        : await profileForPlayer(
            client,
            winnerId,
            { lock: true }
          );

    const loserProfile =
      !loserId ||
      String(loserId)
        .startsWith("bot:")
        ? null
        : await profileForPlayer(
            client,
            loserId,
            { lock: true }
          );

    await client.query("COMMIT");

    for (
      const item of
        roomParticipants(room)
    ) {
      if (
        item.isBot ||
        !item.socketId
      ) {
        continue;
      }

      const socket =
        io.sockets.sockets.get(
          item.socketId
        );

      if (!socket) continue;

      const won =
        item.playerId === winnerId;

      const other = opponent(
        room,
        item.playerId
      );

      socket.emit(
        "match_result",
        {
          roomId: room.roomId,
          won,
          reason,

          myElapsedMs:
            item.elapsedMs,

          opponentElapsedMs:
            other?.elapsedMs ??
            null,

          rewards: won
            ? rewards.winnerRewards
            : rewards.loserRewards,

          profile: won
            ? winnerProfile
            : loserProfile,
        }
      );

      if (
        won &&
        reason.includes("left")
      ) {
        socket.emit(
          "opponent_left",
          {
            roomId: room.roomId,
            reason,
          }
        );
      }

      if (
        !won &&
        other?.elapsedMs
      ) {
        socket.emit(
          "opponent_finished",
          {
            roomId: room.roomId,

            elapsedMs:
              other.elapsedMs,
          }
        );
      }
    }
  } catch (error) {
    await client.query("ROLLBACK");
    room.resolved = false;
    throw error;
  } finally {
    client.release();
  }
}

function removeFromQueues(
  socketId,
  playerId = ""
) {
  for (
    const [key, queue] of
      waitingQueues.entries()
  ) {
    const next = queue.filter(
      (item) =>
        item.socketId !==
          socketId &&
        (
          !playerId ||
          item.player.id !==
            playerId
        )
    );

    if (next.length) {
      waitingQueues.set(
        key,
        next
      );
    } else {
      waitingQueues.delete(key);
    }
  }
}

function removePrivateRooms(
  socketId
) {
  for (
    const [code, room] of
      privateRooms.entries()
  ) {
    if (
      room.ownerSocketId ===
      socketId
    ) {
      privateRooms.delete(code);
    }
  }
}

function normalizeRoomCode(value) {
  return safeText(
    value,
    "",
    6
  )
    .toUpperCase()
    .replace(
      /[^A-Z0-9]/g,
      ""
    );
}

function generateRoomCode() {
  const alphabet =
    "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

  for (
    let attempt = 0;
    attempt < 32;
    attempt += 1
  ) {
    let code = "";

    for (
      let index = 0;
      index < 6;
      index += 1
    ) {
      code +=
        alphabet[
          randomInt(
            0,
            alphabet.length - 1
          )
        ];
    }

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

function botPlanForDifficulty(
  difficulty
) {
  const roll =
    randomInt(0, 9999);

  const noFinish =
    difficulty === "Hard"
      ? 2530
      : 1070;

  if (roll < 560) {
    return {
      finishMs: null,

      leaveMs:
        randomInt(0, 119) *
        1000,
    };
  }

  if (
    roll <
    560 + noFinish
  ) {
    return {
      finishMs: null,
      leaveMs: null,
    };
  }

  const min =
    difficulty === "Hard"
      ? 35_000
      : 18_000;

  const max =
    difficulty === "Hard"
      ? 115_000
      : 95_000;

  return {
    finishMs:
      randomInt(min, max),

    leaveMs: null,
  };
}

io.on(
  "connection",
  (socket) => {
    let packetWindowStartedAt =
      nowMs();

    let packetCount = 0;

    socket.use(
      (_packet, next) => {
        const current =
          nowMs();

        if (
          current -
            packetWindowStartedAt >=
          60_000
        ) {
          packetWindowStartedAt =
            current;

          packetCount = 0;
        }

        packetCount += 1;

        if (packetCount > 120) {
          socket.emit(
            "match_error",
            {
              code:
                "SOCKET_RATE_LIMIT",

              message:
                "Çok fazla gerçek zamanlı istek gönderildi.",
            }
          );

          return;
        }

        next();
      }
    );

    socket.on(
      "join_match",
      async (payload = {}) => {
        const playerId =
          socketAuthPlayer(
            payload
          );

        if (!playerId) {
          socket.emit(
            "match_error",
            {
              code:
                "AUTH_REQUIRED",

              message:
                "Oturum geçersiz.",
            }
          );

          return;
        }

        const gameKey =
          normalizeGameKey(
            payload.gameKey
          );

        const mode =
          matchMode(gameKey);

        const difficulty =
          safeDifficulty(
            payload.difficulty
          );

        const fallbackTicketKey =
          `${playerId}:` +
          `${gameKey}:` +
          `${difficulty}`;

        if (
          !botFallbackTickets.has(
            fallbackTicketKey
          )
        ) {
          botFallbackTickets.set(
            fallbackTicketKey,
            nowMs()
          );
        }

        const cosmetic =
          safePlayerCosmetic(
            payload.player,
            playerId
          );

        removeFromQueues(
          socket.id,
          playerId
        );

        removePrivateRooms(
          socket.id
        );

        try {
          const preview =
            await profileForPlayer(
              pool,
              playerId
            );

          if (!preview) {
            throw Object.assign(
              new Error(
                "Oyuncu bulunamadı."
              ),
              {
                status: 404,

                code:
                  "PLAYER_NOT_FOUND",
              }
            );
          }

          const stage =
            mode === "tournament"
              ? preview.tournament
                  .currentStage
              : 0;

          const key = queueKey(
            gameKey,

            mode === "tournament"
              ? stageDifficulty(
                  stage,
                  mode
                )
              : difficulty,

            stage
          );

          const queue =
            waitingQueues.get(key) ||
            [];

          while (
            queue.length > 0
          ) {
            const other =
              queue.shift();

            const otherSocket =
              io.sockets.sockets.get(
                other.socketId
              );

            if (
              !otherSocket ||
              other.player.id ===
                playerId
            ) {
              continue;
            }

            waitingQueues.set(
              key,
              queue
            );

            const room =
              await createRealtimeRoom(
                {
                  socketA: socket,
                  playerA: cosmetic,

                  socketB:
                    otherSocket,

                  playerB:
                    other.player,

                  gameKey,
                  difficulty,
                }
              );

            botFallbackTickets.delete(
              `${playerId}:` +
                `${gameKey}:` +
                `${difficulty}`
            );

            botFallbackTickets.delete(
              `${other.player.id}:` +
                `${gameKey}:` +
                `${difficulty}`
            );

            socket.emit(
              "match_found",
              matchFoundPayload(
                room,
                playerId
              )
            );

            otherSocket.emit(
              "match_found",
              matchFoundPayload(
                room,
                other.player.id
              )
            );

            return;
          }

          queue.push({
            socketId: socket.id,
            player: cosmetic,
            joinedAt: nowMs(),
          });

          waitingQueues.set(
            key,
            queue
          );

          socket.emit(
            "waiting",
            {
              gameKey,
              difficulty,
            }
          );
        } catch (error) {
          socket.emit(
            "match_error",
            {
              code:
                error.code ||
                "MATCH_START_FAILED",

              message:
                error.status >= 500
                  ? "Eşleşme başlatılamadı."
                  : error.message,
            }
          );
        }
      }
    );

    socket.on(
      "start_bot_match",
      async (payload = {}) => {
        const playerId =
          socketAuthPlayer(
            payload
          );

        if (!playerId) {
          socket.emit(
            "match_error",
            {
              code:
                "AUTH_REQUIRED",

              message:
                "Oturum geçersiz.",
            }
          );

          return;
        }

        const gameKey =
          normalizeGameKey(
            payload.gameKey
          );

        const difficulty =
          safeDifficulty(
            payload.difficulty
          );

        const fallbackTicketKey =
          `${playerId}:` +
          `${gameKey}:` +
          `${difficulty}`;

        const queuedAt =
          botFallbackTickets.get(
            fallbackTicketKey
          );

        if (
          queuedAt == null ||
          nowMs() - queuedAt <
            BOT_FALLBACK_MIN_WAIT_MS
        ) {
          const elapsed =
            queuedAt == null
              ? 0
              : nowMs() - queuedAt;

          const remaining =
            Math.max(
              0,
              BOT_FALLBACK_MIN_WAIT_MS -
                elapsed
            );

          socket.emit(
            "match_error",
            {
              code:
                "BOT_FALLBACK_TOO_EARLY",

              message:
                "Bot eşleşmesi için önce " +
                "gerçek oyuncu kuyruğunda " +
                "beklemelisiniz " +
                `(${Math.ceil(
                  remaining / 1000
                )} sn).`,
            }
          );

          return;
        }

        const cosmetic =
          safePlayerCosmetic(
            payload.player,
            playerId
          );

        const bot = {
          id:
            `bot:${sessionId()}`,

          name: "",

          country:
            safeCountry(
              payload.botCountry
            ),

          isBot: true,
        };

        try {
          const room =
            await createRealtimeRoom(
              {
                socketA: socket,
                playerA: cosmetic,
                socketB: null,
                playerB: bot,
                gameKey,
                difficulty,

                botPlan:
                  botPlanForDifficulty(
                    difficulty
                  ),
              }
            );

          botFallbackTickets.delete(
            fallbackTicketKey
          );

          socket.emit(
            "bot_match_started",
            matchFoundPayload(
              room,
              playerId
            )
          );
        } catch (error) {
          socket.emit(
            "match_error",
            {
              code:
                error.code ||
                "BOT_MATCH_FAILED",

              message:
                error.status >= 500
                  ? "Bot maçı başlatılamadı."
                  : error.message,
            }
          );
        }
      }
    );

    socket.on(
      "create_friend_room",
      async (payload = {}) => {
        const playerId =
          socketAuthPlayer(
            payload
          );

        if (!playerId) {
          socket.emit(
            "friend_room_error",
            {
              code:
                "AUTH_REQUIRED",

              message:
                "Oturum geçersiz.",
            }
          );

          return;
        }

        const cosmetic =
          safePlayerCosmetic(
            payload.player,
            playerId
          );

        const difficulty =
          safeDifficulty(
            payload.difficulty
          );

        try {
          const profile =
            await profileForPlayer(
              pool,
              playerId
            );

          if (
            !profile?.username
          ) {
            throw Object.assign(
              new Error(
                "Önce kullanıcı adı belirlemelisiniz."
              ),
              {
                code:
                  "USERNAME_REQUIRED",

                status: 409,
              }
            );
          }

          const code =
            generateRoomCode();

          removeFromQueues(
            socket.id,
            playerId
          );

          removePrivateRooms(
            socket.id
          );

          privateRooms.set(
            code,
            {
              code,

              ownerSocketId:
                socket.id,

              player: cosmetic,
              difficulty,
              createdAt: nowMs(),
            }
          );

          socket.emit(
            "friend_room_created",
            {
              roomCode: code,
              difficulty,
            }
          );
        } catch (error) {
          socket.emit(
            "friend_room_error",
            {
              code:
                error.code ||
                "ROOM_CREATE_FAILED",

              message:
                error.message,
            }
          );
        }
      }
    );

    socket.on(
      "join_friend_room",
      async (payload = {}) => {
        const playerId =
          socketAuthPlayer(
            payload
          );

        const code =
          normalizeRoomCode(
            payload.roomCode
          );

        if (!playerId) {
          socket.emit(
            "friend_room_error",
            {
              code:
                "AUTH_REQUIRED",

              message:
                "Oturum geçersiz.",
            }
          );

          return;
        }

        const waiting =
          privateRooms.get(code);

        if (
          !waiting ||
          code.length !== 6
        ) {
          socket.emit(
            "friend_room_error",
            {
              code:
                "ROOM_NOT_FOUND",

              message:
                "Oda bulunamadı.",
            }
          );

          return;
        }

        const ownerSocket =
          io.sockets.sockets.get(
            waiting.ownerSocketId
          );

        if (!ownerSocket) {
          privateRooms.delete(code);

          socket.emit(
            "friend_room_error",
            {
              code: "OWNER_LEFT",

              message:
                "Oda sahibi bağlantıdan ayrılmış.",
            }
          );

          return;
        }

        const cosmetic =
          safePlayerCosmetic(
            payload.player,
            playerId
          );

        try {
          privateRooms.delete(code);

          const room =
            await createRealtimeRoom(
              {
                socketA: socket,
                playerA: cosmetic,

                socketB:
                  ownerSocket,

                playerB:
                  waiting.player,

                gameKey:
                  "target_number_friend",

                difficulty:
                  waiting.difficulty,
              }
            );

          socket.emit(
            "match_found",
            matchFoundPayload(
              room,
              playerId,
              { roomCode: code }
            )
          );

          ownerSocket.emit(
            "match_found",
            matchFoundPayload(
              room,
              waiting.player.id,
              { roomCode: code }
            )
          );
        } catch (error) {
          const message =
            error.status >= 500
              ? "Oda başlatılamadı."
              : error.message;

          const errorPayload = {
            code:
              error.code ||
              "ROOM_JOIN_FAILED",

            message,
          };

          socket.emit(
            "friend_room_error",
            errorPayload
          );

          ownerSocket.emit(
            "friend_room_error",
            errorPayload
          );
        }
      }
    );

    socket.on(
      "player_finished",
      async (payload = {}) => {
        const playerId =
          socketAuthPlayer(
            payload
          );

        const active =
          activeRooms.get(
            socket.id
          );

        if (
          !playerId ||
          !active ||
          active.playerId !==
            playerId
        ) {
          return;
        }

        const room =
          realtimeRooms.get(
            active.roomId
          );

        const me =
          participant(
            room,
            playerId
          );

        if (
          !room ||
          !me ||
          room.resolved
        ) {
          return;
        }

        if (
          nowMs() >
          room.deadlineAt
        ) {
          return;
        }

        if (
          nowMs() -
            room.createdAt <
          MIN_VALID_SOLVE_MS
        ) {
          socket.emit(
            "match_error",
            {
              code:
                "SOLUTION_TOO_FAST",

              message:
                "Çözüm olağan dışı hızda gönderildi.",
            }
          );

          return;
        }

        if (
          !validateSolution(
            room.puzzle,
            payload.numberSlots,
            payload.operatorSlots
          )
        ) {
          socket.emit(
            "match_error",
            {
              code:
                "INVALID_SOLUTION",

              message:
                "Çözüm sunucu doğrulamasından geçmedi.",
            }
          );

          return;
        }

        me.finishedAt = nowMs();

        me.elapsedMs = Math.max(
          1,
          me.finishedAt -
            room.createdAt
        );

        try {
          await resolveRealtimeRoom(
            room,
            me.playerId,

            opponent(
              room,
              me.playerId
            )?.playerId,

            "finished",
            me.elapsedMs
          );
        } catch (_error) {
          socket.emit(
            "match_error",
            {
              code:
                "RESULT_SAVE_FAILED",

              message:
                "Maç sonucu kaydedilemedi.",
            }
          );
        }
      }
    );

    socket.on(
      "resume_match",
      async (payload = {}) => {
        const playerId =
          socketAuthPlayer(
            payload
          );

        const roomId =
          safeText(
            payload.roomId,
            "",
            128
          );

        if (!playerId) {
          socket.emit(
            "resume_error",
            {
              code:
                "AUTH_REQUIRED",

              message:
                "Oturum geçersiz.",
            }
          );

          return;
        }

        const room =
          realtimeRooms.get(
            roomId
          );

        if (
          !room ||
          !participant(
            room,
            playerId
          )
        ) {
          socket.emit(
            "resume_error",
            {
              code:
                "ROOM_NOT_FOUND",

              message:
                "Aktif oda bulunamadı.",
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
                "Bu maç sona ermiş.",
            }
          );

          return;
        }

        attachSocket(
          socket,
          room,
          playerId
        );

        socket.emit(
          "resume_state",
          {
            match:
              matchFoundPayload(
                room,
                playerId
              ),

            opponentFinishedMs:
              opponent(
                room,
                playerId
              )?.elapsedMs ?? null,
          }
        );
      }
    );

    socket.on(
      "player_backgrounded",
      (payload = {}) => {
        const playerId =
          socketAuthPlayer(
            payload
          );

        const active =
          activeRooms.get(
            socket.id
          );

        const room = active
          ? realtimeRooms.get(
              active.roomId
            )
          : null;

        const me = playerId
          ? participant(
              room,
              playerId
            )
          : null;

        if (
          !room ||
          !me ||
          room.resolved
        ) {
          return;
        }

        me.awaySince =
          me.awaySince || nowMs();

        clearParticipantTimer(me);

        me.timeoutHandle =
          setTimeout(() => {
            if (!room.resolved) {
              resolveRealtimeRoom(
                room,

                opponent(
                  room,
                  playerId
                )?.playerId,

                playerId,

                "reconnect_timeout"
              ).catch(
                console.error
              );
            }
          }, ROOM_RECONNECT_TIMEOUT_MS);

        if (
          typeof me.timeoutHandle
            .unref === "function"
        ) {
          me.timeoutHandle.unref();
        }
      }
    );

    socket.on(
      "player_foregrounded",
      (payload = {}) => {
        const playerId =
          socketAuthPlayer(
            payload
          );

        const active =
          activeRooms.get(
            socket.id
          );

        const room = active
          ? realtimeRooms.get(
              active.roomId
            )
          : null;

        const me = playerId
          ? participant(
              room,
              playerId
            )
          : null;

        if (!me) return;

        me.awaySince = null;

        clearParticipantTimer(me);
      }
    );

    socket.on(
      "cancel_match",
      async (payload = {}) => {
        const playerId =
          socketAuthPlayer(
            payload
          );

        removeFromQueues(
          socket.id,
          playerId || ""
        );

        removePrivateRooms(
          socket.id
        );

        const active =
          activeRooms.get(
            socket.id
          );

        const room = active
          ? realtimeRooms.get(
              active.roomId
            )
          : null;

        if (
          playerId &&
          room &&
          !room.resolved
        ) {
          await resolveRealtimeRoom(
            room,

            opponent(
              room,
              playerId
            )?.playerId,

            playerId,
            "cancelled"
          ).catch(console.error);
        }
      }
    );

    socket.on(
      "disconnect",
      () => {
        removeFromQueues(
          socket.id
        );

        removePrivateRooms(
          socket.id
        );

        const active =
          activeRooms.get(
            socket.id
          );

        if (!active) return;

        activeRooms.delete(
          socket.id
        );

        const room =
          realtimeRooms.get(
            active.roomId
          );

        const me =
          participant(
            room,
            active.playerId
          );

        if (
          !room ||
          !me ||
          room.resolved
        ) {
          return;
        }

        me.socketId = null;
        me.connected = false;
        me.awaySince = nowMs();

        clearParticipantTimer(me);

        me.timeoutHandle =
          setTimeout(() => {
            if (!room.resolved) {
              resolveRealtimeRoom(
                room,

                opponent(
                  room,
                  me.playerId
                )?.playerId,

                me.playerId,

                "disconnect_timeout"
              ).catch(
                console.error
              );
            }
          }, ROOM_RECONNECT_TIMEOUT_MS);

        if (
          typeof me.timeoutHandle
            .unref === "function"
        ) {
          me.timeoutHandle.unref();
        }
      }
    );
  }
);

app.get("/", (_req, res) => {
  res.json({
    ok: true,

    service:
      "target-number-authoritative-server",

    socketPath: SOCKET_PATH,
    database: Boolean(pool),

    authConfigured: Boolean(
      AUTH_JWT_SECRET &&
        GOOGLE_WEB_CLIENT_ID &&
        GOOGLE_WEB_CLIENT_SECRET &&
        PLAY_GAMES_APPLICATION_ID
    ),

    activeRooms:
      Array.from(
        realtimeRooms.values()
      ).filter(
        (room) => !room.resolved
      ).length,

    waitingPlayers:
      Array.from(
        waitingQueues.values()
      ).reduce(
        (sum, queue) =>
          sum + queue.length,
        0
      ),
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
      });
    } catch (_error) {
      res.status(503).json({
        ok: false,
        database: false,
      });
    }
  }
);

app.use(
  (error, _req, res, _next) => {
    if (
      error?.type ===
      "entity.too.large"
    ) {
      res.status(413).json({
        ok: false,

        code:
          "BODY_TOO_LARGE",

        message:
          "İstek gövdesi çok büyük.",
      });

      return;
    }

    sendError(
      res,
      error,
      "Sunucu hatası oluştu."
    );
  }
);

setInterval(async () => {
  const cutoff = nowMs();

  for (
    const [key, bucket] of
      rateBuckets.entries()
  ) {
    if (
      bucket.resetAt <= cutoff
    ) {
      rateBuckets.delete(key);
    }
  }

  for (
    const [key, cached] of
      leaderboardCache.entries()
  ) {
    if (
      cached.expiresAt <= cutoff
    ) {
      leaderboardCache.delete(key);
    }
  }

  for (
    const [code, room] of
      privateRooms.entries()
  ) {
    if (
      cutoff - room.createdAt >
      PRIVATE_ROOM_TTL_MS
    ) {
      privateRooms.delete(code);
    }
  }

  for (
    const [key, queuedAt] of
      botFallbackTickets.entries()
  ) {
    if (
      cutoff - queuedAt >
      10 * 60 * 1000
    ) {
      botFallbackTickets.delete(key);
    }
  }

  for (
    const [roomId, room] of
      realtimeRooms.entries()
  ) {
    if (
      room.resolved &&
      cutoff - room.resolvedAt >
        RESOLVED_ROOM_TTL_MS
    ) {
      realtimeRooms.delete(roomId);
    }
  }

  if (pool) {
    await pool
      .query(
        `DELETE FROM game_sessions
         WHERE (
           status <> 'active'
           AND updated_at <
             NOW() - INTERVAL '2 days'
         )
         OR (
           status = 'active'
           AND deadline_at <
             NOW() - INTERVAL '1 day'
         )`
      )
      .catch((error) =>
        console.error(
          "session cleanup",
          error.message
        )
      );
  }
}, 10 * 60 * 1000).unref();

initDatabase()
  .then(() => {
    server.listen(
      PORT,
      "0.0.0.0",
      () => {
        console.log(
          `Server listening on 0.0.0.0:${PORT}`
        );
      }
    );
  })
  .catch((error) => {
    console.error(
      "Database init failed",
      error
    );

    process.exit(1);
  });