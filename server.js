const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
const server = http.createServer(app);

const LOG_HTTP = process.env.LOG_HTTP === "1";
const SOCKET_PATH = "/socket.io/";
const DATABASE_URL = process.env.DATABASE_URL;

const MAX_GLOBAL_GAME_RIGHTS = Number(process.env.MAX_GLOBAL_GAME_RIGHTS || 10);
const GAME_RIGHT_REFILL_MS = Number(process.env.GAME_RIGHT_REFILL_MS || 10 * 60 * 1000);
const USERNAME_CHANGE_COOLDOWN_MS = Number(
  process.env.USERNAME_CHANGE_COOLDOWN_MS || 30 * 24 * 60 * 60 * 1000
);
const MAX_SCORE_DELTA = Number(process.env.MAX_SCORE_DELTA || 100_000);
const MAX_XP_DELTA = Number(process.env.MAX_XP_DELTA || 100_000);
const ROOM_RECONNECT_TIMEOUT_MS = Number(process.env.ROOM_RECONNECT_TIMEOUT_MS || 60_000);
const PRIVATE_ROOM_TTL_MS = Number(process.env.PRIVATE_ROOM_TTL_MS || 5 * 60_000);
const RESOLVED_ROOM_TTL_MS = Number(process.env.RESOLVED_ROOM_TTL_MS || 2 * 60_000);

app.use((req, _res, next) => {
  if (LOG_HTTP) {
    console.log(
      "HTTP request:",
      req.method,
      req.url,
      "ua:",
      req.headers["user-agent"] || "-"
    );
  }
  next();
});

app.use(express.json({ limit: "32kb" }));

const pool = DATABASE_URL
  ? new Pool({
      connectionString: DATABASE_URL,
      ssl:
        DATABASE_URL.includes("localhost") || DATABASE_URL.includes("127.0.0.1")
          ? false
          : { rejectUnauthorized: false },
      max: Number(process.env.PG_POOL_MAX || 3),
      idleTimeoutMillis: 10_000,
      connectionTimeoutMillis: 5_000,
    })
  : null;

const io = new Server(server, {
  path: SOCKET_PATH,
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
  },
  transports: ["websocket", "polling"],
  pingInterval: 30_000,
  pingTimeout: 15_000,
  maxHttpBufferSize: 16_384,
});

async function initDatabase() {
  if (!pool) {
    console.warn(
      "DATABASE_URL tanımlı değil. Skor tablosu ve oyuncu durumu endpointleri veritabanı olmadan çalışmaz."
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

    CREATE TABLE IF NOT EXISTS player_secure_state (
      player_id TEXT PRIMARY KEY REFERENCES players(player_id) ON DELETE CASCADE,
      total_xp INTEGER NOT NULL DEFAULT 0 CHECK (total_xp >= 0),
      remaining_rights INTEGER NOT NULL DEFAULT 10 CHECK (remaining_rights >= 0),
      rights_last_refill_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      rights_updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      username_change_count INTEGER NOT NULL DEFAULT 0 CHECK (username_change_count >= 0),
      username_last_change_at TIMESTAMPTZ,
      username_updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS player_reward_events (
      player_id TEXT NOT NULL REFERENCES players(player_id) ON DELETE CASCADE,
      event_id TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (player_id, event_id)
    );

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

    CREATE INDEX IF NOT EXISTS idx_reward_events_created
      ON player_reward_events (created_at);
  `);

  console.log("PostgreSQL tabloları hazır.");
}

function currentMonthKey() {
  return new Date().toISOString().slice(0, 7);
}

function safeText(value, fallback, maxLength) {
  const text = String(value || fallback || "").trim();
  return (text || fallback || "").slice(0, maxLength);
}

function safePlayerId(value) {
  return safeText(value, "", 96)
    .replace(/[^a-zA-Z0-9_.:-]/g, "")
    .slice(0, 96);
}

function safeUsername(value) {
  const username = safeText(value, "Oyuncu", 20).replace(/\s+/g, "");
  return username || "Oyuncu";
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
  return Math.max(0, Math.min(Math.floor(number), 2_000_000_000));
}

function safeSignedDelta(value) {
  const number = Number(value || 0);
  if (!Number.isFinite(number)) return 0;
  return Math.max(-MAX_SCORE_DELTA, Math.min(Math.trunc(number), MAX_SCORE_DELTA));
}

function safePositiveDelta(value, maxValue = MAX_SCORE_DELTA) {
  const number = Number(value || 0);
  if (!Number.isFinite(number)) return 0;
  return Math.max(0, Math.min(Math.floor(number), maxValue));
}

function safeEventId(value) {
  return safeText(value, "", 96)
    .replace(/[^a-zA-Z0-9_.:-]/g, "")
    .slice(0, 96);
}

function dateToMillis(value, fallback = Date.now()) {
  if (!value) return fallback;
  const ms = value instanceof Date ? value.getTime() : new Date(value).getTime();
  return Number.isFinite(ms) ? ms : fallback;
}

function requireDatabase(res) {
  if (pool) return true;

  res.status(503).json({
    ok: false,
    message: "DATABASE_URL tanımlı değil.",
  });

  return false;
}

function publicError(message, statusCode = 400, code) {
  const error = new Error(message);
  error.statusCode = statusCode;
  error.publicCode = code;
  return error;
}

function sendError(res, error, fallbackMessage, logLabel) {
  const statusCode = Number(error.statusCode || 500);
  const isPublicError = statusCode >= 400 && statusCode < 500;

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
    message: isPublicError ? error.message : fallbackMessage,
  });
}

function levelStateForTotalXp(totalXp) {
  let safeTotalXp = safeScore(totalXp);
  let remainingXp = safeTotalXp;
  let level = 1;

  while (level < 1000) {
    const required = level * 2;
    if (remainingXp < required) break;
    remainingXp -= required;
    level += 1;
  }

  return {
    totalXp: safeTotalXp,
    level,
    xpInCurrentLevel: level < 1000 ? remainingXp : 0,
    xpRequiredForNextLevel: level < 1000 ? level * 2 : 0,
  };
}

async function ensurePlayer(client, playerId, username, country) {
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
    [playerId, username, country]
  );

  await client.query(
    `INSERT INTO player_scores (player_id)
     VALUES ($1)
     ON CONFLICT (player_id) DO NOTHING`,
    [playerId]
  );

  await client.query(
    `INSERT INTO player_secure_state (
       player_id,
       remaining_rights,
       rights_last_refill_at,
       rights_updated_at,
       updated_at
     )
     VALUES ($1, $2, NOW(), NOW(), NOW())
     ON CONFLICT (player_id) DO NOTHING`,
    [playerId, MAX_GLOBAL_GAME_RIGHTS]
  );
}

async function usernameBelongsToAnother(client, username, playerId) {
  const result = await client.query(
    `SELECT player_id
     FROM players
     WHERE LOWER(username) = LOWER($1)
       AND player_id <> $2
     LIMIT 1`,
    [username, playerId]
  );

  return result.rowCount > 0;
}

function calculateRights(row, nowMs = Date.now()) {
  let remainingRights = Math.max(
    0,
    Math.min(Number(row.remaining_rights ?? MAX_GLOBAL_GAME_RIGHTS), MAX_GLOBAL_GAME_RIGHTS)
  );

  let lastRefillMs = dateToMillis(row.rights_last_refill_at, nowMs);

  if (remainingRights < MAX_GLOBAL_GAME_RIGHTS) {
    const refillCount = Math.floor(
      Math.max(0, nowMs - lastRefillMs) / GAME_RIGHT_REFILL_MS
    );

    if (refillCount > 0) {
      remainingRights = Math.min(MAX_GLOBAL_GAME_RIGHTS, remainingRights + refillCount);
      lastRefillMs =
        remainingRights >= MAX_GLOBAL_GAME_RIGHTS
          ? nowMs
          : lastRefillMs + refillCount * GAME_RIGHT_REFILL_MS;
    }
  }

  return {
    remainingRights,
    maxRights: MAX_GLOBAL_GAME_RIGHTS,
    lastRefillTimeMillis: lastRefillMs,
    updatedAtMillis: dateToMillis(row.rights_updated_at, nowMs),
    millisUntilNextRight:
      remainingRights >= MAX_GLOBAL_GAME_RIGHTS
        ? 0
        : Math.max(0, lastRefillMs + GAME_RIGHT_REFILL_MS - nowMs),
  };
}

async function refreshRightsLocked(client, playerId) {
  const state = await client.query(
    `SELECT *
     FROM player_secure_state
     WHERE player_id = $1
     FOR UPDATE`,
    [playerId]
  );

  const row = state.rows[0];
  const nowMs = Date.now();
  const rights = calculateRights(row, nowMs);

  if (
    rights.remainingRights !== row.remaining_rights ||
    rights.lastRefillTimeMillis !== dateToMillis(row.rights_last_refill_at, nowMs)
  ) {
    await client.query(
      `UPDATE player_secure_state
       SET remaining_rights = $2,
           rights_last_refill_at = to_timestamp($3 / 1000.0),
           rights_updated_at = NOW(),
           updated_at = NOW()
       WHERE player_id = $1`,
      [playerId, rights.remainingRights, rights.lastRefillTimeMillis]
    );

    rights.updatedAtMillis = Date.now();
  }

  return rights;
}

async function buildPlayerState(client, playerId) {
  const result = await client.query(
    `SELECT
       p.username,
       p.country,
       ps.general_score,
       ps.infinite_score,
       st.total_xp,
       st.remaining_rights,
       st.rights_last_refill_at,
       st.rights_updated_at,
       st.username_change_count,
       st.username_last_change_at,
       st.username_updated_at
     FROM players p
     JOIN player_scores ps ON ps.player_id = p.player_id
     JOIN player_secure_state st ON st.player_id = p.player_id
     WHERE p.player_id = $1`,
    [playerId]
  );

  if (!result.rows[0]) {
    throw publicError("Oyuncu bulunamadı.", 404, "PLAYER_NOT_FOUND");
  }

  const row = result.rows[0];
  const rights = await refreshRightsLocked(client, playerId);

  return {
    username: row.username,
    country: row.country,
    totalScore: Number(row.general_score || 0),
    infiniteScore: Number(row.infinite_score || 0),
    totalXp: Number(row.total_xp || 0),
    level: levelStateForTotalXp(row.total_xp),
    rights,
    profile: {
      changeCountAfterInitial: Number(row.username_change_count || 0),
      lastChangeTimeMillis: dateToMillis(row.username_last_change_at, 0),
      updatedAtMillis: dateToMillis(row.username_updated_at, Date.now()),
    },
  };
}

app.post("/player/state/sync", async (req, res) => {
  if (!requireDatabase(res)) return;

  const playerId = safePlayerId(req.body.playerId);
  const username = safeUsername(req.body.username);
  const country = safeCountry(req.body.country);

  if (!playerId) {
    return res.status(400).json({
      ok: false,
      message: "playerId zorunlu.",
    });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");
    await ensurePlayer(client, playerId, username, country);
    const state = await buildPlayerState(client, playerId);
    await client.query("COMMIT");

    res.json({
      ok: true,
      state,
    });
  } catch (error) {
    await client.query("ROLLBACK");
    sendError(res, error, "Oyuncu durumu alınamadı.", "player state sync error:");
  } finally {
    client.release();
  }
});

app.post("/player/username/update", async (req, res) => {
  if (!requireDatabase(res)) return;

  const playerId = safePlayerId(req.body.playerId);
  const username = safeUsername(req.body.username);
  const country = safeCountry(req.body.country);

  if (!playerId) {
    return res.status(400).json({
      ok: false,
      message: "playerId zorunlu.",
    });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");
    await ensurePlayer(client, playerId, username, country);

    if (await usernameBelongsToAnother(client, username, playerId)) {
      throw publicError("Bu kullanıcı adı zaten alınmış.", 409, "USERNAME_TAKEN");
    }

    const locked = await client.query(
      `SELECT *
       FROM player_secure_state
       WHERE player_id = $1
       FOR UPDATE`,
      [playerId]
    );

    const current = await client.query(
      `SELECT username
       FROM players
       WHERE player_id = $1
       FOR UPDATE`,
      [playerId]
    );

    const oldUsername = current.rows[0]?.username || "";
    const stateRow = locked.rows[0];
    const alreadyHasName = oldUsername && oldUsername !== "Oyuncu";

    if (alreadyHasName && oldUsername.toLowerCase() !== username.toLowerCase()) {
      const lastChangeMs = dateToMillis(stateRow.username_last_change_at, 0);
      const waitMs = Math.max(
        0,
        lastChangeMs + USERNAME_CHANGE_COOLDOWN_MS - Date.now()
      );

      if (waitMs > 0) {
        throw publicError(
          "Kullanıcı adını yeniden değiştirmek için süre dolmadı.",
          429,
          "USERNAME_COOLDOWN"
        );
      }
    }

    await client.query(
      `UPDATE players
       SET username = $2,
           country = $3,
           updated_at = NOW()
       WHERE player_id = $1`,
      [playerId, username, country]
    );

    await client.query(
      `UPDATE player_secure_state
       SET username_change_count =
             CASE WHEN $2::boolean THEN username_change_count + 1 ELSE username_change_count END,
           username_last_change_at = NOW(),
           username_updated_at = NOW(),
           updated_at = NOW()
       WHERE player_id = $1`,
      [playerId, Boolean(alreadyHasName)]
    );

    const state = await buildPlayerState(client, playerId);
    await client.query("COMMIT");

    res.json({
      ok: true,
      state,
    });
  } catch (error) {
    await client.query("ROLLBACK");
    sendError(res, error, "Kullanıcı adı güncellenemedi.", "username update error:");
  } finally {
    client.release();
  }
});

app.post("/player/right/consume", async (req, res) => {
  if (!requireDatabase(res)) return;

  const playerId = safePlayerId(req.body.playerId);
  const username = safeUsername(req.body.username);
  const country = safeCountry(req.body.country);

  if (!playerId) {
    return res.status(400).json({
      ok: false,
      message: "playerId zorunlu.",
    });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");
    await ensurePlayer(client, playerId, username, country);

    const rights = await refreshRightsLocked(client, playerId);

    if (rights.remainingRights <= 0) {
      const state = await buildPlayerState(client, playerId);
      await client.query("COMMIT");

      return res.json({
        ok: true,
        consumed: false,
        state,
      });
    }

    await client.query(
      `UPDATE player_secure_state
       SET remaining_rights = remaining_rights - 1,
           rights_updated_at = NOW(),
           updated_at = NOW()
       WHERE player_id = $1`,
      [playerId]
    );

    const state = await buildPlayerState(client, playerId);
    await client.query("COMMIT");

    res.json({
      ok: true,
      consumed: true,
      state,
    });
  } catch (error) {
    await client.query("ROLLBACK");
    sendError(res, error, "Oyun hakkı kullanılamadı.", "right consume error:");
  } finally {
    client.release();
  }
});

app.post("/player/reward/add", async (req, res) => {
  if (!requireDatabase(res)) return;

  const playerId = safePlayerId(req.body.playerId);
  const username = safeUsername(req.body.username);
  const country = safeCountry(req.body.country);
  const eventId = safeEventId(req.body.eventId) || crypto.randomUUID();
  const generalDelta = safeSignedDelta(req.body.generalScoreDelta);
  const infiniteDelta = safePositiveDelta(req.body.infiniteScoreDelta);
  const xpDelta = safePositiveDelta(req.body.xpDelta, MAX_XP_DELTA);

  if (!playerId) {
    return res.status(400).json({
      ok: false,
      message: "playerId zorunlu.",
    });
  }

  if (generalDelta === 0 && infiniteDelta === 0 && xpDelta === 0) {
    return res.status(400).json({
      ok: false,
      message: "Eklenecek ödül yok.",
    });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");
    await ensurePlayer(client, playerId, username, country);

    const inserted = await client.query(
      `INSERT INTO player_reward_events (player_id, event_id)
       VALUES ($1, $2)
       ON CONFLICT DO NOTHING`,
      [playerId, eventId]
    );

    if (inserted.rowCount > 0) {
      await client.query(
        `UPDATE player_scores
         SET general_score = GREATEST(0, general_score + $2),
             infinite_score = GREATEST(0, infinite_score + $3),
             updated_at = NOW()
         WHERE player_id = $1`,
        [playerId, generalDelta, infiniteDelta]
      );

      await client.query(
        `INSERT INTO player_monthly_scores (
           player_id,
           month_key,
           general_score,
           infinite_score,
           updated_at
         )
         VALUES ($1, $2, GREATEST(0, $3), GREATEST(0, $4), NOW())
         ON CONFLICT (player_id, month_key)
         DO UPDATE SET
           general_score = GREATEST(0, player_monthly_scores.general_score + $3),
           infinite_score = GREATEST(0, player_monthly_scores.infinite_score + $4),
           updated_at = NOW()`,
        [playerId, currentMonthKey(), generalDelta, infiniteDelta]
      );

      await client.query(
        `UPDATE player_secure_state
         SET total_xp = LEAST(2000000000, total_xp + $2),
             updated_at = NOW()
         WHERE player_id = $1`,
        [playerId, xpDelta]
      );
    }

    const state = await buildPlayerState(client, playerId);
    await client.query("COMMIT");

    res.json({
      ok: true,
      applied: inserted.rowCount > 0,
      state,
    });
  } catch (error) {
    await client.query("ROLLBACK");
    sendError(res, error, "Ödül kaydedilemedi.", "reward add error:");
  } finally {
    client.release();
  }
});

app.post("/leaderboard/username/claim", async (req, res) => {
  if (!requireDatabase(res)) return;

  const playerId = safePlayerId(req.body.playerId);
  const username = safeUsername(req.body.username);
  const country = safeCountry(req.body.country);

  if (!playerId) {
    return res.status(400).json({
      ok: false,
      message: "playerId zorunlu.",
    });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");
    await ensurePlayer(client, playerId, username, country);

    if (await usernameBelongsToAnother(client, username, playerId)) {
      throw publicError("Bu kullanıcı adı zaten alınmış.", 409, "USERNAME_TAKEN");
    }

    await client.query(
      `UPDATE players
       SET username = $2,
           country = $3,
           updated_at = NOW()
       WHERE player_id = $1`,
      [playerId, username, country]
    );

    await client.query("COMMIT");

    res.json({
      ok: true,
    });
  } catch (error) {
    await client.query("ROLLBACK");
    sendError(res, error, "Kullanıcı adı kaydedilemedi.", "username claim error:");
  } finally {
    client.release();
  }
});

app.post("/leaderboard/scores/sync", async (req, res) => {
  if (!requireDatabase(res)) return;

  const playerId = safePlayerId(req.body.playerId);
  const username = safeUsername(req.body.username);
  const country = safeCountry(req.body.country);
  const generalScore = safeScore(req.body.generalScore);
  const infiniteScore = safeScore(req.body.infiniteScore);

  if (!playerId) {
    return res.status(400).json({
      ok: false,
      message: "playerId zorunlu.",
    });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");
    await ensurePlayer(client, playerId, username, country);

    await client.query(
      `UPDATE player_scores
       SET general_score = GREATEST(general_score, $2),
           infinite_score = GREATEST(infinite_score, $3),
           updated_at = NOW()
       WHERE player_id = $1`,
      [playerId, generalScore, infiniteScore]
    );

    await client.query("COMMIT");

    res.json({
      ok: true,
    });
  } catch (error) {
    await client.query("ROLLBACK");
    sendError(res, error, "Skor senkronize edilemedi.", "leaderboard sync error:");
  } finally {
    client.release();
  }
});

app.post("/leaderboard/scores/add", async (req, res) => {
  if (!requireDatabase(res)) return;

  const playerId = safePlayerId(req.body.playerId);
  const username = safeUsername(req.body.username);
  const country = safeCountry(req.body.country);
  const generalDelta = safeSignedDelta(req.body.generalScoreDelta);
  const infiniteDelta = safePositiveDelta(req.body.infiniteScoreDelta);

  if (!playerId) {
    return res.status(400).json({
      ok: false,
      message: "playerId zorunlu.",
    });
  }

  if (generalDelta === 0 && infiniteDelta === 0) {
    return res.status(400).json({
      ok: false,
      message: "Eklenecek skor yok.",
    });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");
    await ensurePlayer(client, playerId, username, country);

    await client.query(
      `UPDATE player_scores
       SET general_score = GREATEST(0, general_score + $2),
           infinite_score = GREATEST(0, infinite_score + $3),
           updated_at = NOW()
       WHERE player_id = $1`,
      [playerId, generalDelta, infiniteDelta]
    );

    await client.query(
      `INSERT INTO player_monthly_scores (
         player_id,
         month_key,
         general_score,
         infinite_score,
         updated_at
       )
       VALUES ($1, $2, GREATEST(0, $3), GREATEST(0, $4), NOW())
       ON CONFLICT (player_id, month_key)
       DO UPDATE SET
         general_score = GREATEST(0, player_monthly_scores.general_score + $3),
         infinite_score = GREATEST(0, player_monthly_scores.infinite_score + $4),
         updated_at = NOW()`,
      [playerId, currentMonthKey(), generalDelta, infiniteDelta]
    );

    await client.query("COMMIT");

    res.json({
      ok: true,
    });
  } catch (error) {
    await client.query("ROLLBACK");
    sendError(res, error, "Skor eklenemedi.", "leaderboard add error:");
  } finally {
    client.release();
  }
});

app.get("/leaderboard", async (req, res) => {
  if (!requireDatabase(res)) return;

  const scoreType = req.query.scoreType === "infinite" ? "infinite" : "general";
  const period = req.query.period === "month" ? "month" : "all";
  const scope = req.query.scope === "country" ? "country" : "world";
  const country = safeCountry(req.query.country);
  const playerId = safePlayerId(req.query.playerId);

  const scoreColumn = scoreType === "infinite" ? "infinite_score" : "general_score";
  const tableName = period === "month" ? "player_monthly_scores" : "player_scores";
  const monthKey = currentMonthKey();

  const values = [];
  const where = [`s.${scoreColumn} > 0`];

  if (period === "month") {
    values.push(monthKey);
    where.push(`s.month_key = $${values.length}`);
  }

  if (scope === "country") {
    values.push(country);
    where.push(`p.country = $${values.length}`);
  }

  try {
    const rows = await pool.query(
      `SELECT
         p.username,
         p.country,
         s.${scoreColumn} AS score,
         ROW_NUMBER() OVER (
           ORDER BY s.${scoreColumn} DESC, s.updated_at ASC, p.username ASC
         ) AS rank
       FROM ${tableName} s
       JOIN players p ON p.player_id = s.player_id
       WHERE ${where.join(" AND ")}
       ORDER BY s.${scoreColumn} DESC, s.updated_at ASC, p.username ASC
       LIMIT 100`,
      values
    );

    async function rankFor(includeCountry) {
      if (!playerId) return null;

      const rankValues = [];
      const rankWhere = [`s.${scoreColumn} > 0`];

      if (period === "month") {
        rankValues.push(monthKey);
        rankWhere.push(`s.month_key = $${rankValues.length}`);
      }

      if (includeCountry) {
        rankValues.push(country);
        rankWhere.push(`p.country = $${rankValues.length}`);
      }

      rankValues.push(playerId);
      const playerIndex = rankValues.length;

      const result = await pool.query(
        `WITH ranked AS (
           SELECT
             p.player_id,
             s.${scoreColumn} AS score,
             ROW_NUMBER() OVER (
               ORDER BY s.${scoreColumn} DESC, s.updated_at ASC, p.username ASC
             ) AS rank
           FROM ${tableName} s
           JOIN players p ON p.player_id = s.player_id
           WHERE ${rankWhere.join(" AND ")}
         )
         SELECT rank, score
         FROM ranked
         WHERE player_id = $${playerIndex}
         LIMIT 1`,
        rankValues
      );

      return result.rows[0] || null;
    }

    const myWorld = await rankFor(false);
    const myCountry = await rankFor(true);

    res.json({
      ok: true,
      scoreType,
      period,
      scope,
      country,
      rows: rows.rows.map((row) => ({
        rank: Number(row.rank),
        username: row.username,
        country: row.country,
        score: Number(row.score),
      })),
      myWorldRank: myWorld ? Number(myWorld.rank) : null,
      myCountryRank: myCountry ? Number(myCountry.rank) : null,
      myScore: Number((scope === "country" ? myCountry : myWorld)?.score || 0),
    });
  } catch (error) {
    sendError(res, error, "Skor tablosu alınamadı.", "leaderboard get error:");
  }
});

function randomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function generateTargetNumberPuzzle(difficulty) {
  const isHard = String(difficulty) === "Hard";
  const count = isHard ? 4 : 3;
  const minNumber = isHard ? 2 : 1;
  const maxNumber = isHard ? 20 : 9;

  for (let attempt = 0; attempt < 50; attempt += 1) {
    const numbers = Array.from(
      { length: count },
      () => randomInt(minNumber, maxNumber)
    );

    const ops = ["+", "-", "*"];
    let value = numbers[0];

    for (let i = 1; i < numbers.length; i += 1) {
      const op = ops[randomInt(0, ops.length - 1)];
      const next = numbers[i];

      if (op === "+") value += next;
      else if (op === "-") value -= next;
      else value *= next;
    }

    const target = Math.abs(Math.trunc(value));

    if (isHard) {
      if (target > 20 && target < 200) {
        return {
          difficulty: "Hard",
          target,
          numbers,
        };
      }
    } else if (target >= 10 && target < 50) {
      return {
        difficulty: "Medium",
        target,
        numbers,
      };
    }
  }

  return {
    difficulty: isHard ? "Hard" : "Medium",
    target: isHard ? randomInt(21, 199) : randomInt(10, 49),
    numbers: Array.from(
      { length: count },
      () => randomInt(minNumber, maxNumber)
    ),
  };
}

function normalizeGameKey(value) {
  return (
    safeText(value, "target_number", 40)
      .replace(/[^a-zA-Z0-9_.:-]/g, "")
      .slice(0, 40) || "target_number"
  );
}

function queueKey(gameKey, difficulty) {
  return `${normalizeGameKey(gameKey)}:${String(difficulty || "Medium")}`;
}

function safePlayer(payload, fallbackId) {
  const data = payload && typeof payload === "object" ? payload : {};

  return {
    id: safePlayerId(data.id || data.playerId || fallbackId) || safePlayerId(fallbackId),
    name: safeUsername(data.name || data.playerName),
    country: safeCountry(data.country || data.playerCountry),
  };
}

function normalizeRoomCode(value) {
  return String(value || "")
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, "")
    .slice(0, 6);
}

function generateRoomCode() {
  let code = "";
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

  do {
    code = Array.from(
      { length: 6 },
      () => chars[randomInt(0, chars.length - 1)]
    ).join("");
  } while (privateRooms.has(code));

  return code;
}

const waitingQueues = new Map();
const realtimeRooms = new Map();
const activeRooms = new Map();
const privateRooms = new Map();

function roomParticipants(room) {
  return room ? [room.a, room.b].filter(Boolean) : [];
}

function getParticipant(room, playerId) {
  return roomParticipants(room).find((participant) => participant.playerId === playerId);
}

function getOpponent(room, playerId) {
  return roomParticipants(room).find((participant) => participant.playerId !== playerId);
}

function attachSocketToRoom(socket, room, playerId) {
  const participant = getParticipant(room, playerId);
  if (!participant) return;

  participant.socketId = socket.id;
  participant.connected = true;
  participant.awaySince = null;

  socket.join(room.roomId);

  activeRooms.set(socket.id, {
    roomId: room.roomId,
    playerId,
  });
}

function createRealtimeRoom(socketA, playerA, socketB, playerB, gameKey, difficulty, puzzle) {
  const roomId = crypto.randomUUID();

  const room = {
    roomId,
    gameKey,
    difficulty,
    puzzle,
    createdAt: Date.now(),
    resolved: false,
    resolvedAt: null,
    reason: null,
    winnerPlayerId: null,
    loserPlayerId: null,
    a: {
      playerId: playerA.id,
      name: playerA.name,
      country: playerA.country,
      socketId: socketA.id,
      connected: true,
      finishedAt: null,
      elapsedMs: null,
      awaySince: null,
      timeout: null,
    },
    b: {
      playerId: playerB.id,
      name: playerB.name,
      country: playerB.country,
      socketId: socketB.id,
      connected: true,
      finishedAt: null,
      elapsedMs: null,
      awaySince: null,
      timeout: null,
    },
  };

  realtimeRooms.set(roomId, room);
  attachSocketToRoom(socketA, room, playerA.id);
  attachSocketToRoom(socketB, room, playerB.id);

  return room;
}

function resolveRoom(room, reason, winnerPlayerId, loserPlayerId) {
  if (!room || room.resolved) return;

  room.resolved = true;
  room.resolvedAt = Date.now();
  room.reason = reason;
  room.winnerPlayerId = winnerPlayerId || null;
  room.loserPlayerId = loserPlayerId || null;
}

function clearAwayTimeout(participant) {
  if (!participant) return;

  if (participant.timeout) {
    clearTimeout(participant.timeout);
  }

  participant.timeout = null;
  participant.awaySince = null;
}

function scheduleAwayTimeout(room, playerId) {
  const participant = getParticipant(room, playerId);
  if (!participant || participant.timeout) return;

  participant.timeout = setTimeout(() => {
    const freshRoom = realtimeRooms.get(room.roomId);
    const freshParticipant = getParticipant(freshRoom, playerId);
    const opponent = getOpponent(freshRoom, playerId);

    if (
      !freshRoom ||
      freshRoom.resolved ||
      !freshParticipant ||
      freshParticipant.finishedAt
    ) {
      return;
    }

    resolveRoom(
      freshRoom,
      "reconnect_timeout",
      opponent?.playerId,
      freshParticipant.playerId
    );

    const opponentSocket = opponent?.socketId
      ? io.sockets.sockets.get(opponent.socketId)
      : null;

    if (opponentSocket) {
      opponentSocket.emit("opponent_left", {
        roomId: freshRoom.roomId,
        reason: "reconnect_timeout",
      });
    }
  }, ROOM_RECONNECT_TIMEOUT_MS).unref();
}

function removeFromAllQueues(socketId, playerId) {
  for (const [key, queue] of waitingQueues.entries()) {
    const nextQueue = queue.filter((item) => {
      if (item.socketId === socketId) return false;
      if (playerId && item.player?.id === playerId) return false;
      return true;
    });

    if (nextQueue.length === 0) {
      waitingQueues.delete(key);
    } else {
      waitingQueues.set(key, nextQueue);
    }
  }
}

function removePrivateRoomsForSocket(socketId) {
  for (const [roomCode, room] of privateRooms.entries()) {
    if (room.ownerSocketId === socketId) {
      privateRooms.delete(roomCode);
    }
  }
}

function leaveRoomAsCancel(socket) {
  const active = activeRooms.get(socket.id);
  if (!active) return;

  const room = realtimeRooms.get(active.roomId);
  const participant = getParticipant(room, active.playerId);
  const opponent = getOpponent(room, active.playerId);

  if (
    room &&
    participant &&
    opponent &&
    !room.resolved &&
    !participant.finishedAt &&
    !opponent.finishedAt
  ) {
    resolveRoom(room, "cancelled", opponent.playerId, participant.playerId);

    const opponentSocket = opponent.socketId
      ? io.sockets.sockets.get(opponent.socketId)
      : null;

    if (opponentSocket) {
      opponentSocket.emit("opponent_left", {
        roomId: room.roomId,
        reason: "cancelled",
      });
    }
  }

  if (participant) {
    clearAwayTimeout(participant);
    participant.connected = false;
    participant.socketId = null;
  }

  activeRooms.delete(socket.id);
  socket.leave(active.roomId);
}

function expireRooms() {
  const now = Date.now();

  for (const [roomCode, room] of privateRooms.entries()) {
    if (now - room.createdAt > PRIVATE_ROOM_TTL_MS) {
      privateRooms.delete(roomCode);
    }
  }

  for (const [roomId, room] of realtimeRooms.entries()) {
    if (room.resolved && now - room.resolvedAt > RESOLVED_ROOM_TTL_MS) {
      realtimeRooms.delete(roomId);
    }
  }
}

app.get("/", (_req, res) => {
  res.json({
    ok: true,
    service: "target-number-matchmaking",
    socketPath: SOCKET_PATH,
    database: Boolean(pool),
    waitingQueues: Array.from(waitingQueues.entries()).map(([key, queue]) => ({
      key,
      count: queue.length,
    })),
    privateRooms: privateRooms.size,
    activeRooms: Array.from(realtimeRooms.values()).filter((room) => !room.resolved).length,
  });
});

app.get("/health", async (_req, res) => {
  if (!pool) {
    return res.json({
      ok: true,
      database: false,
    });
  }

  try {
    await pool.query("SELECT 1");

    res.json({
      ok: true,
      database: true,
    });
  } catch (error) {
    console.error("health database error:", {
      message: error.message,
      code: error.code,
      detail: error.detail,
    });

    res.status(500).json({
      ok: false,
      database: false,
      message: "Database bağlantısı başarısız.",
    });
  }
});

app.get("/socket-check", (_req, res) => {
  res.json({
    ok: true,
    socketPath: SOCKET_PATH,
    androidUrlMustNotInclude: "/socket.io",
    transports: ["websocket", "polling"],
  });
});

io.engine.on("connection_error", (error) => {
  if (!LOG_HTTP) return;

  console.log("Engine.IO connection_error:", {
    code: error.code,
    message: error.message,
    context: error.context,
    url: error.req && error.req.url,
    userAgent: error.req && error.req.headers && error.req.headers["user-agent"],
    origin: error.req && error.req.headers && error.req.headers.origin,
  });
});

io.on("connection", (socket) => {
  if (LOG_HTTP) {
    console.log("Socket connected:", socket.id, "transport:", socket.conn.transport.name);
  }

  socket.conn.on("upgrade", (transport) => {
    if (LOG_HTTP) {
      console.log("Socket upgraded:", socket.id, "transport:", transport.name);
    }
  });

  socket.on("join_match", (payload = {}) => {
    const gameKey = normalizeGameKey(payload.gameKey);
    const difficulty = String(payload.difficulty || "Medium");
    const player = safePlayer(payload.player, `guest:${socket.id}`);
    const puzzle = generateTargetNumberPuzzle(difficulty);

    removeFromAllQueues(socket.id, player.id);
    removePrivateRoomsForSocket(socket.id);
    leaveRoomAsCancel(socket);

    const key = queueKey(gameKey, difficulty);
    const queue = waitingQueues.get(key) || [];

    while (queue.length > 0) {
      const opponent = queue.shift();
      const opponentSocket = io.sockets.sockets.get(opponent.socketId);

      if (!opponentSocket || opponent.player.id === player.id) {
        continue;
      }

      waitingQueues.set(key, queue);

      const selectedPuzzle = opponent.puzzle || puzzle;

      const room = createRealtimeRoom(
        socket,
        player,
        opponentSocket,
        opponent.player,
        gameKey,
        difficulty,
        selectedPuzzle
      );

      socket.emit("match_found", {
        roomId: room.roomId,
        opponent: {
          name: opponent.player.name,
          country: opponent.player.country,
        },
        puzzle: selectedPuzzle,
      });

      opponentSocket.emit("match_found", {
        roomId: room.roomId,
        opponent: {
          name: player.name,
          country: player.country,
        },
        puzzle: selectedPuzzle,
      });

      return;
    }

    queue.push({
      socketId: socket.id,
      player,
      puzzle,
      joinedAt: Date.now(),
    });

    waitingQueues.set(key, queue);

    socket.emit("waiting", {
      gameKey,
      difficulty,
    });
  });

  socket.on("create_friend_room", (payload = {}) => {
    expireRooms();

    const gameKey = normalizeGameKey(payload.gameKey);
    const difficulty = String(payload.difficulty || "Medium");
    const player = safePlayer(payload.player, `guest:${socket.id}`);
    const roomCode = generateRoomCode();

    removeFromAllQueues(socket.id, player.id);
    removePrivateRoomsForSocket(socket.id);
    leaveRoomAsCancel(socket);

    privateRooms.set(roomCode, {
      roomCode,
      ownerSocketId: socket.id,
      gameKey,
      difficulty,
      player,
      puzzle: generateTargetNumberPuzzle(difficulty),
      createdAt: Date.now(),
    });

    socket.emit("friend_room_created", {
      roomCode,
      gameKey,
      difficulty,
    });
  });

  socket.on("join_friend_room", (payload = {}) => {
    expireRooms();

    const roomCode = normalizeRoomCode(payload.roomCode);
    const room = privateRooms.get(roomCode);

    if (!roomCode || roomCode.length !== 6) {
      return socket.emit("friend_room_error", {
        message: "Geçerli 6 haneli oda kodu gir.",
      });
    }

    if (!room) {
      return socket.emit("friend_room_error", {
        message: "Oda bulunamadı. Kodu kontrol edip tekrar deneyin.",
      });
    }

    if (room.ownerSocketId === socket.id) {
      return socket.emit("friend_room_error", {
        message: "Kendi oluşturduğun odaya aynı cihazdan katılamazsın.",
      });
    }

    const ownerSocket = io.sockets.sockets.get(room.ownerSocketId);

    if (!ownerSocket) {
      privateRooms.delete(roomCode);

      return socket.emit("friend_room_error", {
        message: "Oda sahibi bağlantıdan ayrılmış.",
      });
    }

    const player = safePlayer(payload.player, `guest:${socket.id}`);

    privateRooms.delete(roomCode);
    removeFromAllQueues(socket.id, player.id);
    removePrivateRoomsForSocket(socket.id);
    leaveRoomAsCancel(socket);

    const realtimeRoom = createRealtimeRoom(
      socket,
      player,
      ownerSocket,
      room.player,
      room.gameKey,
      room.difficulty,
      room.puzzle
    );

    socket.emit("match_found", {
      roomId: realtimeRoom.roomId,
      roomCode,
      opponent: {
        name: room.player.name,
        country: room.player.country,
      },
      puzzle: room.puzzle,
    });

    ownerSocket.emit("match_found", {
      roomId: realtimeRoom.roomId,
      roomCode,
      opponent: {
        name: player.name,
        country: player.country,
      },
      puzzle: room.puzzle,
    });
  });

  socket.on("resume_match", (payload = {}) => {
    const roomId = String(payload.roomId || "").trim();
    const player = safePlayer(payload.player, `guest:${socket.id}`);
    const room = realtimeRooms.get(roomId);
    const participant = getParticipant(room, player.id);
    const opponent = getOpponent(room, player.id);

    if (!room || !participant) {
      return socket.emit("resume_error", {
        code: "ROOM_NOT_FOUND",
        message: "Yeniden bağlanılacak aktif oda bulunamadı.",
      });
    }

    if (room.resolved) {
      return socket.emit("resume_error", {
        code: "MATCH_RESOLVED",
        message: "Bu maç zaten sona ermiş.",
        opponentFinishedMs: Number(opponent?.elapsedMs || 0),
      });
    }

    if (
      participant.awaySince &&
      Date.now() > participant.awaySince + ROOM_RECONNECT_TIMEOUT_MS
    ) {
      resolveRoom(room, "reconnect_timeout", opponent?.playerId, participant.playerId);

      return socket.emit("resume_error", {
        code: "RECONNECT_EXPIRED",
        message: "1 dakikalık yeniden bağlanma süresi doldu.",
        opponentFinishedMs: Number(opponent?.elapsedMs || 0),
      });
    }

    if (participant.socketId && participant.socketId !== socket.id) {
      activeRooms.delete(participant.socketId);
    }

    attachSocketToRoom(socket, room, participant.playerId);
    clearAwayTimeout(participant);

    socket.emit("resume_state", {
      roomId: room.roomId,
      opponent: {
        name: opponent?.name || "Rakip",
        country: opponent?.country || "",
      },
      puzzle: room.puzzle,
      opponentFinishedMs: Number(opponent?.elapsedMs || 0),
    });
  });

  socket.on("player_backgrounded", (payload = {}) => {
    const active = activeRooms.get(socket.id);
    const room = realtimeRooms.get(String(payload.roomId || active?.roomId || "").trim());
    const participant = getParticipant(room, active?.playerId);

    if (!room || !participant || room.resolved || participant.finishedAt) {
      return;
    }

    participant.awaySince = participant.awaySince || Date.now();
    scheduleAwayTimeout(room, participant.playerId);
  });

  socket.on("player_foregrounded", (payload = {}) => {
    const active = activeRooms.get(socket.id);
    const room = realtimeRooms.get(String(payload.roomId || active?.roomId || "").trim());
    const participant = getParticipant(room, active?.playerId);

    if (!room || !participant) {
      return;
    }

    if (room.resolved && room.loserPlayerId === participant.playerId) {
      return socket.emit("resume_error", {
        code: "RECONNECT_EXPIRED",
        message: "1 dakika içinde oyuna dönmediğiniz için mağlup sayıldınız.",
      });
    }

    clearAwayTimeout(participant);
  });

  socket.on("player_finished", (payload = {}) => {
    const roomId = String(payload.roomId || "").trim();
    const room = realtimeRooms.get(roomId);
    const active = activeRooms.get(socket.id);
    const participant = getParticipant(room, active?.playerId);
    const opponent = getOpponent(room, active?.playerId);
    const elapsedMs = Math.max(1, Number(payload.elapsedMs || 0));

    if (!room || !participant || !Number.isFinite(elapsedMs) || room.resolved) {
      return;
    }

    participant.finishedAt = Date.now();
    participant.elapsedMs = Math.floor(elapsedMs);
    clearAwayTimeout(participant);

    resolveRoom(room, "finished", participant.playerId, opponent?.playerId);

    const opponentSocket = opponent?.socketId
      ? io.sockets.sockets.get(opponent.socketId)
      : null;

    if (opponentSocket) {
      opponentSocket.emit("opponent_finished", {
        roomId,
        elapsedMs: participant.elapsedMs,
      });
    }
  });

  socket.on("cancel_match", () => {
    removeFromAllQueues(socket.id);
    removePrivateRoomsForSocket(socket.id);
    leaveRoomAsCancel(socket);
  });

  socket.on("disconnect", (reason) => {
    if (LOG_HTTP) {
      console.log("Socket disconnected:", socket.id, reason);
    }

    const active = activeRooms.get(socket.id);
    const room = realtimeRooms.get(active?.roomId);
    const participant = getParticipant(room, active?.playerId);

    removeFromAllQueues(socket.id);
    removePrivateRoomsForSocket(socket.id);

    if (!room || !participant) {
      return;
    }

    activeRooms.delete(socket.id);
    participant.connected = false;
    participant.socketId = null;

    if (!room.resolved && !participant.finishedAt) {
      participant.awaySince = participant.awaySince || Date.now();
      scheduleAwayTimeout(room, participant.playerId);
    }
  });
});

setInterval(expireRooms, 60_000).unref();

const PORT = Number(process.env.PORT || 10000);

initDatabase()
  .catch((error) => {
    console.error("Database init failed:", {
      message: error.message,
      code: error.code,
      detail: error.detail,
      stack: error.stack,
    });
  })
  .finally(() => {
    server.listen(PORT, "0.0.0.0", () => {
      console.log(`Target number matchmaking server running on port ${PORT}`);
    });
  });