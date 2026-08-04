const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const crypto = require("crypto");
const https = require("https");
const { Pool } = require("pg");

const app = express();

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

const server = http.createServer(app);

const SOCKET_PATH = "/socket.io/";
const DATABASE_URL = process.env.DATABASE_URL;

const GOOGLE_WEB_CLIENT_ID = process.env.GOOGLE_WEB_CLIENT_ID || "";
const GOOGLE_WEB_CLIENT_SECRET = process.env.GOOGLE_WEB_CLIENT_SECRET || "";
const PLAY_GAMES_APP_ID = process.env.PLAY_GAMES_APP_ID || "";
const SESSION_SECRET = process.env.SESSION_SECRET || "";
const SESSION_TTL_SECONDS = Number(process.env.SESSION_TTL_SECONDS || 24 * 60 * 60);

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

    CREATE TABLE IF NOT EXISTS player_progress (
      player_id TEXT PRIMARY KEY REFERENCES players(player_id) ON DELETE CASCADE,
      total_xp INTEGER NOT NULL DEFAULT 0 CHECK (total_xp >= 0),
      infinite_run_score INTEGER NOT NULL DEFAULT 0 CHECK (infinite_run_score >= 0),
      infinite_next_stage INTEGER NOT NULL DEFAULT 1 CHECK (infinite_next_stage >= 1),
      tournament_stage INTEGER NOT NULL DEFAULT 1 CHECK (tournament_stage BETWEEN 1 AND 12),
      tournament_rights INTEGER NOT NULL DEFAULT 3 CHECK (tournament_rights BETWEEN 0 AND 3),
      tournament_bank INTEGER NOT NULL DEFAULT 0 CHECK (tournament_bank >= 0),
      tournament_completed BOOLEAN NOT NULL DEFAULT FALSE,
      hundred_active BOOLEAN NOT NULL DEFAULT FALSE,
      hundred_stage INTEGER NOT NULL DEFAULT 0 CHECK (hundred_stage BETWEEN 0 AND 12),
      game_rights INTEGER NOT NULL DEFAULT 10 CHECK (game_rights BETWEEN 0 AND 10),
      game_rights_refill_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      diamond_balance INTEGER NOT NULL DEFAULT 0 CHECK (diamond_balance >= 0),
      level_reward_claimed_through INTEGER NOT NULL DEFAULT 0
        CHECK (level_reward_claimed_through BETWEEN 0 AND 1000),
      bot_fallback_game_key TEXT,
      bot_fallback_difficulty TEXT,
      bot_fallback_eligible_at TIMESTAMPTZ,
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
      ADD COLUMN IF NOT EXISTS hundred_active BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE player_progress
      ADD COLUMN IF NOT EXISTS hundred_stage INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE player_progress
      ADD COLUMN IF NOT EXISTS game_rights INTEGER NOT NULL DEFAULT 10;
    ALTER TABLE player_progress
      ADD COLUMN IF NOT EXISTS game_rights_refill_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
    ALTER TABLE player_progress
      ADD COLUMN IF NOT EXISTS diamond_balance INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE player_progress
      ADD COLUMN IF NOT EXISTS level_reward_claimed_through INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE player_progress
      ADD COLUMN IF NOT EXISTS bot_fallback_game_key TEXT;
    ALTER TABLE player_progress
      ADD COLUMN IF NOT EXISTS bot_fallback_difficulty TEXT;
    ALTER TABLE player_progress
      ADD COLUMN IF NOT EXISTS bot_fallback_eligible_at TIMESTAMPTZ;
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

    CREATE TABLE IF NOT EXISTS player_task_events (
      player_id TEXT NOT NULL REFERENCES players(player_id) ON DELETE CASCADE,
      source_key TEXT NOT NULL,
      event_type TEXT NOT NULL CHECK (event_type IN ('login', 'game')),
      game_key TEXT,
      multiplayer BOOLEAN NOT NULL DEFAULT FALSE,
      won BOOLEAN NOT NULL DEFAULT FALSE,
      occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (player_id, source_key)
    );

    CREATE TABLE IF NOT EXISTS player_task_claims (
      player_id TEXT NOT NULL REFERENCES players(player_id) ON DELETE CASCADE,
      period_type TEXT NOT NULL CHECK (period_type IN ('daily', 'weekly', 'monthly')),
      period_key TEXT NOT NULL,
      task_code TEXT NOT NULL,
      reward_score INTEGER NOT NULL DEFAULT 0 CHECK (reward_score >= 0),
      reward_diamonds INTEGER NOT NULL DEFAULT 0 CHECK (reward_diamonds >= 0),
      claimed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (player_id, period_type, period_key, task_code)
    );

    CREATE INDEX IF NOT EXISTS idx_task_events_player_time
      ON player_task_events (player_id, occurred_at DESC);

    CREATE INDEX IF NOT EXISTS idx_secure_challenges_player_active
      ON secure_game_challenges (player_id, mode, completed_at, expires_at);

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

async function recordTaskEventInTransaction(client, {
  playerId, sourceKey, eventType, gameKey = null, multiplayer = false, won = false,
}) {
  if (!playerId || !sourceKey) return false;
  await ensureAuthenticatedPlayer(client, playerId);
  const result = await client.query(
    `INSERT INTO player_task_events
     (player_id, source_key, event_type, game_key, multiplayer, won, occurred_at)
     VALUES ($1, $2, $3, $4, $5, $6, NOW())
     ON CONFLICT (player_id, source_key) DO NOTHING
     RETURNING source_key`,
    [playerId, String(sourceKey).slice(0, 180), eventType, gameKey, multiplayer === true, won === true]
  );
  return result.rowCount > 0;
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

async function readTaskCenterState(client, playerId) {
  const now = new Date();
  const periods = ["daily", "weekly", "monthly"].map((type) => taskPeriodInfo(type, now));
  const earliest = new Date(Math.min(...periods.map((item) => item.start.getTime())));
  const eventsResult = await client.query(
    `SELECT event_type, game_key, multiplayer, won, occurred_at
     FROM player_task_events
     WHERE player_id = $1 AND occurred_at >= $2
     ORDER BY occurred_at ASC`,
    [playerId, earliest]
  );
  const favoriteResult = await client.query(
    `SELECT game_key, COUNT(*)::INTEGER AS play_count
     FROM player_task_events
     WHERE player_id = $1 AND event_type = 'game' AND game_key IS NOT NULL
     GROUP BY game_key
     ORDER BY play_count DESC, game_key ASC
     LIMIT 1`,
    [playerId]
  );
  const favoriteGameKey = favoriteResult.rows[0]?.game_key || null;
  const claimsResult = await client.query(
    `SELECT period_type, period_key, task_code
     FROM player_task_claims
     WHERE player_id = $1 AND period_key = ANY($2::text[])`,
    [playerId, periods.map((item) => item.key)]
  );
  const claims = new Set(claimsResult.rows.map((row) => `${row.period_type}:${row.period_key}:${row.task_code}`));

  const periodStates = periods.map((period) => {
    const config = TASK_PERIOD_CONFIG[period.type];
    const events = eventsResult.rows.filter((row) => {
      const time = new Date(row.occurred_at).getTime();
      return time >= period.start.getTime() && time < period.end.getTime();
    });
    const gameEvents = events.filter((row) => row.event_type === "game");
    const multiplayerEvents = gameEvents.filter((row) => row.multiplayer === true);
    const distinctGames = new Set(gameEvents.map((row) => row.game_key).filter(Boolean)).size;
    const distinctMultiplayerGames = new Set(multiplayerEvents.map((row) => row.game_key).filter(Boolean)).size;
    const nonFavoriteGames = favoriteGameKey
      ? gameEvents.filter((row) => row.game_key !== favoriteGameKey).length : 0;
    const nonFavoriteMultiplayerGames = favoriteGameKey
      ? multiplayerEvents.filter((row) => row.game_key !== favoriteGameKey).length : 0;
    const counts = {
      login: events.filter((row) => row.event_type === "login").length,
      multiplayer_play: multiplayerEvents.length,
      multiplayer_win: multiplayerEvents.filter((row) => row.won === true).length,
      different_games: period.type === "daily" ? distinctGames : gameEvents.length,
      different_multiplayer_games: period.type === "daily" ? distinctMultiplayerGames : multiplayerEvents.length,
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
        claimed: claims.has(`${period.type}:${period.key}:${definition.code}`),
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
      masterClaimed: claims.has(`${period.type}:${period.key}:all_complete`),
    };
  });

  return { serverNowMillis: now.getTime(), periods: periodStates };
}

async function claimTaskRewardInTransaction(client, playerId, periodType, taskCode) {
  const type = TASK_PERIOD_CONFIG[periodType] ? periodType : "daily";
  const period = taskPeriodInfo(type);
  const taskCenter = await readTaskCenterState(client, playerId);
  const periodState = taskCenter.periods.find((item) => item.type === type);
  const isMaster = taskCode === "all_complete";
  const task = periodState?.tasks.find((item) => item.code === taskCode);
  if ((!isMaster && (!task || !task.completed)) || (isMaster && !periodState?.allComplete)) {
    const error = new Error("Bu görev henüz tamamlanmadı.");
    error.statusCode = 409;
    error.publicCode = "TASK_NOT_COMPLETE";
    throw error;
  }
  const rewardScore = isMaster ? 0 : task.rewardScore;
  const rewardDiamonds = isMaster ? periodState.masterRewardDiamonds : 0;
  const inserted = await client.query(
    `INSERT INTO player_task_claims
     (player_id, period_type, period_key, task_code, reward_score, reward_diamonds, claimed_at)
     VALUES ($1, $2, $3, $4, $5, $6, NOW())
     ON CONFLICT (player_id, period_type, period_key, task_code) DO NOTHING
     RETURNING task_code`,
    [playerId, type, period.key, taskCode, rewardScore, rewardDiamonds]
  );
  if (inserted.rowCount > 0) {
    if (rewardScore > 0) await addPositiveGeneralAndXpInTransaction(client, playerId, rewardScore, 0);
    if (rewardDiamonds > 0) {
      await client.query(
        `UPDATE player_progress SET diamond_balance = LEAST(diamond_balance + $2, 2000000000), updated_at = NOW()
         WHERE player_id = $1`,
        [playerId, rewardDiamonds]
      );
    }
  }
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


function secureDifficulty(value) {
  return String(value || "Medium") === "Hard" ? "Hard" : "Medium";
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

function generateSecurePuzzle(difficultyValue) {
  const difficulty = secureDifficulty(difficultyValue);
  const count = difficulty === "Hard" ? 4 : 3;
  const min = difficulty === "Hard" ? 2 : 1;
  const max = difficulty === "Hard" ? 20 : 9;
  const targetMin = difficulty === "Hard" ? 21 : 1;
  const targetMax = difficulty === "Hard" ? 199 : 49;
  for (let attempt = 0; attempt < 500; attempt += 1) {
    const numbers = [];
    let oneUsed = false;
    while (numbers.length < count) {
      const value = crypto.randomInt(min, max + 1);
      if (value === 1 && oneUsed) continue;
      if (value === 1) oneUsed = true;
      numbers.push(value);
    }
    const shuffledNumbers = shuffled(numbers);
    const target = buildSolvableTarget(shuffledNumbers, targetMin, targetMax, difficulty === "Hard");
    if (target !== null) return { difficulty, target, numbers: shuffledNumbers };
  }
  return difficulty === "Hard"
    ? { difficulty, target: 24, numbers: shuffled([10, 10, 5, 4]) }
    : { difficulty, target: 15, numbers: shuffled([3, 5, 7]) };
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

function tournamentStageReward(stageValue) {
  const stage = Math.max(1, Math.min(Number(stageValue || 1), 12));
  return stage >= 12 ? 480 : stage * 20;
}

const GAME_RIGHT_MAX = 10;
const GAME_RIGHT_REFILL_MS = 10 * 60 * 1000;
const BOT_FALLBACK_MIN_WAIT_MS = 20 * 1000;
const USERNAME_CHANGE_COOLDOWN_MS = 30 * 24 * 60 * 60 * 1000;

async function normalizeGameRightsInTransaction(client, playerId) {
  await ensureAuthenticatedPlayer(client, playerId);
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
  await client.query(
    `UPDATE player_progress SET game_rights = $2,
       game_rights_refill_at = TO_TIMESTAMP($3 / 1000.0), updated_at = NOW()
     WHERE player_id = $1`,
    [playerId, remaining, nextAnchor]
  );
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
  await ensureAuthenticatedPlayer(client, playerId);
  const result = await client.query(
    `SELECT general_score FROM player_scores WHERE player_id = $1 FOR UPDATE`,
    [playerId]
  );
  const generalScore = Number(result.rows[0]?.general_score || 0);
  const requiredScore = minimumTwoPlayerStake(difficulty);
  if (generalScore < requiredScore) {
    const error = new Error(`Bu zorluk için en az ${requiredScore} genel puan gerekli.`);
    error.statusCode = 409;
    error.publicCode = "INSUFFICIENT_SCORE";
    throw error;
  }
  const stakePoints = normalizeRequestedStake(wagerPoints, difficulty, generalScore, allowAutomatic);
  return { generalScore, stakePoints };
}

async function consumeGameRightInTransaction(client, playerId, difficulty, wagerPoints = minimumTwoPlayerStake(difficulty), allowAutomatic = false) {
  const entry = await assertTwoPlayerEntryScoreInTransaction(
    client, playerId, difficulty, wagerPoints, allowAutomatic
  );
  const state = await normalizeGameRightsInTransaction(client, playerId);
  if (state.remainingRights <= 0) {
    const error = new Error("İki oyunculu oyun hakkın kalmadı.");
    error.statusCode = 409;
    error.publicCode = "NO_GAME_RIGHT";
    throw error;
  }
  const now = Date.now();
  const wasFull = state.remainingRights >= GAME_RIGHT_MAX;
  const remaining = state.remainingRights - 1;
  const anchor = wasFull ? now : state.lastRefillTimeMillis;
  await client.query(
    `UPDATE player_progress SET game_rights = $2,
       game_rights_refill_at = TO_TIMESTAMP($3 / 1000.0), updated_at = NOW()
     WHERE player_id = $1`,
    [playerId, remaining, anchor]
  );
  return { ...state, ...entry, remainingRights: remaining, lastRefillTimeMillis: anchor,
    millisUntilNextRight: GAME_RIGHT_REFILL_MS };
}

async function consumeGameRightsForPlayers(playerIds, difficulty, wagerPoints = minimumTwoPlayerStake(difficulty)) {
  const uniqueIds = [...new Set(playerIds.map(String))].sort();
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    for (const playerId of uniqueIds) {
      await consumeGameRightInTransaction(client, playerId, difficulty, wagerPoints, false);
    }
    await client.query("COMMIT");
    return true;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

async function refundGameRightInTransaction(client, playerId) {
  await ensureAuthenticatedPlayer(client, playerId);
  const state = await normalizeGameRightsInTransaction(client, playerId);
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

async function refundConsumedGameRights(playerIds) {
  if (!pool) return new Map();
  const uniqueIds = [...new Set((playerIds || []).filter(Boolean).map(String))].sort();
  if (uniqueIds.length === 0) return new Map();
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    for (const playerId of uniqueIds) {
      await refundGameRightInTransaction(client, playerId);
    }
    const states = new Map();
    for (const playerId of uniqueIds) {
      states.set(playerId, {
        ...(await readAuthoritativePlayerState(client, playerId)),
        generalDelta: 0,
        infiniteDelta: 0,
        xpDelta: 0,
      });
    }
    await client.query("COMMIT");
    return states;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

async function markBotFallbackEligibility(playerId, gameKey, difficulty) {
  if (!pool || !playerId) return;
  const normalizedGameKey = gameKey === "target_number_tournament"
    ? "target_number_tournament"
    : "target_number";
  const normalizedDifficulty = secureDifficulty(difficulty);
  await pool.query(
    `UPDATE player_progress SET
       bot_fallback_eligible_at = CASE
         WHEN bot_fallback_game_key = $2
          AND bot_fallback_difficulty = $3
          AND bot_fallback_eligible_at IS NOT NULL
         THEN bot_fallback_eligible_at
         ELSE NOW() + ($4 * INTERVAL '1 millisecond')
       END,
       bot_fallback_game_key = $2,
       bot_fallback_difficulty = $3,
       updated_at = NOW()
     WHERE player_id = $1`,
    [playerId, normalizedGameKey, normalizedDifficulty, BOT_FALLBACK_MIN_WAIT_MS]
  );
}

async function clearBotFallbackEligibilityForPlayers(playerIds) {
  if (!pool) return;
  const uniqueIds = [...new Set((playerIds || []).filter(Boolean).map(String))];
  if (uniqueIds.length === 0) return;
  await pool.query(
    `UPDATE player_progress SET
       bot_fallback_game_key = NULL,
       bot_fallback_difficulty = NULL,
       bot_fallback_eligible_at = NULL,
       updated_at = NOW()
     WHERE player_id = ANY($1::text[])`,
    [uniqueIds]
  );
}

async function consumeBotFallbackEligibilityInTransaction(
  client,
  playerId,
  expectedGameKey,
  expectedDifficulty
) {
  const normalizedGameKey = expectedGameKey === "target_number_tournament"
    ? "target_number_tournament"
    : "target_number";
  const normalizedDifficulty = secureDifficulty(expectedDifficulty);
  const result = await client.query(
    `SELECT bot_fallback_game_key, bot_fallback_difficulty, bot_fallback_eligible_at
     FROM player_progress WHERE player_id = $1 FOR UPDATE`,
    [playerId]
  );
  const row = result.rows[0] || {};
  const eligibleAt = row.bot_fallback_eligible_at
    ? new Date(row.bot_fallback_eligible_at).getTime()
    : 0;
  if (
    row.bot_fallback_game_key !== normalizedGameKey ||
    row.bot_fallback_difficulty !== normalizedDifficulty ||
    eligibleAt <= 0 ||
    Date.now() < eligibleAt
  ) {
    const error = new Error("Bot eşleşmesi için önce gerçek oyuncu aranmalıdır.");
    error.statusCode = 409;
    error.publicCode = "BOT_FALLBACK_NOT_READY";
    throw error;
  }
  await client.query(
    `UPDATE player_progress SET
       bot_fallback_game_key = NULL,
       bot_fallback_difficulty = NULL,
       bot_fallback_eligible_at = NULL,
       updated_at = NOW()
     WHERE player_id = $1`,
    [playerId]
  );
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
    const monthKey = currentMonthKey();
    await client.query(
      `UPDATE player_scores
       SET general_score = LEAST(general_score + $2, 2000000000),
           updated_at = NOW()
       WHERE player_id = $1`,
      [playerId, generalDelta]
    );
    await client.query(
      `INSERT INTO player_monthly_scores
         (player_id, month_key, general_score, infinite_score, updated_at)
       VALUES ($1, $2, $3, 0, NOW())
       ON CONFLICT (player_id, month_key) DO UPDATE SET
         general_score = LEAST(
           player_monthly_scores.general_score + EXCLUDED.general_score,
           2000000000
         ),
         updated_at = NOW()`,
      [playerId, monthKey, generalDelta]
    );
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

async function readAuthoritativePlayerState(client, playerId) {
  const levelRewardSettlement = await settleLevelMilestoneRewardsInTransaction(client, playerId);
  const result = await client.query(
    `SELECT s.general_score, s.infinite_score,
            p.total_xp, p.infinite_run_score, p.infinite_next_stage,
            p.diamond_balance, p.level_reward_claimed_through,
            p.tournament_stage, p.tournament_rights,
            p.tournament_bank, p.tournament_completed,
            p.hundred_active, p.hundred_stage,
            p.game_rights, p.game_rights_refill_at,
            pl.username, pl.country, pl.username_user_set,
            pl.username_change_count, pl.username_last_changed_at,
            pl.updated_at AS profile_updated_at
     FROM player_scores s
     JOIN player_progress p ON p.player_id = s.player_id
     JOIN players pl ON pl.player_id = s.player_id
     WHERE s.player_id = $1`,
    [playerId]
  );
  const row = result.rows[0] || {};
  const gameRights = await normalizeGameRightsInTransaction(client, playerId);
  return {
    generalScore: Number(row.general_score || 0),
    infiniteScore: Number(row.infinite_score || 0),
    totalXp: Number(row.total_xp || 0),
    diamondBalance: Math.max(0, Number(row.diamond_balance || 0)),
    levelRewardClaimedThrough: Math.max(
      0,
      Math.min(1000, Number(row.level_reward_claimed_through || 0))
    ),
    levelRewardSettlement,
    runScore: Number(row.infinite_run_score || 0),
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
      currentStage: Math.max(1, Math.min(Number(row.tournament_stage || 1), 12)),
      remainingRights: Math.max(0, Math.min(Number(row.tournament_rights ?? 3), 3)),
      totalScore: Math.max(0, Number(row.tournament_bank || 0)),
      completed: row.tournament_completed === true,
    },
    hundred: {
      active: row.hundred_active === true,
      stage: Math.max(0, Math.min(Number(row.hundred_stage || 0), 12)),
    },
    gameRights,
  };
}

async function applyTournamentOutcomeInTransaction(client, playerId, won, requestedStage) {
  await ensureAuthenticatedPlayer(client, playerId);
  const locked = await client.query(
    `SELECT tournament_stage, tournament_rights, tournament_bank, tournament_completed
     FROM player_progress WHERE player_id = $1 FOR UPDATE`,
    [playerId]
  );
  const row = locked.rows[0] || {};
  const currentStage = Math.max(1, Math.min(Number(row.tournament_stage || 1), 12));
  const remainingRights = Math.max(0, Math.min(Number(row.tournament_rights ?? 3), 3));
  const bank = Math.max(0, Number(row.tournament_bank || 0));
  const completedBefore = row.tournament_completed === true;
  const stage = Math.max(1, Math.min(Number(requestedStage || currentStage), 12));
  if (stage !== currentStage || completedBefore || remainingRights <= 0) {
    const error = new Error("Turnuva aşaması sunucu ilerlemesiyle uyuşmuyor.");
    error.statusCode = 409;
    error.publicCode = "TOURNAMENT_STATE_MISMATCH";
    throw error;
  }

  let nextStage = currentStage;
  let nextRights = remainingRights;
  let nextBank = bank;
  let completed = false;
  let awardedScore = 0;
  let xpDelta = 0;

  if (won === true) {
    const stageReward = tournamentStageReward(currentStage);
    nextBank = Math.min(2_000_000_000, bank + stageReward);
    xpDelta = stageReward;
    completed = currentStage >= 12;
    nextStage = completed ? 12 : currentStage + 1;
    if (completed) awardedScore = nextBank;
  } else if (won === false) {
    nextRights = Math.max(0, remainingRights - 1);
    if (nextRights === 0) {
      awardedScore = bank;
      nextStage = 1;
      nextRights = 3;
      nextBank = 0;
      completed = false;
    }
  }

  await client.query(
    `UPDATE player_progress SET
       tournament_stage = $2,
       tournament_rights = $3,
       tournament_bank = $4,
       tournament_completed = $5,
       total_xp = LEAST(total_xp + $6, 2000000000),
       updated_at = NOW()
     WHERE player_id = $1`,
    [playerId, nextStage, nextRights, nextBank, completed, xpDelta]
  );

  if (awardedScore > 0) {
    const monthKey = currentMonthKey();
    await client.query(
      `UPDATE player_scores SET
         general_score = LEAST(general_score + $2, 2000000000),
         updated_at = NOW()
       WHERE player_id = $1`,
      [playerId, awardedScore]
    );
    await client.query(
      `INSERT INTO player_monthly_scores
       (player_id, month_key, general_score, infinite_score, updated_at)
       VALUES ($1, $2, $3, 0, NOW())
       ON CONFLICT (player_id, month_key) DO UPDATE SET
         general_score = LEAST(player_monthly_scores.general_score + EXCLUDED.general_score, 2000000000),
         updated_at = NOW()`,
      [playerId, monthKey, awardedScore]
    );
  }

  const state = await readAuthoritativePlayerState(client, playerId);
  return {
    ...state,
    generalDelta: awardedScore,
    infiniteDelta: 0,
    xpDelta,
    awardedScore,
    won,
    tournament: {
      ...state.tournament,
      awardedScore,
    },
  };
}

async function applyTournamentOutcome(playerId, won, requestedStage) {
  if (!pool || !playerId) return null;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await applyTournamentOutcomeInTransaction(client, playerId, won, requestedStage);
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
    const monthKey = currentMonthKey();
    await client.query(
      `UPDATE player_scores SET
         general_score = LEAST(general_score + $2, 2000000000), updated_at = NOW()
       WHERE player_id = $1`,
      [playerId, safeGeneral]
    );
    await client.query(
      `INSERT INTO player_monthly_scores
       (player_id, month_key, general_score, infinite_score, updated_at)
       VALUES ($1, $2, $3, 0, NOW())
       ON CONFLICT (player_id, month_key) DO UPDATE SET
         general_score = LEAST(player_monthly_scores.general_score + EXCLUDED.general_score, 2000000000),
         updated_at = NOW()`,
      [playerId, monthKey, safeGeneral]
    );
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

async function completeHundredStageInTransaction(client, playerId, stageValue) {
  await ensureAuthenticatedPlayer(client, playerId);
  const locked = await client.query(
    `SELECT hundred_active, hundred_stage
     FROM player_progress WHERE player_id = $1 FOR UPDATE`,
    [playerId]
  );
  const row = locked.rows[0] || {};
  const currentStage = Math.max(1, Math.min(Number(row.hundred_stage || 1), 12));
  const stage = Math.max(1, Math.min(Number(stageValue || currentStage), 12));
  if (row.hundred_active !== true || stage !== currentStage) {
    const error = new Error("100 kişilik oyun aşaması sunucu durumuyla uyuşmuyor.");
    error.statusCode = 409;
    error.publicCode = "HUNDRED_STATE_MISMATCH";
    throw error;
  }

  let generalDelta = 0;
  let xpDelta = 0;
  let nextStage = currentStage + 1;
  let runCompleted = false;
  if (currentStage >= 12) {
    generalDelta = 240;
    xpDelta = 480;
    nextStage = 0;
    runCompleted = true;
    await addPositiveGeneralAndXpInTransaction(client, playerId, generalDelta, xpDelta);
  }

  await client.query(
    `UPDATE player_progress SET
       hundred_active = $2,
       hundred_stage = $3,
       updated_at = NOW()
     WHERE player_id = $1`,
    [playerId, !runCompleted, nextStage]
  );
  const state = await readAuthoritativePlayerState(client, playerId);
  return {
    ...state,
    generalDelta,
    infiniteDelta: 0,
    xpDelta,
    awardedScore: generalDelta,
    won: runCompleted ? true : null,
    hundredStage: nextStage,
    hundredRunCompleted: runCompleted,
  };
}

async function forfeitHundredRunInTransaction(client, playerId) {
  await ensureAuthenticatedPlayer(client, playerId);
  const locked = await client.query(
    `SELECT hundred_active, hundred_stage
     FROM player_progress WHERE player_id = $1 FOR UPDATE`,
    [playerId]
  );
  const row = locked.rows[0] || {};
  if (row.hundred_active !== true) {
    const state = await readAuthoritativePlayerState(client, playerId);
    return {
      ...state,
      generalDelta: 0,
      infiniteDelta: 0,
      xpDelta: 0,
      awardedScore: 0,
      won: false,
      hundredStage: 0,
      hundredRunCompleted: true,
    };
  }
  const stage = Math.max(1, Math.min(Number(row.hundred_stage || 1), 12));
  const activeChallenge = await client.query(
    `SELECT challenge_id FROM secure_game_challenges
     WHERE player_id = $1 AND mode = 'hundred' AND completed_at IS NULL
     ORDER BY created_at DESC LIMIT 1`,
    [playerId]
  );
  await recordTaskEventInTransaction(client, {
    playerId,
    sourceKey: activeChallenge.rows[0]?.challenge_id
      ? `challenge:${activeChallenge.rows[0].challenge_id}`
      : `hundred-forfeit:${stage}:${Date.now()}`,
    eventType: "game",
    gameKey: "target_number",
    multiplayer: true,
    won: false,
  });
  const generalDelta = stage * 10;
  const xpDelta = stage * 20;
  await addPositiveGeneralAndXpInTransaction(client, playerId, generalDelta, xpDelta);
  await client.query(
    `UPDATE player_progress SET
       hundred_active = FALSE,
       hundred_stage = 0,
       updated_at = NOW()
     WHERE player_id = $1`,
    [playerId]
  );
  await client.query(
    `UPDATE secure_game_challenges SET
       completed_at = COALESCE(completed_at, NOW()),
       result = CASE WHEN completed_at IS NULL
         THEN '{"status":"forfeit"}'::jsonb ELSE result END
     WHERE player_id = $1 AND mode = 'hundred' AND completed_at IS NULL`,
    [playerId]
  );
  const state = await readAuthoritativePlayerState(client, playerId);
  return {
    ...state,
    generalDelta,
    infiniteDelta: 0,
    xpDelta,
    awardedScore: generalDelta,
    won: false,
    hundredStage: 0,
    hundredRunCompleted: true,
  };
}

function secureRandomInt(minInclusive, maxExclusive) {
  if (maxExclusive <= minInclusive) return minInclusive;
  return crypto.randomInt(minInclusive, maxExclusive);
}

const BOT_AVERAGE_REQUIRED_TWO_PLAYER_FINISHES = 5;
const BOT_CALIBRATION_MIN_FINISH_MS = 90 * 1000;
const BOT_CALIBRATION_MAX_FINISH_MS = 119_000;
const BOT_AVERAGE_VARIANCE_MS = 4 * 1000;
const BOT_MIN_FINISH_MS = 1_000;
const BOT_MAX_FINISH_MS = 119_000;

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

async function readTwoPlayerFinishProfileInTransaction(client, playerId) {
  const result = await client.query(
    `SELECT two_player_finish_count, two_player_finish_total_ms
     FROM player_progress
     WHERE player_id = $1
     FOR UPDATE`,
    [playerId]
  );
  const row = result.rows[0] || {};
  return normalizeTwoPlayerFinishProfile({
    finishCount: row.two_player_finish_count,
    finishTotalMs: row.two_player_finish_total_ms,
  });
}

async function recordTwoPlayerFinishTimeInTransaction(client, playerId, elapsedMs) {
  const parsedElapsedMs = Number(elapsedMs);
  if (!Number.isFinite(parsedElapsedMs) || parsedElapsedMs <= 0) return;
  const safeElapsedMs = Math.max(
    1,
    Math.min(Math.floor(parsedElapsedMs), 2 * 60 * 1000)
  );
  await client.query(
    `UPDATE player_progress
     SET two_player_finish_count = LEAST(two_player_finish_count + 1, 2000000000),
         two_player_finish_total_ms = LEAST(
           two_player_finish_total_ms + $2::bigint,
           9223372036854775807::bigint
         ),
         updated_at = NOW()
     WHERE player_id = $1`,
    [playerId, safeElapsedMs]
  );
}

async function recordTwoPlayerFinishTime(playerId, elapsedMs) {
  if (!pool || !playerId) return;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await ensureAuthenticatedPlayer(client, playerId);
    await recordTwoPlayerFinishTimeInTransaction(client, playerId, elapsedMs);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

function createSecureTwoPlayerBotPlan(difficulty, finishProfile = {}) {
  const cannotFinishBps = difficulty === "Hard" ? 2530 : 1070;
  const roll = secureRandomInt(0, 10000);
  if (roll < 560) {
    return { finishMs: null, leaveMs: secureRandomInt(0, 120) * 1000 };
  }
  if (roll < 560 + cannotFinishBps) {
    return { finishMs: null, leaveMs: null };
  }

  const profile = normalizeTwoPlayerFinishProfile(finishProfile);
  if (
    profile.finishCount < BOT_AVERAGE_REQUIRED_TWO_PLAYER_FINISHES ||
    profile.averageFinishMs === null
  ) {
    return {
      finishMs: secureRandomInt(
        BOT_CALIBRATION_MIN_FINISH_MS,
        BOT_CALIBRATION_MAX_FINISH_MS + 1
      ),
      leaveMs: null,
    };
  }

  const averageFinishMs = Math.max(
    BOT_MIN_FINISH_MS,
    Math.min(profile.averageFinishMs, BOT_MAX_FINISH_MS)
  );
  const minimumFinishMs = Math.max(
    BOT_MIN_FINISH_MS,
    averageFinishMs - BOT_AVERAGE_VARIANCE_MS
  );
  const maximumFinishMs = Math.min(
    BOT_MAX_FINISH_MS,
    averageFinishMs + BOT_AVERAGE_VARIANCE_MS
  );

  return {
    finishMs: secureRandomInt(minimumFinishMs, maximumFinishMs + 1),
    leaveMs: null,
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

async function settleBotChallengeAsForfeitInTransaction(client, challenge, playerId) {
  const elapsedServerMs = Math.max(0, Date.now() - new Date(challenge.created_at).getTime());
  let response;
  if (challenge.mode === "tournament_bot") {
    const tournamentResult = await applyTournamentOutcomeInTransaction(
      client, playerId, false, Number(challenge.stage)
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
    const monthKey = currentMonthKey();
    await client.query(
      `UPDATE player_scores SET general_score = GREATEST(0, LEAST(general_score + $2, 2000000000)),
         updated_at = NOW() WHERE player_id = $1`,
      [playerId, rewards.generalDelta]
    );
    await client.query(
      `INSERT INTO player_monthly_scores (player_id, month_key, general_score, infinite_score, updated_at)
       VALUES ($1, $2, GREATEST($3, 0), 0, NOW())
       ON CONFLICT (player_id, month_key) DO UPDATE SET
         general_score = GREATEST(0, LEAST(player_monthly_scores.general_score + $3, 2000000000)),
         updated_at = NOW()`,
      [playerId, monthKey, rewards.generalDelta]
    );
    const state = await readAuthoritativePlayerState(client, playerId);
    response = {
      ok: true,
      ...rewards,
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
    gameKey: "target_number",
    multiplayer: true,
    won: false,
  });
  await client.query(
    `UPDATE secure_game_challenges SET completed_at = NOW(), result = $2::jsonb
     WHERE challenge_id = $1 AND completed_at IS NULL`,
    [challenge.challenge_id, JSON.stringify({ status: "completed", response })]
  );
  return response;
}

function validateChallengeAnswer(puzzle, numberSlotsRaw, operatorsRaw) {
  const numbers = Array.isArray(puzzle?.numbers) ? puzzle.numbers.map(Number) : [];
  const numberSlots = Array.isArray(numberSlotsRaw) ? numberSlotsRaw.map(Number) : [];
  const operators = Array.isArray(operatorsRaw) ? operatorsRaw.map(String) : [];
  if (numberSlots.length !== numbers.length || operators.length !== numbers.length - 1) return false;
  const sorted = [...numberSlots].sort((a, b) => a - b);
  if (!sorted.every((value, index) => Number.isInteger(value) && value === index)) return false;
  const orderedNumbers = numberSlots.map((index) => numbers[index]);
  const result = evaluateExpression(orderedNumbers, operators);
  return result !== null && Math.abs(result - Number(puzzle.target)) < 0.0001;
}

async function ensureAuthenticatedPlayer(client, playerId) {
  const fallbackUsername = `Oyuncu_${String(playerId).slice(-8)}`;
  await client.query(
    `INSERT INTO players (player_id, username, country, created_at, updated_at)
     VALUES ($1, $2, 'TR', NOW(), NOW())
     ON CONFLICT (player_id) DO NOTHING`,
    [playerId, fallbackUsername]
  );
  await ensurePlayerScoreRow(client, playerId);
  await client.query(
    `INSERT INTO player_progress (player_id, total_xp, updated_at)
     VALUES ($1, 0, NOW())
     ON CONFLICT (player_id) DO NOTHING`,
    [playerId]
  );
}


async function applyAuthoritativeScoreDelta(playerId, generalDelta, infiniteDelta, xpDelta) {
  if (!pool || !playerId) return null;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await ensureAuthenticatedPlayer(client, playerId);
    const monthKey = currentMonthKey();
    await client.query(
      `UPDATE player_scores SET
         general_score = GREATEST(0, LEAST(general_score + $2, 2000000000)),
         infinite_score = GREATEST(0, LEAST(infinite_score + $3, 2000000000)),
         updated_at = NOW()
       WHERE player_id = $1`,
      [playerId, generalDelta, infiniteDelta]
    );
    await client.query(
      `INSERT INTO player_monthly_scores (player_id, month_key, general_score, infinite_score, updated_at)
       VALUES ($1, $2, GREATEST($3, 0), GREATEST($4, 0), NOW())
       ON CONFLICT (player_id, month_key) DO UPDATE SET
         general_score = GREATEST(0, LEAST(player_monthly_scores.general_score + $3, 2000000000)),
         infinite_score = GREATEST(0, LEAST(player_monthly_scores.infinite_score + $4, 2000000000)),
         updated_at = NOW()`,
      [playerId, monthKey, generalDelta, infiniteDelta]
    );
    await client.query(
      `UPDATE player_progress SET
         total_xp = GREATEST(0, LEAST(total_xp + $2, 2000000000)),
         updated_at = NOW()
       WHERE player_id = $1`,
      [playerId, xpDelta]
    );
    const state = await readAuthoritativePlayerState(client, playerId);
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

async function awardRealtimeRoom(room, winner, loser) {
  if (!room || room.awardedAt) return;
  room.awardedAt = Date.now();

  if (room.isFriend) {
    await Promise.all([
      winner ? recordTaskGameEvent(winner.playerId, `room:${room.roomId}`, "target_number", true, true) : null,
      loser ? recordTaskGameEvent(loser.playerId, `room:${room.roomId}`, "target_number", true, false) : null,
    ]);
    return;
  }

  if (room.gameKey === "target_number_tournament") {
    const [winnerState, loserState] = await Promise.all([
      winner ? applyTournamentOutcome(winner.playerId, true, winner.tournamentStage) : null,
      loser ? applyTournamentOutcome(loser.playerId, false, loser.tournamentStage) : null,
    ]);
    const winnerSocket = winner?.socketId ? io.sockets.sockets.get(winner.socketId) : null;
    const loserSocket = loser?.socketId ? io.sockets.sockets.get(loser.socketId) : null;
    if (winnerSocket && winnerState) winnerSocket.emit("authoritative_tournament", winnerState);
    if (loserSocket && loserState) loserSocket.emit("authoritative_tournament", loserState);
    await Promise.all([
      winner ? recordTaskGameEvent(winner.playerId, `room:${room.roomId}`, "target_number", true, true) : null,
      loser ? recordTaskGameEvent(loser.playerId, `room:${room.roomId}`, "target_number", true, false) : null,
    ]);
    return;
  }

  if (room.gameKey !== "target_number") return;
  const reward = Math.max(minimumTwoPlayerStake(room.difficulty), Number(room.stakePoints || 0));
  const winnerXp = secureDifficulty(room.difficulty) === "Hard" ? 30 : 20;
  const [winnerState, loserState] = await Promise.all([
    winner ? applyAuthoritativeScoreDelta(winner.playerId, reward, 0, winnerXp) : null,
    loser ? applyAuthoritativeScoreDelta(loser.playerId, -reward, 0, 0) : null,
  ]);
  const winnerSocket = winner?.socketId ? io.sockets.sockets.get(winner.socketId) : null;
  const loserSocket = loser?.socketId ? io.sockets.sockets.get(loser.socketId) : null;
  if (winnerSocket && winnerState) winnerSocket.emit("authoritative_reward", winnerState);
  if (loserSocket && loserState) loserSocket.emit("authoritative_reward", loserState);
  if (winner?.elapsedMs != null) {
    try {
      // Gerçek oyunculu normal ikili maçta süre istemciden değil sunucu saatinden gelir.
      await recordTwoPlayerFinishTime(winner.playerId, winner.elapsedMs);
    } catch (error) {
      console.error("two-player finish average update error:", error);
    }
  }
  await Promise.all([
    winner ? recordTaskGameEvent(winner.playerId, `room:${room.roomId}`, "target_number", true, true) : null,
    loser ? recordTaskGameEvent(loser.playerId, `room:${room.roomId}`, "target_number", true, false) : null,
  ]);
}

app.post("/auth/play-games", async (req, res) => {
  const authCode = safeText(req.body.authCode, "", 4096);
  if (!authCode) {
    res.status(400).json({ ok: false, message: "Play Games yetkilendirme kodu gerekli." });
    return;
  }
  try {
    const playerId = await exchangePlayGamesAuthCode(authCode);
    if (pool) {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        await ensureAuthenticatedPlayer(client, playerId);
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

app.get("/player/state", requireAuth, async (req, res) => {
  if (!requireDatabase(res)) return;
  const playerId = req.auth.sub;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await ensureAuthenticatedPlayer(client, playerId);
    const activeHundred = await client.query(
      `SELECT hundred_active FROM player_progress WHERE player_id = $1 FOR UPDATE`,
      [playerId]
    );
    const shouldSettleAbandonedHundred = activeHundred.rows[0]?.hundred_active === true;
    const state = shouldSettleAbandonedHundred
      ? await forfeitHundredRunInTransaction(client, playerId)
      : await readAuthoritativePlayerState(client, playerId);
    await client.query("COMMIT");
    res.json({ ok: true, abandonedHundredSettled: shouldSettleAbandonedHundred, ...state });
  } catch (error) {
    await client.query("ROLLBACK");
    sendLeaderboardError(res, error, "Oyuncu durumu yüklenemedi.", "player state error:");
  } finally {
    client.release();
  }
});

app.post("/game/hundred/start", requireAuth, async (req, res) => {
  if (!requireDatabase(res)) return;
  const fresh = req.body.fresh === true;
  const challengeId = crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString("hex");
  const lifetimeMs = 2 * 60 * 1000;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await ensureAuthenticatedPlayer(client, req.auth.sub);
    if (fresh) {
      await client.query(
        `UPDATE player_progress SET hundred_active = TRUE, hundred_stage = 1, updated_at = NOW()
         WHERE player_id = $1`,
        [req.auth.sub]
      );
    }
    const locked = await client.query(
      `SELECT hundred_active, hundred_stage
       FROM player_progress WHERE player_id = $1 FOR UPDATE`,
      [req.auth.sub]
    );
    const progress = locked.rows[0] || {};
    if (progress.hundred_active !== true) {
      const error = new Error("100 kişilik oyun aktif değil.");
      error.statusCode = 409;
      throw error;
    }
    const stage = Math.max(1, Math.min(Number(progress.hundred_stage || 1), 12));
    const difficulty = hundredDifficultyForStage(stage);
    const puzzle = generateSecurePuzzle(difficulty);
    await client.query(
      `UPDATE secure_game_challenges
       SET completed_at = NOW(), result = '{"status":"superseded"}'::jsonb
       WHERE player_id = $1 AND mode = 'hundred' AND completed_at IS NULL`,
      [req.auth.sub]
    );
    await client.query(
      `INSERT INTO secure_game_challenges
       (challenge_id, player_id, mode, difficulty, stage, puzzle, expires_at)
       VALUES ($1, $2, 'hundred', $3, $4, $5::jsonb,
               NOW() + ($6 * INTERVAL '1 millisecond'))`,
      [challengeId, req.auth.sub, difficulty, stage, JSON.stringify(puzzle), lifetimeMs]
    );
    await client.query("COMMIT");
    res.json({
      ok: true,
      challengeId,
      mode: "hundred",
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
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const response = await forfeitHundredRunInTransaction(client, req.auth.sub);
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
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await ensureAuthenticatedPlayer(client, req.auth.sub);
    const state = await readAuthoritativePlayerState(client, req.auth.sub);
    await client.query("COMMIT");
    res.json({ ok: true, ...state });
  } catch (error) {
    await client.query("ROLLBACK");
    sendLeaderboardError(res, error, "Turnuva durumu alınamadı.", "tournament state error:");
  } finally {
    client.release();
  }
});

app.post("/game/tournament/reset", requireAuth, async (req, res) => {
  if (!requireDatabase(res)) return;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await ensureAuthenticatedPlayer(client, req.auth.sub);
    await client.query(
      `UPDATE player_progress SET
         tournament_stage = 1,
         tournament_rights = 3,
         tournament_bank = 0,
         tournament_completed = FALSE,
         updated_at = NOW()
       WHERE player_id = $1`,
      [req.auth.sub]
    );
    const state = await readAuthoritativePlayerState(client, req.auth.sub);
    await client.query("COMMIT");
    res.json({ ok: true, ...state, awardedScore: 0 });
  } catch (error) {
    await client.query("ROLLBACK");
    sendLeaderboardError(res, error, "Turnuva sıfırlanamadı.", "tournament reset error:");
  } finally {
    client.release();
  }
});

app.post("/game/bot/start", requireAuth, async (req, res) => {
  if (!requireDatabase(res)) return;
  const tournamentMode = req.body.mode === "tournament";
  const matchMode = safeText(req.body.matchMode, "quick", 32);
  const immediateBotMode = !tournamentMode && ["quick", "ready_room", "open_table"].includes(matchMode);
  const challengeId = crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString("hex");
  const lifetimeMs = 2 * 60 * 1000;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await ensureAuthenticatedPlayer(client, req.auth.sub);
    const requestedDifficulty = secureDifficulty(req.body.difficulty);
    if (!immediateBotMode) {
      await consumeBotFallbackEligibilityInTransaction(
        client,
        req.auth.sub,
        tournamentMode ? "target_number_tournament" : "target_number",
        requestedDifficulty
      );
    }

    let stakePoints = 0;
    if (!tournamentMode) {
      if (matchMode === "open_table") {
        const scoreResult = await client.query(
          `SELECT general_score FROM player_scores WHERE player_id = $1 FOR UPDATE`,
          [req.auth.sub]
        );
        const availableScore = Number(scoreResult.rows[0]?.general_score || 0);
        assertOpenTableStake(req.body.wagerPoints, availableScore, requestedDifficulty);
      }
      const consumed = await consumeGameRightInTransaction(
        client,
        req.auth.sub,
        requestedDifficulty,
        req.body.wagerPoints,
        matchMode === "quick"
      );
      stakePoints = consumed.stakePoints;
    }

    let stage = 1;
    let difficulty = requestedDifficulty;
    const challengeMode = tournamentMode ? "tournament_bot" : "two_player_bot";

    const activeResult = await client.query(
      `SELECT * FROM secure_game_challenges
       WHERE player_id = $1 AND mode = $2 AND completed_at IS NULL
       ORDER BY created_at ASC FOR UPDATE`,
      [req.auth.sub, challengeMode]
    );
    for (const activeChallenge of activeResult.rows) {
      await settleBotChallengeAsForfeitInTransaction(client, activeChallenge, req.auth.sub);
    }

    if (tournamentMode) {
      const progressResult = await client.query(
        `SELECT tournament_stage, tournament_rights, tournament_completed
         FROM player_progress WHERE player_id = $1 FOR UPDATE`,
        [req.auth.sub]
      );
      const progress = progressResult.rows[0] || {};
      if (progress.tournament_completed === true || Number(progress.tournament_rights || 0) <= 0) {
        const error = new Error("Turnuva şu anda başlatılamıyor.");
        error.statusCode = 409;
        throw error;
      }
      stage = Math.max(1, Math.min(Number(progress.tournament_stage || 1), 12));
      difficulty = stage <= 4 ? "Medium" : "Hard";
    }

    const puzzle = generateSecurePuzzle(difficulty);
    const finishProfile = await readTwoPlayerFinishProfileInTransaction(
      client,
      req.auth.sub
    );
    const plan = createSecureTwoPlayerBotPlan(difficulty, finishProfile);
    await client.query(
      `INSERT INTO secure_game_challenges
       (challenge_id, player_id, mode, difficulty, stage, puzzle, wager_points, expires_at, result)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7,
               NOW() + ($8 * INTERVAL '1 millisecond'), $9::jsonb)`,
      [challengeId, req.auth.sub, challengeMode, difficulty, stage,
       JSON.stringify(puzzle), stakePoints, lifetimeMs, JSON.stringify({ status: "active", plan, matchMode })]
    );
    const state = await readAuthoritativePlayerState(client, req.auth.sub);
    await client.query("COMMIT");
    res.json({
      ok: true,
      challengeId,
      mode: challengeMode,
      stage,
      puzzle,
      finishMs: plan.finishMs,
      leaveMs: plan.leaveMs,
      stakePoints,
      matchMode,
      tournament: state.tournament,
      expiresAtMillis: Date.now() + lifetimeMs,
    });
  } catch (error) {
    await client.query("ROLLBACK");
    sendLeaderboardError(res, error, "Bot eşleşmesi başlatılamadı.", "bot start error:");
  } finally {
    client.release();
  }
});

app.post("/game/challenges/start", requireAuth, async (req, res) => {
  if (!requireDatabase(res)) return;
  const mode = safeText(req.body.mode, "", 32);
  if (mode !== "infinite") {
    res.status(400).json({ ok: false, message: "Bu endpoint yalnızca sonsuz modu destekler." });
    return;
  }
  const requestedDifficulty = secureDifficulty(req.body.difficulty);
  const freshInfiniteRun = req.body.fresh === true;
  const challengeId = crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString("hex");
  // Sonsuz modda uygulama arka plana alındığında yerel sayaç duraklatıldığı için
  // challenge uzun ömürlü tutulur; puan yine yalnızca tek kullanımlık kayıt ve doğru çözümle alınır.
  const lifetimeMs = 7 * 24 * 60 * 60 * 1000;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await ensureAuthenticatedPlayer(client, req.auth.sub);

    let stage = 1;
    let difficulty = requestedDifficulty;
    if (mode === "infinite") {
      if (freshInfiniteRun) {
        await client.query(
          `UPDATE player_progress
           SET infinite_run_score = 0, infinite_next_stage = 1, updated_at = NOW()
           WHERE player_id = $1`,
          [req.auth.sub]
        );
      }
      const progressResult = await client.query(
        `SELECT infinite_next_stage
         FROM player_progress
         WHERE player_id = $1
         FOR UPDATE`,
        [req.auth.sub]
      );
      stage = Math.max(1, Math.min(Number(progressResult.rows[0]?.infinite_next_stage || 1), 1000));
      difficulty = stage <= 5 ? "Medium" : "Hard";
    }

    const puzzle = generateSecurePuzzle(difficulty);
    await client.query(
      `UPDATE secure_game_challenges
       SET completed_at = NOW(), result = '{"status":"superseded"}'::jsonb
       WHERE player_id = $1 AND mode = $2 AND completed_at IS NULL`,
      [req.auth.sub, mode]
    );
    await client.query(
      `INSERT INTO secure_game_challenges
       (challenge_id, player_id, mode, difficulty, stage, puzzle, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb, NOW() + ($7 * INTERVAL '1 millisecond'))`,
      [challengeId, req.auth.sub, mode, difficulty, stage, JSON.stringify(puzzle), lifetimeMs]
    );
    await client.query("COMMIT");
    res.json({
      ok: true,
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

app.post("/game/challenges/complete", requireAuth, async (req, res) => {
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
    if (challenge.completed_at) {
      const previousResponse = challenge.result?.response;
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
    if (challenge.mode === "hundred" && elapsedServerMs > 90 * 1000) {
      const error = new Error("100 kişilik oyun aşamasının süresi doldu.");
      error.statusCode = 409;
      error.publicCode = "HUNDRED_STAGE_EXPIRED";
      throw error;
    }
    if (!validateChallengeAnswer(challenge.puzzle, req.body.numberSlots, req.body.operators)) {
      const error = new Error("İşlem sonucu sunucuda doğrulanamadı."); error.statusCode = 422; throw error;
    }
    if (challenge.mode === "two_player_bot") {
      // Yalnızca sunucuda doğrulanmış normal ikili oyun çözümleri ortalamaya eklenir.
      await recordTwoPlayerFinishTimeInTransaction(
        client,
        req.auth.sub,
        elapsedServerMs
      );
    }
    let won = null;
    let outcomeReason = null;
    let rewards = challengeRewards(challenge.mode, challenge.stage);
    if (challenge.mode === "two_player_bot" || challenge.mode === "tournament_bot") {
      const outcome = botOutcomeForElapsed(challenge.result?.plan || {}, elapsedServerMs, true);
      won = outcome.won;
      outcomeReason = outcome.reason;
      rewards = twoPlayerBotRewards(challenge.difficulty, won === true, challenge.wager_points);
    }

    if (challenge.mode === "hundred") {
      const hundredResult = await completeHundredStageInTransaction(
        client,
        req.auth.sub,
        Number(challenge.stage)
      );
      await recordTaskEventInTransaction(client, {
        playerId: req.auth.sub,
        sourceKey: `challenge:${challengeId}`,
        eventType: "game",
        gameKey: "target_number",
        multiplayer: true,
        won: true,
      });
      const response = {
        ok: true,
        ...hundredResult,
        runScore: hundredResult.runScore || 0,
        elapsedServerMs,
      };
      await client.query(
        `UPDATE secure_game_challenges SET completed_at = NOW(), result = $2::jsonb WHERE challenge_id = $1`,
        [challengeId, JSON.stringify({ status: "completed", response })]
      );
      await client.query("COMMIT");
      res.json(response);
      return;
    }

    if (challenge.mode === "tournament_bot") {
      const tournamentResult = await applyTournamentOutcomeInTransaction(
        client,
        req.auth.sub,
        won,
        Number(challenge.stage)
      );
      await recordTaskEventInTransaction(client, {
        playerId: req.auth.sub,
        sourceKey: `challenge:${challengeId}`,
        eventType: "game",
        gameKey: "target_number",
        multiplayer: true,
        won: won === true,
      });
      const response = {
        ok: true,
        ...tournamentResult,
        runScore: tournamentResult.runScore || 0,
        won,
        outcomeReason,
        elapsedServerMs,
      };
      await client.query(
        `UPDATE secure_game_challenges SET completed_at = NOW(), result = $2::jsonb WHERE challenge_id = $1`,
        [challengeId, JSON.stringify({ status: "completed", response })]
      );
      await client.query("COMMIT");
      res.json(response);
      return;
    }

    const monthKey = currentMonthKey();
    await ensureAuthenticatedPlayer(client, req.auth.sub);

    let infiniteRunScore = 0;
    if (challenge.mode === "infinite") {
      const progressUpdate = await client.query(
        `UPDATE player_progress
         SET total_xp = LEAST(total_xp + $2, 2000000000),
             infinite_run_score = LEAST(infinite_run_score + $3, 2000000000),
             infinite_next_stage = GREATEST(infinite_next_stage, $4 + 1),
             updated_at = NOW()
         WHERE player_id = $1
         RETURNING infinite_run_score`,
        [req.auth.sub, rewards.xpDelta, rewards.infiniteDelta, Number(challenge.stage)]
      );
      infiniteRunScore = Number(progressUpdate.rows[0]?.infinite_run_score || 0);
      await client.query(
        `UPDATE player_scores
         SET general_score = LEAST(general_score + $2, 2000000000),
             infinite_score = GREATEST(infinite_score, $3),
             updated_at = NOW()
         WHERE player_id = $1`,
        [req.auth.sub, rewards.generalDelta, infiniteRunScore]
      );
      await client.query(
        `INSERT INTO player_monthly_scores (player_id, month_key, general_score, infinite_score, updated_at)
         VALUES ($1, $2, $3, $4, NOW())
         ON CONFLICT (player_id, month_key) DO UPDATE SET
           general_score = LEAST(player_monthly_scores.general_score + EXCLUDED.general_score, 2000000000),
           infinite_score = GREATEST(player_monthly_scores.infinite_score, EXCLUDED.infinite_score),
           updated_at = NOW()`,
        [req.auth.sub, monthKey, rewards.generalDelta, infiniteRunScore]
      );
    } else {
      await client.query(
        `UPDATE player_scores
         SET general_score = GREATEST(0, LEAST(general_score + $2, 2000000000)),
             updated_at = NOW()
         WHERE player_id = $1`,
        [req.auth.sub, rewards.generalDelta]
      );
      await client.query(
        `INSERT INTO player_monthly_scores (player_id, month_key, general_score, infinite_score, updated_at)
         VALUES ($1, $2, GREATEST($3, 0), 0, NOW())
         ON CONFLICT (player_id, month_key) DO UPDATE SET
           general_score = GREATEST(0, LEAST(player_monthly_scores.general_score + $3, 2000000000)),
           updated_at = NOW()`,
        [req.auth.sub, monthKey, rewards.generalDelta]
      );
      await client.query(
        `UPDATE player_progress
         SET total_xp = LEAST(total_xp + $2, 2000000000), updated_at = NOW()
         WHERE player_id = $1`,
        [req.auth.sub, rewards.xpDelta]
      );
    }

    if (challenge.mode === "two_player_bot") {
      await recordTaskEventInTransaction(client, {
        playerId: req.auth.sub,
        sourceKey: `challenge:${challengeId}`,
        eventType: "game",
        gameKey: "target_number",
        multiplayer: true,
        won: won === true,
      });
    }
    const state = await readAuthoritativePlayerState(client, req.auth.sub);
    const response = {
      ok: true,
      ...rewards,
      ...state,
      runScore: Number(state.runScore || infiniteRunScore || 0),
      won,
      outcomeReason,
      elapsedServerMs,
    };
    await client.query(
      `UPDATE secure_game_challenges SET completed_at = NOW(), result = $2::jsonb WHERE challenge_id = $1`,
      [challengeId, JSON.stringify({ status: "completed", response })]
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





app.post("/game/bot/resolve", requireAuth, async (req, res) => {
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
    if (challenge.completed_at) {
      const previousResponse = challenge.result?.response;
      if (previousResponse) {
        await client.query("COMMIT");
        res.json(previousResponse);
        return;
      }
      const error = new Error("Bu bot eşleşmesi daha önce sonuçlandı."); error.statusCode = 409; throw error;
    }
    const elapsedServerMs = Date.now() - new Date(challenge.created_at).getTime();
    const outcome = botOutcomeForElapsed(challenge.result?.plan || {}, elapsedServerMs, false);
    if (!outcome.resolvable) {
      const error = new Error("Bot eşleşmesi henüz sonuçlanmadı."); error.statusCode = 409; throw error;
    }

    let response;
    if (challenge.mode === "tournament_bot") {
      const tournamentResult = await applyTournamentOutcomeInTransaction(
        client, req.auth.sub, outcome.won, Number(challenge.stage)
      );
      response = {
        ok: true,
        ...tournamentResult,
        runScore: tournamentResult.runScore || 0,
        won: outcome.won,
        outcomeReason: outcome.reason,
        elapsedServerMs,
      };
    } else {
      const rewards = twoPlayerBotRewards(challenge.difficulty, outcome.won === true, challenge.wager_points);
      await ensureAuthenticatedPlayer(client, req.auth.sub);
      const monthKey = currentMonthKey();
      await client.query(
        `UPDATE player_scores
         SET general_score = GREATEST(0, LEAST(general_score + $2, 2000000000)),
             updated_at = NOW()
         WHERE player_id = $1`,
        [req.auth.sub, rewards.generalDelta]
      );
      await client.query(
        `INSERT INTO player_monthly_scores (player_id, month_key, general_score, infinite_score, updated_at)
         VALUES ($1, $2, GREATEST($3, 0), 0, NOW())
         ON CONFLICT (player_id, month_key) DO UPDATE SET
           general_score = GREATEST(0, LEAST(player_monthly_scores.general_score + $3, 2000000000)),
           updated_at = NOW()`,
        [req.auth.sub, monthKey, rewards.generalDelta]
      );
      await client.query(
        `UPDATE player_progress
         SET total_xp = LEAST(total_xp + $2, 2000000000), updated_at = NOW()
         WHERE player_id = $1`,
        [req.auth.sub, rewards.xpDelta]
      );
      const state = await readAuthoritativePlayerState(client, req.auth.sub);
      response = {
        ok: true,
        ...rewards,
        ...state,
        won: outcome.won,
        outcomeReason: outcome.reason,
        elapsedServerMs,
      };
    }

    await recordTaskEventInTransaction(client, {
      playerId: req.auth.sub,
      sourceKey: `challenge:${challengeId}`,
      eventType: "game",
      gameKey: "target_number",
      multiplayer: true,
      won: outcome.won === true,
    });

    await client.query(
      `UPDATE secure_game_challenges
       SET completed_at = NOW(), result = $2::jsonb
       WHERE challenge_id = $1`,
      [challengeId, JSON.stringify({ status: "completed", response })]
    );
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
    if (challenge.completed_at && challenge.result?.response) {
      await client.query("COMMIT");
      res.json(challenge.result.response);
      return;
    }
    const elapsedServerMs = Math.max(0, Date.now() - new Date(challenge.created_at).getTime());
    let response;
    if (challenge.mode === "tournament_bot") {
      const tournamentResult = await applyTournamentOutcomeInTransaction(
        client, req.auth.sub, false, Number(challenge.stage)
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
      await ensureAuthenticatedPlayer(client, req.auth.sub);
      const monthKey = currentMonthKey();
      await client.query(
        `UPDATE player_scores SET
           general_score = GREATEST(0, LEAST(general_score + $2, 2000000000)), updated_at = NOW()
         WHERE player_id = $1`,
        [req.auth.sub, rewards.generalDelta]
      );
      await client.query(
        `INSERT INTO player_monthly_scores
         (player_id, month_key, general_score, infinite_score, updated_at)
         VALUES ($1, $2, GREATEST($3, 0), 0, NOW())
         ON CONFLICT (player_id, month_key) DO UPDATE SET
           general_score = GREATEST(0, LEAST(player_monthly_scores.general_score + $3, 2000000000)),
           updated_at = NOW()`,
        [req.auth.sub, monthKey, rewards.generalDelta]
      );
      const state = await readAuthoritativePlayerState(client, req.auth.sub);
      response = {
        ok: true,
        ...rewards,
        ...state,
        won: false,
        outcomeReason: "player_forfeit",
        elapsedServerMs,
      };
    }
    await recordTaskEventInTransaction(client, {
      playerId: req.auth.sub,
      sourceKey: `challenge:${challengeId}`,
      eventType: "game",
      gameKey: "target_number",
      multiplayer: true,
      won: false,
    });
    await client.query(
      `UPDATE secure_game_challenges SET completed_at = NOW(), result = $2::jsonb WHERE challenge_id = $1`,
      [challengeId, JSON.stringify({ status: "completed", response })]
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
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await ensureAuthenticatedPlayer(client, req.auth.sub);
    const taskCenter = await readTaskCenterState(client, req.auth.sub);
    const state = await readAuthoritativePlayerState(client, req.auth.sub);
    await client.query("COMMIT");
    res.json({ ok: true, taskCenter, ...state });
  } catch (error) {
    await client.query("ROLLBACK");
    sendLeaderboardError(res, error, "Görevler yüklenemedi.", "task state error:");
  } finally {
    client.release();
  }
});

app.post("/tasks/login", requireAuth, async (req, res) => {
  if (!requireDatabase(res)) return;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await ensureAuthenticatedPlayer(client, req.auth.sub);
    const daily = taskPeriodInfo("daily");
    await recordTaskEventInTransaction(client, {
      playerId: req.auth.sub,
      sourceKey: `login:${daily.key}`,
      eventType: "login",
    });
    const taskCenter = await readTaskCenterState(client, req.auth.sub);
    const state = await readAuthoritativePlayerState(client, req.auth.sub);
    await client.query("COMMIT");
    res.json({ ok: true, taskCenter, ...state });
  } catch (error) {
    await client.query("ROLLBACK");
    sendLeaderboardError(res, error, "Günlük giriş görevi kaydedilemedi.", "task login error:");
  } finally {
    client.release();
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
    await ensureAuthenticatedPlayer(client, req.auth.sub);
    await claimTaskRewardInTransaction(client, req.auth.sub, periodType, taskCode);
    const taskCenter = await readTaskCenterState(client, req.auth.sub);
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

app.get("/leaderboard", requireAuth, async (req, res) => {
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

  const playerId = req.auth.sub;

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
const publicOpenTables = new Map();

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

function randomStakeForGroup(group, difficulty) {
  const minimum = Math.max(group.minScore, minimumTwoPlayerStake(difficulty));
  const maximum = group.maxScore == null
    ? Math.min(2_000_000_000, Math.max(minimum, minimum * secureRandomInt(2, 15)))
    : Math.max(minimum, group.maxScore);
  return randomStakeWithNaturalEnding(minimum, maximum);
}

function emitRoomLobbyChanged(difficulty) {
  io.emit("room_lobby_changed", {
    difficulty: difficulty ? secureDifficulty(difficulty) : "",
    changedAtMillis: Date.now(),
  });
}

function removeOpenTablesForSocket(socketId) {
  const changedDifficulties = new Set();
  for (const [listingId, table] of publicOpenTables.entries()) {
    if (table.ownerSocketId === socketId) {
      changedDifficulties.add(table.difficulty);
      publicOpenTables.delete(listingId);
    }
  }
  for (const difficulty of changedDifficulties) emitRoomLobbyChanged(difficulty);
}

function expireOldOpenTables() {
  const now = Date.now();
  const changedDifficulties = new Set();
  for (const [listingId, table] of publicOpenTables.entries()) {
    if (now - table.createdAt > 15 * 60 * 1000 || !io.sockets.sockets.get(table.ownerSocketId)) {
      changedDifficulties.add(table.difficulty);
      publicOpenTables.delete(listingId);
    }
  }
  for (const difficulty of changedDifficulties) emitRoomLobbyChanged(difficulty);
}

const PRIVATE_ROOM_TTL_MS = Number(
  process.env.PRIVATE_ROOM_TTL_MS ||
    15 * 60 * 1000
);

const ROOM_RECONNECT_TIMEOUT_MS = Number(
  process.env.ROOM_RECONNECT_TIMEOUT_MS ||
    60 * 1000
);

const REALTIME_MATCH_LIMIT_MS = Number(
  process.env.REALTIME_MATCH_LIMIT_MS ||
    2 * 60 * 1000
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
  const gameKey = String(
    value || "target_number"
  )
    .trim()
    .slice(0, 96);

  if (
    /^target_number_tournament(?:_stage_\d+)?$/i.test(
      gameKey
    )
  ) {
    return "target_number_tournament";
  }

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
}

function clearRoomTimeouts(room) {
  roomParticipants(room).forEach(
    clearParticipantTimeout
  );
  if (room?.deadlineHandle) {
    clearTimeout(room.deadlineHandle);
    room.deadlineHandle = null;
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
    if (!room.isFriend && room.gameKey === "target_number_tournament") {
      const states = await Promise.all(
        participants.map((participant) =>
          applyTournamentOutcome(participant.playerId, false, participant.tournamentStage)
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
    } else if (!room.isFriend && room.gameKey === "target_number") {
      const reward = Math.max(minimumTwoPlayerStake(room.difficulty), Number(room.stakePoints || 0));
      const states = await Promise.all(
        participants.map((participant) =>
          applyAuthoritativeScoreDelta(participant.playerId, -reward, 0, 0)
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
          "target_number",
          true,
          false
        )
      )
    );
    room.awardedAt = Date.now();
  } catch (error) {
    console.error("realtime game deadline reward error:", error);
  }

  console.log("Realtime match deadline reached:", roomId, room.gameKey);
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
  prepareMs = 0
) {
  const roomId =
    typeof crypto.randomUUID ===
    "function"
      ? crypto.randomUUID()
      : crypto
          .randomBytes(16)
          .toString("hex");

  const createdAt = Date.now();
  const safePrepareMs = Math.max(0, Math.min(Number(prepareMs || 0), 30_000));
  const room = {
    roomId,
    gameKey,
    difficulty,
    puzzle,
    stakePoints: Math.max(0, Math.floor(Number(stakePoints || 0))),
    matchMode: safeText(matchMode, "quick", 32),
    createdAt,
    startsAtMillis: createdAt + safePrepareMs,
    resolved: false,
    resolvedReason: null,
    resolvedAt: null,
    winnerPlayerId: null,
    loserPlayerId: null,
    isFriend: false,
    awardedAt: null,
    deadlineHandle: null,

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
        tournamentStage: tournamentStage == null
          ? null
          : Math.max(1, Math.min(Number(tournamentStage || 1), 12)),
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
        tournamentStage: opponentTournamentStage == null
          ? null
          : Math.max(1, Math.min(Number(opponentTournamentStage || 1), 12)),
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

  room.deadlineHandle = setTimeout(() => {
    resolveRoomByGameDeadline(room.roomId).catch((error) => {
      console.error("realtime deadline handler error:", error);
    });
  }, safePrepareMs + REALTIME_MATCH_LIMIT_MS);
  if (typeof room.deadlineHandle.unref === "function") {
    room.deadlineHandle.unref();
  }

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
        room.gameKey === "target_number" &&
        Date.now() < Number(room.startsAtMillis || 0);

      if (isFreePreparationExit) {
        const participants = roomParticipants(room);
        markRoomResolved(room, "prestart_cancelled", null, null);

        refundConsumedGameRights(participants.map((item) => item.playerId))
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


function authenticatedSocketPlayer(socket, payload, errorEvent = "match_error") {
  const session = verifySessionToken(payload?.authToken);
  if (!session) {
    socket.emit(errorEvent, {
      code: "AUTH_REQUIRED",
      message: "Play Games oturumu doğrulanamadı. Ana ekrana dönüp tekrar deneyin.",
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
    socket.emit(errorEvent, {
      code: "AUTH_REQUIRED",
      message: "Play Games oturumu doğrulanamadı. Ana ekrana dönüp tekrar deneyin.",
    });
    return null;
  }
  if (!pool) {
    socket.emit(errorEvent, { code: "DATABASE_REQUIRED", message: "Sunucu veritabanı hazır değil." });
    return null;
  }
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await ensureAuthenticatedPlayer(client, session.sub);
    const result = await client.query(
      `SELECT p.username, p.country, g.tournament_stage, s.general_score
       FROM players p
       JOIN player_progress g ON g.player_id = p.player_id
       JOIN player_scores s ON s.player_id = p.player_id
       WHERE p.player_id = $1`,
      [session.sub]
    );
    await client.query("COMMIT");
    const row = result.rows[0] || {};
    return {
      player: safePlayer({ id: session.sub, name: row.username, country: row.country }, session.sub),
      tournamentStage: Math.max(1, Math.min(Number(row.tournament_stage || 1), 12)),
      generalScore: Math.max(0, Number(row.general_score || 0)),
    };
  } catch (error) {
    await client.query("ROLLBACK");
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
  const difficulty = secureDifficulty(req.query.difficulty);
  try {
    const scoreResult = await pool.query(
      `SELECT general_score FROM player_scores WHERE player_id = $1`,
      [req.auth.sub]
    );
    const requesterScore = Math.max(0, Number(scoreResult.rows[0]?.general_score || 0));
    const realTables = [...publicOpenTables.values()]
      .filter((table) => table.player.id !== req.auth.sub && table.difficulty === difficulty)
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
        isBot: false,
      }));
      while (rooms.length < targetCount) {
        const botIdentity = createLobbyBotIdentity(usedLobbyBotNames);
        const stakePoints = randomStakeForGroup(group, difficulty);
        rooms.push({
          listingId: `bot:${group.id}:${crypto.randomBytes(8).toString("hex")}`,
          opponentName: botIdentity.name,
          opponentCountry: botIdentity.country,
          stakePoints,
          isBot: true,
        });
      }
      return {
        ...group,
        eligible: requesterScore >= group.minScore &&
          (group.maxScore == null || requesterScore <= group.maxScore),
        rooms,
      };
    });
    res.json({ ok: true, score: requesterScore, difficulty, groups });
  } catch (error) {
    sendLeaderboardError(res, error, "Oda listesi alınamadı.", "room lobby error:");
  }
});

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
    "create_open_table",
    async (payload = {}) => {
      expireOldOpenTables();
      const identity = await authenticatedSocketPlayerFromDatabase(socket, payload, "match_error");
      if (!identity) return;
      const difficulty = secureDifficulty(payload.difficulty);
      let stakePoints;
      try {
        assertOpenTableStake(payload.stakePoints, identity.generalScore, difficulty);
        stakePoints = normalizeRequestedStake(payload.stakePoints, difficulty, identity.generalScore, false);
      } catch (error) {
        socket.emit("match_error", { code: error.publicCode || "INVALID_WAGER", message: error.message });
        return;
      }

      removeFromAllQueues(socket.id, identity.player.id);
      removeOpenTablesForSocket(socket.id);
      leaveRoomAsCancel(socket);

      const listingId = `real:${crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(12).toString("hex")}`;
      publicOpenTables.set(listingId, {
        listingId,
        ownerSocketId: socket.id,
        player: identity.player,
        generalScore: identity.generalScore,
        difficulty,
        stakePoints,
        puzzle: generateSecurePuzzle(difficulty),
        createdAt: Date.now(),
      });
      emitRoomLobbyChanged(difficulty);
      socket.emit("open_table_created", { listingId, stakePoints, difficulty });
      socket.emit("waiting", { gameKey: "target_number", difficulty, matchMode: "open_table", stakePoints });
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
      const tournamentStage = gameKey === "target_number_tournament" ? identity.tournamentStage : null;
      const matchMode = gameKey === "target_number_tournament"
        ? "tournament"
        : safeText(payload.matchMode, "quick", 32);
      const listingId = safeText(payload.listingId, "", 128);
      const excludedOpponentMatchKey = safeText(payload.excludedOpponentMatchKey, "", 64);

      if (gameKey === "target_number_tournament") {
        difficulty = tournamentStage <= 4 ? "Medium" : "Hard";
      } else {
        difficulty = secureDifficulty(difficulty);
      }

      removeFromAllQueues(socket.id, player.id);
      removePrivateRoomsForSocket(socket.id, false);
      removeOpenTablesForSocket(socket.id);
      leaveRoomAsCancel(socket);

      if (gameKey === "target_number" && listingId.startsWith("real:")) {
        expireOldOpenTables();
        const table = publicOpenTables.get(listingId);
        const ownerSocket = table ? io.sockets.sockets.get(table.ownerSocketId) : null;
        if (!table || !ownerSocket || table.player.id === player.id) {
          socket.emit("match_error", { code: "ROOM_NOT_FOUND", message: "Seçilen masa artık uygun değil." });
          return;
        }
        if (identity.generalScore < table.stakePoints) {
          socket.emit("match_error", { code: "INSUFFICIENT_SCORE", message: "Bu masaya katılmak için yeterli puanınız yok." });
          return;
        }
        try {
          await consumeGameRightsForPlayers([player.id, table.player.id], table.difficulty, table.stakePoints);
        } catch (error) {
          const message = error.message || "İki oyunculu oyun hakkı doğrulanamadı.";
          socket.emit("match_error", { code: error.publicCode || "NO_GAME_RIGHT", message });
          ownerSocket.emit("match_error", { code: error.publicCode || "NO_GAME_RIGHT", message });
          publicOpenTables.delete(listingId);
          emitRoomLobbyChanged(table.difficulty);
          return;
        }
        publicOpenTables.delete(listingId);
        emitRoomLobbyChanged(table.difficulty);
        await clearBotFallbackEligibilityForPlayers([player.id, table.player.id]);
        const room = createRealtimeRoom(
          socket, player, ownerSocket, table.player, "target_number", table.difficulty,
          table.puzzle, null, null, table.stakePoints, "ready_room", TWO_PLAYER_PREPARE_MS
        );
        socket.emit("match_found", {
          roomId: room.roomId, opponent: { name: table.player.name, country: table.player.country, matchKey: matchmakingPlayerKey(table.player.id) },
          puzzle: table.puzzle, stakePoints: table.stakePoints, matchMode: "ready_room",
          startsAtMillis: room.startsAtMillis
        });
        ownerSocket.emit("match_found", {
          roomId: room.roomId, opponent: { name: player.name, country: player.country, matchKey: matchmakingPlayerKey(player.id) },
          puzzle: table.puzzle, stakePoints: table.stakePoints, matchMode: "open_table",
          startsAtMillis: room.startsAtMillis
        });
        return;
      }

      const puzzle = generateSecurePuzzle(difficulty);
      let requestedStake = 0;
      if (gameKey === "target_number") {
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
      const quickRange = gameKey === "target_number" && matchMode === "quick"
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
        if (gameKey === "target_number") {
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
        if (gameKey !== "target_number_tournament") {
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
          gameKey === "target_number" ? TWO_PLAYER_PREPARE_MS : 0
        );
        socket.emit("match_found", {
          roomId: room.roomId, opponent: { name: opponent.player.name, country: opponent.player.country, matchKey: matchmakingPlayerKey(opponent.player.id) },
          puzzle: selectedPuzzle, stakePoints: selectedStake, matchMode,
          startsAtMillis: room.startsAtMillis
        });
        opponentSocket.emit("match_found", {
          roomId: room.roomId, opponent: { name: player.name, country: player.country, matchKey: matchmakingPlayerKey(player.id) },
          puzzle: selectedPuzzle, stakePoints: selectedStake, matchMode: opponent.matchMode || matchMode,
          startsAtMillis: room.startsAtMillis
        });
        console.log("Match found:", room.roomId, key, "stake:", selectedStake);
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
    (payload = {}) => {
      const roomId = String(
        payload.roomId || ""
      ).trim();

      const player = authenticatedSocketPlayer(socket, payload, "resume_error");
      if (!player) return;

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
            matchKey: opponent?.playerId
              ? matchmakingPlayerKey(opponent.playerId)
              : "",
          },

          puzzle: room.puzzle,
          stakePoints: room.stakePoints || 0,
          matchMode: room.matchMode || "quick",
          startsAtMillis: room.startsAtMillis || room.createdAt,

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
    async (payload = {}) => {
      expireOldPrivateRooms();

      const gameKey = String(
        payload.gameKey ||
          "target_number"
      );

      const difficulty = String(
        payload.difficulty ||
          "Medium"
      );

      const identity = await authenticatedSocketPlayerFromDatabase(socket, payload, "friend_room_error");
      if (!identity) return;
      const player = identity.player;

      const puzzle = generateSecurePuzzle(difficulty);

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
    (payload = {}) => {
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

      if (Date.now() < Number(room.startsAtMillis || room.createdAt || 0)) {
        socket.emit("match_error", {
          code: "MATCH_NOT_STARTED",
          message: "Hazırlık geri sayımı henüz tamamlanmadı.",
        });
        return;
      }

      if (!validateChallengeAnswer(room.puzzle, payload.numberSlots, payload.operators)) {
        socket.emit("match_error", {
          code: "INVALID_SOLUTION",
          message: "Gönderilen işlem sunucuda doğrulanamadı.",
        });
        return;
      }

      participant.finishedAt = Date.now();

      // Süre istemciden alınmaz. Cihaz saati veya değiştirilmiş APK sonucu
      // etkileyemesin diye oda başlangıcından sunucu saatiyle hesaplanır.
      participant.elapsedMs = Math.max(
        1,
        participant.finishedAt - Number(room.startsAtMillis || room.createdAt)
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

      awardRealtimeRoom(room, participant, opponent).catch((error) => {
        console.error("realtime reward error:", error);
      });

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
      removeOpenTablesForSocket(socket.id);

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
      removeOpenTablesForSocket(socket.id);

      markSocketDisconnected(socket);
    }
  );
});

setInterval(() => {
  expireOldPrivateRooms();
  expireOldOpenTables();
  expireResolvedRooms();
}, 60_000).unref();

const PORT = Number(
  process.env.PORT || 10000
);

assertSecurityEnvironment();

initDatabase()
  .then(() => {
    server.listen(
      PORT,
      "0.0.0.0",
      () => {
        console.log(`Target number matchmaking server running on port ${PORT}`);
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