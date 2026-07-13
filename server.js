"use strict";

const crypto = require("crypto");
const express = require("express");
const http = require("http");
const { Pool } = require("pg");
const { Server } = require("socket.io");

const PORT = Number(process.env.PORT || 10000);
const SOCKET_PATH = "/socket.io/";
const MATCH_RECONNECT_GRACE_MS = 60_000;
const FINISHED_ROOM_RETENTION_MS = 5 * 60_000;
const MAX_SCORE = 2_000_000_000;

const app = express();
const server = http.createServer(app);

app.use(express.json({ limit: "64kb" }));
app.use((req, _res, next) => {
  console.log(`HTTP request: ${req.method} ${req.originalUrl} ua: ${req.headers["user-agent"] || "-"}`);
  next();
});

const databaseUrl = String(process.env.DATABASE_URL || "").trim();
const pool = databaseUrl
  ? new Pool({
      connectionString: databaseUrl,
      ssl:
        databaseUrl.includes("localhost") || databaseUrl.includes("127.0.0.1")
          ? false
          : { rejectUnauthorized: false },
      max: Number(process.env.PG_POOL_MAX || 10),
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 10_000,
    })
  : null;

function requireDatabase(res) {
  if (pool) return true;
  res.status(503).json({
    ok: false,
    message: "DATABASE_URL tanımlı değil.",
  });
  return false;
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
  return Math.max(0, Math.min(Math.floor(number), MAX_SCORE));
}

function safeDelta(value) {
  const number = Number(value || 0);
  if (!Number.isFinite(number)) return 0;
  return Math.max(
    0,
    Math.min(Math.floor(number), Number(process.env.MAX_SCORE_DELTA || 100_000))
  );
}

function currentMonthKey() {
  const now = new Date();
  return `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, "0")}`;
}

function usernameTakenError() {
  const error = new Error("Bu kullanıcı adı başka bir oyuncu tarafından kullanılıyor.");
  error.publicCode = "USERNAME_TAKEN";
  error.statusCode = 409;
  return error;
}

function sendLeaderboardError(res, error, fallbackMessage, logPrefix) {
  console.error(logPrefix, {
    message: error?.message,
    code: error?.code,
    detail: error?.detail,
    stack: error?.stack,
  });

  const isPublicError = Boolean(error?.publicCode);
  res.status(isPublicError ? error.statusCode || 400 : 500).json({
    ok: false,
    code: error?.publicCode,
    message: isPublicError ? error.message : fallbackMessage,
  });
}

async function initializeDatabase() {
  if (!pool) {
    console.warn("DATABASE_URL tanımlı değil. Skor tablosu endpointleri veritabanı olmadan çalışmaz.");
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

async function ensureUsernameAvailable(client, playerId, username) {
  await client.query("SELECT pg_advisory_xact_lock(hashtext(LOWER($1::text)))", [username]);
  const result = await client.query(
    `SELECT player_id
     FROM players
     WHERE LOWER(username) = LOWER($1)
       AND player_id <> $2
     LIMIT 1`,
    [username, playerId]
  );
  if (result.rowCount > 0) throw usernameTakenError();
}

async function upsertPlayer(client, playerId, username, country) {
  await ensureUsernameAvailable(client, playerId, username);
  await client.query(
    `INSERT INTO players (player_id, username, country, updated_at)
     VALUES ($1, $2, $3, NOW())
     ON CONFLICT (player_id)
     DO UPDATE SET
       username = EXCLUDED.username,
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
}

app.post("/leaderboard/username/claim", async (req, res) => {
  if (!requireDatabase(res)) return;
  const playerId = safePlayerId(req.body.playerId);
  const username = safeUsername(req.body.username);
  const country = safeCountry(req.body.country);
  if (!playerId) {
    res.status(400).json({ ok: false, message: "playerId zorunlu." });
    return;
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await upsertPlayer(client, playerId, username, country);
    await client.query("COMMIT");
    res.json({ ok: true });
  } catch (error) {
    await client.query("ROLLBACK");
    sendLeaderboardError(res, error, "Kullanıcı adı kaydedilemedi.", "username claim error:");
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
    res.status(400).json({ ok: false, message: "playerId zorunlu." });
    return;
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await upsertPlayer(client, playerId, username, country);
    await client.query(
      `UPDATE player_scores
       SET
         general_score = GREATEST(general_score, $2),
         infinite_score = GREATEST(infinite_score, $3),
         updated_at = NOW()
       WHERE player_id = $1`,
      [playerId, generalScore, infiniteScore]
    );
    await client.query("COMMIT");
    res.json({ ok: true });
  } catch (error) {
    await client.query("ROLLBACK");
    sendLeaderboardError(res, error, "Skor eşitlenemedi.", "leaderboard sync error:");
  } finally {
    client.release();
  }
});

app.post("/leaderboard/scores/add", async (req, res) => {
  if (!requireDatabase(res)) return;
  const playerId = safePlayerId(req.body.playerId);
  const username = safeUsername(req.body.username);
  const country = safeCountry(req.body.country);
  const generalDelta = safeDelta(req.body.generalScoreDelta);
  const infiniteDelta = safeDelta(req.body.infiniteScoreDelta);
  const monthKey = currentMonthKey();
  if (!playerId) {
    res.status(400).json({ ok: false, message: "playerId zorunlu." });
    return;
  }

  if (generalDelta <= 0 && infiniteDelta <= 0) {
    res.json({ ok: true, skipped: true });
    return;
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await upsertPlayer(client, playerId, username, country);
    await client.query(
      `UPDATE player_scores
       SET
         general_score = LEAST(general_score + $2, ${MAX_SCORE}),
         infinite_score = LEAST(infinite_score + $3, ${MAX_SCORE}),
         updated_at = NOW()
       WHERE player_id = $1`,
      [playerId, generalDelta, infiniteDelta]
    );
    await client.query(
      `INSERT INTO player_monthly_scores
         (player_id, month_key, general_score, infinite_score, updated_at)
       VALUES ($1, $2, $3, $4, NOW())
       ON CONFLICT (player_id, month_key)
       DO UPDATE SET
         general_score = LEAST(player_monthly_scores.general_score + EXCLUDED.general_score, ${MAX_SCORE}),
         infinite_score = LEAST(player_monthly_scores.infinite_score + EXCLUDED.infinite_score, ${MAX_SCORE}),
         updated_at = NOW()`,
      [playerId, monthKey, generalDelta, infiniteDelta]
    );
    await client.query("COMMIT");
    res.json({ ok: true });
  } catch (error) {
    await client.query("ROLLBACK");
    sendLeaderboardError(res, error, "Skor kaydedilemedi.", "leaderboard add error:");
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
  const monthKey = currentMonthKey();
  const scoreColumn = scoreType === "infinite" ? "infinite_score" : "general_score";
  const tableName = period === "month" ? "player_monthly_scores" : "player_scores";

  function buildWhere(includeCountry) {
    const values = [];
    const conditions = [`s.${scoreColumn} > 0`];
    if (period === "month") {
      values.push(monthKey);
      conditions.push(`s.month_key = $${values.length}`);
    }
    if (includeCountry) {
      values.push(country);
      conditions.push(`p.country = $${values.length}`);
    }
    return { values, whereSql: conditions.join(" AND ") };
  }

  async function getMyRank(includeCountry) {
    if (!playerId) return null;
    const built = buildWhere(includeCountry);
    const values = [...built.values, playerId];
    const playerParamIndex = values.length;
    const result = await pool.query(
      `WITH ranked AS (
         SELECT
           p.player_id,
           s.${scoreColumn} AS score,
           ROW_NUMBER() OVER (
             ORDER BY s.${scoreColumn} DESC, s.updated_at ASC, p.username ASC
           ) AS position
         FROM ${tableName} s
         JOIN players p ON p.player_id = s.player_id
         WHERE ${built.whereSql}
       )
       SELECT position, score
       FROM ranked
       WHERE player_id = $${playerParamIndex}
       LIMIT 1`,
      values
    );
    const row = result.rows[0];
    return row ? { rank: Number(row.position), score: Number(row.score) } : null;
  }

  try {
    const listBuilt = buildWhere(scope === "country");
    const listResult = await pool.query(
      `WITH ranked AS (
         SELECT
           p.player_id,
           p.username,
           p.country,
           s.${scoreColumn} AS score,
           ROW_NUMBER() OVER (
             ORDER BY s.${scoreColumn} DESC, s.updated_at ASC, p.username ASC
           ) AS position
         FROM ${tableName} s
         JOIN players p ON p.player_id = s.player_id
         WHERE ${listBuilt.whereSql}
       )
       SELECT position, username, country, score
       FROM ranked
       ORDER BY position ASC
       LIMIT 50`,
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
      myWorldRank: myWorld ? myWorld.rank : null,
      myCountryRank: myCountry ? myCountry.rank : null,
      myScore: myWorld ? myWorld.score : 0,
      rows: listResult.rows.map((row) => ({
        rank: Number(row.position),
        username: row.username,
        country: row.country,
        score: Number(row.score),
      })),
    });
  } catch (error) {
    console.error("leaderboard get error:", error);
    res.status(500).json({ ok: false, message: "Skor tablosu alınamadı." });
  }
});

const io = new Server(server, {
  path: SOCKET_PATH,
  cors: {
    origin: true,
    methods: ["GET", "POST"],
    credentials: false,
  },
  transports: ["websocket", "polling"],
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
const privateRooms = new Map();
const realtimeRooms = new Map();
const activeBySocketId = new Map();
const PRIVATE_ROOM_TTL_MS = Number(process.env.PRIVATE_ROOM_TTL_MS || 15 * 60_000);

function normalizeMatchGameKey(value) {
  const gameKey = String(value || "target_number").trim().slice(0, 96);
  if (/^target_number_tournament(?:_stage_\d+)?$/i.test(gameKey)) {
    return "target_number_tournament";
  }
  return gameKey || "target_number";
}

function queueKey(gameKey, difficulty) {
  return `${String(gameKey || "default")}::${String(difficulty || "default")}`;
}

function safeGameKey(value) {
  return normalizeMatchGameKey(value);
}

function safeDifficulty(value) {
  return String(value || "Medium").trim().slice(0, 32) || "Medium";
}

function safeSessionToken(value) {
  const token = String(value || "").trim().slice(0, 160);
  return token || crypto.randomUUID();
}

function normalizeRoomCode(value) {
  return String(value || "")
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, "")
    .slice(0, 6);
}

function generateRoomCode() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let code = "";
  for (let index = 0; index < 6; index += 1) {
    code += alphabet[crypto.randomInt(0, alphabet.length)];
  }
  return code;
}

function generateUniqueRoomCode() {
  for (let attempt = 0; attempt < 32; attempt += 1) {
    const code = generateRoomCode();
    if (!privateRooms.has(code)) return code;
  }
  return crypto.randomBytes(4).toString("hex").toUpperCase().slice(0, 6);
}

function safePlayer(rawPlayer) {
  return {
    name: safeUsername(rawPlayer?.name),
    country: safeCountry(rawPlayer?.country),
  };
}

function safePuzzle(rawPuzzle, difficulty) {
  const numbers = Array.isArray(rawPuzzle?.numbers)
    ? rawPuzzle.numbers
        .map(Number)
        .filter(Number.isFinite)
        .slice(0, 8)
        .map((number) => Math.floor(number))
    : [];
  const target = Number(rawPuzzle?.target);
  if (!Number.isFinite(target) || target <= 0 || numbers.length < 3) return null;
  return {
    difficulty: String(rawPuzzle?.difficulty || difficulty || "Medium").slice(0, 32),
    target: Math.floor(target),
    numbers,
  };
}

function removeFromAllQueues(socketId) {
  for (const [key, queue] of waitingQueues.entries()) {
    const filtered = queue.filter((entry) => entry.socketId !== socketId);
    if (filtered.length) waitingQueues.set(key, filtered);
    else waitingQueues.delete(key);
  }
}

function removePrivateRoomOwnedBy(socketId, notify = true) {
  for (const [roomCode, room] of privateRooms.entries()) {
    if (room.host.socketId !== socketId) continue;
    privateRooms.delete(roomCode);
    if (notify) {
      io.sockets.sockets.get(socketId)?.emit("friend_room_closed", {
        roomCode,
        reason: "cancelled",
      });
    }
  }
}

function expireOldPrivateRooms() {
  const now = Date.now();
  for (const [roomCode, room] of privateRooms.entries()) {
    if (now - room.createdAt <= PRIVATE_ROOM_TTL_MS) continue;
    privateRooms.delete(roomCode);
    io.sockets.sockets.get(room.host.socketId)?.emit("friend_room_closed", {
      roomCode,
      reason: "expired",
    });
  }
}

function makePlayerSlot(entry) {
  return {
    sessionToken: entry.sessionToken,
    socketId: entry.socketId,
    player: entry.player,
    finishedMs: null,
    backgroundedAt: 0,
    disconnectedAt: 0,
    abandoned: false,
    graceTimer: null,
  };
}

function clearGraceTimer(player) {
  if (player?.graceTimer) clearTimeout(player.graceTimer);
  if (player) player.graceTimer = null;
}

function findPlayer(room, sessionToken) {
  return room?.players.find((player) => player.sessionToken === sessionToken) || null;
}

function opponentOf(room, player) {
  return room.players.find((candidate) => candidate !== player) || null;
}

function socketForPlayer(player) {
  return player?.socketId ? io.sockets.sockets.get(player.socketId) : null;
}

function matchPayload(room, player) {
  const opponent = opponentOf(room, player);
  return {
    roomId: room.roomId,
    gameKey: room.gameKey,
    difficulty: room.difficulty,
    sessionToken: player.sessionToken,
    matchStartedAtMs: room.startedAt,
    reconnectGraceMs: MATCH_RECONNECT_GRACE_MS,
    opponent: opponent?.player || { name: "Rakip", country: "" },
    puzzle: room.puzzle,
    myFinishedMs: player.finishedMs,
    opponentFinishedMs: opponent?.finishedMs || null,
    opponentAbandoned: Boolean(opponent?.abandoned),
  };
}

function attachPlayerSocket(room, player, socket) {
  clearGraceTimer(player);
  if (player.socketId && player.socketId !== socket.id) {
    activeBySocketId.delete(player.socketId);
    const oldSocket = io.sockets.sockets.get(player.socketId);
    oldSocket?.leave(room.roomId);
  }
  player.socketId = socket.id;
  player.backgroundedAt = 0;
  player.disconnectedAt = 0;
  socket.join(room.roomId);
  activeBySocketId.set(socket.id, {
    roomId: room.roomId,
    sessionToken: player.sessionToken,
  });
}

function cleanupRoom(roomId) {
  const room = realtimeRooms.get(roomId);
  if (!room) return;
  for (const player of room.players) {
    clearGraceTimer(player);
    if (player.socketId) activeBySocketId.delete(player.socketId);
  }
  realtimeRooms.delete(roomId);
}

function scheduleRoomCleanup(room) {
  if (room.cleanupTimer) return;
  room.cleanupTimer = setTimeout(() => cleanupRoom(room.roomId), FINISHED_ROOM_RETENTION_MS);
  room.cleanupTimer.unref?.();
}

function markPlayerAbandoned(room, player, reason) {
  if (!room || !player || player.abandoned) return;
  clearGraceTimer(player);
  player.abandoned = true;
  player.backgroundedAt = 0;
  player.disconnectedAt = 0;

  if (player.socketId) {
    activeBySocketId.delete(player.socketId);
    io.sockets.sockets.get(player.socketId)?.leave(room.roomId);
    player.socketId = null;
  }

  const opponent = opponentOf(room, player);
  const opponentSocket = socketForPlayer(opponent);
  opponentSocket?.emit("opponent_left", {
    roomId: room.roomId,
    reason,
  });
  room.endedAt = room.endedAt || Date.now();
  scheduleRoomCleanup(room);
}

function scheduleReconnectGrace(room, player, awayStartedAt, reason) {
  if (!room || !player || player.abandoned || player.finishedMs) return;
  clearGraceTimer(player);
  const now = Date.now();
  const safeStartedAt = Math.min(now, Math.max(now - MATCH_RECONNECT_GRACE_MS, Number(awayStartedAt) || now));
  const remainingMs = Math.max(0, MATCH_RECONNECT_GRACE_MS - (now - safeStartedAt));
  player.graceTimer = setTimeout(() => {
    const stillAway = player.backgroundedAt > 0 || player.disconnectedAt > 0;
    if (stillAway && !player.abandoned) markPlayerAbandoned(room, player, reason);
  }, remainingMs);
  player.graceTimer.unref?.();
}

function createRealtimeRoom(first, second, forcedRoomId = null, isPrivateRoom = false) {
  const roomId = forcedRoomId || crypto.randomUUID();
  const room = {
    roomId,
    gameKey: first.gameKey,
    difficulty: first.difficulty,
    puzzle: first.puzzle,
    startedAt: Date.now(),
    endedAt: 0,
    cleanupTimer: null,
    isPrivateRoom,
    players: [makePlayerSlot(first), makePlayerSlot(second)],
  };
  realtimeRooms.set(roomId, room);

  for (const player of room.players) {
    const socket = io.sockets.sockets.get(player.socketId);
    if (!socket) {
      player.disconnectedAt = Date.now();
      scheduleReconnectGrace(room, player, player.disconnectedAt, "connection_lost");
      continue;
    }
    attachPlayerSocket(room, player, socket);
    socket.emit("match_found", matchPayload(room, player));
  }
  return room;
}

function parseJoin(socket, raw) {
  const gameKey = safeGameKey(raw?.gameKey);
  const difficulty = safeDifficulty(raw?.difficulty);
  const puzzle = safePuzzle(raw?.puzzle, difficulty);
  if (!puzzle) return { error: "Geçerli bulmaca bilgisi bulunamadı." };
  return {
    entry: {
      socketId: socket.id,
      gameKey,
      difficulty,
      player: safePlayer(raw?.player),
      puzzle,
      sessionToken: safeSessionToken(raw?.sessionToken),
      queuedAt: Date.now(),
    },
  };
}

function attemptResume(socket, raw, eventName = "match_resumed") {
  const roomId = String(raw?.roomId || "").trim();
  const sessionToken = String(raw?.sessionToken || "").trim();
  const room = realtimeRooms.get(roomId);
  const player = findPlayer(room, sessionToken);
  if (!room || !player) {
    socket.emit("match_resume_failed", { message: "Maç oturumu bulunamadı." });
    return;
  }

  if (room.isPrivateRoom) {
    socket.emit("match_resume_failed", { message: "Arkadaş odalarında yeniden bağlanma desteklenmiyor." });
    return;
  }

  const awayStartedAt = player.backgroundedAt || player.disconnectedAt || 0;
  const expired = player.abandoned ||
    (awayStartedAt > 0 && Date.now() - awayStartedAt >= MATCH_RECONNECT_GRACE_MS);
  if (expired) {
    if (!player.abandoned) markPlayerAbandoned(room, player, "reconnect_timeout");
    socket.emit("match_resume_failed", { message: "1 dakikalık yeniden bağlanma süresi doldu." });
    return;
  }

  attachPlayerSocket(room, player, socket);
  socket.emit(eventName, matchPayload(room, player));
}

app.get("/", (_req, res) => {
  res.json({
    ok: true,
    service: "target-number-matchmaking",
    socket: "socket.io",
    socketPath: SOCKET_PATH,
    database: Boolean(pool),
    leaderboard: Boolean(pool),
    transports: ["websocket", "polling"],
    reconnectGraceMs: MATCH_RECONNECT_GRACE_MS,
    waitingQueues: Array.from(waitingQueues.entries()).map(([key, queue]) => ({
      key,
      count: queue.length,
    })),
    activeRooms: realtimeRooms.size,
    privateRooms: privateRooms.size,
  });
});

app.get("/health", async (_req, res) => {
  if (!pool) {
    res.json({ ok: true, database: false });
    return;
  }
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, database: true });
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
    androidUrlMustBe: "https://renderdepo-tpqh.onrender.com",
    androidUrlMustNotInclude: "/socket.io",
    transports: ["websocket", "polling"],
    reconnectGraceMs: MATCH_RECONNECT_GRACE_MS,
  });
});

io.engine.on("connection_error", (error) => {
  console.log("Engine.IO connection_error:", {
    code: error.code,
    message: error.message,
    context: error.context,
    url: error.req && error.req.url,
    userAgent: error.req && error.req.headers && error.req.headers["user-agent"],
    origin: error.req && error.req.headers && error.req.headers.origin,
  });
});

io.engine.on("connection", (rawSocket) => {
  console.log("Engine.IO connected:", rawSocket.id, "transport:", rawSocket.transport.name);
});

io.on("connection", (socket) => {
  console.log("Socket connected:", socket.id, "transport:", socket.conn.transport.name);
  socket.conn.on("upgrade", (transport) => {
    console.log("Socket upgraded:", socket.id, "transport:", transport.name);
  });

  socket.on("join_match", (raw = {}) => {
    removeFromAllQueues(socket.id);
    const parsed = parseJoin(socket, raw);
    if (parsed.error) {
      socket.emit("match_error", { message: parsed.error });
      return;
    }
    const entry = parsed.entry;
    const key = queueKey(entry.gameKey, entry.difficulty);
    const queue = waitingQueues.get(key) || [];

    let opponent = null;
    while (queue.length && !opponent) {
      const candidate = queue.shift();
      const candidateSocket = io.sockets.sockets.get(candidate.socketId);
      if (candidateSocket && candidate.sessionToken !== entry.sessionToken) opponent = candidate;
    }

    if (queue.length) waitingQueues.set(key, queue);
    else waitingQueues.delete(key);

    if (opponent) createRealtimeRoom(opponent, entry);
    else waitingQueues.set(key, [...queue, entry]);
  });

  socket.on("cancel_match", () => {
    removeFromAllQueues(socket.id);
    removePrivateRoomOwnedBy(socket.id, false);
    const active = activeBySocketId.get(socket.id);
    if (active) {
      const room = realtimeRooms.get(active.roomId);
      const player = findPlayer(room, active.sessionToken);
      markPlayerAbandoned(room, player, "cancelled");
    }
  });

  socket.on("create_friend_room", (raw = {}) => {
    expireOldPrivateRooms();
    removePrivateRoomOwnedBy(socket.id, false);
    const parsed = parseJoin(socket, raw);
    if (parsed.error) {
      socket.emit("friend_room_error", { message: parsed.error });
      return;
    }

    const roomCode = generateUniqueRoomCode();
    privateRooms.set(roomCode, { host: parsed.entry, createdAt: Date.now() });
    socket.emit("friend_room_created", { roomCode });
  });

  socket.on("join_friend_room", (raw = {}) => {
    expireOldPrivateRooms();
    const roomCode = normalizeRoomCode(raw?.roomCode);
    const privateRoom = privateRooms.get(roomCode);
    if (!roomCode || roomCode.length !== 6) {
      socket.emit("friend_room_error", { message: "Geçerli 6 haneli oda kodu gir." });
      return;
    }
    if (!privateRoom) {
      socket.emit("friend_room_error", { message: "Oda bulunamadı. Kodu kontrol edip tekrar deneyin." });
      return;
    }
    const parsed = parseJoin(socket, raw);
    if (parsed.error) {
      socket.emit("friend_room_error", { message: parsed.error });
      return;
    }
    if (privateRoom.host.socketId === socket.id) {
      socket.emit("friend_room_error", { message: "Kendi odanıza tekrar katılamazsınız." });
      return;
    }
    const ownerSocket = io.sockets.sockets.get(privateRoom.host.socketId);
    if (!ownerSocket) {
      privateRooms.delete(roomCode);
      socket.emit("friend_room_error", { message: "Oda sahibi bağlantıdan ayrılmış." });
      return;
    }
    privateRooms.delete(roomCode);
    createRealtimeRoom(privateRoom.host, parsed.entry, null, true);
  });

  socket.on("player_finished", (raw = {}) => {
    const roomId = String(raw?.roomId || "").trim();
    const sessionToken = String(raw?.sessionToken || "").trim();
    const room = realtimeRooms.get(roomId);
    const active = activeBySocketId.get(socket.id);
    const player = findPlayer(room, sessionToken || active?.sessionToken);
    if (!room || !player || player.abandoned || player.finishedMs) return;

    const elapsedMs = Math.max(1, Math.min(24 * 60 * 60_000, Math.floor(Number(raw?.elapsedMs) || 1)));
    player.finishedMs = elapsedMs;
    const opponent = opponentOf(room, player);
    socketForPlayer(opponent)?.emit("opponent_finished", { roomId, elapsedMs });
    room.endedAt = room.endedAt || Date.now();
    scheduleRoomCleanup(room);
  });

  socket.on("player_backgrounded", (raw = {}) => {
    const room = realtimeRooms.get(String(raw?.roomId || "").trim());
    const player = findPlayer(room, String(raw?.sessionToken || "").trim());
    if (!room || !player || player.abandoned || room.isPrivateRoom) return;
    const now = Date.now();
    const clientTime = Number(raw?.clientChangedAtMillis) || now;
    player.backgroundedAt = Math.min(now, Math.max(now - MATCH_RECONNECT_GRACE_MS, clientTime));
    scheduleReconnectGrace(room, player, player.backgroundedAt, "background_timeout");
  });

  socket.on("player_foregrounded", (raw = {}) => {
    attemptResume(socket, raw, "match_resumed");
  });

  socket.on("resume_match", (raw = {}) => {
    attemptResume(socket, raw, "match_resumed");
  });

  socket.on("abandon_match", (raw = {}) => {
    const room = realtimeRooms.get(String(raw?.roomId || "").trim());
    const player = findPlayer(room, String(raw?.sessionToken || "").trim());
    if (room && player) markPlayerAbandoned(room, player, "abandoned");
    removeFromAllQueues(socket.id);
  });

  socket.on("disconnect", (reason) => {
    console.log("Socket disconnected:", socket.id, reason);
    removeFromAllQueues(socket.id);
    removePrivateRoomOwnedBy(socket.id, false);

    const active = activeBySocketId.get(socket.id);
    activeBySocketId.delete(socket.id);
    if (!active) return;

    const room = realtimeRooms.get(active.roomId);
    const player = findPlayer(room, active.sessionToken);
    if (!room || !player || player.abandoned) return;
    if (room.isPrivateRoom) {
      markPlayerAbandoned(room, player, "disconnect");
      return;
    }
    player.socketId = null;
    if (!player.backgroundedAt) player.disconnectedAt = Date.now();
    const awayStartedAt = player.backgroundedAt || player.disconnectedAt;
    scheduleReconnectGrace(room, player, awayStartedAt, "disconnect_timeout");
  });
});

setInterval(expireOldPrivateRooms, 60_000).unref();

initializeDatabase()
  .catch((error) => {
    console.error("Database initialization error:", error);
  })
  .finally(() => {
    server.listen(PORT, "0.0.0.0", () => {
      console.log(`Target number matchmaking server running on port ${PORT}`);
    });
  });