const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();

app.use((req, res, next) => {
  console.log("HTTP request:", req.method, req.url, "ua:", req.headers["user-agent"] || "-");
  next();
});

app.use(express.json({ limit: "64kb" }));

const server = http.createServer(app);

const SOCKET_PATH = "/socket.io/";
const DATABASE_URL = process.env.DATABASE_URL;

const pool = DATABASE_URL
  ? new Pool({
      connectionString: DATABASE_URL,
      ssl:
        DATABASE_URL.includes("localhost") || DATABASE_URL.includes("127.0.0.1")
          ? false
          : { rejectUnauthorized: false },
      max: Number(process.env.PG_POOL_MAX || 10),
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 10_000,
    })
  : null;

async function initDatabase() {
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

function safeDelta(value) {
  const number = Number(value || 0);

  if (!Number.isFinite(number)) return 0;

  return Math.max(
    0,
    Math.min(Math.floor(number), Number(process.env.MAX_SCORE_DELTA || 100_000))
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

function sendLeaderboardError(res, error, fallbackMessage, logLabel) {
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

  if (result.rowCount > 0) {
    throw usernameTakenError();
  }
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
    res.status(400).json({
      ok: false,
      message: "playerId zorunlu.",
    });

    return;
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");
    await upsertPlayer(client, playerId, username, country);
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
});

app.post("/leaderboard/scores/sync", async (req, res) => {
  if (!requireDatabase(res)) return;

  const playerId = safePlayerId(req.body.playerId);
  const username = safeUsername(req.body.username);
  const country = safeCountry(req.body.country);
  const generalScore = safeScore(req.body.generalScore);
  const infiniteScore = safeScore(req.body.infiniteScore);

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
    res.status(400).json({
      ok: false,
      message: "playerId zorunlu.",
    });

    return;
  }

  if (generalDelta <= 0 && infiniteDelta <= 0) {
    res.json({
      ok: true,
      skipped: true,
    });

    return;
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    await upsertPlayer(client, playerId, username, country);

    await client.query(
      `UPDATE player_scores
       SET
         general_score = LEAST(general_score + $2, 2000000000),
         infinite_score = LEAST(infinite_score + $3, 2000000000),
         updated_at = NOW()
       WHERE player_id = $1`,
      [playerId, generalDelta, infiniteDelta]
    );

    await client.query(
      `INSERT INTO player_monthly_scores
         (player_id, month_key, general_score, infinite_score, updated_at)
       VALUES
         ($1, $2, $3, $4, NOW())
       ON CONFLICT (player_id, month_key)
       DO UPDATE SET
         general_score = LEAST(player_monthly_scores.general_score + EXCLUDED.general_score, 2000000000),
         infinite_score = LEAST(player_monthly_scores.infinite_score + EXCLUDED.infinite_score, 2000000000),
         updated_at = NOW()`,
      [playerId, monthKey, generalDelta, infiniteDelta]
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
});

app.get("/leaderboard", async (req, res) => {
  if (!requireDatabase(res)) return;

  const scoreType = req.query.scoreType === "infinite" ? "infinite" : "general";
  const period = req.query.period === "month" ? "month" : "all";
  const scope = req.query.scope === "country" ? "country" : "world";
  const country = safeCountry(req.query.country);
  const limit = Math.max(1, Math.min(Number(req.query.limit) || 50, 100));
  const offset = Math.max(0, Number(req.query.offset) || 0);

  const scoreColumn = scoreType === "infinite" ? "infinite_score" : "general_score";
  const scoreAlias = scoreType === "infinite" ? "infiniteScore" : "generalScore";

  const values = [];
  const where = [];
  let fromSql = "";
  let scoreExpr = "";

  if (period === "month") {
    fromSql = `
      FROM player_monthly_scores scores
      JOIN players p ON p.player_id = scores.player_id
    `;
    values.push(currentMonthKey());
    where.push(`scores.month_key = $${values.length}`);
    scoreExpr = `scores.${scoreColumn}`;
  } else {
    fromSql = `
      FROM player_scores scores
      JOIN players p ON p.player_id = scores.player_id
    `;
    scoreExpr = `scores.${scoreColumn}`;
  }

  if (scope === "country") {
    values.push(country);
    where.push(`p.country = $${values.length}`);
  }

  values.push(limit);
  const limitIndex = values.length;

  values.push(offset);
  const offsetIndex = values.length;

  const whereSql = where.length > 0 ? `WHERE ${where.join(" AND ")}` : "";

  try {
    const { rows } = await pool.query(
      `
        SELECT
          p.player_id AS "playerId",
          p.username AS "username",
          p.country AS "country",
          ${scoreExpr} AS "${scoreAlias}",
          ROW_NUMBER() OVER (
            ORDER BY ${scoreExpr} DESC, p.updated_at ASC, p.player_id ASC
          ) AS "rank"
        ${fromSql}
        ${whereSql}
        ORDER BY ${scoreExpr} DESC, p.updated_at ASC, p.player_id ASC
        LIMIT $${limitIndex}
        OFFSET $${offsetIndex}
      `,
      values
    );

    res.json({
      ok: true,
      scoreType,
      period,
      scope,
      items: rows.map((row) => ({
        playerId: row.playerId,
        username: row.username,
        country: row.country,
        score:
          scoreType === "infinite"
            ? Number(row.infiniteScore || 0)
            : Number(row.generalScore || 0),
        rank: Number(row.rank || 0),
      })),
    });
  } catch (error) {
    sendLeaderboardError(
      res,
      error,
      "Liderlik tablosu yüklenemedi.",
      "leaderboard get error:"
    );
  }
});

app.get("/leaderboard/me", async (req, res) => {
  if (!requireDatabase(res)) return;

  const playerId = safePlayerId(req.query.playerId);

  if (!playerId) {
    res.status(400).json({
      ok: false,
      message: "playerId zorunlu.",
    });

    return;
  }

  try {
    const { rows } = await pool.query(
      `
        SELECT
          p.player_id AS "playerId",
          p.username AS "username",
          p.country AS "country",
          s.general_score AS "generalScore",
          s.infinite_score AS "infiniteScore"
        FROM players p
        JOIN player_scores s ON s.player_id = p.player_id
        WHERE p.player_id = $1
        LIMIT 1
      `,
      [playerId]
    );

    const me = rows[0];

    if (!me) {
      res.status(404).json({
        ok: false,
        message: "Oyuncu bulunamadı.",
      });
      return;
    }

    res.json({
      ok: true,
      item: {
        playerId: me.playerId,
        username: me.username,
        country: me.country,
        generalScore: Number(me.generalScore || 0),
        infiniteScore: Number(me.infiniteScore || 0),
      },
    });
  } catch (error) {
    sendLeaderboardError(
      res,
      error,
      "Oyuncu bilgisi alınamadı.",
      "leaderboard me error:"
    );
  }
});

const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
  },
  path: SOCKET_PATH,
  transports: ["websocket", "polling"],
});

const waitingQueues = new Map();
const activeRooms = new Map();
const privateRooms = new Map();
const roomStates = new Map();
const backgroundTimers = new Map();
const PRIVATE_ROOM_TTL_MS = Number(process.env.PRIVATE_ROOM_TTL_MS || 15 * 60 * 1000);
const RECONNECT_GRACE_MS = Number(process.env.RECONNECT_GRACE_MS || 60 * 1000);

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

function safePlayer(rawPlayer = {}, fallbackId = "") {
  const playerId = safePlayerId(rawPlayer.id || rawPlayer.playerId || fallbackId);

  return {
    id: playerId,
    name: safeUsername(rawPlayer.name),
    country: safeCountry(rawPlayer.country),
  };
}

function safePuzzle(rawPuzzle = {}, fallbackDifficulty = "Medium") {
  const difficulty = String(rawPuzzle.difficulty || fallbackDifficulty || "Medium").trim() || "Medium";
  const target = Number(rawPuzzle.target);
  const rawNumbers = Array.isArray(rawPuzzle.numbers) ? rawPuzzle.numbers : [];

  if (!Number.isFinite(target) || rawNumbers.length === 0) return null;

  const numbers = rawNumbers
    .map((value) => Number(value))
    .filter((value) => Number.isFinite(value))
    .map((value) => Math.trunc(value));

  if (numbers.length !== rawNumbers.length) return null;

  return {
    difficulty,
    target: Math.trunc(target),
    numbers,
  };
}

function normalizeRoomCode(value) {
  return String(value || "")
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, "")
    .slice(0, 6);
}

function randomRoomCode() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let code = "";

  for (let i = 0; i < 6; i += 1) {
    const index = crypto.randomInt(0, alphabet.length);
    code += alphabet[index];
  }

  return code;
}

function generateUniqueRoomCode() {
  let attempts = 0;

  while (attempts < 20) {
    const code = randomRoomCode();
    if (!privateRooms.has(code)) return code;
    attempts += 1;
  }

  return crypto.randomBytes(4).toString("hex").slice(0, 6).toUpperCase();
}

function clearBackgroundTimer(playerId) {
  const existing = backgroundTimers.get(playerId);

  if (existing) {
    clearTimeout(existing);
    backgroundTimers.delete(playerId);
  }
}

function setActiveRoomMapping(socketId, roomId, opponentId, gameKey, difficulty, playerId) {
  activeRooms.set(socketId, {
    roomId,
    opponentId,
    gameKey,
    difficulty,
    playerId,
  });
}

function getOpponentParticipant(room, playerId) {
  for (const [id, participant] of room.participants.entries()) {
    if (id !== playerId) return participant;
  }
  return null;
}

function buildPublicPlayer(player) {
  return {
    name: player.name,
    country: player.country,
  };
}

function buildMatchPayload(room, forPlayerId, extra = {}) {
  const selfParticipant = room.participants.get(forPlayerId);
  const opponent = getOpponentParticipant(room, forPlayerId);

  if (!selfParticipant || !opponent) return null;

  return {
    roomId: room.roomId,
    isBot: false,
    opponent: buildPublicPlayer(opponent),
    puzzle: room.puzzle,
    resumed: Boolean(extra.resumed),
    opponentFinishedMs: Number(extra.opponentFinishedMs || 0),
    ...(extra.roomCode ? { roomCode: extra.roomCode } : {}),
  };
}

function removeRoomCompletely(roomId) {
  const room = roomStates.get(roomId);

  if (!room) return;

  for (const participant of room.participants.values()) {
    clearBackgroundTimer(participant.playerId);

    if (participant.socketId) {
      activeRooms.delete(participant.socketId);
      const socket = io.sockets.sockets.get(participant.socketId);

      if (socket) {
        try {
          socket.leave(roomId);
        } catch (_) {
        }
      }
    }
  }

  roomStates.delete(roomId);
}

function cleanupRoomIfSettled(roomId) {
  const room = roomStates.get(roomId);
  if (!room) return;

  const participants = Array.from(room.participants.values());
  if (participants.length < 2) {
    removeRoomCompletely(roomId);
    return;
  }

  const everyoneFinished = participants.every((participant) => participant.finished || participant.forfeited);
  if (everyoneFinished) {
    removeRoomCompletely(roomId);
  }
}

function scheduleBackgroundForfeit(roomId, playerId) {
  clearBackgroundTimer(playerId);

  const timer = setTimeout(() => {
    const room = roomStates.get(roomId);
    if (!room) {
      backgroundTimers.delete(playerId);
      return;
    }

    const participant = room.participants.get(playerId);
    if (!participant || participant.socketId || participant.finished || participant.forfeited) {
      backgroundTimers.delete(playerId);
      return;
    }

    participant.forfeited = true;
    participant.backgroundedAt = null;
    backgroundTimers.delete(playerId);

    const opponent = getOpponentParticipant(room, playerId);
    if (opponent && opponent.socketId && !opponent.finished) {
      io.to(opponent.socketId).emit("opponent_left", {
        roomId,
        reason: "timeout",
      });
    }

    cleanupRoomIfSettled(roomId);
  }, RECONNECT_GRACE_MS);

  if (typeof timer.unref === "function") {
    timer.unref();
  }

  backgroundTimers.set(playerId, timer);
}

function markParticipantBackgrounded(roomId, playerId) {
  const room = roomStates.get(roomId);
  if (!room) return;

  const participant = room.participants.get(playerId);
  if (!participant || participant.finished || participant.forfeited) return;

  participant.backgroundedAt = Date.now();

  if (participant.socketId) {
    activeRooms.delete(participant.socketId);
    participant.socketId = null;
  }

  scheduleBackgroundForfeit(roomId, playerId);
}

function createRealtimeRoom(socket, opponentSocket, gameKey, difficulty, puzzle, player, opponentPlayer) {
  const roomId = `room_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`;

  socket.join(roomId);
  opponentSocket.join(roomId);

  const room = {
    roomId,
    gameKey,
    difficulty,
    puzzle,
    participants: new Map([
      [
        player.id,
        {
          playerId: player.id,
          socketId: socket.id,
          name: player.name,
          country: player.country,
          finished: false,
          finishedElapsedMs: null,
          forfeited: false,
          backgroundedAt: null,
        },
      ],
      [
        opponentPlayer.id,
        {
          playerId: opponentPlayer.id,
          socketId: opponentSocket.id,
          name: opponentPlayer.name,
          country: opponentPlayer.country,
          finished: false,
          finishedElapsedMs: null,
          forfeited: false,
          backgroundedAt: null,
        },
      ],
    ]),
  };

  roomStates.set(roomId, room);

  setActiveRoomMapping(socket.id, roomId, opponentSocket.id, gameKey, difficulty, player.id);
  setActiveRoomMapping(opponentSocket.id, roomId, socket.id, gameKey, difficulty, opponentPlayer.id);

  return roomId;
}

function removePrivateRoomsForSocket(socketId, notifyOwner = true) {
  for (const [roomCode, room] of privateRooms.entries()) {
    if (room.ownerSocketId === socketId) {
      privateRooms.delete(roomCode);

      if (notifyOwner) {
        io.to(socketId).emit("friend_room_closed", {
          roomCode,
        });
      }
    }
  }
}

function expireOldPrivateRooms() {
  const now = Date.now();

  for (const [roomCode, room] of privateRooms.entries()) {
    if (now - room.createdAt > PRIVATE_ROOM_TTL_MS) {
      privateRooms.delete(roomCode);

      io.to(room.ownerSocketId).emit("friend_room_closed", {
        roomCode,
      });
    }
  }
}

function removeFromAllQueues(socketId) {
  for (const [key, queue] of waitingQueues.entries()) {
    const filtered = queue.filter((entry) => entry.socketId !== socketId);
    if (filtered.length > 0) waitingQueues.set(key, filtered);
    else waitingQueues.delete(key);
  }
}

function leaveRoomAsCancel(socket) {
  const active = activeRooms.get(socket.id);
  if (!active) return;

  const room = roomStates.get(active.roomId);

  activeRooms.delete(socket.id);

  if (!room) return;

  const participant = room.participants.get(active.playerId);
  if (participant) {
    participant.forfeited = true;
    participant.backgroundedAt = null;
    participant.socketId = null;
    clearBackgroundTimer(participant.playerId);
  }

  const opponent = getOpponentParticipant(room, active.playerId);
  if (opponent && opponent.socketId && !opponent.finished) {
    io.to(opponent.socketId).emit("opponent_left", {
      roomId: active.roomId,
      reason: "cancel",
    });
  }

  cleanupRoomIfSettled(active.roomId);
}

function handleSocketDisconnect(socket, reason) {
  const active = activeRooms.get(socket.id);
  if (!active) return;

  const room = roomStates.get(active.roomId);
  if (!room) {
    activeRooms.delete(socket.id);
    return;
  }

  const participant = room.participants.get(active.playerId);
  if (!participant) {
    activeRooms.delete(socket.id);
    return;
  }

  activeRooms.delete(socket.id);
  participant.socketId = null;

  if (participant.finished || participant.forfeited) {
    cleanupRoomIfSettled(active.roomId);
    return;
  }

  participant.backgroundedAt = Date.now();
  scheduleBackgroundForfeit(active.roomId, participant.playerId);

  console.log("Socket background grace başladı:", socket.id, active.roomId, reason);
}

app.get("/", (req, res) => {
  res.json({
    ok: true,
    service: "target-number-matchmaking",
    socket: "socket.io",
    socketPath: SOCKET_PATH,
    database: Boolean(pool),
    leaderboard: Boolean(pool),
    transports: ["websocket", "polling"],
    waitingQueues: Array.from(waitingQueues.entries()).map(([key, queue]) => ({
      key,
      count: queue.length,
    })),
    activeRooms: roomStates.size,
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
    console.error("Health check DB error:", {
      message: error.message,
      code: error.code,
      detail: error.detail,
      stack: error.stack,
    });

    res.status(500).json({
      ok: false,
      database: false,
      message: "Veritabanına erişilemiyor.",
    });
  }
});

io.on("connection", (socket) => {
  console.log("Socket connected:", socket.id);

  socket.on("error", (error) => {
    console.error("Socket error:", socket.id, error?.message || error);
  });

  socket.conn.on("packet", (packet) => {
    if (packet.type === "ping" || packet.type === "pong") return;
    console.log("Socket packet:", socket.id, packet.type, packet.data ? "with data" : "");
  });

  socket.conn.on("upgrade", (transport) => {
    console.log("Socket upgraded:", socket.id, "transport:", transport.name);
  });

  socket.on("join_match", (payload = {}) => {
    const gameKey = normalizeMatchGameKey(payload.gameKey);
    const difficulty = String(payload.difficulty || "Medium");
    const player = safePlayer(payload.player, socket.id);
    const puzzle = safePuzzle(payload.puzzle, difficulty);

    if (!player.id) {
      socket.emit("match_error", {
        message: "playerId zorunlu.",
      });
      return;
    }

    if (!puzzle) {
      socket.emit("match_error", {
        message: "Geçersiz puzzle verisi.",
      });
      return;
    }

    removeFromAllQueues(socket.id);
    removePrivateRoomsForSocket(socket.id, false);
    leaveRoomAsCancel(socket);

    const key = queueKey(gameKey, difficulty);
    const queue = waitingQueues.get(key) || [];

    while (queue.length > 0) {
      const opponent = queue.shift();
      const opponentSocket = io.sockets.sockets.get(opponent.socketId);

      if (!opponentSocket || opponentSocket.id === socket.id) {
        continue;
      }

      waitingQueues.set(key, queue);

      const selectedPuzzle = opponent.puzzle || puzzle;
      const roomId = createRealtimeRoom(
        socket,
        opponentSocket,
        gameKey,
        difficulty,
        selectedPuzzle,
        player,
        opponent.player
      );
      const room = roomStates.get(roomId);

      socket.emit("match_found", buildMatchPayload(room, player.id));
      opponentSocket.emit("match_found", buildMatchPayload(room, opponent.player.id));

      console.log("Match found:", roomId, key);

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

    console.log("Player waiting:", socket.id, key);
  });

  socket.on("create_friend_room", (payload = {}) => {
    expireOldPrivateRooms();

    const gameKey = String(payload.gameKey || "target_number");
    const difficulty = String(payload.difficulty || "Medium");
    const player = safePlayer(payload.player, socket.id);
    const puzzle = safePuzzle(payload.puzzle, difficulty);

    if (!player.id) {
      socket.emit("friend_room_error", {
        message: "playerId zorunlu.",
      });
      return;
    }

    if (!puzzle) {
      socket.emit("friend_room_error", {
        message: "Geçersiz puzzle verisi.",
      });
      return;
    }

    removeFromAllQueues(socket.id);
    removePrivateRoomsForSocket(socket.id, false);
    leaveRoomAsCancel(socket);

    const roomCode = generateUniqueRoomCode();

    privateRooms.set(roomCode, {
      roomCode,
      ownerSocketId: socket.id,
      gameKey,
      difficulty,
      player,
      puzzle,
      createdAt: Date.now(),
    });

    socket.emit("friend_room_created", {
      roomCode,
      gameKey,
      difficulty,
    });

    console.log("Friend room created:", roomCode, socket.id, queueKey(gameKey, difficulty));
  });

  socket.on("join_friend_room", (payload = {}) => {
    expireOldPrivateRooms();

    const roomCode = normalizeRoomCode(payload.roomCode);
    const room = privateRooms.get(roomCode);

    if (!roomCode || roomCode.length !== 6) {
      socket.emit("friend_room_error", {
        message: "Geçerli 6 haneli oda kodu gir.",
      });
      return;
    }

    if (!room) {
      socket.emit("friend_room_error", {
        message: "Oda bulunamadı. Kodu kontrol edip tekrar deneyin.",
      });
      return;
    }

    if (room.ownerSocketId === socket.id) {
      socket.emit("friend_room_error", {
        message: "Kendi oluşturduğun odaya aynı cihazdan katılamazsın.",
      });
      return;
    }

    const ownerSocket = io.sockets.sockets.get(room.ownerSocketId);

    if (!ownerSocket) {
      privateRooms.delete(roomCode);

      socket.emit("friend_room_error", {
        message: "Oda sahibi bağlantıdan ayrılmış.",
      });
      return;
    }

    const player = safePlayer(payload.player, socket.id);

    if (!player.id) {
      socket.emit("friend_room_error", {
        message: "playerId zorunlu.",
      });
      return;
    }

    removeFromAllQueues(socket.id);
    removePrivateRoomsForSocket(socket.id, false);
    leaveRoomAsCancel(socket);

    privateRooms.delete(roomCode);

    const roomId = createRealtimeRoom(
      socket,
      ownerSocket,
      room.gameKey,
      room.difficulty,
      room.puzzle,
      player,
      room.player
    );
    const activeRoom = roomStates.get(roomId);

    socket.emit("match_found", buildMatchPayload(activeRoom, player.id, { roomCode }));
    ownerSocket.emit("match_found", buildMatchPayload(activeRoom, room.player.id, { roomCode }));

    console.log("Friend match found:", roomCode, roomId, queueKey(room.gameKey, room.difficulty));
  });

  socket.on("player_finished", (payload = {}) => {
    const roomId = String(payload.roomId || "");
    const elapsedMs = Math.max(1, Number(payload.elapsedMs || 0));
    const mapping = activeRooms.get(socket.id);

    if (!roomId || !Number.isFinite(elapsedMs) || !mapping || mapping.roomId !== roomId) return;

    const room = roomStates.get(roomId);
    if (!room) return;

    const participant = room.participants.get(mapping.playerId);
    if (!participant) return;

    participant.finished = true;
    participant.finishedElapsedMs = Math.floor(elapsedMs);
    participant.backgroundedAt = null;
    clearBackgroundTimer(participant.playerId);

    const opponent = getOpponentParticipant(room, participant.playerId);
    if (opponent && opponent.socketId) {
      io.to(opponent.socketId).emit("opponent_finished", {
        roomId,
        elapsedMs: participant.finishedElapsedMs,
      });
    }

    cleanupRoomIfSettled(roomId);
  });

  socket.on("player_backgrounded", (payload = {}) => {
    const roomId = String(payload.roomId || "");
    const playerId = safePlayerId(payload.playerId);
    const mapping = activeRooms.get(socket.id);

    const resolvedRoomId = roomId || mapping?.roomId || "";
    const resolvedPlayerId = playerId || mapping?.playerId || "";

    if (!resolvedRoomId || !resolvedPlayerId) return;

    markParticipantBackgrounded(resolvedRoomId, resolvedPlayerId);
  });

  socket.on("resume_match", (payload = {}) => {
    const roomId = String(payload.roomId || "");
    const gameKey = normalizeMatchGameKey(payload.gameKey);
    const playerId = safePlayerId(payload.playerId);

    if (!roomId || !playerId) {
      socket.emit("resume_error", {
        message: "Tekrar bağlanmak için geçerli roomId ve playerId gerekli.",
      });
      return;
    }

    const room = roomStates.get(roomId);
    if (!room) {
      socket.emit("resume_error", {
        message: "Maç bulunamadı veya zaten kapandı.",
      });
      return;
    }

    if (room.gameKey !== gameKey) {
      socket.emit("resume_error", {
        message: "Maç bilgisi eşleşmedi.",
      });
      return;
    }

    const participant = room.participants.get(playerId);
    if (!participant) {
      socket.emit("resume_error", {
        message: "Bu oyuncu için aktif maç bulunamadı.",
      });
      return;
    }

    if (participant.forfeited) {
      socket.emit("resume_error", {
        message: "1 dakikalık süre dolduğu için maça tekrar bağlanılamadı.",
      });
      return;
    }

    if (participant.finished) {
      socket.emit("resume_error", {
        message: "Bu maç zaten tamamlandı.",
      });
      return;
    }

    if (
      participant.backgroundedAt &&
      Date.now() - participant.backgroundedAt > RECONNECT_GRACE_MS
    ) {
      participant.forfeited = true;
      clearBackgroundTimer(participant.playerId);

      const opponent = getOpponentParticipant(room, participant.playerId);
      if (opponent && opponent.socketId && !opponent.finished) {
        io.to(opponent.socketId).emit("opponent_left", {
          roomId,
          reason: "timeout",
        });
      }

      removeRoomCompletely(roomId);

      socket.emit("resume_error", {
        message: "1 dakikalık süre dolduğu için maça tekrar bağlanılamadı.",
      });
      return;
    }

    clearBackgroundTimer(participant.playerId);
    participant.socketId = socket.id;
    participant.backgroundedAt = null;

    socket.join(roomId);

    const opponent = getOpponentParticipant(room, participant.playerId);
    setActiveRoomMapping(
      socket.id,
      roomId,
      opponent?.socketId || null,
      room.gameKey,
      room.difficulty,
      participant.playerId
    );

    if (opponent && opponent.socketId) {
      const opponentMapping = activeRooms.get(opponent.socketId);
      if (opponentMapping) {
        opponentMapping.opponentId = socket.id;
        activeRooms.set(opponent.socketId, opponentMapping);
      }
    }

    socket.emit(
      "match_resumed",
      buildMatchPayload(room, participant.playerId, {
        resumed: true,
        opponentFinishedMs: opponent?.finishedElapsedMs || 0,
      })
    );

    console.log("Match resumed:", roomId, playerId, socket.id);
  });

  socket.on("cancel_match", () => {
    removeFromAllQueues(socket.id);
    removePrivateRoomsForSocket(socket.id, false);
    leaveRoomAsCancel(socket);
  });

  socket.on("disconnect", (reason) => {
    console.log("Socket disconnected:", socket.id, reason);
    removeFromAllQueues(socket.id);
    removePrivateRoomsForSocket(socket.id, false);
    handleSocketDisconnect(socket, reason);
  });
});

setInterval(expireOldPrivateRooms, 60_000).unref();

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