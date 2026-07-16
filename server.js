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

function safeSignedDelta(value) {
  const number = Number(value || 0);
  const maxDelta = Number(process.env.MAX_SCORE_DELTA || 100_000);

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
         general_score = $2,
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
  const generalDelta = safeSignedDelta(req.body.generalScoreDelta);
  const infiniteDelta = safeDelta(req.body.infiniteScoreDelta);
  const monthKey = currentMonthKey();

  if (!playerId) {
    res.status(400).json({
      ok: false,
      message: "playerId zorunlu.",
    });

    return;
  }

  if (generalDelta === 0 && infiniteDelta <= 0) {
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
         general_score = GREATEST(0, LEAST(general_score + $2, 2000000000)),
         infinite_score = LEAST(infinite_score + $3, 2000000000),
         updated_at = NOW()
       WHERE player_id = $1`,
      [playerId, generalDelta, infiniteDelta]
    );

    await client.query(
      `INSERT INTO player_monthly_scores
         (player_id, month_key, general_score, infinite_score, updated_at)
       VALUES
         ($1, $2, GREATEST($3, 0), $4, NOW())
       ON CONFLICT (player_id, month_key)
       DO UPDATE SET
         general_score = GREATEST(
           0,
           LEAST(player_monthly_scores.general_score + $3, 2000000000)
         ),
         infinite_score = LEAST(
           player_monthly_scores.infinite_score + EXCLUDED.infinite_score,
           2000000000
         ),
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

    return {
      values,
      whereSql: conditions.join(" AND "),
    };
  }

  async function getMyRank(includeCountry) {
    if (!playerId) return null;

    const built = buildWhere(includeCountry);
    const values = [...built.values, playerId];
    const playerParamIndex = values.length;

    const sql = `
      WITH ranked AS (
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
        WHERE ${built.whereSql}
      )
      SELECT position, score
      FROM ranked
      WHERE player_id = $${playerParamIndex}
      LIMIT 1
    `;

    const result = await pool.query(sql, values);
    const row = result.rows[0];

    if (!row) return null;

    return {
      rank: Number(row.position),
      score: Number(row.score),
    };
  }

  try {
    const listBuilt = buildWhere(scope === "country");

    const listSql = `
      WITH ranked AS (
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
      LIMIT 50
    `;

    const listResult = await pool.query(listSql, listBuilt.values);

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

  transports: ["websocket", "polling"],
  allowEIO3: true,
  pingInterval: 25000,
  pingTimeout: 20000,

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
const PRIVATE_ROOM_TTL_MS = Number(process.env.PRIVATE_ROOM_TTL_MS || 15 * 60 * 1000);
const ROOM_RECONNECT_TIMEOUT_MS = Number(process.env.ROOM_RECONNECT_TIMEOUT_MS || 60 * 1000);
const RESOLVED_ROOM_TTL_MS = Number(process.env.RESOLVED_ROOM_TTL_MS || 10 * 60 * 1000);

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

function safePlayerId(value, fallback = "") {
  const cleaned = String(value || fallback || "")
    .trim()
    .replace(/[^a-zA-Z0-9_.:-]/g, "")
    .slice(0, 96);

  return cleaned || String(fallback || "").trim().slice(0, 96);
}

function safePlayer(rawPlayer, fallbackId = "") {
  const id = safePlayerId(rawPlayer?.id, fallbackId);
  const name = String(rawPlayer?.name || "Oyuncu").trim().slice(0, 24) || "Oyuncu";
  const country = String(rawPlayer?.country || "").trim().toUpperCase().slice(0, 3);

  return {
    id,
    name,
    country,
  };
}

function safePuzzle(rawPuzzle, difficulty) {
  const numbers = Array.isArray(rawPuzzle?.numbers)
    ? rawPuzzle.numbers
        .map((n) => Number(n))
        .filter((n) => Number.isFinite(n))
        .slice(0, 8)
    : [];

  const target = Number(rawPuzzle?.target);

  if (!Number.isFinite(target) || target <= 0 || numbers.length < 3) {
    return null;
  }

  return {
    difficulty: String(rawPuzzle?.difficulty || difficulty || "Medium"),
    target: Math.floor(target),
    numbers: numbers.map((n) => Math.floor(n)),
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
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let code = "";

  for (let i = 0; i < 6; i += 1) {
    code += alphabet[crypto.randomInt(0, alphabet.length)];
  }

  return code;
}

function generateUniqueRoomCode() {
  for (let attempt = 0; attempt < 32; attempt += 1) {
    const code = generateRoomCode();

    if (!privateRooms.has(code)) {
      return code;
    }
  }

  return crypto.randomBytes(4).toString("hex").toUpperCase().slice(0, 6);
}

function roomParticipants(room) {
  return Object.values(room?.participants || {});
}

function getParticipant(room, playerId) {
  if (!room || !playerId) return null;
  return room.participants[playerId] || null;
}

function getOpponentParticipant(room, playerId) {
  return roomParticipants(room).find((participant) => participant.playerId !== playerId) || null;
}

function clearParticipantTimeout(participant) {
  if (participant?.timeoutHandle) {
    clearTimeout(participant.timeoutHandle);
    participant.timeoutHandle = null;
  }
}

function clearRoomTimeouts(room) {
  roomParticipants(room).forEach(clearParticipantTimeout);
}

function attachSocketToRoom(socket, room, playerId) {
  const participant = getParticipant(room, playerId);
  if (!participant) return;

  participant.socketId = socket.id;
  participant.connected = true;
  socket.join(room.roomId);
  activeRooms.set(socket.id, {
    roomId: room.roomId,
    playerId,
  });
}

function clearParticipantAwayState(room, playerId) {
  const participant = getParticipant(room, playerId);
  if (!participant) return;

  clearParticipantTimeout(participant);
  participant.connected = true;
  participant.awaySince = null;
  participant.backgrounded = false;
  participant.reconnectDeadlineAt = null;
}

function markRoomResolved(room, reason, winnerPlayerId, loserPlayerId) {
  if (!room || room.resolved) return;

  room.resolved = true;
  room.resolvedReason = reason;
  room.winnerPlayerId = winnerPlayerId || null;
  room.loserPlayerId = loserPlayerId || null;
  room.resolvedAt = Date.now();
  clearRoomTimeouts(room);
}

function resolveRoomByAwayTimeout(roomId, loserPlayerId) {
  const room = realtimeRooms.get(roomId);
  if (!room || room.resolved) return;

  const loser = getParticipant(room, loserPlayerId);
  const opponent = getOpponentParticipant(room, loserPlayerId);

  if (!loser || loser.finishedAt) return;

  markRoomResolved(room, "timeout", opponent?.playerId, loserPlayerId);

  const opponentSocket = opponent?.socketId
    ? io.sockets.sockets.get(opponent.socketId)
    : null;

  if (opponentSocket && !opponent.finishedAt) {
    opponentSocket.emit("opponent_left", {
      roomId,
      reason: "timeout",
    });
  }

  const loserSocket = loser.socketId ? io.sockets.sockets.get(loser.socketId) : null;
  if (loserSocket) {
    loserSocket.emit("resume_error", {
      code: "RECONNECT_EXPIRED",
      message: "1 dakika içinde oyuna dönmediğiniz için mağlup sayıldınız.",
      opponentFinishedMs: Number(opponent?.elapsedMs || 0),
    });
  }

  console.log("Reconnect timeout loss:", roomId, loserPlayerId);
}

function scheduleParticipantAwayTimeout(room, playerId) {
  const participant = getParticipant(room, playerId);

  if (!room || room.resolved || !participant || participant.finishedAt) {
    return;
  }

  if (!participant.awaySince) {
    participant.awaySince = Date.now();
  }

  participant.reconnectDeadlineAt = participant.awaySince + ROOM_RECONNECT_TIMEOUT_MS;

  clearParticipantTimeout(participant);

  const waitMs = Math.max(0, participant.reconnectDeadlineAt - Date.now());

  participant.timeoutHandle = setTimeout(() => {
    resolveRoomByAwayTimeout(room.roomId, playerId);
  }, waitMs);

  if (typeof participant.timeoutHandle.unref === "function") {
    participant.timeoutHandle.unref();
  }
}

function createRealtimeRoom(socket, player, opponentSocket, opponentPlayer, gameKey, difficulty, puzzle) {
  const roomId =
    typeof crypto.randomUUID === "function"
      ? crypto.randomUUID()
      : crypto.randomBytes(16).toString("hex");

  const room = {
    roomId,
    gameKey,
    difficulty,
    puzzle,
    createdAt: Date.now(),
    resolved: false,
    resolvedReason: null,
    resolvedAt: null,
    winnerPlayerId: null,
    loserPlayerId: null,
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
  attachSocketToRoom(socket, room, player.id);
  attachSocketToRoom(opponentSocket, room, opponentPlayer.id);

  return room;
}

function removePrivateRoomsForSocket(socketId, notify = true) {
  for (const [roomCode, room] of privateRooms.entries()) {
    if (room.ownerSocketId !== socketId) continue;

    privateRooms.delete(roomCode);

    const ownerSocket = io.sockets.sockets.get(socketId);
    if (notify && ownerSocket) {
      ownerSocket.emit("friend_room_closed", {
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

    const ownerSocket = io.sockets.sockets.get(room.ownerSocketId);
    if (ownerSocket) {
      ownerSocket.emit("friend_room_closed", {
        roomCode,
        reason: "expired",
      });
    }
  }
}

function expireResolvedRooms() {
  const now = Date.now();

  for (const [roomId, room] of realtimeRooms.entries()) {
    if (!room.resolved || !room.resolvedAt) continue;
    if (now - room.resolvedAt <= RESOLVED_ROOM_TTL_MS) continue;

    clearRoomTimeouts(room);
    realtimeRooms.delete(roomId);
  }
}

function removeFromAllQueues(socketId, playerId = "") {
  for (const [key, queue] of waitingQueues.entries()) {
    const filtered = queue.filter((item) => {
      if (item.socketId === socketId) return false;
      if (playerId && item.player?.id === playerId) return false;
      return true;
    });

    if (filtered.length === 0) {
      waitingQueues.delete(key);
    } else {
      waitingQueues.set(key, filtered);
    }
  }
}

function getRoomContextBySocket(socket) {
  const active = activeRooms.get(socket.id);
  if (!active) return {};

  const room = realtimeRooms.get(active.roomId);
  if (!room) {
    activeRooms.delete(socket.id);
    return {};
  }

  const participant = getParticipant(room, active.playerId);
  const opponent = getOpponentParticipant(room, active.playerId);

  return {
    active,
    room,
    participant,
    opponent,
  };
}

function leaveRoomAsCancel(socket) {
  const { active, room, participant, opponent } = getRoomContextBySocket(socket);
  if (!active) return;

  if (room && participant) {
    if (!room.resolved && !participant.finishedAt && opponent && !opponent.finishedAt) {
      markRoomResolved(room, "cancelled", opponent.playerId, participant.playerId);

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

    clearParticipantTimeout(participant);
    participant.connected = false;
    participant.awaySince = null;
    participant.backgrounded = false;
    participant.reconnectDeadlineAt = null;
    participant.socketId = null;
  }

  activeRooms.delete(socket.id);
  socket.leave(active.roomId);
}

function markSocketDisconnected(socket) {
  const { active, room, participant } = getRoomContextBySocket(socket);
  if (!active || !room || !participant) return;

  activeRooms.delete(socket.id);

  if (room.resolved || participant.finishedAt) {
    participant.connected = false;
    participant.socketId = null;
    return;
  }

  participant.connected = false;
  participant.socketId = null;
  if (!participant.awaySince) {
    participant.awaySince = Date.now();
  }
  scheduleParticipantAwayTimeout(room, participant.playerId);
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
    activeRooms: Array.from(realtimeRooms.values()).filter((room) => !room.resolved).length,
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

app.get("/socket-check", (req, res) => {
  res.json({
    ok: true,
    socketPath: SOCKET_PATH,
    androidUrlMustBe: "https://renderdepo-tpqh.onrender.com",
    androidUrlMustNotInclude: "/socket.io",
    transports: ["websocket", "polling"],
  });
});

io.engine.on("connection_error", (err) => {
  console.log("Engine.IO connection_error:", {
    code: err.code,
    message: err.message,
    context: err.context,
    url: err.req && err.req.url,
    userAgent: err.req && err.req.headers && err.req.headers["user-agent"],
    origin: err.req && err.req.headers && err.req.headers.origin,
  });
});

io.engine.on("connection", (rawSocket) => {
  console.log(
    "Engine.IO connected:",
    rawSocket.id,
    "transport:",
    rawSocket.transport.name
  );
});

io.on("connection", (socket) => {
  console.log(
    "Socket connected:",
    socket.id,
    "transport:",
    socket.conn.transport.name
  );

  socket.conn.on("upgrade", (transport) => {
    console.log("Socket upgraded:", socket.id, "transport:", transport.name);
  });

  socket.on("join_match", (payload = {}) => {
    const gameKey = normalizeMatchGameKey(payload.gameKey);
    const difficulty = String(payload.difficulty || "Medium");
    const player = safePlayer(payload.player, `guest:${socket.id}`);
    const puzzle = safePuzzle(payload.puzzle, difficulty);

    if (!puzzle) {
      socket.emit("match_error", {
        message: "Geçersiz puzzle verisi.",
      });

      return;
    }

    removeFromAllQueues(socket.id, player.id);
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

      if (opponent.player?.id && opponent.player.id === player.id) {
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

      console.log("Match found:", room.roomId, key);

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

    console.log("Player waiting:", socket.id, key, player.id);
  });

  socket.on("resume_match", (payload = {}) => {
    const roomId = String(payload.roomId || "").trim();
    const player = safePlayer(payload.player, `guest:${socket.id}`);
    const room = realtimeRooms.get(roomId);

    if (!roomId || !room) {
      socket.emit("resume_error", {
        code: "ROOM_NOT_FOUND",
        message: "Yeniden bağlanılacak aktif oda bulunamadı.",
      });
      return;
    }

    const participant = getParticipant(room, player.id);
    const opponent = getOpponentParticipant(room, player.id);

    if (!participant) {
      socket.emit("resume_error", {
        code: "PLAYER_NOT_FOUND",
        message: "Bu oyuncu için yeniden bağlanma bilgisi bulunamadı.",
      });
      return;
    }

    if (room.resolved) {
      socket.emit("resume_error", {
        code: "MATCH_RESOLVED",
        message: "Bu maç zaten sona ermiş.",
        opponentFinishedMs: Number(opponent?.elapsedMs || 0),
      });
      return;
    }

    if (participant.awaySince && Date.now() > participant.awaySince + ROOM_RECONNECT_TIMEOUT_MS) {
      resolveRoomByAwayTimeout(room.roomId, participant.playerId);
      socket.emit("resume_error", {
        code: "RECONNECT_EXPIRED",
        message: "1 dakikalık yeniden bağlanma süresi doldu.",
        opponentFinishedMs: Number(opponent?.elapsedMs || 0),
      });
      return;
    }

    if (participant.socketId && participant.socketId !== socket.id) {
      activeRooms.delete(participant.socketId);
    }

    attachSocketToRoom(socket, room, participant.playerId);
    clearParticipantAwayState(room, participant.playerId);

    socket.emit("resume_state", {
      roomId: room.roomId,
      opponent: {
        name: opponent?.name || "Rakip",
        country: opponent?.country || "",
      },
      puzzle: room.puzzle,
      opponentFinishedMs: Number(opponent?.elapsedMs || 0),
    });

    console.log("Match resumed:", room.roomId, participant.playerId, socket.id);
  });

  socket.on("player_backgrounded", (payload = {}) => {
    const fallbackActive = activeRooms.get(socket.id);
    const roomId = String(payload.roomId || fallbackActive?.roomId || "").trim();
    const room = realtimeRooms.get(roomId);
    const playerId =
      fallbackActive?.playerId ||
      roomParticipants(room).find((item) => item.socketId === socket.id)?.playerId;
    const participant = getParticipant(room, playerId);

    if (!room || !participant || room.resolved || participant.finishedAt) return;

    if (!participant.awaySince) {
      participant.awaySince = Date.now();
    }
    participant.backgrounded = true;
    scheduleParticipantAwayTimeout(room, participant.playerId);

    console.log("Player backgrounded:", roomId, participant.playerId);
  });

  socket.on("player_foregrounded", (payload = {}) => {
    const fallbackActive = activeRooms.get(socket.id);
    const roomId = String(payload.roomId || fallbackActive?.roomId || "").trim();
    const room = realtimeRooms.get(roomId);
    const playerId =
      fallbackActive?.playerId ||
      roomParticipants(room).find((item) => item.socketId === socket.id)?.playerId;
    const participant = getParticipant(room, playerId);

    if (!room || !participant) return;

    if (room.resolved && room.loserPlayerId === participant.playerId) {
      socket.emit("resume_error", {
        code: "RECONNECT_EXPIRED",
        message: "1 dakika içinde oyuna dönmediğiniz için mağlup sayıldınız.",
        opponentFinishedMs: Number(getOpponentParticipant(room, participant.playerId)?.elapsedMs || 0),
      });
      return;
    }

    clearParticipantAwayState(room, participant.playerId);
    console.log("Player foregrounded:", roomId, participant.playerId);
  });

  socket.on("create_friend_room", (payload = {}) => {
    expireOldPrivateRooms();

    const gameKey = String(payload.gameKey || "target_number");
    const difficulty = String(payload.difficulty || "Medium");
    const player = safePlayer(payload.player, `guest:${socket.id}`);
    const puzzle = safePuzzle(payload.puzzle, difficulty);

    if (!puzzle) {
      socket.emit("friend_room_error", {
        message: "Geçersiz puzzle verisi.",
      });

      return;
    }

    removeFromAllQueues(socket.id, player.id);
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

    const player = safePlayer(payload.player, `guest:${socket.id}`);

    removeFromAllQueues(socket.id, player.id);
    removePrivateRoomsForSocket(socket.id, false);
    leaveRoomAsCancel(socket);

    privateRooms.delete(roomCode);

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

    console.log("Friend match found:", roomCode, realtimeRoom.roomId, queueKey(room.gameKey, room.difficulty));
  });

  socket.on("player_finished", (payload = {}) => {
    const roomId = String(payload.roomId || "").trim();
    const elapsedMs = Math.max(1, Number(payload.elapsedMs || 0));
    const room = realtimeRooms.get(roomId);
    const active = activeRooms.get(socket.id);
    const playerId =
      active?.playerId ||
      roomParticipants(room).find((item) => item.socketId === socket.id)?.playerId;
    const participant = getParticipant(room, playerId);
    const opponent = getOpponentParticipant(room, playerId);

    if (!room || !participant || !Number.isFinite(elapsedMs) || room.resolved) return;

    participant.finishedAt = Date.now();
    participant.elapsedMs = Math.floor(elapsedMs);
    clearParticipantAwayState(room, participant.playerId);

    markRoomResolved(room, "finished", participant.playerId, opponent?.playerId);

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
    removePrivateRoomsForSocket(socket.id, false);
    leaveRoomAsCancel(socket);
  });

  socket.on("disconnect", (reason) => {
    console.log("Socket disconnected:", socket.id, reason);
    removeFromAllQueues(socket.id);
    removePrivateRoomsForSocket(socket.id, false);
    markSocketDisconnected(socket);
  });
});

setInterval(() => {
  expireOldPrivateRooms();
  expireResolvedRooms();
}, 60_000).unref();

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