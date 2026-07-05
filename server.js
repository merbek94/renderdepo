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

  // Basit kötüye kullanım freni.
  // Gerçek güvenlik için skoru sunucu tarafında doğrulamak gerekir.
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

async function upsertPlayer(client, playerId, username, country) {
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

    console.error("leaderboard sync error:", error);

    res.status(500).json({
      ok: false,
      message: "Skor senkronize edilemedi.",
    });
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

    console.error("leaderboard add error:", error);

    res.status(500).json({
      ok: false,
      message: "Skor kaydedilemedi.",
    });
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
      error: process.env.NODE_ENV === "production" ? undefined : error.message,
    });
  }
});  if (!requireDatabase(res)) return;

  const scoreType = req.query.scoreType === "infinite" ? "infinite" : "general";
  const period = req.query.period === "month" ? "month" : "all";
  const scope = req.query.scope === "country" ? "country" : "world";
  const country = safeCountry(req.query.country);
  const playerId = safePlayerId(req.query.playerId);
  const monthKey = currentMonthKey();

  const scoreColumn = scoreType === "infinite" ? "infinite_score" : "general_score";
  const tableName = period === "month" ? "player_monthly_scores" : "player_scores";
  const monthWhere = period === "month" ? "AND s.month_key = $1" : "";
  const params = period === "month" ? [monthKey] : [];

  try {
    const worldRankSql = `
      WITH ranked AS (
        SELECT 
          p.player_id,
          p.username,
          p.country,
          s.${scoreColumn} AS score,
          ROW_NUMBER() OVER (
            ORDER BY s.${scoreColumn} DESC, p.updated_at ASC, p.username ASC
          ) AS rank
        FROM ${tableName} s
        JOIN players p ON p.player_id = s.player_id
        WHERE s.${scoreColumn} > 0 ${monthWhere}
      )
      SELECT * FROM ranked
    `;

    const countryRankSql = `
      WITH ranked AS (
        SELECT 
          p.player_id,
          p.username,
          p.country,
          s.${scoreColumn} AS score,
          ROW_NUMBER() OVER (
            ORDER BY s.${scoreColumn} DESC, p.updated_at ASC, p.username ASC
          ) AS rank
        FROM ${tableName} s
        JOIN players p ON p.player_id = s.player_id
        WHERE s.${scoreColumn} > 0 ${monthWhere} 
          AND p.country = $${params.length + 1}
      )
      SELECT * FROM ranked
    `;

    const listSql = `
      WITH ranked AS (
        SELECT 
          p.player_id,
          p.username,
          p.country,
          s.${scoreColumn} AS score,
          ROW_NUMBER() OVER (
            ORDER BY s.${scoreColumn} DESC, p.updated_at ASC, p.username ASC
          ) AS rank
        FROM ${tableName} s
        JOIN players p ON p.player_id = s.player_id
        WHERE s.${scoreColumn} > 0 ${monthWhere}
        ${scope === "country" ? `AND p.country = $${params.length + 1}` : ""}
      )
      SELECT rank, username, country, score
      FROM ranked
      ORDER BY rank ASC
      LIMIT 50
    `;

    const worldResult = await pool.query(worldRankSql, params);
    const countryResult = await pool.query(countryRankSql, [...params, country]);

    const listResult = await pool.query(
      listSql,
      scope === "country" ? [...params, country] : params
    );

    const worldMe = playerId
      ? worldResult.rows.find((row) => row.player_id === playerId)
      : null;

    const countryMe = playerId
      ? countryResult.rows.find((row) => row.player_id === playerId)
      : null;

    res.json({
      ok: true,
      scoreType,
      period,
      scope,
      country,
      monthKey,
      myWorldRank: worldMe ? Number(worldMe.rank) : null,
      myCountryRank: countryMe ? Number(countryMe.rank) : null,
      myScore: worldMe ? Number(worldMe.score) : 0,
      rows: listResult.rows.map((row) => ({
        rank: Number(row.rank),
        username: row.username,
        country: row.country,
        score: Number(row.score),
      })),
    });
  } catch (error) {
    console.error("leaderboard get error:", error);

    res.status(500).json({
      ok: false,
      message: "Skor tablosu alınamadı.",
    });
  }
});

const io = new Server(server, {
  // Android tarafıyla aynı path. Android URL'sine /socket.io yazma; sadece base URL kullan.
  path: SOCKET_PATH,

  // Mobil uygulama native client olduğu için Origin bazen boş gelebilir.
  // Origin kısıtı yüzünden xhr poll/websocket hatası almamak için burada serbest bırakıyoruz.
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

function queueKey(gameKey, difficulty) {
  return `${String(gameKey || "default")}::${String(difficulty || "default")}`;
}

function safePlayer(rawPlayer) {
  const name = String(rawPlayer?.name || "Oyuncu").trim().slice(0, 24) || "Oyuncu";
  const country = String(rawPlayer?.country || "").trim().toUpperCase().slice(0, 3);

  return {
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

function removeFromAllQueues(socketId) {
  for (const [key, queue] of waitingQueues.entries()) {
    const filtered = queue.filter((item) => item.socketId !== socketId);

    if (filtered.length === 0) {
      waitingQueues.delete(key);
    } else {
      waitingQueues.set(key, filtered);
    }
  }
}

function leaveRoomAsCancel(socket) {
  const room = activeRooms.get(socket.id);

  if (!room) return;

  socket.to(room.roomId).emit("opponent_left", {
    roomId: room.roomId,
    reason: "cancelled",
  });

  const opponentSocket = io.sockets.sockets.get(room.opponentId);

  if (opponentSocket) {
    activeRooms.delete(opponentSocket.id);
    opponentSocket.leave(room.roomId);
  }

  activeRooms.delete(socket.id);
  socket.leave(room.roomId);
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
    activeRooms: activeRooms.size / 2,
  });
});

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    database: Boolean(pool),
  });
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
    const gameKey = String(payload.gameKey || "target_number");
    const difficulty = String(payload.difficulty || "Medium");
    const player = safePlayer(payload.player);
    const puzzle = safePuzzle(payload.puzzle, difficulty);

    if (!puzzle) {
      socket.emit("match_error", {
        message: "Geçersiz puzzle verisi.",
      });
      return;
    }

    removeFromAllQueues(socket.id);
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

      const roomId =
        typeof crypto.randomUUID === "function"
          ? crypto.randomUUID()
          : crypto.randomBytes(16).toString("hex");

      const selectedPuzzle = opponent.puzzle || puzzle;

      socket.join(roomId);
      opponentSocket.join(roomId);

      activeRooms.set(socket.id, {
        roomId,
        opponentId: opponentSocket.id,
        gameKey,
        difficulty,
      });

      activeRooms.set(opponentSocket.id, {
        roomId,
        opponentId: socket.id,
        gameKey,
        difficulty,
      });

      socket.emit("match_found", {
        roomId,
        opponent: opponent.player,
        puzzle: selectedPuzzle,
      });

      opponentSocket.emit("match_found", {
        roomId,
        opponent: player,
        puzzle: selectedPuzzle,
      });

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

  socket.on("player_finished", (payload = {}) => {
    const roomId = String(payload.roomId || "");
    const elapsedMs = Math.max(1, Number(payload.elapsedMs || 0));

    if (!roomId || !Number.isFinite(elapsedMs)) return;

    socket.to(roomId).emit("opponent_finished", {
      roomId,
      elapsedMs: Math.floor(elapsedMs),
    });
  });

  socket.on("cancel_match", () => {
    removeFromAllQueues(socket.id);
    leaveRoomAsCancel(socket);
  });

  socket.on("disconnect", (reason) => {
    console.log("Socket disconnected:", socket.id, reason);
    removeFromAllQueues(socket.id);
    leaveRoomAsCancel(socket);
  });
});

const PORT = Number(process.env.PORT || 10000);

initDatabase()
  .catch((error) => {
    console.error("Database init failed:", error);
  })
  .finally(() => {
    server.listen(PORT, "0.0.0.0", () => {
      console.log(`Target number matchmaking server running on port ${PORT}`);
    });
  });