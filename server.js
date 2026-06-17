const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const crypto = require("crypto");

const app = express();
app.use(express.json());

const server = http.createServer(app);

const allowedOrigin = process.env.CLIENT_ORIGIN || "*";
const io = new Server(server, {
  cors: {
    origin: allowedOrigin,
    methods: ["GET", "POST"],
  },
  // Android tarafında da doğrudan websocket kullanılmalı.
  // Bu ayar "xhr poll error" hatasını engellemek için eklendi.
  transports: ["websocket"],
  pingInterval: 25_000,
  pingTimeout: 20_000,
});

const waitingQueues = new Map(); // key -> [{ socketId, player, puzzle, joinedAt }]
const activeRooms = new Map(); // socketId -> { roomId, opponentId, gameKey, difficulty }

function queueKey(gameKey, difficulty) {
  return `${String(gameKey || "default")}::${String(difficulty || "default")}`;
}

function safePlayer(rawPlayer) {
  const name = String(rawPlayer?.name || "Oyuncu").trim().slice(0, 24) || "Oyuncu";
  const country = String(rawPlayer?.country || "").trim().toUpperCase().slice(0, 3);
  return { name, country };
}

function safePuzzle(rawPuzzle, difficulty) {
  const numbers = Array.isArray(rawPuzzle?.numbers)
    ? rawPuzzle.numbers.map((n) => Number(n)).filter((n) => Number.isFinite(n)).slice(0, 8)
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
    waitingQueues: Array.from(waitingQueues.entries()).map(([key, queue]) => ({
      key,
      count: queue.length,
    })),
    activeRooms: activeRooms.size / 2,
  });
});

app.get("/health", (req, res) => {
  res.json({ ok: true });
});

io.on("connection", (socket) => {
  socket.on("join_match", (payload = {}) => {
    const gameKey = String(payload.gameKey || "target_number");
    const difficulty = String(payload.difficulty || "Medium");
    const player = safePlayer(payload.player);
    const puzzle = safePuzzle(payload.puzzle, difficulty);

    if (!puzzle) {
      socket.emit("match_error", { message: "Geçersiz puzzle verisi." });
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

      return;
    }

    queue.push({
      socketId: socket.id,
      player,
      puzzle,
      joinedAt: Date.now(),
    });

    waitingQueues.set(key, queue);
    socket.emit("waiting", { gameKey, difficulty });
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

  socket.on("disconnect", () => {
    removeFromAllQueues(socket.id);
    leaveRoomAsCancel(socket);
  });
});

const PORT = Number(process.env.PORT || 10000);

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Target number matchmaking server running on port ${PORT}`);
});