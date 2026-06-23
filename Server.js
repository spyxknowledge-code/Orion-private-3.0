const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { DatabaseSync } = require('node:sqlite');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(express.static('public'));
app.use(express.json());

const db = new DatabaseSync('orionchat.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    email TEXT,
    password_hash TEXT,
    room_id TEXT,
    joined_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS rooms (
    id TEXT PRIMARY KEY,
    password TEXT NOT NULL,
    created_by TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id TEXT,
    sender TEXT,
    encrypted_text TEXT,
    iv TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    edited BOOLEAN DEFAULT 0,
    read_by TEXT DEFAULT '[]'
  );
`);

function getRoomPassword(roomId) {
  const stmt = db.prepare('SELECT password FROM rooms WHERE id = ?');
  const row = stmt.get(roomId);
  return row ? row.password : null;
}

app.post('/register', (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: 'All fields required' });
  const hash = bcrypt.hashSync(password, 10);
  const insert = db.prepare('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)');
  try { insert.run(username, email, hash); } catch (e) { return res.status(400).json({ error: 'Username or email already taken' }); }
  const token = jwt.sign({ username }, 'orionsecret', { expiresIn: '7d' });
  res.json({ token, username });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user) return res.status(401).json({ error: 'User not found' });
  const valid = bcrypt.compareSync(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Wrong password' });
  const token = jwt.sign({ username }, 'orionsecret', { expiresIn: '7d' });
  res.json({ token, username });
});

app.post('/create_room', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  let decoded;
  try { decoded = jwt.verify(token, 'orionsecret'); } catch (e) { return res.status(401).json({ error: 'Invalid token' }); }
  const { roomId, password } = req.body;
  if (!roomId || !password) return res.status(400).json({ error: 'Room ID and password required' });
  const exists = db.prepare('SELECT id FROM rooms WHERE id = ?').get(roomId);
  if (exists) return res.status(400).json({ error: 'Room ID already taken' });
  const insert = db.prepare('INSERT INTO rooms (id, password, created_by) VALUES (?, ?, ?)');
  insert.run(roomId, password, decoded.username);
  db.prepare('UPDATE users SET room_id = ? WHERE username = ?').run(roomId, decoded.username);
  res.json({ success: true, roomId });
});

app.post('/join_room', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  let decoded;
  try { decoded = jwt.verify(token, 'orionsecret'); } catch (e) { return res.status(401).json({ error: 'Invalid token' }); }
  const { roomId, password } = req.body;
  if (!roomId || !password) return res.status(400).json({ error: 'Room ID and password required' });
  const storedPass = getRoomPassword(roomId);
  if (!storedPass || storedPass !== password) return res.status(401).json({ error: 'Invalid room ID or password' });
  db.prepare('UPDATE users SET room_id = ? WHERE username = ?').run(roomId, decoded.username);
  res.json({ success: true, roomId });
});

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('No token'));
  try {
    const decoded = jwt.verify(token, 'orionsecret');
    const user = db.prepare('SELECT room_id FROM users WHERE username = ?').get(decoded.username);
    if (!user || !user.room_id) return next(new Error('User not in any room'));
    socket.user = { username: decoded.username, room: user.room_id };
    next();
  } catch (e) { next(new Error('Invalid token')); }
});

const rooms = {};

io.on('connection', (socket) => {
  const { username, room } = socket.user;
  socket.join(room);
  if (!rooms[room]) rooms[room] = [];
  rooms[room].push(username);
  socket.to(room).emit('user-joined', { username, count: rooms[room].length });
  io.to(room).emit('online-count', rooms[room].length);

  const stmt = db.prepare('SELECT id, sender, encrypted_text, iv, timestamp, edited, read_by FROM messages WHERE room_id = ? ORDER BY timestamp DESC LIMIT 50');
  const msgs = stmt.all(room).reverse();
  socket.emit('history', msgs);

  socket.on('send-message', (data) => {
    const { encrypted, iv } = data;
    const insert = db.prepare('INSERT INTO messages (room_id, sender, encrypted_text, iv, read_by) VALUES (?, ?, ?, ?, ?)');
    const result = insert.run(room, username, encrypted, iv, JSON.stringify([]));
    const msgId = result.lastInsertRowid;
    io.to(room).emit('new-message', {
      id: msgId,
      sender: username,
      encrypted,
      iv,
      timestamp: new Date().toISOString(),
      edited: false,
      read_by: []
    });
  });

  socket.on('edit-message', (data) => {
    const { msgId, encrypted, iv } = data;
    const row = db.prepare('SELECT sender FROM messages WHERE id = ? AND room_id = ?').get(msgId, room);
    if (!row || row.sender !== username) return;
    const update = db.prepare('UPDATE messages SET encrypted_text = ?, iv = ?, edited = 1 WHERE id = ?');
    update.run(encrypted, iv, msgId);
    io.to(room).emit('message-edited', { msgId, encrypted, iv });
  });

  socket.on('mark-read', (msgIds) => {
    if (!Array.isArray(msgIds) || msgIds.length === 0) return;
    msgIds.forEach(id => {
      const msg = db.prepare('SELECT read_by FROM messages WHERE id = ? AND room_id = ?').get(id, room);
      if (!msg) return;
      let readers = JSON.parse(msg.read_by || '[]');
      if (!readers.includes(username)) {
        readers.push(username);
        db.prepare('UPDATE messages SET read_by = ? WHERE id = ?').run(JSON.stringify(readers), id);
        io.to(room).emit('message-read', { msgId: id, reader: username });
      }
    });
  });

  socket.on('typing', (isTyping) => {
    socket.to(room).emit('user-typing', { username, isTyping });
  });

  socket.on('disconnect', () => {
    if (rooms[room]) {
      rooms[room] = rooms[room].filter(u => u !== username);
      io.to(room).emit('user-left', { username, count: rooms[room].length });
      io.to(room).emit('online-count', rooms[room].length);
    }
  });
});

const PORT = process.env.PORT || 3003;
server.listen(PORT, '0.0.0.0', () => console.log(`Orion Private Chat running on port ${PORT}`));
