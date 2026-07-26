require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'default_secret';
const ADMIN_KEY = process.env.ADMIN_KEY || 'admin123';

app.use(cors());
app.use(express.json());

const db = new sqlite3.Database('./data.db');
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    balance REAL DEFAULT 0,
    role TEXT DEFAULT 'user',
    temp BOOLEAN DEFAULT 0,
    expire INTEGER DEFAULT 0
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    lottery TEXT,
    code TEXT,
    multiple REAL,
    time TEXT,
    timestamp INTEGER,
    raw TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS paid_awards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    raw TEXT,
    UNIQUE(username, raw)
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time TEXT,
    user TEXT,
    type TEXT,
    amount REAL,
    balance REAL,
    detail TEXT
  )`);
});

function generateToken(username) {
  return jwt.sign({ username }, JWT_SECRET, { expiresIn: '7d' });
}

function verifyToken(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: '未登录' });
  const token = auth.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ error: '登录已过期' });
  }
}

function verifyAdmin(req, res, next) {
  db.get('SELECT role FROM users WHERE username = ?', [req.user.username], (err, user) => {
    if (err || !user || user.role !== 'admin') {
      return res.status(403).json({ error: '需要管理员权限' });
    }
    next();
  });
}

app.post('/api/register', (req, res) => {
  const { username, password, adminKey } = req.body;
  if (!username || !password || !adminKey) {
    return res.status(400).json({ error: '缺少参数' });
  }
  if (adminKey !== ADMIN_KEY) {
    return res.status(403).json({ error: '管理员密钥错误' });
  }
  db.get('SELECT username FROM users WHERE username = ?', [username], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (row) return res.status(400).json({ error: '用户名已存在' });
    const hashed = bcrypt.hashSync(password, 10);
    db.run('INSERT INTO users (username, password, balance, role) VALUES (?, ?, ?, ?)',
      [username, hashed, 100, 'user'],
      function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: '用户创建成功', username });
      }
    );
  });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: '请输入账号和密码' });
  }
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) return res.status(401).json({ error: '账号或密码错误' });
    if (user.temp && user.expire && Date.now() > user.expire) {
      db.run('DELETE FROM users WHERE username = ?', [username]);
      return res.status(401).json({ error: '试用已过期，请重新申请' });
    }
    if (!bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: '账号或密码错误' });
    }
    const token = generateToken(username);
    res.json({ token, username, balance: user.balance, role: user.role, temp: !!user.temp, expire: user.expire });
  });
});

app.get('/api/user', verifyToken, (req, res) => {
  db.get('SELECT username, balance, role, temp, expire FROM users WHERE username = ?', [req.user.username], (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) return res.status(404).json({ error: '用户不存在' });
    res.json(user);
  });
});

app.post('/api/change-password', verifyToken, (req, res) => {
  const { oldPassword, newPassword } = req.body;
  if (!oldPassword || !newPassword) return res.status(400).json({ error: '请完整填写' });
  db.get('SELECT password FROM users WHERE username = ?', [req.user.username], (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) return res.status(404).json({ error: '用户不存在' });
    if (!bcrypt.compareSync(oldPassword, user.password)) {
      return res.status(401).json({ error: '原密码错误' });
    }
    const hashed = bcrypt.hashSync(newPassword, 10);
    db.run('UPDATE users SET password = ? WHERE username = ?', [hashed, req.user.username], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      const logSql = 'INSERT INTO logs (time, user, type, amount, balance, detail) VALUES (?, ?, ?, ?, ?, ?)';
      db.run(logSql, [new Date().toISOString(), req.user.username, '修改密码', 0, 0, '密码已修改']);
      res.json({ message: '密码修改成功' });
    });
  });
});

app.post('/api/order', verifyToken, (req, res) => {
  const { lottery, codes, multiple } = req.body;
  if (!lottery || !codes || !Array.isArray(codes) || codes.length === 0) {
    return res.status(400).json({ error: '无效下单数据' });
  }
  const totalAmount = codes.length * multiple;
  db.get('SELECT balance FROM users WHERE username = ?', [req.user.username], (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) return res.status(404).json({ error: '用户不存在' });
    if (user.balance < totalAmount) {
      return res.status(400).json({ error: '余额不足' });
    }
    db.run('UPDATE users SET balance = balance - ? WHERE username = ?', [totalAmount, req.user.username], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      const now = new Date();
      const timeStr = now.toISOString().replace('T', ' ').slice(0, 16);
      const timestamp = now.getTime();
      const stmt = db.prepare('INSERT INTO orders (username, lottery, code, multiple, time, timestamp, raw) VALUES (?, ?, ?, ?, ?, ?, ?)');
      codes.forEach(code => {
        const raw = `${lottery} | ${code} = ${multiple} | ${timeStr}`;
        stmt.run([req.user.username, lottery, code, multiple, timeStr, timestamp, raw]);
      });
      stmt.finalize();
      const logSql = 'INSERT INTO logs (time, user, type, amount, balance, detail) VALUES (?, ?, ?, ?, ?, ?)';
      db.run(logSql, [timeStr, req.user.username, '下单', -totalAmount, user.balance - totalAmount, `${codes.length}注，倍数${multiple}`]);
      res.json({ newBalance: user.balance - totalAmount });
    });
  });
});

app.get('/api/orders', verifyToken, (req, res) => {
  db.all('SELECT * FROM orders WHERE username = ? ORDER BY timestamp DESC', [req.user.username], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// ========== ✅ 修复后的退码（余额返还正确） ==========
app.post('/api/refund', verifyToken, (req, res) => {
  const { codes } = req.body;
  if (!codes || !Array.isArray(codes) || codes.length === 0) {
    return res.status(400).json({ error: '请选择要撤销的号码' });
  }
  const now = Date.now();
  const halfHour = 30 * 60 * 1000;
  const placeholders = codes.map(() => '?').join(',');
  const sql = `SELECT * FROM orders WHERE username = ? AND code IN (${placeholders}) AND (${now} - timestamp) <= ? ORDER BY timestamp DESC`;
  db.all(sql, [req.user.username, ...codes, halfHour], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    if (rows.length === 0) {
      return res.status(400).json({ error: '未找到可撤销的订单（可能已超时）' });
    }
    let refundAmount = 0;
    rows.forEach(row => refundAmount += row.multiple);
    const ids = rows.map(r => r.id);
    const idPlaceholders = ids.map(() => '?').join(',');
    db.run(`DELETE FROM orders WHERE id IN (${idPlaceholders}) AND username = ?`, [...ids, req.user.username], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      // ✅ 退码返还余额（加号）
      db.run('UPDATE users SET balance = balance + ? WHERE username = ?', [refundAmount, req.user.username], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        const logSql = 'INSERT INTO logs (time, user, type, amount, balance, detail) VALUES (?, ?, ?, ?, ?, ?)';
        db.run(logSql, [new Date().toISOString(), req.user.username, '退码', refundAmount, 0, `撤销${rows.length}注，返还${refundAmount}`]);
        res.json({ newBalance: refundAmount, message: `成功撤销${rows.length}注，返还${refundAmount}元` });
      });
    });
  });
});

app.post('/api/payout', verifyToken, (req, res) => {
  const { lines } = req.body;
  if (!lines || !Array.isArray(lines) || lines.length === 0) {
    return res.status(400).json({ error: '无中奖号码' });
  }
  const sql = 'SELECT * FROM orders WHERE username = ? AND raw IN (' + lines.map(() => '?').join(',') + ')';
  db.all(sql, [req.user.username, ...lines], (err, orders) => {
    if (err) return res.status(500).json({ error: err.message });
    if (orders.length === 0) return res.status(400).json({ error: '未找到匹配订单' });
    const paidCheck = 'SELECT raw FROM paid_awards WHERE username = ? AND raw IN (' + lines.map(() => '?').join(',') + ')';
    db.all(paidCheck, [req.user.username, ...lines], (err, paidRows) => {
      if (err) return res.status(500).json({ error: err.message });
      const paidSet = new Set(paidRows.map(r => r.raw));
      const validOrders = orders.filter(o => !paidSet.has(o.raw));
      if (validOrders.length === 0) {
        return res.status(400).json({ error: '所有号码已派奖' });
      }
      let totalPrize = 0;
      validOrders.forEach(o => totalPrize += o.multiple * 95);
      db.run('UPDATE users SET balance = balance + ? WHERE username = ?', [totalPrize, req.user.username], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        const stmt = db.prepare('INSERT INTO paid_awards (username, raw) VALUES (?, ?)');
        validOrders.forEach(o => stmt.run([req.user.username, o.raw]));
        stmt.finalize();
        const logSql = 'INSERT INTO logs (time, user, type, amount, balance, detail) VALUES (?, ?, ?, ?, ?, ?)';
        db.run(logSql, [new Date().toISOString(), req.user.username, '派奖', totalPrize, 0, `中奖${validOrders.length}注，赔率95倍`]);
        res.json({ newBalance: totalPrize, message: `派奖成功，奖金${totalPrize}` });
      });
    });
  });
});

app.get('/api/admin/orders', verifyToken, verifyAdmin, (req, res) => {
  db.all('SELECT * FROM orders ORDER BY timestamp DESC', (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.get('/api/admin/users', verifyToken, verifyAdmin, (req, res) => {
  db.all('SELECT username, balance, role, temp, expire FROM users', (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/admin/adjust-balance', verifyToken, verifyAdmin, (req, res) => {
  const { username, amount } = req.body;
  if (!username || amount === undefined) return res.status(400).json({ error: '参数错误' });
  db.run('UPDATE users SET balance = balance + ? WHERE username = ?', [amount, username], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    db.get('SELECT balance FROM users WHERE username = ?', [username], (err, user) => {
      if (err) return res.status(500).json({ error: err.message });
      const logSql = 'INSERT INTO logs (time, user, type, amount, balance, detail) VALUES (?, ?, ?, ?, ?, ?)';
      db.run(logSql, [new Date().toISOString(), req.user.username, '调额', amount, user.balance, `调整用户${username}`]);
      res.json({ newBalance: user.balance });
    });
  });
});

app.post('/api/admin/delete-user', verifyToken, verifyAdmin, (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: '缺少用户名' });
  if (username === req.user.username) {
    return res.status(400).json({ error: '不能删除当前登录账号' });
  }
  db.run('DELETE FROM users WHERE username = ?', [username], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    db.run('DELETE FROM orders WHERE username = ?', [username]);
    db.run('DELETE FROM paid_awards WHERE username = ?', [username]);
    const logSql = 'INSERT INTO logs (time, user, type, amount, balance, detail) VALUES (?, ?, ?, ?, ?, ?)';
    db.run(logSql, [new Date().toISOString(), req.user.username, '删除账号', 0, 0, `删除用户 ${username}`]);
    res.json({ message: '用户已删除' });
  });
});

app.get('/api/admin/logs', verifyToken, verifyAdmin, (req, res) => {
  db.all('SELECT * FROM logs ORDER BY time DESC LIMIT 2000', (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/admin/check-win', verifyToken, verifyAdmin, (req, res) => {
  const { lottery, award } = req.body;
  if (!award || award.length < 4) return res.status(400).json({ error: '开奖号码至少4位' });
  function isWin(code, award) {
    for (let i = 0; i < 4; i++) {
      if (code[i] !== 'X' && code[i] !== award[i]) return false;
    }
    return true;
  }
  const sql = 'SELECT * FROM orders WHERE lottery = ?';
  db.all(sql, [lottery], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    const wins = rows.filter(row => isWin(row.code, award));
    const paidSql = 'SELECT raw FROM paid_awards';
    db.all(paidSql, (err, paidRows) => {
      if (err) return res.status(500).json({ error: err.message });
      const paidSet = new Set(paidRows.map(r => r.raw));
      const result = wins.filter(w => !paidSet.has(w.raw));
      res.json(result);
    });
  });
});

app.post('/api/admin/payout', verifyToken, verifyAdmin, (req, res) => {
  const { winRows } = req.body;
  if (!winRows || winRows.length === 0) return res.status(400).json({ error: '无中奖记录' });
  const userMap = {};
  winRows.forEach(row => {
    const user = row.username;
    const prize = row.multiple * 95;
    if (userMap[user]) userMap[user] += prize;
    else userMap[user] = prize;
  });
  db.serialize(() => {
    db.run('BEGIN TRANSACTION');
    let success = true;
    for (const [user, amount] of Object.entries(userMap)) {
      db.run('UPDATE users SET balance = balance + ? WHERE username = ?', [amount, user], function(err) {
        if (err) { success = false; }
      });
      const stmt = db.prepare('INSERT INTO paid_awards (username, raw) VALUES (?, ?)');
      winRows.filter(w => w.username === user).forEach(w => stmt.run([user, w.raw]));
      stmt.finalize();
    }
    if (success) {
      db.run('COMMIT');
      const logSql = 'INSERT INTO logs (time, user, type, amount, balance, detail) VALUES (?, ?, ?, ?, ?, ?)';
      db.run(logSql, [new Date().toISOString(), req.user.username, '派奖', 0, 0, `全局派奖，共${Object.keys(userMap).length}位用户`]);
      res.json({ message: '派奖成功', userMap });
    } else {
      db.run('ROLLBACK');
      res.status(500).json({ error: '派奖失败' });
    }
  });
});

function initAdmin() {
  db.get('SELECT * FROM users WHERE username = ?', ['13724724789'], (err, row) => {
    if (!row) {
      const hashed = bcrypt.hashSync('123456', 10);
      db.run('INSERT INTO users (username, password, balance, role) VALUES (?, ?, ?, ?)',
        ['13724724789', hashed, 9999, 'admin']);
      console.log('✅ 管理员账号创建: 13724724789 / 123456');
    }
  });
}
initAdmin();

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
