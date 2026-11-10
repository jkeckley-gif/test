'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

dotenv.config();

const DEFAULT_SECRET = process.env.JWT_SECRET;
const DEFAULT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h';
const DEFAULT_DATABASE_PATH = process.env.USERS_DB_PATH || path.join(__dirname, 'data', 'users.db');
// bcrypt silently ignores input beyond 72 bytes.
const MAX_PASSWORD_BYTES = 72;
const SQLITE_CONSTRAINT_UNIQUE = 2067;

function requireSecret(secret) {
  if (typeof secret !== 'string' || secret.length === 0) {
    throw new Error('A JWT secret is required; set the JWT_SECRET environment variable');
  }

  return secret;
}

function isPasswordTooLong(password) {
  return Buffer.byteLength(password, 'utf8') > MAX_PASSWORD_BYTES;
}

function hashPassword(password, saltRounds = 10) {
  if (typeof password !== 'string' || password.length === 0) {
    throw new TypeError('Password must be a non-empty string');
  }

  if (isPasswordTooLong(password)) {
    throw new TypeError(`Password must be at most ${MAX_PASSWORD_BYTES} bytes`);
  }

  return bcrypt.hash(password, saltRounds);
}

async function comparePassword(password, hashedPassword) {
  if (typeof password !== 'string' || password.length === 0) {
    throw new TypeError('Password must be a non-empty string');
  }

  if (typeof hashedPassword !== 'string' || hashedPassword.length === 0) {
    throw new TypeError('Hashed password must be a non-empty string');
  }

  if (isPasswordTooLong(password)) {
    return false;
  }

  return bcrypt.compare(password, hashedPassword);
}

function generateToken(payload, secret = DEFAULT_SECRET, options = {}) {
  if (!payload) {
    throw new TypeError('Token payload is required');
  }

  return jwt.sign(payload, requireSecret(secret), {
    expiresIn: DEFAULT_EXPIRES_IN,
    ...options,
  });
}

function verifyToken(token, secret = DEFAULT_SECRET) {
  if (!token || typeof token !== 'string') {
    throw new TypeError('JWT token is required');
  }

  return jwt.verify(token, requireSecret(secret));
}

function extractBearerToken(authorizationHeader) {
  if (!authorizationHeader || typeof authorizationHeader !== 'string') {
    return null;
  }

  const match = authorizationHeader.match(/^Bearer\s+(.+)$/i);
  return match ? match[1] : null;
}

function authenticate(secret = DEFAULT_SECRET) {
  requireSecret(secret);

  return function authMiddleware(req, res, next) {
    const token = extractBearerToken(req.headers.authorization);

    if (!token) {
      return res.status(401).json({ error: 'Missing or invalid authorization header' });
    }

    try {
      const payload = verifyToken(token, secret);
      req.user = payload;
      return next();
    } catch (error) {
      return res.status(401).json({ error: error.message || 'Invalid token' });
    }
  };
}

function normalizeEmail(email) {
  return typeof email === 'string' ? email.trim().toLowerCase() : '';
}

function createUserStore(databasePath = DEFAULT_DATABASE_PATH) {
  if (databasePath !== ':memory:') {
    fs.mkdirSync(path.dirname(databasePath), { recursive: true });
  }

  const db = new DatabaseSync(databasePath);
  db.exec(`
    PRAGMA busy_timeout = 5000;
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
  `);

  const insertUser = db.prepare('INSERT INTO users (id, email, password_hash) VALUES (?, ?, ?)');
  const selectUserByEmail = db.prepare('SELECT id, email, password_hash FROM users WHERE email = ?');

  return {
    // Returns null when the email is already registered.
    createUser({ email, passwordHash }) {
      const user = { id: crypto.randomUUID(), email, passwordHash };

      try {
        insertUser.run(user.id, user.email, user.passwordHash);
      } catch (error) {
        if (error.errcode === SQLITE_CONSTRAINT_UNIQUE) {
          return null;
        }
        throw error;
      }

      return user;
    },

    findUserByEmail(email) {
      const row = selectUserByEmail.get(email);
      return row ? { id: row.id, email: row.email, passwordHash: row.password_hash } : null;
    },

    close() {
      db.close();
    },
  };
}

function createLoginLimiter({ maxAttempts = 5, maxAttemptsPerIp = 50, windowMs = 15 * 60 * 1000 } = {}) {
  const failures = new Map();

  function activeEntry(key, now) {
    const entry = failures.get(key);
    if (entry && entry.resetAt <= now) {
      failures.delete(key);
      return null;
    }
    return entry || null;
  }

  function increment(key, now) {
    const entry = activeEntry(key, now) || { count: 0, resetAt: now + windowMs };
    entry.count += 1;
    failures.set(key, entry);
  }

  function pruneExpired(now) {
    for (const [key, entry] of failures) {
      if (entry.resetAt <= now) {
        failures.delete(key);
      }
    }
  }

  return {
    // Returns seconds until the client may retry, or 0 if not blocked.
    retryAfter(ip, email, now = Date.now()) {
      const blocking = [
        [activeEntry(`acct:${ip}:${email}`, now), maxAttempts],
        [activeEntry(`ip:${ip}`, now), maxAttemptsPerIp],
      ].filter(([entry, limit]) => entry && entry.count >= limit);

      if (blocking.length === 0) {
        return 0;
      }

      const resetAt = Math.max(...blocking.map(([entry]) => entry.resetAt));
      return Math.ceil((resetAt - now) / 1000);
    },

    recordFailure(ip, email, now = Date.now()) {
      if (failures.size > 10000) {
        pruneExpired(now);
      }
      increment(`acct:${ip}:${email}`, now);
      increment(`ip:${ip}`, now);
    },

    recordSuccess(ip, email) {
      failures.delete(`acct:${ip}:${email}`);
    },
  };
}

function createAuthRouter(secret = DEFAULT_SECRET, options = {}) {
  requireSecret(secret);

  const router = express.Router();
  const userStore = options.userStore || createUserStore(options.databasePath);
  const loginLimiter = options.loginLimiter || createLoginLimiter(options.loginLimit);

  router.post('/register', async (req, res) => {
    const { password } = req.body || {};
    const email = normalizeEmail((req.body || {}).email);

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    if (userStore.findUserByEmail(email)) {
      return res.status(409).json({ error: 'User already exists' });
    }

    let passwordHash;
    try {
      passwordHash = await hashPassword(password);
    } catch (error) {
      return res.status(400).json({ error: error.message || 'Unable to create user' });
    }

    const user = userStore.createUser({ email, passwordHash });
    if (!user) {
      return res.status(409).json({ error: 'User already exists' });
    }

    return res.status(201).json({
      message: 'User created successfully',
      user: { id: user.id, email: user.email },
    });
  });

  router.post('/login', async (req, res) => {
    const { password } = req.body || {};
    const email = normalizeEmail((req.body || {}).email);

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const ip = req.ip;
    const retryAfter = loginLimiter.retryAfter(ip, email);
    if (retryAfter > 0) {
      res.set('Retry-After', String(retryAfter));
      return res.status(429).json({ error: 'Too many failed login attempts; try again later' });
    }

    try {
      const user = userStore.findUserByEmail(email);
      const valid = user ? await comparePassword(password, user.passwordHash) : false;

      if (!valid) {
        loginLimiter.recordFailure(ip, email);
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      loginLimiter.recordSuccess(ip, email);
      const token = generateToken({ sub: user.id, email: user.email }, secret);
      return res.json({ token, user: { id: user.id, email: user.email } });
    } catch (error) {
      loginLimiter.recordFailure(ip, email);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
  });

  return router;
}

function createApp(secret = DEFAULT_SECRET, options = {}) {
  const app = express();

  app.use(express.json());
  app.use('/auth', createAuthRouter(secret, options));

  app.get('/health', (req, res) => {
    res.json({ status: 'ok' });
  });

  app.get('/profile', authenticate(secret), (req, res) => {
    res.json({ user: req.user });
  });

  return app;
}

class AuthService {
  constructor(secret = DEFAULT_SECRET) {
    this.secret = requireSecret(secret);
  }

  hashPassword(password, saltRounds = 10) {
    return hashPassword(password, saltRounds);
  }

  comparePassword(password, hashedPassword) {
    return comparePassword(password, hashedPassword);
  }

  generateToken(payload, options = {}) {
    return generateToken(payload, this.secret, options);
  }

  signToken(payload, options = {}) {
    return this.generateToken(payload, options);
  }

  verifyToken(token) {
    return verifyToken(token, this.secret);
  }

  decodeToken(token) {
    return this.verifyToken(token);
  }

  authenticate() {
    return authenticate(this.secret);
  }
}

if (require.main === module) {
  const app = createApp();
  const port = Number(process.env.PORT || 3000);
  app.listen(port, () => {
    // eslint-disable-next-line no-console
    console.log(`Auth service listening on port ${port}`);
  });
}

module.exports = {
  AuthService,
  DEFAULT_SECRET,
  DEFAULT_EXPIRES_IN,
  MAX_PASSWORD_BYTES,
  createUserStore,
  createLoginLimiter,
  hashPassword,
  comparePassword,
  generateToken,
  signToken: generateToken,
  verifyToken,
  decodeToken: verifyToken,
  extractBearerToken,
  authenticate,
  createAuthRouter,
  createApp,
  createServer: createApp,
};

module.exports.default = module.exports;
