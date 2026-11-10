'use strict';

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

dotenv.config();

const DEFAULT_SECRET = process.env.JWT_SECRET || 'change-me';
const DEFAULT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h';

function hashPassword(password, saltRounds = 10) {
  if (typeof password !== 'string' || password.length === 0) {
    throw new TypeError('Password must be a non-empty string');
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

  return bcrypt.compare(password, hashedPassword);
}

function generateToken(payload, secret = DEFAULT_SECRET, options = {}) {
  if (!payload) {
    throw new TypeError('Token payload is required');
  }

  return jwt.sign(payload, secret, {
    expiresIn: DEFAULT_EXPIRES_IN,
    ...options,
  });
}

function verifyToken(token, secret = DEFAULT_SECRET) {
  if (!token || typeof token !== 'string') {
    throw new TypeError('JWT token is required');
  }

  return jwt.verify(token, secret);
}

function extractBearerToken(authorizationHeader) {
  if (!authorizationHeader || typeof authorizationHeader !== 'string') {
    return null;
  }

  const match = authorizationHeader.match(/^Bearer\s+(.+)$/i);
  return match ? match[1] : null;
}

function authenticate(secret = DEFAULT_SECRET) {
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

function createAuthRouter(secret = DEFAULT_SECRET) {
  const router = express.Router();
  const users = new Map();

  router.post('/register', async (req, res) => {
    const { email, password } = req.body || {};

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    if (users.has(email)) {
      return res.status(409).json({ error: 'User already exists' });
    }

    try {
      const passwordHash = await hashPassword(password);
      const user = { id: Date.now().toString(36), email, passwordHash };
      users.set(email, user);

      return res.status(201).json({
        message: 'User created successfully',
        user: { id: user.id, email: user.email },
      });
    } catch (error) {
      return res.status(400).json({ error: error.message || 'Unable to create user' });
    }
  });

  router.post('/login', async (req, res) => {
    const { email, password } = req.body || {};

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = users.get(email);

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    try {
      const valid = await comparePassword(password, user.passwordHash);
      if (!valid) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const token = generateToken({ sub: user.id, email: user.email }, secret);
      return res.json({ token, user: { id: user.id, email: user.email } });
    } catch (error) {
      return res.status(401).json({ error: error.message || 'Invalid credentials' });
    }
  });

  return router;
}

function createApp(secret = DEFAULT_SECRET) {
  const app = express();

  app.use(express.json());
  app.use('/auth', createAuthRouter(secret));

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
    this.secret = secret;
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
