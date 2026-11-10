'use strict';

const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const {
  AuthService,
  hashPassword,
  comparePassword,
  generateToken,
  verifyToken,
  createApp,
  authenticate,
} = require('../index');

function requestJson(server, method, path, headers = {}, body = undefined) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : JSON.stringify(body);
    const requestOptions = {
      hostname: '127.0.0.1',
      port: server.address().port,
      path,
      method,
      headers: {
        ...headers,
      },
    };

    if (payload !== undefined) {
      requestOptions.headers['Content-Type'] = 'application/json';
      requestOptions.headers['Content-Length'] = Buffer.byteLength(payload);
    }

    const req = http.request(requestOptions, (res) => {
      let raw = '';
      res.on('data', (chunk) => {
        raw += chunk;
      });
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          body: raw ? JSON.parse(raw) : null,
        });
      });
    });

    req.on('error', reject);

    if (payload !== undefined) {
      req.write(payload);
    }

    req.end();
  });
}

describe('JWT auth helpers', () => {
  test('hashes and verifies passwords', async () => {
    const hashed = await hashPassword('super-secret');
    expect(hashed).not.toBe('super-secret');
    expect(await comparePassword('super-secret', hashed)).toBe(true);
    expect(await comparePassword('wrong-password', hashed)).toBe(false);
  });

  test('generates and verifies tokens', () => {
    const token = generateToken({ sub: 'user-123', email: 'user@example.com' }, 'test-secret');
    const decoded = verifyToken(token, 'test-secret');

    expect(decoded.sub).toBe('user-123');
    expect(decoded.email).toBe('user@example.com');
  });

  test('auth middleware accepts bearer tokens', async () => {
    const app = createApp('test-secret', { databasePath: ':memory:' });
    const server = app.listen(0);
    const token = generateToken({ sub: 'user-123' }, 'test-secret');

    try {
      const response = await requestJson(server, 'GET', '/profile', {
        authorization: `Bearer ${token}`,
      });

      expect(response.statusCode).toBe(200);
      expect(response.body.user.sub).toBe('user-123');
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  test('authenticate rejects missing bearer token', () => {
    const handler = authenticate('test-secret');
    const req = { headers: {} };
    const res = {
      status(code) {
        this.code = code;
        return this;
      },
      json(payload) {
        this.payload = payload;
        return this;
      },
    };
    const next = jest.fn();

    handler(req, res, next);

    expect(res.code).toBe(401);
    expect(res.payload.error).toMatch(/Missing|invalid authorization/i);
    expect(next).not.toHaveBeenCalled();
  });
});

async function withServer(app, fn) {
  const server = app.listen(0);
  try {
    return await fn(server);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

describe('security hardening', () => {
  test('requires a JWT secret', () => {
    expect(() => generateToken({ sub: 'user-123' }, undefined)).toThrow(/JWT secret is required/);
    expect(() => verifyToken('a.b.c', '')).toThrow(/JWT secret is required/);
    expect(() => createApp(undefined, { databasePath: ':memory:' })).toThrow(/JWT secret is required/);
    expect(() => authenticate(undefined)).toThrow(/JWT secret is required/);
    expect(() => new AuthService(undefined)).toThrow(/JWT secret is required/);
  });

  test('rejects passwords longer than 72 bytes', async () => {
    const prefix = 'a'.repeat(72);
    const hashed = await hashPassword(prefix);

    expect(() => hashPassword(`${prefix}b`)).toThrow(/at most 72 bytes/);
    expect(await comparePassword(`${prefix}b`, hashed)).toBe(false);
    expect(() => hashPassword('é'.repeat(37))).toThrow(/at most 72 bytes/);
  });
});

describe('auth routes', () => {
  test('registered accounts survive a restart', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'auth-test-'));
    const databasePath = path.join(dir, 'users.db');

    try {
      const register = await withServer(createApp('test-secret', { databasePath }), (server) =>
        requestJson(server, 'POST', '/auth/register', {}, { email: 'a@example.com', password: 'alpha' }));
      expect(register.statusCode).toBe(201);

      const login = await withServer(createApp('test-secret', { databasePath }), (server) =>
        requestJson(server, 'POST', '/auth/login', {}, { email: 'A@example.com', password: 'alpha' }));
      expect(login.statusCode).toBe(200);
      expect(login.body.user.id).toBe(register.body.user.id);
      expect(verifyToken(login.body.token, 'test-secret').sub).toBe(register.body.user.id);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('concurrent registrations for one email create a single account', async () => {
    await withServer(createApp('test-secret', { databasePath: ':memory:' }), async (server) => {
      const responses = await Promise.all(['alpha', 'beta', 'gamma'].map((password) =>
        requestJson(server, 'POST', '/auth/register', {}, { email: 'a@example.com', password })));
      const statuses = responses.map((response) => response.statusCode).sort();
      expect(statuses).toEqual([201, 409, 409]);

      const winner = ['alpha', 'beta', 'gamma'][responses.findIndex((response) => response.statusCode === 201)];
      const login = await requestJson(server, 'POST', '/auth/login', {}, { email: 'a@example.com', password: winner });
      expect(login.statusCode).toBe(200);
    });
  });

  test('concurrent registrations receive distinct ids', async () => {
    await withServer(createApp('test-secret', { databasePath: ':memory:' }), async (server) => {
      const responses = await Promise.all(Array.from({ length: 5 }, (_, i) =>
        requestJson(server, 'POST', '/auth/register', {}, { email: `user${i}@example.com`, password: 'pw' })));
      const ids = responses.map((response) => response.body.user.id);
      expect(new Set(ids).size).toBe(ids.length);
    });
  });

  test('throttles repeated failed logins', async () => {
    const app = createApp('test-secret', { databasePath: ':memory:', loginLimit: { maxAttempts: 3 } });
    await withServer(app, async (server) => {
      await requestJson(server, 'POST', '/auth/register', {}, { email: 'a@example.com', password: 'alpha' });

      for (let i = 0; i < 3; i += 1) {
        const response = await requestJson(server, 'POST', '/auth/login', {}, { email: 'a@example.com', password: 'wrong' });
        expect(response.statusCode).toBe(401);
      }

      const blocked = await requestJson(server, 'POST', '/auth/login', {}, { email: 'a@example.com', password: 'alpha' });
      expect(blocked.statusCode).toBe(429);
    });
  });
});
