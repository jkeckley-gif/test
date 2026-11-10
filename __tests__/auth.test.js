'use strict';

const http = require('http');
const { hashPassword, comparePassword, generateToken, verifyToken, createApp, authenticate } = require('../index');

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
    const app = createApp('test-secret');
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
