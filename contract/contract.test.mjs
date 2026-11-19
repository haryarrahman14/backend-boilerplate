// Black-box contract suite. Zero dependencies (node >= 20):
//   BASE_URL=http://localhost:8081 DATABASE_URL=postgres://... node --test contract/
// Needs the service started as contract/run.sh does: SMTP at Mailpit, S3 at MinIO, a high RATE_LIMIT_AUTH_PER_MINUTE,
// TRUSTED_PROXY_HOPS=1, TRUSTED_PROXY_CIDRS covering loopback, and EMAIL_TOKEN_COOLDOWN_SECONDS=0.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';

const BASE = process.env.BASE_URL ?? 'http://localhost:8080';
const API = `${BASE}/api/v1`;
const MAILPIT = process.env.MAILPIT_URL ?? 'http://localhost:8025';
const DATABASE_URL = process.env.DATABASE_URL;

const run = randomUUID().slice(0, 8);
const newEmail = (tag) => `${tag}-${run}-${randomUUID().slice(0, 6)}@example.com`;
const PASSWORD = 'correct horse battery';

async function call(method, path, { body, token, headers = {}, raw } = {}) {
  const res = await fetch(path.startsWith('http') ? path : API + path, {
    method,
    headers: {
      ...(body !== undefined || raw !== undefined ? { 'Content-Type': 'application/json' } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...headers,
    },
    body: raw ?? (body !== undefined ? JSON.stringify(body) : undefined),
  });
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* not json */ }
  return { status: res.status, json, text, headers: res.headers };
}

function expectError(res, status, code) {
  assert.equal(res.status, status, `expected ${status} ${code}, got ${res.status}: ${res.text}`);
  assert.equal(res.json?.error?.code, code, res.text);
  assert.equal(typeof res.json.error.message, 'string');
}

// Emails go out in the background, so poll Mailpit for the newest mail to `to` containing a token link.
async function mailToken(to, linkPath, { skip = 0 } = {}) {
  for (let i = 0; i < 50; i++) {
    const list = await (await fetch(`${MAILPIT}/api/v1/search?query=${encodeURIComponent(`to:${to}`)}`)).json();
    const tokens = [];
    for (const m of list.messages ?? []) {
      const msg = await (await fetch(`${MAILPIT}/api/v1/message/${m.ID}`)).json();
      const hit = (msg.Text ?? '').match(new RegExp(`${linkPath}\\?token=([A-Za-z0-9_-]+)`));
      if (hit) tokens.push({ token: hit[1], at: new Date(msg.Date).getTime() });
    }
    if (tokens.length > skip) return tokens.sort((a, b) => b.at - a.at)[0].token;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`no ${linkPath} mail for ${to}`);
}
async function mailCount(to) {
  const list = await (await fetch(`${MAILPIT}/api/v1/search?query=${encodeURIComponent(`to:${to}`)}`)).json();
  return (list.messages ?? []).length;
}

async function register(email = newEmail('u'), name = 'Test User') {
  const res = await call('POST', '/auth/register', { body: { email, password: PASSWORD, name } });
  assert.equal(res.status, 201, res.text);
  return { email, user: res.json.user };
}
async function login(email, password = PASSWORD, headers = {}) {
  const res = await call('POST', '/auth/login', { body: { email, password }, headers });
  assert.equal(res.status, 200, res.text);
  return res.json;
}
async function signedUp() {
  const { email, user } = await register();
  return { email, user, ...(await login(email)) };
}

before(async () => {
  const res = await fetch(`${BASE}/health`).catch(() => null);
  assert.ok(res?.ok, `service not reachable at ${BASE}`);
});

// ---------- platform ----------

test('tables live in auth and storage, not in public', { skip: !DATABASE_URL && 'DATABASE_URL not set' }, () => {
  const q = (sql) => execFileSync('psql', [DATABASE_URL, '-Atc', sql]).toString().trim().split('\n').filter(Boolean).sort();
  assert.deepEqual(q("SELECT table_schema || '.' || table_name FROM information_schema.tables WHERE table_schema IN ('auth','storage')"),
    ['auth.sessions', 'auth.user_tokens', 'auth.users', 'storage.files']);
  // public keeps only the migration tool's own bookkeeping table
  const leftovers = q("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_name IN ('users','sessions','user_tokens','files')");
  assert.deepEqual(leftovers, [], `boilerplate tables still in public: ${leftovers}`);
  assert.deepEqual(q("SELECT column_name FROM information_schema.columns WHERE table_schema='auth' AND table_name='sessions' AND column_name='previous_refresh_token_hash'"), ['previous_refresh_token_hash']);
});

test('health, readiness, docs', async () => {
  const live = await call('GET', `${BASE}/health`);
  assert.equal(live.status, 200);
  assert.deepEqual(live.json, { status: 'ok' });
  const ready = await call('GET', `${BASE}/health/ready`);
  assert.equal(ready.status, 200);
  assert.deepEqual(ready.json, { status: 'ok' });
  const spec = await call('GET', `${BASE}/openapi.json`);
  assert.equal(spec.status, 200);
  assert.ok(spec.json.openapi?.startsWith('3.'), 'openapi 3 document');
  for (const p of ['/api/v1/auth/login', '/api/v1/auth/refresh', '/api/v1/users/me', '/api/v1/files/presign']) {
    assert.ok(spec.json.paths[p], `openapi is missing ${p}`);
  }
  assert.equal((await fetch(`${BASE}/docs`)).status, 200);
});

test('request id + security headers', async () => {
  const echoed = await call('GET', `${BASE}/health`, { headers: { 'X-Request-Id': 'abc_123-XYZ' } });
  assert.equal(echoed.headers.get('x-request-id'), 'abc_123-XYZ');
  const generated = await call('GET', `${BASE}/health`);
  assert.ok(generated.headers.get('x-request-id')?.length >= 8);
  const bad = await call('GET', `${BASE}/health`, { headers: { 'X-Request-Id': 'has spaces!' } });
  assert.notEqual(bad.headers.get('x-request-id'), 'has spaces!');
  assert.equal(generated.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(generated.headers.get('x-frame-options'), 'DENY');
  assert.equal(generated.headers.get('referrer-policy'), 'no-referrer');
});

test('unknown route and malformed json use the error envelope', async () => {
  expectError(await call('GET', '/nope'), 404, 'not_found');
  expectError(await call('GET', `${BASE}/nope`), 404, 'not_found'); // outside the /api/v1 prefix too
  expectError(await call('POST', `${BASE}/health`), 404, 'not_found');
  expectError(await call('POST', '/auth/login', { raw: '{"email":' }), 400, 'bad_request');
  // known path, unsupported method -> 404 (the contract has no 405)
  expectError(await call('GET', '/auth/login'), 404, 'not_found');
  expectError(await call('DELETE', '/users/me'), 404, 'not_found');
  // body without a JSON content type
  const noType = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: '{"email":"a@b.co","password":"x"}' });
  assert.equal(noType.status, 400);
  assert.equal((await noType.json()).error.code, 'bad_request');
  // valid JSON, wrong shape / wrong type
  expectError(await call('POST', '/auth/login', { raw: '[1,2]' }), 422, 'validation_error');
  expectError(await call('POST', '/auth/login', { body: { email: 5, password: true } }), 422, 'validation_error');
  // body over 1 MB
  expectError(await call('POST', '/auth/login', { body: { email: 'a@b.co', password: 'x'.repeat(1_100_000) } }), 413, 'payload_too_large');
});

test('CORS allows the configured origin only', async () => {
  const ok = await fetch(`${API}/auth/login`, {
    method: 'OPTIONS',
    headers: { Origin: 'http://localhost:3000', 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'content-type,authorization' },
  });
  assert.equal(ok.headers.get('access-control-allow-origin'), 'http://localhost:3000');
  const evil = await fetch(`${API}/auth/login`, {
    method: 'OPTIONS',
    headers: { Origin: 'http://evil.example', 'Access-Control-Request-Method': 'POST' },
  });
  assert.equal(evil.headers.get('access-control-allow-origin'), null);
});

// ---------- register / login ----------

test('register validates input', async () => {
  const bad = await call('POST', '/auth/register', { body: { email: 'not-an-email', password: 'short', name: '' } });
  expectError(bad, 422, 'validation_error');
  const fields = bad.json.error.details.map((d) => d.field).sort();
  assert.deepEqual(fields, ['email', 'name', 'password']);
  expectError(await call('POST', '/auth/register', { body: {} }), 422, 'validation_error');
  // strict address syntax: nothing a mail library could re-interpret as "Name <other@address>"
  for (const email of [`victim-${run}<attacker@evil.example>`, `"a b"@example.com`, 'a@b', 'a@@example.com', 'jos\u00e9@example.com', 'a b@example.com', 'a@exa_mple.com']) {
    expectError(await call('POST', '/auth/register', { body: { email, password: PASSWORD, name: 'A' } }), 422, 'validation_error');
  }
  // lone surrogate: rejected cleanly, never a 500
  const surrogate = await call('POST', '/auth/register', { raw: '{"email":"a\\ud800b@example.com","password":"correct horse battery","name":"A"}' });
  assert.ok([400, 422].includes(surrogate.status), `lone surrogate gave ${surrogate.status}`);
  expectError(
    await call('POST', '/auth/register', { body: { email: newEmail('long'), password: 'x'.repeat(129), name: 'A' } }),
    422, 'validation_error',
  );
  // minimum is 15 characters (NIST SP 800-63B-4, password-only login), counted in code points
  expectError(await call('POST', '/auth/register', { body: { email: newEmail('p14'), password: 'x'.repeat(14), name: 'A' } }), 422, 'validation_error');
  assert.equal((await call('POST', '/auth/register', { body: { email: newEmail('p15'), password: '😀'.repeat(15), name: 'A' } })).status, 201);
  assert.equal((await call('POST', '/auth/register', { body: { email: newEmail('p128'), password: 'x'.repeat(128), name: 'A' } })).status, 201);
});

test('register normalises email, hides the hash, rejects duplicates', async () => {
  const email = newEmail('Case');
  const res = await call('POST', '/auth/register', { body: { email: `  ${email.toUpperCase()} `, password: PASSWORD, name: '  Ada  ' } });
  assert.equal(res.status, 201, res.text);
  const u = res.json.user;
  assert.equal(u.email, email.toLowerCase());
  assert.equal(u.name, 'Ada');
  assert.equal(u.role, 'user');
  assert.equal(u.email_verified, false);
  assert.match(u.id, /^[0-9a-f-]{36}$/);
  assert.ok(!Number.isNaN(Date.parse(u.created_at)));
  assert.deepEqual(Object.keys(u).sort(), ['created_at', 'email', 'email_verified', 'id', 'name', 'role']);
  assert.equal(res.json.access_token, undefined, 'register returns no tokens');
  expectError(await call('POST', '/auth/register', { body: { email, password: PASSWORD, name: 'Dup' } }), 409, 'email_taken');
  // login is case-insensitive too
  const t = await login(email.toUpperCase());
  assert.equal(t.user.id, u.id);
});

test('login: token shape, and identical failure for unknown user vs wrong password', async () => {
  const { email } = await register();
  const t = await login(email);
  assert.equal(t.token_type, 'Bearer');
  assert.equal(t.expires_in, 900);
  assert.equal(t.access_token.split('.').length, 3);
  const claims = JSON.parse(Buffer.from(t.access_token.split('.')[1], 'base64url').toString());
  assert.equal(claims.sub, t.user.id);
  assert.ok(claims.sid && claims.exp && claims.iat);
  assert.equal(claims.exp - claims.iat, 900);
  assert.equal(t.refresh_token.split('.')[0], claims.sid, 'refresh token is <session_id>.<secret>');
  assert.ok(t.refresh_token.split('.')[1].length >= 43);

  const wrong = await call('POST', '/auth/login', { body: { email, password: 'wrong password!' } });
  const unknown = await call('POST', '/auth/login', { body: { email: newEmail('ghost'), password: PASSWORD } });
  expectError(wrong, 401, 'invalid_credentials');
  expectError(unknown, 401, 'invalid_credentials');
  assert.equal(wrong.json.error.message, unknown.json.error.message);
  // login validates presence only: bad shapes are a plain miss, never a 422 hint
  for (const body of [{ email: 'not-an-email', password: PASSWORD }, { email, password: 'x' }, { email, password: 'y'.repeat(200) }]) {
    const res = await call('POST', '/auth/login', { body });
    expectError(res, 401, 'invalid_credentials');
    assert.equal(res.json.error.message, wrong.json.error.message);
  }
  expectError(await call('POST', '/auth/login', { body: { email: 'a\u0000b@example.com', password: PASSWORD } }), 401, 'invalid_credentials');
  expectError(await call('POST', '/auth/login', { body: { email, password: '' } }), 422, 'validation_error');
  expectError(await call('POST', '/auth/login', { body: { email } }), 422, 'validation_error');
});

test('access token is required and strictly verified', async () => {
  const t = await signedUp();
  expectError(await call('GET', '/users/me'), 401, 'unauthorized');
  expectError(await call('GET', '/users/me', { token: 'garbage' }), 401, 'unauthorized');
  expectError(await call('GET', '/users/me', { headers: { Authorization: `Basic ${t.access_token}` } }), 401, 'unauthorized');
  // alg=none forgery with the same claims
  const [, payload] = t.access_token.split('.');
  const none = `${Buffer.from('{"alg":"none","typ":"JWT"}').toString('base64url')}.${payload}.`;
  expectError(await call('GET', '/users/me', { token: none }), 401, 'unauthorized');
  // tampered signature
  const tampered = t.access_token.slice(0, -3) + (t.access_token.endsWith('AAA') ? 'BBB' : 'AAA');
  expectError(await call('GET', '/users/me', { token: tampered }), 401, 'unauthorized');
  const me = await call('GET', '/users/me', { token: t.access_token });
  assert.equal(me.status, 200);
  assert.equal((await call('GET', '/users/me', { headers: { Authorization: `bearer ${t.access_token}` } })).status, 200, 'scheme is case-insensitive');
  assert.equal(me.json.user.id, t.user.id);
});

// ---------- refresh ----------

test('refresh rotates, and reusing an old refresh token kills the session', async () => {
  const t1 = await signedUp();
  const r = await call('POST', '/auth/refresh', { body: { refresh_token: t1.refresh_token } });
  assert.equal(r.status, 200, r.text);
  const t2 = r.json;
  assert.notEqual(t2.refresh_token, t1.refresh_token);
  assert.equal(t2.refresh_token.split('.')[0], t1.refresh_token.split('.')[0], 'same session id after rotation');
  assert.equal(t2.user.id, t1.user.id);
  assert.equal((await call('GET', '/users/me', { token: t2.access_token })).status, 200);

  // replay of the rotated token -> 401 and the whole session is revoked
  expectError(await call('POST', '/auth/refresh', { body: { refresh_token: t1.refresh_token } }), 401, 'unauthorized');
  expectError(await call('POST', '/auth/refresh', { body: { refresh_token: t2.refresh_token } }), 401, 'unauthorized');
  expectError(await call('GET', '/users/me', { token: t2.access_token }), 401, 'unauthorized');
});

test('refresh rejects malformed and unknown tokens', async () => {
  const live = await signedUp();
  const [sid, secret] = live.refresh_token.split('.');
  for (const bad of ['nope', 'a.b', `${randomUUID()}.${'A'.repeat(43)}`, `not-a-uuid.${'A'.repeat(43)}`, `${sid.toUpperCase()}.${secret}`, `${sid.replaceAll('-', '')}.${secret}`]) {
    expectError(await call('POST', '/auth/refresh', { body: { refresh_token: bad } }), 401, 'unauthorized');
  }
  // The session id is public (token prefix, JWT sid). Knowing it must not be enough to log the user out:
  // a well-formed secret that was never issued is a plain 401 and revokes nothing.
  for (const guess of ['A'.repeat(43), randomBytes(32).toString('base64url'), `${secret.slice(0, 42)}${secret.endsWith('A') ? 'B' : 'A'}`]) {
    expectError(await call('POST', '/auth/refresh', { body: { refresh_token: `${sid}.${guess}` } }), 401, 'unauthorized');
  }
  expectError(await call('POST', '/auth/refresh', { body: { refresh_token: `${live.refresh_token}\n` } }), 401, 'unauthorized');
  assert.equal((await call('GET', '/users/me', { token: live.access_token })).status, 200, 'session must survive wrong guesses');
  const rotated = await call('POST', '/auth/refresh', { body: { refresh_token: live.refresh_token } });
  assert.equal(rotated.status, 200, 'the real token still works after wrong guesses');
  // ...and guesses after a rotation do not revoke either; only the genuinely previous token does
  expectError(await call('POST', '/auth/refresh', { body: { refresh_token: `${sid}.${'B'.repeat(43)}` } }), 401, 'unauthorized');
  assert.equal((await call('GET', '/users/me', { token: rotated.json.access_token })).status, 200);
  expectError(await call('POST', '/auth/refresh', { body: { refresh_token: live.refresh_token } }), 401, 'unauthorized');
  expectError(await call('GET', '/users/me', { token: rotated.json.access_token }), 401, 'unauthorized');
  expectError(await call('POST', '/auth/refresh', { body: {} }), 422, 'validation_error');
});

// ---------- logout / sessions ----------

test('logout revokes the session immediately', async () => {
  const t = await signedUp();
  assert.equal((await call('POST', '/auth/logout', { token: t.access_token })).status, 204);
  expectError(await call('GET', '/users/me', { token: t.access_token }), 401, 'unauthorized');
  expectError(await call('POST', '/auth/refresh', { body: { refresh_token: t.refresh_token } }), 401, 'unauthorized');
});

test('sessions: list, revoke one, logout-all', async () => {
  const { email } = await register();
  // TRUSTED_PROXY_HOPS=1: the right-most X-Forwarded-For entry is the client, the left side is attacker-controlled
  const a = await login(email, PASSWORD, { 'User-Agent': 'device-a', 'X-Forwarded-For': '6.6.6.6, 203.0.113.9' });
  const b = await login(email, PASSWORD, { 'User-Agent': 'device-b', 'X-Forwarded-For': 'not-an-ip' });
  const c = await login(email, PASSWORD, { 'User-Agent': 'x'.repeat(400) });

  const list = await call('GET', '/auth/sessions', { token: a.access_token });
  assert.equal(list.status, 200);
  assert.equal(list.json.data.length, 3);
  const current = list.json.data.filter((s) => s.current);
  assert.equal(current.length, 1);
  assert.equal(current[0].user_agent, 'device-a');
  assert.equal(current[0].ip, '203.0.113.9');
  const bIp = list.json.data.find((s) => s.user_agent === 'device-b').ip;
  assert.ok(['127.0.0.1', '::1'].includes(bIp), `invalid forwarded value must fall back to the socket peer, got ${bIp}`);
  assert.ok(list.json.data.every((s) => s.user_agent.length <= 255), 'user agent truncated to 255');
  assert.deepEqual(Object.keys(list.json.data[0]).sort(), ['created_at', 'current', 'id', 'ip', 'last_used_at', 'user_agent']);

  const bId = list.json.data.find((s) => s.user_agent === 'device-b').id;
  // another user cannot revoke it
  const other = await signedUp();
  expectError(await call('DELETE', `/auth/sessions/${bId}`, { token: other.access_token }), 404, 'not_found');
  expectError(await call('DELETE', '/auth/sessions/not-a-uuid', { token: a.access_token }), 404, 'not_found');
  expectError(await call('DELETE', `/auth/sessions/${bId.replaceAll('-', '')}`, { token: a.access_token }), 404, 'not_found');
  expectError(await call('DELETE', `/auth/sessions/%7B${bId}%7D`, { token: a.access_token }), 404, 'not_found');
  assert.equal((await call('DELETE', `/auth/sessions/${bId}`, { token: a.access_token })).status, 204);
  expectError(await call('GET', '/users/me', { token: b.access_token }), 401, 'unauthorized');
  expectError(await call('DELETE', `/auth/sessions/${bId}`, { token: a.access_token }), 404, 'not_found'); // already revoked
  assert.equal((await call('GET', '/auth/sessions', { token: a.access_token })).json.data.length, 2);

  assert.equal((await call('POST', '/auth/logout-all', { token: a.access_token })).status, 204);
  expectError(await call('GET', '/users/me', { token: a.access_token }), 401, 'unauthorized');
  expectError(await call('GET', '/users/me', { token: c.access_token }), 401, 'unauthorized');
});

// ---------- email verification ----------

test('verify email: single use, a resend does not kill the earlier link, consuming one kills the rest', async () => {
  const { email } = await register();
  const first = await mailToken(email, '/verify-email');

  const resend = await call('POST', '/auth/resend-verification', { body: { email } });
  assert.equal(resend.status, 202);
  const second = await mailToken(email, '/verify-email', { skip: 1 });
  assert.notEqual(first, second);

  // resend-verification is anonymous: if it invalidated the earlier link, anyone could keep killing the one a user is about to click
  expectError(await call('POST', '/auth/verify-email', { body: { token: 'made-up-token' } }), 400, 'invalid_token');
  assert.equal((await call('POST', '/auth/verify-email', { body: { token: first } })).status, 204, 'earlier link still works after a resend');
  expectError(await call('POST', '/auth/verify-email', { body: { token: first } }), 400, 'invalid_token');
  expectError(await call('POST', '/auth/verify-email', { body: { token: second } }), 400, 'invalid_token');

  const t = await login(email);
  assert.equal(t.user.email_verified, true);

  // already verified -> same 202, but no new mail
  const before = await mailCount(email);
  const again = await call('POST', '/auth/resend-verification', { body: { email } });
  assert.equal(again.status, 202);
  assert.deepEqual(again.json, resend.json);
  await new Promise((r) => setTimeout(r, 500));
  assert.equal(await mailCount(email), before);
});

// ---------- password reset / change ----------

test('forgot/reset password: no enumeration, single use, revokes every session', async () => {
  const { email } = await register();
  const session = await login(email);

  expectError(await call('POST', '/auth/forgot-password', { body: { email: 'not-an-email' } }), 422, 'validation_error');
  expectError(await call('POST', '/auth/resend-verification', { body: {} }), 422, 'validation_error');
  const known = await call('POST', '/auth/forgot-password', { body: { email } });
  const unknown = await call('POST', '/auth/forgot-password', { body: { email: newEmail('ghost') } });
  assert.equal(known.status, 202);
  assert.equal(unknown.status, 202);
  assert.deepEqual(known.json, unknown.json);

  const token = await mailToken(email, '/reset-password');
  const NEW = 'a brand new password';
  // a weak password must not burn the token
  expectError(await call('POST', '/auth/reset-password', { body: { token, password: 'short' } }), 422, 'validation_error');
  // a verification token is not a reset token
  const verifyToken = await mailToken(email, '/verify-email');
  expectError(await call('POST', '/auth/reset-password', { body: { token: verifyToken, password: NEW } }), 400, 'invalid_token');

  // 8 concurrent requests must still leave exactly one usable reset link
  await Promise.all(Array.from({ length: 8 }, () => call('POST', '/auth/forgot-password', { body: { email } })));
  await new Promise((r) => setTimeout(r, 1500));
  const list = await (await fetch(`${MAILPIT}/api/v1/search?query=${encodeURIComponent(`to:${email} subject:reset`)}`)).json();
  const all = [];
  for (const m of list.messages ?? []) {
    const hit = ((await (await fetch(`${MAILPIT}/api/v1/message/${m.ID}`)).json()).Text ?? '').match(/reset-password\?token=([A-Za-z0-9_-]+)/);
    if (hit) all.push(hit[1]);
  }
  assert.ok(all.length >= 9, `expected 9 reset mails, found ${all.length}`);
  const results = [];
  for (const [i, tok] of all.entries()) {
    results.push((await call('POST', '/auth/reset-password', { body: { token: tok, password: `${NEW} ${i}` } })).status);
  }
  assert.equal(results.filter((c) => c === 204).length, 1, `exactly one reset link may work, got ${results}`);
  assert.ok(results.every((c) => c === 204 || c === 400), `${results}`);
  const winner = `${NEW} ${results.indexOf(204)}`;
  await login(email, winner);
  const token2 = (await call('POST', '/auth/forgot-password', { body: { email } }), await mailToken(email, '/reset-password', { skip: all.length }));
  assert.equal((await call('POST', '/auth/reset-password', { body: { token: token2, password: NEW } })).status, 204);
  expectError(await call('POST', '/auth/reset-password', { body: { token: token2, password: 'yet another password' } }), 400, 'invalid_token');

  expectError(await call('GET', '/users/me', { token: session.access_token }), 401, 'unauthorized');
  expectError(await call('POST', '/auth/refresh', { body: { refresh_token: session.refresh_token } }), 401, 'unauthorized');
  expectError(await call('POST', '/auth/login', { body: { email, password: PASSWORD } }), 401, 'invalid_credentials');
  const t = await login(email, NEW);
  assert.equal(t.user.email_verified, true, 'reset link proves email ownership');
});

test('change password keeps this session, revokes the others', async () => {
  const { email } = await register();
  const here = await login(email);
  const elsewhere = await login(email);
  const NEW = 'changed password 123';
  assert.equal((await call('POST', '/auth/forgot-password', { body: { email } })).status, 202);
  const staleReset = await mailToken(email, '/reset-password');

  expectError(
    await call('POST', '/auth/change-password', { token: here.access_token, body: { current_password: 'not my password', new_password: NEW } }),
    401, 'invalid_credentials',
  );
  expectError(
    await call('POST', '/auth/change-password', { token: here.access_token, body: { current_password: PASSWORD, new_password: 'short' } }),
    422, 'validation_error',
  );
  expectError(await call('POST', '/auth/change-password', { body: { current_password: PASSWORD, new_password: NEW } }), 401, 'unauthorized');

  const ok = await call('POST', '/auth/change-password', { token: here.access_token, body: { current_password: PASSWORD, new_password: NEW } });
  assert.equal(ok.status, 204, ok.text);
  assert.equal((await call('GET', '/users/me', { token: here.access_token })).status, 200);
  expectError(await call('GET', '/users/me', { token: elsewhere.access_token }), 401, 'unauthorized');
  await login(email, NEW);
  // change-password must leave reset links alone: the mailbox owner outranks whoever knows the password
  const RECOVERED = 'recovered by the mailbox owner';
  assert.equal((await call('POST', '/auth/reset-password', { body: { token: staleReset, password: RECOVERED } })).status, 204);
  expectError(await call('GET', '/users/me', { token: here.access_token }), 401, 'unauthorized');
  expectError(await call('POST', '/auth/login', { body: { email, password: NEW } }), 401, 'invalid_credentials');
  await login(email, RECOVERED);
});

test('a pre-registered address can always be recovered by the mailbox owner', async () => {
  // The attacker registers the victim's address first and keeps a session.
  const { email } = await register(newEmail('victim'), 'Squatter');
  const attacker = await login(email);
  let attackerPassword = PASSWORD;
  // The victim asks for a reset link; the attacker loops change-password trying to cancel it.
  assert.equal((await call('POST', '/auth/forgot-password', { body: { email } })).status, 202);
  const link = await mailToken(email, '/reset-password');
  for (let i = 0; i < 3; i++) {
    const next = `attacker rotation ${i} ${run}`;
    const res = await call('POST', '/auth/change-password', { token: attacker.access_token, body: { current_password: attackerPassword, new_password: next } });
    assert.equal(res.status, 204, res.text);
    attackerPassword = next;
  }
  const res = await call('POST', '/auth/reset-password', { body: { token: link, password: 'owned by the real owner' } });
  assert.equal(res.status, 204, `the owner's reset link must survive change-password: ${res.text}`);
  expectError(await call('GET', '/users/me', { token: attacker.access_token }), 401, 'unauthorized');
  expectError(await call('POST', '/auth/refresh', { body: { refresh_token: attacker.refresh_token } }), 401, 'unauthorized');
  expectError(await call('POST', '/auth/login', { body: { email, password: attackerPassword } }), 401, 'invalid_credentials');
  assert.equal((await login(email, 'owned by the real owner')).user.email_verified, true);
});

test('mail carries fixed text and the link only, never registrant-chosen text', async () => {
  const marker = `ZZ-PHISH-${run}`;
  const email = newEmail('mailbody');
  const reg = await call('POST', '/auth/register', { body: { email, password: PASSWORD, name: `${marker} visit evil.example` } });
  assert.equal(reg.status, 201, reg.text);
  await mailToken(email, '/verify-email');
  await call('POST', '/auth/forgot-password', { body: { email } });
  await mailToken(email, '/reset-password');
  const list = await (await fetch(`${MAILPIT}/api/v1/search?query=${encodeURIComponent(`to:${email}`)}`)).json();
  assert.equal(list.messages.length, 2);
  for (const m of list.messages) {
    const msg = await (await fetch(`${MAILPIT}/api/v1/message/${m.ID}`)).json();
    const all = `${msg.Subject}\n${msg.Text}\n${msg.HTML ?? ''}`;
    assert.ok(!all.includes(marker), `registrant text leaked into mail "${msg.Subject}"`);
    if (/verify-email\?token=/.test(msg.Text)) assert.match(msg.Text, /If you did not create this account, ignore this email and do not use the link\./);
  }
});

test('login racing reset-password never leaves a session from the old password', async () => {
  // Logins in flight with the OLD password while a reset commits: none of the sessions they return may be alive afterwards.
  for (let round = 0; round < 3; round++) {
    const { email } = await register();
    await call('POST', '/auth/forgot-password', { body: { email } });
    const token = await mailToken(email, '/reset-password');
    const logins = [];
    const fire = (delay) => new Promise((r) => setTimeout(r, delay)).then(() => call('POST', '/auth/login', { body: { email, password: PASSWORD } }));
    for (let i = 0; i < 12; i++) logins.push(fire(i * 12));
    await new Promise((r) => setTimeout(r, 20 + round * 25));
    const reset = await call('POST', '/auth/reset-password', { body: { token, password: `fresh password ${round}` } });
    assert.equal(reset.status, 204, reset.text);
    const results = await Promise.all(logins);
    assert.ok(results.every((r) => r.status === 200 || r.status === 401), `unexpected status: ${results.map((r) => r.status)}`);
    await new Promise((r) => setTimeout(r, 100));
    for (const r of results.filter((x) => x.status === 200)) {
      const me = await call('GET', '/users/me', { token: r.json.access_token });
      const rf = await call('POST', '/auth/refresh', { body: { refresh_token: r.json.refresh_token } });
      // a login that completed entirely before the reset was revoked by it; one that finished after must not have got a session at all
      assert.ok(me.status === 401 && rf.status === 401,
        `round ${round}: a session issued from the old password survived the reset (users/me=${me.status}, refresh=${rf.status})`);
    }
  }
});

// ---------- users / rbac ----------

test('update profile', async () => {
  const t = await signedUp();
  const res = await call('PATCH', '/users/me', { token: t.access_token, body: { name: '  Grace Hopper ', role: 'admin', email: 'x@y.z' } });
  assert.equal(res.status, 200, res.text);
  assert.equal(res.json.user.name, 'Grace Hopper');
  assert.equal(res.json.user.role, 'user', 'role is not mass-assignable');
  assert.equal(res.json.user.email, t.user.email, 'email is not mass-assignable');
  expectError(await call('PATCH', '/users/me', { token: t.access_token, body: { name: '   ' } }), 422, 'validation_error');
  expectError(await call('PATCH', '/users/me', { token: t.access_token, body: { name: 'x'.repeat(101) } }), 422, 'validation_error');
  expectError(await call('PATCH', '/users/me', { token: t.access_token, body: { name: 'nul\u0000byte' } }), 422, 'validation_error');
  // length is counted in code points: 100 emoji are fine, 101 are not
  assert.equal((await call('PATCH', '/users/me', { token: t.access_token, body: { name: '😀'.repeat(100) } })).status, 200);
  expectError(await call('PATCH', '/users/me', { token: t.access_token, body: { name: '😀'.repeat(101) } }), 422, 'validation_error');
  const noop = await call('PATCH', '/users/me', { token: t.access_token, body: {} });
  assert.equal(noop.status, 200);
  assert.equal(noop.json.user.name, '😀'.repeat(100));
});

test('admin route: forbidden for users, role read from DB on every request', { skip: !DATABASE_URL && 'DATABASE_URL not set' }, async () => {
  const t = await signedUp();
  expectError(await call('GET', '/admin/users', { token: t.access_token }), 403, 'forbidden');
  expectError(await call('GET', '/admin/users?page=0', { token: t.access_token }), 403, 'forbidden');
  expectError(await call('GET', '/admin/users'), 401, 'unauthorized');

  assert.match(t.user.id, /^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/, 'refusing to put a non-uuid from the server into SQL');
  execFileSync('psql', [DATABASE_URL, '-qc', `UPDATE auth.users SET role='admin' WHERE id='${t.user.id}'`]);
  // same access token, no re-login needed
  const page = await call('GET', '/admin/users?page=1&per_page=2', { token: t.access_token });
  assert.equal(page.status, 200, page.text);
  assert.equal(page.json.data.length, 2);
  assert.deepEqual({ page: page.json.meta.page, per_page: page.json.meta.per_page }, { page: 1, per_page: 2 });
  assert.ok(page.json.meta.total >= 2);
  assert.equal(page.json.data[0].password_hash, undefined);
  assert.ok(Date.parse(page.json.data[0].created_at) >= Date.parse(page.json.data[1].created_at), 'newest first');
  const dflt = await call('GET', '/admin/users', { token: t.access_token });
  assert.equal(dflt.json.meta.per_page, 20);
  for (const q of ['page=0', 'per_page=101', 'per_page=0', 'page=abc', 'page=1.5', 'page=2147483648', 'page=99999999999999999999']) {
    expectError(await call('GET', `/admin/users?${q}`, { token: t.access_token }), 422, 'validation_error');
  }
});

// ---------- files ----------

test('files: presign, upload, complete, download, list, delete, ownership', async () => {
  const owner = await signedUp();
  const stranger = await signedUp();
  const bytes = Buffer.from(`hello-${run}`.repeat(50));

  expectError(await call('POST', '/files/presign', { body: { filename: 'a.png', content_type: 'image/png', size: 10 } }), 401, 'unauthorized');
  expectError(
    await call('POST', '/files/presign', { token: owner.access_token, body: { filename: 'a.exe', content_type: 'application/x-msdownload', size: 10 } }),
    422, 'validation_error',
  );
  expectError(
    await call('POST', '/files/presign', { token: owner.access_token, body: { filename: 'big.png', content_type: 'image/png', size: 10485761 } }),
    422, 'validation_error',
  );
  expectError(
    await call('POST', '/files/presign', { token: owner.access_token, body: { filename: '', content_type: 'image/png', size: 0 } }),
    422, 'validation_error',
  );
  for (const body of [
    { filename: 'a\u0000.png', content_type: 'image/png', size: 10 },
    { filename: 'a.png', content_type: 'image/png', size: '10' },
    { filename: 'a.png', content_type: 'image/png', size: 1.5 },
  ]) {
    expectError(await call('POST', '/files/presign', { token: owner.access_token, body }), 422, 'validation_error');
  }

  const pre = await call('POST', '/files/presign', {
    token: owner.access_token,
    body: { filename: '../../Evil Name.PNG', content_type: 'image/png', size: bytes.length },
  });
  assert.equal(pre.status, 201, pre.text);
  const { file, upload } = pre.json;
  assert.equal(file.status, 'pending');
  assert.equal(file.filename, '../../Evil Name.PNG');
  assert.equal(file.uploaded_at, null);
  assert.deepEqual(Object.keys(file).sort(), ['content_type', 'created_at', 'filename', 'id', 'size', 'status', 'uploaded_at']);
  assert.equal(upload.method, 'PUT');
  assert.equal(upload.expires_in, 900);
  assert.deepEqual(upload.headers, { 'Content-Type': 'image/png' });
  const key = decodeURIComponent(new URL(upload.url).pathname);
  assert.ok(key.endsWith(`/users/${owner.user.id}/${file.id}.png`), `unexpected object key: ${key}`);

  // before the bytes exist
  const pending = await call('GET', `/files/${file.id}`, { token: owner.access_token });
  assert.equal(pending.json.download_url, null);
  expectError(await call('POST', `/files/${file.id}/complete`, { token: owner.access_token }), 409, 'upload_incomplete');

  // content type is part of the signature
  const wrongType = await fetch(upload.url, { method: 'PUT', headers: { 'Content-Type': 'text/html' }, body: bytes });
  assert.equal(wrongType.status, 403);
  const put = await fetch(upload.url, { method: 'PUT', headers: upload.headers, body: bytes });
  assert.equal(put.status, 200, await put.text());

  expectError(await call('POST', `/files/${file.id}/complete`, { token: stranger.access_token }), 404, 'not_found');
  const done = await call('POST', `/files/${file.id}/complete`, { token: owner.access_token });
  assert.equal(done.status, 200, done.text);
  assert.equal(done.json.file.status, 'uploaded');
  assert.equal(done.json.file.size, bytes.length);
  assert.ok(done.json.file.uploaded_at);
  const again = await call('POST', `/files/${file.id}/complete`, { token: owner.access_token });
  assert.equal(again.status, 200);
  assert.equal(again.json.file.uploaded_at, done.json.file.uploaded_at, 'complete is idempotent');

  const got = await call('GET', `/files/${file.id}`, { token: owner.access_token });
  assert.equal(got.status, 200);
  const dl = await fetch(got.json.download_url);
  assert.equal(dl.status, 200);
  assert.match(dl.headers.get('content-disposition') ?? '', /^attachment/);
  // the upload URL is still valid for 15 minutes, but only for exactly the declared size
  const swap = await fetch(upload.url, { method: 'PUT', headers: upload.headers, body: Buffer.concat([bytes, bytes]) });
  assert.equal(swap.status, 403, 'a different length must not be accepted after complete');
  expectError(await call('GET', `/files/${file.id.replaceAll('-', '')}`, { token: owner.access_token }), 404, 'not_found');
  assert.deepEqual(Buffer.from(await dl.arrayBuffer()), bytes);

  const list = await call('GET', '/files', { token: owner.access_token });
  assert.equal(list.status, 200);
  assert.equal(list.json.meta.total, 1);
  assert.equal(list.json.data[0].id, file.id);
  assert.equal((await call('GET', '/files', { token: stranger.access_token })).json.meta.total, 0);

  expectError(await call('GET', `/files/${file.id}`, { token: stranger.access_token }), 404, 'not_found');
  expectError(await call('DELETE', `/files/${file.id}`, { token: stranger.access_token }), 404, 'not_found');
  expectError(await call('GET', '/files/not-a-uuid', { token: owner.access_token }), 404, 'not_found');

  assert.equal((await call('DELETE', `/files/${file.id}`, { token: owner.access_token })).status, 204);
  expectError(await call('GET', `/files/${file.id}`, { token: owner.access_token }), 404, 'not_found');
  assert.notEqual((await fetch(got.json.download_url)).status, 200, 'object is gone from the bucket');
});

test('files: the bucket only accepts exactly the declared size', async () => {
  const t = await signedUp();
  const pre = await call('POST', '/files/presign', { token: t.access_token, body: { filename: 'liar.pdf', content_type: 'application/pdf', size: 100 } });
  assert.equal(pre.status, 201, pre.text);
  for (const n of [99, 101, 10485761]) {
    const put = await fetch(pre.json.upload.url, { method: 'PUT', headers: pre.json.upload.headers, body: Buffer.alloc(n, 1) });
    assert.equal(put.status, 403, `${n} bytes against a URL signed for 100`);
  }
  expectError(await call('POST', `/files/${pre.json.file.id}/complete`, { token: t.access_token }), 409, 'upload_incomplete');
  const ok = await fetch(pre.json.upload.url, { method: 'PUT', headers: pre.json.upload.headers, body: Buffer.alloc(100, 1) });
  assert.equal(ok.status, 200);
  assert.equal((await call('POST', `/files/${pre.json.file.id}/complete`, { token: t.access_token })).json.file.size, 100);
});

test('change-password racing reset-password never loses the reset', async () => {
  // An attacker with a stolen session + the old password must not be able to overwrite a victim's reset.
  for (const delay of [0, 15, 40]) {
    const { email } = await register();
    const stolen = await login(email);
    await call('POST', '/auth/forgot-password', { body: { email } });
    const token = await mailToken(email, '/reset-password');
    const VICTIM = `victim password ${delay}`, ATTACKER = `attacker password ${delay}`;
    const change = call('POST', '/auth/change-password', { token: stolen.access_token, body: { current_password: PASSWORD, new_password: ATTACKER } });
    await new Promise((r) => setTimeout(r, delay));
    const reset = call('POST', '/auth/reset-password', { body: { token, password: VICTIM } });
    const [c, r] = [(await change).status, (await reset).status];
    assert.ok([204, 401].includes(c) && [204, 400].includes(r), `delay ${delay}: change=${c} reset=${r} (a 500 here is a deadlock)`);
    const victimIn = (await call('POST', '/auth/login', { body: { email, password: VICTIM } })).status === 200;
    const attackerIn = (await call('POST', '/auth/login', { body: { email, password: ATTACKER } })).status === 200;
    if (r === 204) assert.ok(victimIn && !attackerIn, `delay ${delay}: reset returned 204 but the attacker's password won (change=${c})`);
    else assert.ok(attackerIn && !victimIn, `delay ${delay}: change=${c} reset=${r}`);
  }
});
