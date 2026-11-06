const { test, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createHash } = require('node:crypto');
const argon2 = require('argon2');
const { openDatabase } = require('../src/db');
const { createApp } = require('../src/app');

let db;
let server;
let directory;
let origin;
let time;
let parameters;
const secret = Buffer.alloc(32, 7).toString('base64');

async function start() {
		server = createApp(db, { now: () => time }).listen(0, '127.0.0.1');
		await new Promise(resolve => server.once('listening', resolve));
		origin = `http://127.0.0.1:${server.address().port}`;
}

async function stop() {
		server.closeAllConnections();
		await new Promise(resolve => server.close(resolve));
}

beforeEach(async () => {
		({ KDF_PARAMETERS: parameters } = await import('../public/crypto.mjs'));
		directory = fs.mkdtempSync(path.join(os.tmpdir(), 'password-manager-auth-'));
		db = openDatabase(path.join(directory, 'test.sqlite'));
		time = 1800000000;
		const verifier = await argon2.hash(Buffer.from(secret, 'base64'), {
				type: argon2.argon2id, memoryCost: 65536, timeCost: 3, parallelism: 1, hashLength: 32,
		});
		db.prepare('INSERT INTO users (id, email, auth_verifier) VALUES (?, ?, ?)').run('user-1', 'student@example.com', verifier);
		db.prepare(`INSERT INTO vault_keys VALUES (?, ?, ?, ?, ?, ?)`)
				.run('user-1', Buffer.alloc(16, 3), JSON.stringify(parameters), Buffer.alloc(48), Buffer.alloc(12), 1);
		await start();
});

afterEach(async () => {
		await stop();
		db.close();
		fs.rmSync(directory, { recursive: true, force: true });
});

function call(route, { method = 'GET', body, cookie, headers = {} } = {}) {
		return fetch(`${origin}/api/auth${route}`, {
				method,
				headers: {
						...(method === 'POST' ? { Origin: origin, 'Content-Type': 'application/json' } : {}),
						...(cookie ? { Cookie: cookie } : {}), ...headers,
				},
				...(body === undefined ? {} : { body: JSON.stringify(body) }),
		});
}

async function login(cookie) {
		const response = await call('/login', {
				method: 'POST', cookie, body: { email: ' STUDENT@example.com ', authenticationSecret: secret },
		});
		assert.equal(response.status, 200);
		return { cookie: response.headers.get('set-cookie').split(';')[0], result: await response.json(), response };
}

test('returns public KDF metadata and stable same-shaped decoys for unknown accounts', async () => {
		const known = await call('/parameters?email=STUDENT%40example.com');
		assert.equal(known.status, 200);
		assert.equal(known.headers.get('cache-control'), 'no-store');
		const metadata = await known.json();
		assert.equal(metadata.kdfSalt, Buffer.alloc(16, 3).toString('base64'));
		assert.deepEqual(metadata.kdfParameters, parameters);
		const unknown = await (await call('/parameters?email=missing%40example.com')).json();
		assert.deepEqual(Object.keys(unknown), Object.keys(metadata));
		assert.equal(Buffer.from(unknown.kdfSalt, 'base64').length, 16);
		assert.deepEqual(unknown, await (await call('/parameters?email=missing%40example.com')).json());
		assert.equal((await call('/parameters?email=bad')).status, 400);
});

test('issues a secure session cookie, stores only its hash, and protects account information', async () => {
		assert.equal((await call('/me')).status, 401);
		const session = await login();
		const header = session.response.headers.get('set-cookie');
		assert.match(header, /^__Host-session=[A-Za-z0-9_-]{43};/);
		for (const flag of ['HttpOnly', 'Secure', 'SameSite=Strict', 'Path=/']) assert.ok(header.includes(flag));
		assert.doesNotMatch(header, /Domain=|Max-Age=|Expires=/i);
		const rawId = session.cookie.split('=')[1];
		const stored = db.prepare('SELECT * FROM sessions').get();
		assert.equal(stored.session_id_hash, createHash('sha256').update(rawId).digest('hex'));
		assert.notEqual(stored.session_id_hash, rawId);
		assert.equal(stored.absolute_expiry - stored.created_at, 8 * 60 * 60);
		assert.deepEqual(session.result.user, {id:'user-1', email:'student@example.com'});
		assert.deepEqual(Object.keys(session.result).sort(), ['csrfToken', 'user']);
		const me = await call('/me', {cookie:session.cookie});
		assert.equal(me.status, 200);
		assert.deepEqual(await me.json(), session.result);
});

test('unknown accounts and wrong secrets fail with the same generic error', async () => {
		const wrong = await call('/login', {method:'POST', body:{email:'student@example.com', authenticationSecret:Buffer.alloc(32).toString('base64')}});
		// The dummy hash matches this zero secret, but an unknown account must still fail.
		const unknown = await call('/login', {method:'POST', body:{email:'missing@example.com', authenticationSecret:Buffer.alloc(32).toString('base64')}});
		assert.equal(wrong.status, 401);
		assert.equal(unknown.status, 401);
		assert.deepEqual(await wrong.json(), await unknown.json());
		assert.equal(wrong.headers.get('set-cookie'), null);
		assert.equal(db.prepare('SELECT count(*) AS count FROM sessions').get().count, 0);
});

test('successful reauthentication rotates the ID and invalidates the prior cookie and CSRF token', async () => {
		const first = await login();
		const second = await login(first.cookie);
		assert.notEqual(first.cookie, second.cookie);
		assert.notEqual(first.result.csrfToken, second.result.csrfToken);
		assert.equal((await call('/me', {cookie:first.cookie})).status, 401);
		assert.equal((await call('/me', {cookie:second.cookie})).status, 200);
		assert.equal(db.prepare('SELECT count(*) AS count FROM sessions').get().count, 1);
		const logout = await call('/logout', {method:'POST',cookie:second.cookie,headers:{'X-CSRF-Token':first.result.csrfToken}});
		assert.equal(logout.status, 403);
});

test('idle sessions expire at 15 minutes and their rows are removed', async () => {
		const session = await login();
		time += 15 * 60;
		const response = await call('/me', {cookie:session.cookie});
		assert.equal(response.status, 401);
		assert.match(response.headers.get('set-cookie'), /Expires=/);
		assert.equal(db.prepare('SELECT count(*) AS count FROM sessions').get().count, 0);
});

test('authenticated activity refreshes idle time but never extends the absolute lifetime', async () => {
		const session = await login();
		const started = time;
		for (time = started + 14 * 60; time < started + 8 * 60 * 60; time += 14 * 60) {
				assert.equal((await call('/me', {cookie:session.cookie})).status, 200);
		}
		time = started + 8 * 60 * 60;
		assert.equal((await call('/me', {cookie:session.cookie})).status, 401);
});

test('logout requires same-origin JSON and the session-bound CSRF token, then revokes the cookie', async () => {
		const session = await login();
		assert.equal((await call('/logout', {method:'POST',cookie:session.cookie})).status, 403);
		assert.equal((await call('/logout', {method:'POST',cookie:session.cookie,headers:{'X-CSRF-Token':'a'.repeat(64)}})).status, 403);
		assert.equal((await call('/logout', {method:'POST',cookie:session.cookie,headers:{Origin:'https://attacker.example','X-CSRF-Token':session.result.csrfToken}})).status, 403);
		assert.equal((await call('/me', {cookie:session.cookie})).status, 200);
		const response = await call('/logout', {method:'POST',cookie:session.cookie,headers:{'X-CSRF-Token':session.result.csrfToken}});
		assert.equal(response.status, 204);
		assert.match(response.headers.get('set-cookie'), /Expires=/);
		assert.equal((await call('/me', {cookie:session.cookie})).status, 401);
});

test('CSRF tokens cannot be reused with a separate session', async () => {
		const first = await login();
		const second = await login();
		const response = await call('/logout', {method:'POST',cookie:second.cookie,headers:{'X-CSRF-Token':first.result.csrfToken}});
		assert.equal(response.status, 403);
});

test('sessions and their CSRF tokens survive restarting the app against the same database', async () => {
		const session = await login();
		await stop();
		db.close();
		db = openDatabase(path.join(directory, 'test.sqlite'));
		await start();
		const response = await call('/me', {cookie:session.cookie});
		assert.equal(response.status, 200);
		assert.deepEqual(await response.json(), session.result);
});

test('forged, malformed, duplicated, and deleted-account cookies cannot authenticate', async () => {
		const session = await login();
		for (const cookie of ['__Host-session=invalid', `__Host-session=${'x'.repeat(43)}`, `${session.cookie}; ${session.cookie}`]) {
				assert.equal((await call('/me', {cookie})).status, 401);
		}
		db.prepare('DELETE FROM users WHERE id = ?').run('user-1');
		assert.equal((await call('/me', {cookie:session.cookie})).status, 401);
});

test('login rejects missing Origin, non-JSON input, malformed secrets, and extra plaintext fields', async () => {
		const body = {email:'student@example.com',authenticationSecret:secret};
		assert.equal((await call('/login', {method:'POST',body,headers:{Origin:''}})).status, 403);
		assert.equal((await call('/login', {method:'POST',body,headers:{'Content-Type':'text/plain'}})).status, 415);
		assert.equal((await call('/login', {method:'POST',body:{...body,authenticationSecret:'invalid'}})).status, 400);
		assert.equal((await call('/login', {method:'POST',body:{...body,masterPassword:'never send this'}})).status, 400);
});

test('rate-limits repeated login attempts', async () => {
		for (let i = 0; i < 10; i += 1) assert.equal((await call('/login', {method:'POST',body:{}})).status, 400);
		const response = await call('/login', {method:'POST',body:{}});
		assert.equal(response.status, 429);
		assert.ok(response.headers.get('retry-after'));
});

test('bounds expensive login verifications to two concurrent requests', async () => {
		const responses = await Promise.all([0, 1, 2].map(() => call('/login', {method:'POST',body:{email:'student@example.com',authenticationSecret:secret}})));
		assert.deepEqual(responses.map(response => response.status).sort(), [200, 200, 503]);
});
