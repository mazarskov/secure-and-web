const { test, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const argon2 = require('argon2');
const { openDatabase } = require('../src/db');
const { createApp } = require('../src/app');

let db;
let server;
let directory;
let origin;
let parameters;

beforeEach(async () => {
		({ KDF_PARAMETERS: parameters } = await import('../public/crypto.mjs'));
		directory = fs.mkdtempSync(path.join(os.tmpdir(), 'password-manager-registration-'));
		db = openDatabase(path.join(directory, 'test.sqlite'));
		server = createApp(db).listen(0, '127.0.0.1');
		await new Promise(resolve => server.once('listening', resolve));
		origin = `http://127.0.0.1:${server.address().port}`;
});

afterEach(async () => {
		server.closeAllConnections();
		await new Promise(resolve => server.close(resolve));
		db.close();
		fs.rmSync(directory, { recursive: true, force: true });
});

// Storage fixtures only; actual browser wrapping is tested separately.
function payload(email = 'student@example.com') {
		return {
				email,
				authenticationSecret: Buffer.alloc(32, 7).toString('base64'),
				kdfSalt: Buffer.alloc(16, 3).toString('base64'),
				kdfParameters: { ...parameters },
				wrappedDek: Buffer.alloc(48, 4).toString('base64'),
				wrappingNonce: Buffer.alloc(12, 5).toString('base64'),
				cryptoVersion: 1,
		};
}

function register(body, headers = {}) {
		return fetch(`${origin}/api/auth/register`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', Origin: origin, ...headers },
				body: typeof body === 'string' ? body : JSON.stringify(body),
		});
}

test('registration stores a verifiable hash and encrypted vault key, without issuing a session', async () => {
		const request = payload(' Student@Example.com ');
		const response = await register(request);
		assert.equal(response.status, 201);
		assert.equal(response.headers.get('set-cookie'), null);
		assert.equal(response.headers.get('cache-control'), 'no-store');
		const result = await response.json();
		assert.deepEqual(Object.keys(result), ['user']);
		assert.deepEqual(Object.keys(result.user).sort(), ['email', 'id']);
		assert.equal(result.user.email, 'student@example.com');
		const user = db.prepare('SELECT * FROM users').get();
		assert.equal(user.id, result.user.id);
		assert.match(user.auth_verifier, /^\$argon2id\$v=19\$m=65536,t=3,p=1\$/);
		assert.equal(await argon2.verify(user.auth_verifier, Buffer.from(request.authenticationSecret, 'base64')), true);
		assert.notEqual(user.auth_verifier, request.authenticationSecret);
		const key = db.prepare('SELECT * FROM vault_keys').get();
		assert.equal(key.user_id, user.id);
		assert.deepEqual(key.wrapped_dek, Buffer.from(request.wrappedDek, 'base64'));
		assert.deepEqual(key.kdf_salt, Buffer.from(request.kdfSalt, 'base64'));
		assert.deepEqual(key.wrapping_nonce, Buffer.from(request.wrappingNonce, 'base64'));
		assert.deepEqual(JSON.parse(key.kdf_parameters), parameters);
		assert.equal(db.prepare('SELECT count(*) AS count FROM sessions').get().count, 0);
		const reopened = openDatabase(path.join(directory, 'test.sqlite'));
		try {
				assert.equal(reopened.prepare('SELECT id FROM users').get().id, user.id);
		} finally {
				reopened.close();
		}
});

test('case-insensitive duplicate registration leaves one complete account', async () => {
		assert.equal((await register(payload())).status, 201);
		const duplicate = await register(payload('STUDENT@example.com'));
		assert.equal(duplicate.status, 409);
		assert.deepEqual(await duplicate.json(), {error:'Unable to create an account with these details.'});
		assert.equal(db.prepare('SELECT count(*) AS count FROM users').get().count, 1);
		assert.equal(db.prepare('SELECT count(*) AS count FROM vault_keys').get().count, 1);
});

test('independent account verifiers use different salts even for the same authentication secret', async () => {
		assert.equal((await register(payload())).status, 201);
		assert.equal((await register(payload('other@example.com'))).status, 201);
		const users = db.prepare('SELECT auth_verifier FROM users').all();
		assert.notEqual(users[0].auth_verifier, users[1].auth_verifier);
});

test('rejects malformed binary data, unsupported KDF settings, bad email, and unexpected plaintext fields', async () => {
		for (const override of [
				{authenticationSecret:'not-base64'},
				{kdfParameters:{...parameters, memoryKiB:1}},
				{email:'not-an-email'},
				{masterPassword:'must never be accepted'},
				{wrappedDek:Buffer.alloc(32).toString('base64')},
		]) {
				assert.equal((await register({...payload(), ...override})).status, 400);
		}
		assert.equal(db.prepare('SELECT count(*) AS count FROM users').get().count, 0);
});

test('rejects foreign or missing Origin headers and non-JSON requests', async () => {
		assert.equal((await register(payload(), {Origin:'https://attacker.example'})).status, 403);
		assert.equal((await register(payload(), {Origin:''})).status, 403);
		assert.equal((await register(payload(), {'Content-Type':'text/plain'})).status, 415);
});

test('returns controlled JSON errors for malformed and oversized bodies', async () => {
		const malformed = await register('{bad-json');
		assert.equal(malformed.status, 400);
		assert.deepEqual(await malformed.json(), {error:'Invalid JSON.'});
		const oversized = await register({padding:'x'.repeat(5000)});
		assert.equal(oversized.status, 413);
		assert.deepEqual(await oversized.json(), {error:'Request body is too large.'});
});

test('rolls back the user when writing the vault key fails', async () => {
		db.exec("CREATE TRIGGER fail_key BEFORE INSERT ON vault_keys BEGIN SELECT RAISE(ABORT, 'test failure'); END;");
		const response = await register(payload());
		assert.equal(response.status, 500);
		assert.deepEqual(await response.json(), {error:'Unable to process the request.'});
		assert.equal(db.prepare('SELECT count(*) AS count FROM users').get().count, 0);
		assert.equal(db.prepare('SELECT count(*) AS count FROM vault_keys').get().count, 0);
});

test('limits registration attempts per IP and supplies a retry hint', async () => {
		for (let i = 0; i < 5; i += 1) assert.equal((await register({})).status, 400);
		const response = await register({});
		assert.equal(response.status, 429);
		assert.ok(response.headers.get('retry-after'));
});

test('bounds concurrent expensive hashes to two without partially creating the third account', async () => {
		const responses = await Promise.all([0, 1, 2].map(i => register(payload(`user${i}@example.com`))));
		assert.deepEqual(responses.map(response => response.status).sort(), [201, 201, 503]);
		assert.equal(db.prepare('SELECT count(*) AS count FROM users').get().count, 2);
		assert.equal(db.prepare('SELECT count(*) AS count FROM vault_keys').get().count, 2);
});
