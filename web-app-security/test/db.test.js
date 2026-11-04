const { test, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { openDatabase } = require('../src/db');

let directory;
let filename;
let db;

beforeEach(() => {
		directory = fs.mkdtempSync(path.join(os.tmpdir(), 'password-manager-db-'));
		filename = path.join(directory, 'nested', 'test.sqlite');
		db = openDatabase(filename);
});

afterEach(() => {
		if (db?.open) db.close();
		fs.rmSync(directory, { recursive: true, force: true });
});

function addUser(id = 'user-1', email = 'student@example.com') {
		db.prepare('INSERT INTO users (id, email, auth_verifier) VALUES (?, ?, ?)')
				.run(id, email, 'test-only-verifier');
}

function addVaultKey(userId = 'user-1', salt = Buffer.alloc(16), parameters = '{}') {
		db.prepare(`
				INSERT INTO vault_keys
				(user_id, kdf_salt, kdf_parameters, wrapped_dek, wrapping_nonce, crypto_version)
				VALUES (?, ?, ?, ?, ?, ?)
		`).run(userId, salt, parameters, Buffer.alloc(48), Buffer.alloc(12), 1);
}

function addItem(userId = 'user-1', nonce = Buffer.alloc(12)) {
		db.prepare(`
				INSERT INTO vault_items (id, user_id, ciphertext, nonce, crypto_version)
				VALUES (?, ?, ?, ?, ?)
		`).run('item-1', userId, Buffer.alloc(32, 7), nonce, 1);
}

function addSession(userId = 'user-1', expiry = 2000) {
		db.prepare(`
				INSERT INTO sessions
				(session_id_hash, user_id, created_at, last_activity_at, absolute_expiry)
				VALUES (?, ?, ?, ?, ?)
		`).run('a'.repeat(64), userId, 1000, 1000, expiry);
}

test('account, encrypted vault data, and session survive closing and reopening', () => {
		addUser();
		addVaultKey();
		addItem();
		addSession();
		db.close();
		db = openDatabase(filename);

		assert.equal(db.prepare('SELECT email FROM users').get().email, 'student@example.com');
		assert.deepEqual(db.prepare('SELECT wrapped_dek FROM vault_keys').get().wrapped_dek, Buffer.alloc(48));
		assert.deepEqual(db.prepare('SELECT ciphertext FROM vault_items').get().ciphertext, Buffer.alloc(32, 7));
		assert.equal(db.prepare('SELECT absolute_expiry FROM sessions').get().absolute_expiry, 2000);
		assert.deepEqual(db.pragma('foreign_key_check'), []);
});

test('rejects duplicate email addresses regardless of letter case', () => {
		addUser();
		assert.throws(() => addUser('user-2', 'STUDENT@example.com'), { code: 'SQLITE_CONSTRAINT_UNIQUE' });
});

test('rejects vault keys, entries, and sessions belonging to a missing account', () => {
		for (const insert of [addVaultKey, addItem, addSession]) {
				assert.throws(() => insert('missing-user'), { code: 'SQLITE_CONSTRAINT_FOREIGNKEY' });
		}
});

test('only one wrapped vault key can belong to an account', () => {
		addUser();
		addVaultKey();
		assert.throws(() => addVaultKey(), { code: 'SQLITE_CONSTRAINT_PRIMARYKEY' });
});

test('deleting an account removes its vault and sessions but keeps another account', () => {
		addUser();
		addUser('user-2', 'other@example.com');
		addVaultKey();
		addItem();
		addSession();
		db.prepare('DELETE FROM users WHERE id = ?').run('user-1');

		for (const table of ['vault_keys', 'vault_items', 'sessions']) {
				assert.equal(db.prepare(`SELECT count(*) AS count FROM ${table}`).get().count, 0);
		}
		assert.equal(db.prepare('SELECT id FROM users').get().id, 'user-2');
});

test('rejects short salts, malformed metadata, wrong nonce sizes, and invalid expiry', () => {
		addUser();
		assert.throws(() => addVaultKey('user-1', Buffer.alloc(8)), { code: 'SQLITE_CONSTRAINT_CHECK' });
		assert.throws(() => addVaultKey('user-1', Buffer.alloc(16), 'not-json'), { code: 'SQLITE_CONSTRAINT_CHECK' });
		assert.throws(() => addItem('user-1', Buffer.alloc(8)), { code: 'SQLITE_CONSTRAINT_CHECK' });
		assert.throws(() => addSession('user-1', 999), { code: 'SQLITE_CONSTRAINT_CHECK' });
});
