const Database = require('better-sqlite3');
const fs = require('node:fs');
const path = require('node:path');

const defaultDatabasePath = path.join(__dirname, '../data/password-manager.sqlite');

function openDatabase(filename = defaultDatabasePath) {
		fs.mkdirSync(path.dirname(filename), { recursive: true });
		const db = new Database(filename);

		try {
				// Enable ownership relationships on every connection, not just at creation.
				db.pragma('foreign_keys = ON');
				db.pragma('journal_mode = WAL');

				// All tables are created together. Reopening an existing database preserves data.
				db.transaction(() => {
						db.exec(`
								CREATE TABLE IF NOT EXISTS users (
										id TEXT PRIMARY KEY NOT NULL,
										email TEXT NOT NULL COLLATE NOCASE UNIQUE,
										auth_verifier TEXT NOT NULL,
										created_at INTEGER NOT NULL DEFAULT (unixepoch())
								) STRICT;

								CREATE TABLE IF NOT EXISTS vault_keys (
										user_id TEXT PRIMARY KEY NOT NULL REFERENCES users(id) ON DELETE CASCADE,
										kdf_salt BLOB NOT NULL CHECK (length(kdf_salt) >= 16),
										kdf_parameters TEXT NOT NULL CHECK (json_valid(kdf_parameters)),
										wrapped_dek BLOB NOT NULL CHECK (length(wrapped_dek) = 48),
										wrapping_nonce BLOB NOT NULL CHECK (length(wrapping_nonce) = 12),
										crypto_version INTEGER NOT NULL CHECK (crypto_version > 0)
								) STRICT;

								CREATE TABLE IF NOT EXISTS vault_items (
										id TEXT PRIMARY KEY NOT NULL,
										user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
										ciphertext BLOB NOT NULL CHECK (length(ciphertext) >= 16),
										nonce BLOB NOT NULL CHECK (length(nonce) = 12),
										crypto_version INTEGER NOT NULL CHECK (crypto_version > 0),
										created_at INTEGER NOT NULL DEFAULT (unixepoch()),
										updated_at INTEGER NOT NULL DEFAULT (unixepoch())
								) STRICT;

								CREATE TABLE IF NOT EXISTS sessions (
										session_id_hash TEXT PRIMARY KEY NOT NULL CHECK (length(session_id_hash) = 64),
										user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
										created_at INTEGER NOT NULL DEFAULT (unixepoch()),
										last_activity_at INTEGER NOT NULL DEFAULT (unixepoch()),
										absolute_expiry INTEGER NOT NULL,
										CHECK (last_activity_at >= created_at),
										CHECK (absolute_expiry > created_at)
								) STRICT;

								CREATE INDEX IF NOT EXISTS vault_items_user_id ON vault_items(user_id);
								CREATE INDEX IF NOT EXISTS sessions_user_id ON sessions(user_id);
								CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(absolute_expiry);
						`);
				})();

				return db;
		} catch (error) {
				db.close();
				throw error;
		}
}

module.exports = { openDatabase };
