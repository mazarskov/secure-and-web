# Secure Password Manager

A web-based password manager developed for the Web Application Security course.

The application will allow users to securely store, manage, and retrieve their credentials through a web interface. Its main security objective is to ensure that stored credentials are encrypted in the browser before being transmitted to the server.

## 1. Project Scope

The project will implement a web-based password manager with the following core functionality:

* User registration, login, and logout.
* A single master password for account authentication and vault unlocking.
* Client-side encryption and decryption of stored credentials.
* Secure storage of encrypted credentials in an SQLite database.
* Creating, viewing, updating, and deleting vault entries.
* Generation of secure, random passwords.
* Session management and automatic vault locking.
* Security testing against relevant web application vulnerabilities.

## 2. Planned Features

### Authentication

Users will create an account using an email address and a master password.

The master password will be used to derive separate cryptographic keys for authentication and vault encryption. The master password itself will not be transmitted to the backend.

The backend will verify a password-derived authentication secret and establish an authenticated session.

### Password Vault

Authenticated users will be able to create, view, update, and delete credentials.

Each vault entry will contain:

* Website or service name.
* Website URL.
* Username or email address.
* Password.
* Optional notes.

Vault entries will be encrypted in the browser before being sent to the backend. The backend will store and retrieve encrypted records without decrypting them.

### Password Generator

The application will provide a password generator using cryptographically secure random values.

Users will be able to generate passwords with configurable lengths and character types.

### Session Management

Authentication will use server-managed sessions and secure cookies.

Planned security controls include session expiration, session invalidation on logout, and automatic vault locking after inactivity.

## 3. Planned API Routes

The backend will expose the following REST API endpoints.

### Authentication

| Method | Route | Description |
| - | - | - |
| POST | `/api/auth/register` | Register a new user and initialize their encrypted vault. |
| POST | `/api/auth/login` | Authenticate a user and create a session. |
| POST | `/api/auth/logout` | Invalidate the current session. |
| GET | `/api/auth/me` | Retrieve the authenticated user's account information. |
| GET | `/api/auth/parameters` | Retrieve public key-derivation parameters needed for authentication. |

### Vault

| Method | Route | Description |
| - | - | - |
| GET | `/api/vault/key` | Retrieve the encrypted vault key and associated cryptographic metadata. |
| GET | `/api/vault/items` | Retrieve the authenticated user's encrypted vault entries. |
| POST | `/api/vault/items` | Create a new encrypted vault entry. |
| PUT | `/api/vault/items/:id` | Update an existing vault entry. |
| DELETE | `/api/vault/items/:id` | Delete a vault entry. |

All vault endpoints will require authentication. The backend will verify that each requested entry belongs to the authenticated user.

The vault API will accept and return encrypted credential data rather than plaintext passwords.

### Other

GET `/api/health` to check whether the backend is running.

The API routes listed above are planned functionality and can change over time.

## 4. Running the Project Locally

### Prerequisites

* Node.js 22 or newer, with npm (bundled with Node.js).
* Git to clone the repository.
* A web browser to open the application.

Check your installation with `node --version` and `npm --version`.
Use Node.js and npm from the same environment: Windows for PowerShell/Command
Prompt, or Linux installations for WSL.

Dependencies are listed in `package.json` and pinned in `package-lock.json`.
No separate SQLite server, environment variables, or certificate setup is needed.
SQLite is embedded in the app. If a prebuilt native binary is unavailable,
installation requires Python 3 and a C++ build toolchain
(Visual Studio C++ Build Tools on Windows, or `make` and GCC/Clang on Linux).

### Install and Start

```bash
git clone https://github.com/mazarskov/secure-and-web
cd secure-and-web/web-app-security
npm ci
npm run dev
```

`npm run dev` restarts the server when server files change. Alternatively, use
`npm start` to run without watch mode. Stop either command with `Ctrl+C`.

Open <https://127.0.0.1:3000> (or <https://localhost:3000>).
The server listens only on the local machine, on port 3000. If that port is in
use, stop the other process before starting the server.

### Development HTTPS Certificate

A self-signed certificate and its matching key are included in `certs/dev/`.
The browser will show a certificate warning because this certificate is not
publicly trusted. For this local course demo, open the browser's advanced options
and continue to the local address. No installation into the system trust store
is needed. Browser or organization policies may prevent accepting the warning.

**The bundled private key is intentionally public and only for local development.**
Use test data in this demo. Deployment requires a separate trusted certificate
and a private key that is never committed. TLS encrypts the connection, but this
shared development identity does not provide dependable server authentication.

The certificate covers `localhost`, `127.0.0.1`, and `::1`; the server binds to
`127.0.0.1`. It is kept outside `public/`, so Express does not serve the key.
See [certs/dev/README.md](certs/dev/README.md) for validity and regeneration.
OpenSSL is needed only if regenerating the bundled certificate.

### Check the Server

Open <https://127.0.0.1:3000/api/health> after accepting the browser warning.
Expected response:

```json
{"status":"ok"}
```

For a terminal check, explicitly trust only the bundled certificate:

```bash
curl --cacert certs/dev/localhost.pem https://127.0.0.1:3000/api/health
```

On Windows PowerShell, use `curl.exe` instead of `curl`. If Windows curl reports
`CRYPT_E_NO_REVOCATION_CHECK`, add `--ssl-revoke-best-effort`; certificate and
hostname verification remain enabled.

### Local Database

Starting the server automatically creates `data/password-manager.sqlite` and
initializes any missing tables. No manual database setup is needed. The path is
resolved relative to `src/db.js`, so it does not depend on the terminal directory.
The database and its SQLite journal files are ignored by Git and are outside
`public/`. Keep this data directory when restarting to preserve accounts and vaults.

| Table | Purpose |
| --- | --- |
| `users` | Account ID, unique email, authentication verifier, creation time. |
| `vault_keys` | One encrypted vault key per account, salt, KDF parameters, wrapping nonce, format version. |
| `vault_items` | Encrypted entries linked to their owner, nonce, version, timestamps. |
| `sessions` | Hashed session IDs linked to accounts, activity time, absolute expiry. |

IDs are text (the application will generate them). Encrypted data, salts, and
nonces are stored as binary BLOBs; KDF parameters are JSON text. AES-GCM values
include the authentication tag: a wrapped 32-byte key occupies 48 bytes.
Session hashes will be SHA-256 hex strings; timestamps use Unix seconds (UTC).
Future entry updates must explicitly set `updated_at`.

Foreign keys reject records without an existing owner. Deleting an account
cascades to its vault key, entries, and sessions. Email uniqueness ignores letter
case. These storage constraints support the API; request authorization and
session-expiry enforcement will still be implemented separately.

Initialization runs in one transaction and uses `CREATE TABLE IF NOT EXISTS`:
it preserves existing rows on restart. WAL mode supports database reads during
writes. Future changes to existing tables will require migrations; startup does
not automatically alter their definitions.

#### Table Schemas

The SQL below matches `src/db.js`, including keys, defaults, constraints, and
indexes. `STRICT` enforces the declared SQLite column types. Every column is
required (`NOT NULL`); timestamp defaults use Unix seconds.

```sql
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
```

Run the database checks with:

```bash
npm test
```

Tests use temporary databases, leaving the application's data untouched. They
cover persistence after reopening, case-insensitive email uniqueness, foreign
keys, one vault key per account, deletion cleanup, and malformed crypto metadata
or invalid session expiry. No example accounts are inserted by the app.

### Progress

**Step 1:** Express serves the placeholder page and `/api/health` from one origin.
Both npm scripts use `src/server.js`; `dev` enables automatic restarts.

**Step 2:** HTTPS uses the bundled self-signed development certificate, with TLS
1.2 as the minimum. The browser warning is expected for this local demo.

**Step 3:** `src/db.js` opens and initializes SQLite before the server accepts
requests. All four tables, their relationships, and basic data constraints are
implemented. Six database tests pass. Authentication and vault cryptography are
not yet implemented.

Next: derive separate authentication and vault-wrapping secrets from the master
password in the browser.
