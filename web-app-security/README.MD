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
| POST | `/api/auth/register` | Implemented: register a user and store their encrypted vault key. |
| POST | `/api/auth/login` | Implemented: authenticate and issue a new session. |
| POST | `/api/auth/logout` | Implemented: revoke the current session (CSRF token required). |
| GET | `/api/auth/me` | Implemented: retrieve account information and a CSRF token. |
| GET | `/api/auth/parameters?email=...` | Implemented: retrieve public key-derivation parameters. |

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

Authentication routes and the health check are implemented; vault routes remain planned.

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
SQLite is embedded in the app. The `better-sqlite3` and server-side `argon2`
packages use native modules. If a prebuilt binary is unavailable, installation
requires Python 3 and a C++ build toolchain
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

### Browser Key Derivation

The home page now includes a **Key derivation demo**. Start the app, accept the
local certificate warning, enter a test password, and click **Derive secrets**.
Success confirms the computation; it does not create an account. The password
field is cleared, the authentication-secret buffer is overwritten, and the demo
discards its reference to the wrapping key. No secrets are displayed, logged,
sent to the API, or stored in browser storage.

`public/crypto.mjs` implements this flow:

1. Generate a fresh 16-byte salt with `crypto.getRandomValues`.
2. Encode the exact password as UTF-8 and derive a 32-byte root with Argon2id.
3. Apply HKDF-SHA-256 with that salt and label `auth/v1` to derive the 32-byte
   authentication secret. During registration this password-equivalent secret goes
   to the backend over HTTPS, where it is hashed for later verification.
4. Apply HKDF-SHA-256 with label `vault-wrap/v1` to derive a separate AES-256-GCM
   key. It is a non-exportable `CryptoKey`, usable only for wrapping/unwrapping
   the vault key. It stays in the browser.

Version 1 metadata records these fixed parameters:

| Parameter | Value |
| --- | --- |
| Algorithm / Argon2 version | Argon2id / 19 (0x13) |
| Memory | 65,536 KiB (64 MiB) |
| Iterations / parallelism | 3 / 1 |
| Root output / salt length | 32 bytes / 16 bytes |
| Metadata format version | 1 |

The same password, salt, and parameters reproduce the same secrets; different
labels separate their purposes. The salt and parameters are public metadata and
must be retained for later login. This demo generates new metadata on each run
and discards it; the registration form persists it with the account. Unsupported metadata is
rejected before expensive work. Passwords must be nonempty and at most 1024
UTF-8 bytes; they are not trimmed or normalized.

The pinned `argon2-browser` dependency is served from
`/vendor/argon2-bundled.min.js`, including its WebAssembly code. No CDN, frontend
build step, or extra setup is needed after `npm ci`. Only that bundle is exposed
from `node_modules`. The browser must support Web Crypto and WebAssembly.

Clearing buffers is best effort: JavaScript strings, library copies, and
`CryptoKey` objects cannot be reliably erased. The root and wrapping key must
never be sent to the server. The registration form below uses these secrets to
initialize an encrypted vault key.

`npm test` now includes reference-vector checks against independently generated
native Argon2id/HKDF/AES-GCM output, repeatability, wrapping-key permissions,
password/salt changes, fresh salts, and invalid metadata.
The demo was also checked in headless Chrome over HTTPS, including failure when
the Argon2 bundle is unavailable, no network requests during derivation, and no
browser-storage writes.

Implementation references: [argon2-browser](https://github.com/antelle/argon2-browser)
and the [Web Crypto specification](https://www.w3.org/TR/webcrypto/).

### Account Registration

After `npm ci`, run `npm run dev` and open the HTTPS home page. Under **Create an
account**, enter an email and a matching test master password of at least 12
characters (at most 1024 UTF-8 bytes). Passwords are preserved exactly, including
spaces and Unicode. The length rule is checked in the browser: the server sees
a derived secret and cannot measure the original password. Keep using test
credentials with the bundled development certificate.

The registration flow is:

1. The browser generates a salt and derives the authentication and wrapping secrets.
2. It generates a random AES-256 vault key and wraps it with AES-GCM using a fresh
   12-byte nonce. The wrapped key includes the authentication tag (48 bytes total).
3. It sends the payload below as JSON to `POST /api/auth/register`. Binary fields
   use canonical Base64. The master password, root key, wrapping key, and plaintext
   vault key are absent from the request.
4. The server validates the payload and hashes the authentication secret using
   Argon2id with an independent random salt, 64 MiB memory, 3 iterations,
   parallelism 1, and a 32-byte hash. The encoded verifier includes these settings.
5. One database transaction inserts the user and vault-key metadata together.
   If either insert fails, neither record is kept. The response contains only
   the account ID and normalized email.

| Request field | Required format |
| --- | --- |
| `email` | ASCII email, at most 254 characters after trimming; stored lowercase. |
| `authenticationSecret` | Base64 encoding of 32 bytes; never stored directly. |
| `kdfSalt` | Base64 encoding of 16 bytes. |
| `kdfParameters` | Exact version 1 parameter object listed above. |
| `wrappedDek` | Base64 encoding of 48 encrypted bytes. |
| `wrappingNonce` | Base64 encoding of 12 bytes. |
| `cryptoVersion` | Integer `1`. |

Unexpected fields are rejected. The server validates lengths and format; it
cannot decrypt the wrapped key to verify its contents. Email ownership is not
verified in this checkpoint step.

Registration returns `201` on success, `400` for invalid input, `403` for a
missing/foreign Origin, `409` for an unavailable account, `413` for a body over
4 KiB, and `415` for a non-JSON request. Five attempts per IP per 15 minutes are
allowed (`429` after that); this local in-memory limit resets on restart. At
most two hashes run concurrently (`503` with a retry hint when busy). Internal
failures return a generic `500`, without SQL details or request bodies.

The browser supplies its same-origin `Origin` header automatically; API clients
must supply one matching the server's scheme and host. Registration does not
issue a cookie or authenticate the user. The password fields are cleared, the
authentication buffer is overwritten, and remaining secret references are
discarded on completion. No secrets are written to browser storage; JavaScript
strings and library copies still cannot be guaranteed erased.

Code responsibilities: `public/crypto.mjs` prepares the encrypted payload,
`public/app.js` handles the form, `src/registration.js` validates/hashes/saves it,
and `src/app.js` assembles the Express routes. `src/server.js` opens the database
and starts HTTPS.

Registration tests cover real Argon2 verification, random
verifier salts, duplicate accounts, rollback on vault-key failure, input and
Origin checks, request limits, key recovery, and rejection of a wrong password
or modified wrapped key. HTTPS registration was also exercised in headless
Chrome with a temporary database, checking the request fields, cleared password
inputs, duplicate handling, and network-failure recovery. No test accounts were
added to the application's database.

Server hashing reference: [node-argon2](https://github.com/ranisalt/node-argon2).

### Login and Secure Sessions

Create a test account, then use **Sign in** with its email and master password.
The password field is cleared after submission. A successful login shows the
account email; the vault remains locked until the next implementation step.
Reloading the page restores the account session through `/api/auth/me`.
**Check session** explicitly checks validity; there is no automatic keep-alive
polling. Use the same hostname throughout: `localhost` and `127.0.0.1` have
separate host-only cookies.

The login flow is:

1. `GET /api/auth/parameters?email=...` returns the account's public salt and KDF
   parameters. Unknown accounts receive same-shaped decoy metadata, stable within
   a server run. This reduces obvious enumeration signals; it does not guarantee
   account-existence privacy.
2. The browser derives the authentication secret again and posts only `email`
   and Base64 `authenticationSecret` to `POST /api/auth/login`.
3. The server verifies the stored Argon2id hash. Unknown accounts run a dummy
   Argon2 verification of the same cost and always fail. Wrong secrets and
   unknown accounts return the same `401` error.
4. Successful login generates a new 32-byte random session ID. Its SHA-256 hash
   and timestamps go into SQLite; the raw ID goes only into the cookie.
   A previous session presented by the same browser is revoked, preventing
   reuse of a fixed or pre-login ID. Other device sessions remain independent.
5. The response contains `{ user: { id, email }, csrfToken }`. The browser keeps
   the CSRF token in module memory; the session ID is never exposed to JavaScript.

The cookie is named `__Host-session` with `Secure`, `HttpOnly`, `SameSite=Strict`,
`Path=/`, no `Domain`, and no persistent expiry. The server enforces a **15-minute
idle timeout** and an **8-hour absolute lifetime**, regardless of browser cookie
retention. Authenticated activity updates idle time but never extends the
absolute deadline. Expired sessions are rejected, deleted, and cleared from the
browser. Login also cleans up other expired rows. Valid sessions survive a
server restart because they are stored in SQLite.

`GET /api/auth/me` requires a valid cookie and returns account information plus
the session-bound CSRF token. All authentication responses use `Cache-Control:
no-store`. The CSRF token is HMAC-SHA-256 keyed by the high-entropy raw session ID
with context `csrf/v1`; it can be reproduced after a restart without storing a
raw session ID or adding a database column. Verification uses constant-time
comparison after checking the token's format.

`POST /api/auth/logout` requires a same-origin `Origin`, JSON content type, the
session cookie, and `X-CSRF-Token`. It deletes the session row, expires the cookie,
and returns `204`. Replaying the revoked cookie returns `401`. Public registration
and login require same-origin JSON too; authenticated mutations use the added
CSRF token. Future vault mutation routes must use the same session/CSRF guards.
No CORS permissions are granted to external origins.

Login allows 10 attempts per IP per 15 minutes; parameter requests allow 30.
Limits are in-memory and reset on restart. Login verification runs at most two
Argon2 operations concurrently (`503` plus a retry hint if busy). Invalid input
returns `400`, missing/foreign Origin `403`, non-JSON `415`, and throttling `429`.
Passwords, derived authentication secrets, CSRF tokens, and raw session IDs are
not logged or stored in localStorage/sessionStorage. The browser discards the
wrapping key after login for now; vault unlocking is still separate work.

`src/auth-input.js` shares input/Origin checks; `src/authentication.js` handles
parameters, login, account information, and logout routes. `src/sessions.js`
manages IDs, cookies, expiry, and CSRF. `public/auth.mjs` handles the UI.

Validation: all **36 tests** pass. Tests cover cookie flags, ID rotation, idle and
absolute expiry using an injected clock, restart persistence, forged/duplicate
cookies, logout replay, CSRF binding, generic credential errors, and request
limits. Headless Chrome checks exercise the full HTTPS registration/login flow,
HttpOnly cookie behavior, page reload, rotation, idle expiry, logout, and network
failure recovery. These checks use temporary databases.

References: [OWASP session management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
and [OWASP CSRF prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).

### Progress

**Step 1:** Express serves the placeholder page and `/api/health` from one origin.
Both npm scripts use `src/server.js`; `dev` enables automatic restarts.

**Step 2:** HTTPS uses the bundled self-signed development certificate, with TLS
1.2 as the minimum. The browser warning is expected for this local demo.

**Step 3:** `src/db.js` opens and initializes SQLite before the server accepts
requests. All four tables, their relationships, and basic data constraints are
implemented. Six database tests cover persistence and constraints.

**Step 4:** Browser-side Argon2id and HKDF key derivation is implemented, with a
local demo and reference-vector tests.

**Step 5:** Registration generates and wraps the vault key in the browser, then
stores a server-side Argon2id verifier and encrypted key metadata atomically.

**Step 6:** Login, secure server-side sessions, protected account information,
timeouts, ID rotation, CSRF validation, and logout are implemented. The browser
restores an existing account session on reload; the vault remains locked.

Next: retrieve and unwrap the encrypted vault key in the browser, then add
manual locking and inactivity-based vault locking independently of the session.
