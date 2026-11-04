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
The SQLite dependency is installed but is not used yet. If a prebuilt native
binary is unavailable, installation requires Python 3 and a C++ build toolchain
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

### Progress

**Step 1:** `src/server.js` creates an Express application. `/api/health` returns
JSON, and Express serves `public/index.html` at `/`. The API and frontend share
one server and origin. Both npm scripts use this same entry point.

**Step 2:** Node's built-in `https.createServer` serves Express over TLS 1.2 or
newer using the bundled development certificate. Missing or invalid certificate
files stop startup with a helpful message. Plain HTTP is not served. Vault
encryption will separately protect stored entries in a later step.

Validation: the running development server presented the bundled certificate.
The page and health endpoint passed on both local hostnames with explicit
certificate verification. Without explicit trust, the self-signed certificate
was rejected as expected. Plain HTTP was rejected and the private-key URL
returned 404. Browser warning acceptance still needs a manual check.

Next: initialize the SQLite database for users, encrypted vault keys, vault
entries, and sessions.
