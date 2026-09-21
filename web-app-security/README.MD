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

As the project is a W.I.P, instructiond listed here might change over time.

### Prerequisites

The following software is required:

* Node.js (a current LTS release).
* npm.
* Git, for version control.

A separate SQLite database server is not required.

### Installation

Clone the repository and enter the project directory:

```bash
git clone https://github.com/mazarskov/secure-and-web
cd secure-and-web/web-app-security
```

Install the project dependencies:

```bash
npm install
```

### Start the Application

Start the development server(not yet implemeneted):

```bash
npm run dev
```

The application will be available at:

http://localhost:3000

The backend health-check endpoint can be accessed at:

http://localhost:3000/api/health

The health-check endpoint should return:

```json
{
  "status": "ok"
}
```

To run the server without development watch mode(not yet implemented):

```bash
npm start
```

Stop the server by pressing `Ctrl+C` in the terminal.
