const express = require('express');
const argon2 = require('argon2');
const { randomBytes, createHmac } = require('node:crypto');
const { rateLimit } = require('express-rate-limit');
const { normalizeEmail, decodeBase64, sameOriginJson } = require('./auth-input');

// Public dummy verifier: unknown users still pay the same Argon2 cost, but can never authenticate.
const DUMMY_VERIFIER = '$argon2id$v=19$m=65536,t=3,p=1$C+6ukozQA5oHWUbXnaRJag$sLm5DxSW738cBT3Cgj7rOU6y8b9nvTiSqvNZejuLKJU';

function createAuthenticationRouter(db, sessions) {
		const router = express.Router();
		const decoyKey = randomBytes(32);
		let activeVerifications = 0;
		const findUser = db.prepare('SELECT id, email, auth_verifier FROM users WHERE email = ?');
		const findParameters = db.prepare(`
				SELECT kdf_salt, kdf_parameters FROM vault_keys
				JOIN users ON users.id = vault_keys.user_id WHERE email = ?
		`);
		const limiter = limit => rateLimit({
				windowMs: 15 * 60 * 1000, limit, standardHeaders: 'draft-8', legacyHeaders: false,
				message: { error: 'Too many authentication requests. Try again later.' },
		});

		router.get('/parameters', limiter(30), async (req, res) => {
				let email;
				try {
						email = normalizeEmail(req.query.email);
				} catch {
						return res.status(400).json({ error: 'Invalid email.' });
				}
				const stored = findParameters.get(email);
				const { KDF_PARAMETERS } = await import('../public/crypto.mjs');
				// Stable within this server run; response shape does not announce account existence.
				const salt = stored?.kdf_salt ?? createHmac('sha256', decoyKey).update(email).digest().subarray(0, 16);
				res.json({ kdfSalt: salt.toString('base64'), kdfParameters: stored ? JSON.parse(stored.kdf_parameters) : KDF_PARAMETERS });
		});

		router.post('/login', limiter(10), sameOriginJson, express.json({ limit: '4kb' }), async (req, res, next) => {
				let email;
				let secret;
				try {
						if (!req.body || Object.keys(req.body).length !== 2 || !Object.hasOwn(req.body, 'authenticationSecret')) {
								throw new TypeError('Invalid login fields.');
						}
						email = normalizeEmail(req.body.email);
						secret = decodeBase64(req.body.authenticationSecret, 32);
				} catch {
						return res.status(400).json({ error: 'Invalid login data.' });
				} finally {
						if (req.body && typeof req.body === 'object') delete req.body.authenticationSecret;
				}
				if (activeVerifications >= 2) {
						secret.fill(0);
						return res.set('Retry-After', '1').status(503).json({ error: 'Authentication is busy. Try again shortly.' });
				}
				activeVerifications += 1;
				try {
						const user = findUser.get(email);
						const verified = await argon2.verify(user?.auth_verifier ?? DUMMY_VERIFIER, secret);
						if (!user || !verified) return res.status(401).json({ error: 'Invalid email or master password.' });
						// Recheck after asynchronous verification in case the account was removed meanwhile.
						const current = findUser.get(email);
						if (!current || current.id !== user.id || current.auth_verifier !== user.auth_verifier) {
								return res.status(401).json({ error: 'Invalid email or master password.' });
						}
						res.json(sessions.issue(req, res, user));
				} catch (error) {
						next(error);
				} finally {
						activeVerifications -= 1;
						secret.fill(0);
				}
		});

		router.get('/me', sessions.requireSession, (req, res) => {
				res.json({ user: req.auth.user, csrfToken: req.auth.csrfToken });
		});
		router.post('/logout', sameOriginJson, sessions.requireSession, sessions.requireCsrf, sessions.logout);

		return router;
}

module.exports = { createAuthenticationRouter };
