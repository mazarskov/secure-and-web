const express = require('express');
const argon2 = require('argon2');
const { randomUUID } = require('node:crypto');
const { rateLimit } = require('express-rate-limit');

const { decodeBase64, normalizeEmail, sameOriginJson } = require('./auth-input');

async function validateRegistration(body) {
		const fields = ['email', 'authenticationSecret', 'kdfSalt', 'kdfParameters', 'wrappedDek', 'wrappingNonce', 'cryptoVersion'];
		if (!body || typeof body !== 'object' || Array.isArray(body) ||
				Object.keys(body).length !== fields.length || fields.some(field => !Object.hasOwn(body, field))) {
				throw new TypeError('Invalid registration fields.');
		}
		const email = normalizeEmail(body.email);

		// Reuse the browser's versioned format definition without invoking its crypto code.
		const { KDF_PARAMETERS } = await import('../public/crypto.mjs');
		const parameters = body.kdfParameters;
		if (!parameters || Object.keys(parameters).length !== Object.keys(KDF_PARAMETERS).length ||
				Object.entries(KDF_PARAMETERS).some(([key, value]) => parameters[key] !== value) || body.cryptoVersion !== 1) {
				throw new TypeError('Unsupported crypto format.');
		}

		// Validate public fields first so no decoded authentication buffer is left on failure.
		return {
				email,
				kdfSalt: decodeBase64(body.kdfSalt, 16),
				kdfParameters: JSON.stringify(KDF_PARAMETERS),
				wrappedDek: decodeBase64(body.wrappedDek, 48),
				wrappingNonce: decodeBase64(body.wrappingNonce, 12),
				authenticationSecret: decodeBase64(body.authenticationSecret, 32),
		};
}

function createRegistrationRouter(db) {
		const router = express.Router();
		let activeHashes = 0;
		const insertUser = db.prepare('INSERT INTO users (id, email, auth_verifier) VALUES (?, ?, ?)');
		const insertVaultKey = db.prepare(`
				INSERT INTO vault_keys
				(user_id, kdf_salt, kdf_parameters, wrapped_dek, wrapping_nonce, crypto_version)
				VALUES (?, ?, ?, ?, ?, 1)
		`);
		const saveAccount = db.transaction((id, data, verifier) => {
				insertUser.run(id, data.email, verifier);
				insertVaultKey.run(id, data.kdfSalt, data.kdfParameters, data.wrappedDek, data.wrappingNonce);
		});

		router.post('/register', rateLimit({
				windowMs: 15 * 60 * 1000,
				limit: 5,
				standardHeaders: 'draft-8',
				legacyHeaders: false,
				message: { error: 'Too many registration attempts. Try again later.' },
		}), sameOriginJson, express.json({ limit: '4kb' }), async (req, res, next) => {
				let data;
				try {
						data = await validateRegistration(req.body);
				} catch {
						return res.status(400).json({ error: 'Invalid registration data.' });
				} finally {
						// The parsed request contains a password-equivalent Base64 string.
						if (req.body && typeof req.body === 'object') delete req.body.authenticationSecret;
				}

				if (activeHashes >= 2) {
						data.authenticationSecret.fill(0);
						return res.set('Retry-After', '1').status(503).json({ error: 'Registration is busy. Try again shortly.' });
				}
				activeHashes += 1;
				try {
						// This independent random salt is embedded in the encoded Argon2 verifier.
						const verifier = await argon2.hash(data.authenticationSecret, {
								type: argon2.argon2id,
								memoryCost: 65536,
								timeCost: 3,
								parallelism: 1,
								hashLength: 32,
						});
						const id = randomUUID();
						saveAccount(id, data, verifier);
						res.status(201).json({ user: { id, email: data.email } });
				} catch (error) {
						if (error.code === 'SQLITE_CONSTRAINT_UNIQUE' || error.code === 'SQLITE_CONSTRAINT_PRIMARYKEY') {
								return res.status(409).json({ error: 'Unable to create an account with these details.' });
						}
						next(error);
				} finally {
						activeHashes -= 1;
						data.authenticationSecret.fill(0);
				}
		});

		return router;
}

module.exports = { createRegistrationRouter };
