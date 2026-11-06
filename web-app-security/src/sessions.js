const { randomBytes, createHash, createHmac, timingSafeEqual } = require('node:crypto');

const COOKIE_NAME = '__Host-session';
const COOKIE_OPTIONS = { secure: true, httpOnly: true, sameSite: 'strict', path: '/' };
const IDLE_SECONDS = 15 * 60;
const ABSOLUTE_SECONDS = 8 * 60 * 60;
const hashId = value => createHash('sha256').update(value).digest('hex');
const csrfToken = value => createHmac('sha256', value).update('csrf/v1').digest('hex');

function readSessionId(req) {
		const cookies = (req.headers.cookie ?? '').split(';').map(cookie => cookie.trim());
		const matches = cookies.filter(cookie => cookie.startsWith(`${COOKIE_NAME}=`));
		if (matches.length !== 1) return null;
		const value = matches[0].slice(COOKIE_NAME.length + 1);
		return /^[A-Za-z0-9_-]{43}$/.test(value) ? value : null;
}

function createSessionManager(db, now = () => Math.floor(Date.now() / 1000)) {
		const find = db.prepare(`
				SELECT sessions.*, users.email FROM sessions
				JOIN users ON users.id = sessions.user_id WHERE session_id_hash = ?
		`);
		const remove = db.prepare('DELETE FROM sessions WHERE session_id_hash = ?');
		const touch = db.prepare('UPDATE sessions SET last_activity_at = ? WHERE session_id_hash = ?');
		const insert = db.prepare(`
				INSERT INTO sessions (session_id_hash, user_id, created_at, last_activity_at, absolute_expiry)
				VALUES (?, ?, ?, ?, ?)
		`);
		const cleanup = db.prepare('DELETE FROM sessions WHERE absolute_expiry <= ? OR last_activity_at <= ?');
		const rotate = db.transaction((oldId, id, userId, time) => {
				cleanup.run(time, time - IDLE_SECONDS);
				if (oldId) remove.run(hashId(oldId));
				insert.run(hashId(id), userId, time, time, time + ABSOLUTE_SECONDS);
		});

		function issue(req, res, user) {
				const id = randomBytes(32).toString('base64url');
				rotate(readSessionId(req), id, user.id, now());
				res.cookie(COOKIE_NAME, id, COOKIE_OPTIONS);
				return { user: { id: user.id, email: user.email }, csrfToken: csrfToken(id) };
		}

		function requireSession(req, res, next) {
				const id = readSessionId(req);
				const session = id ? find.get(hashId(id)) : null;
				const time = now();
				if (!session || session.absolute_expiry <= time || session.last_activity_at + IDLE_SECONDS <= time) {
						if (session) remove.run(session.session_id_hash);
						res.clearCookie(COOKIE_NAME, COOKIE_OPTIONS);
						return res.status(401).json({ error: 'Authentication required.' });
				}
				touch.run(time, session.session_id_hash);
				req.auth = {
						user: { id: session.user_id, email: session.email },
						csrfToken: csrfToken(id),
						sessionIdHash: session.session_id_hash,
				};
				next();
		}

		function requireCsrf(req, res, next) {
				const token = req.get('X-CSRF-Token');
				if (typeof token !== 'string' || !/^[a-f0-9]{64}$/.test(token) ||
						!timingSafeEqual(Buffer.from(token, 'hex'), Buffer.from(req.auth.csrfToken, 'hex'))) {
						return res.status(403).json({ error: 'Invalid CSRF token.' });
				}
				next();
		}

		function logout(req, res) {
				remove.run(req.auth.sessionIdHash);
				res.clearCookie(COOKIE_NAME, COOKIE_OPTIONS);
				res.status(204).end();
		}

		return { issue, requireSession, requireCsrf, logout };
}

module.exports = { createSessionManager };
