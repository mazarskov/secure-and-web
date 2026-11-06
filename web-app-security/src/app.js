const express = require('express');
const path = require('node:path');
const { createRegistrationRouter } = require('./registration');
const { createAuthenticationRouter } = require('./authentication');
const { createSessionManager } = require('./sessions');

function createApp(db, { now } = {}) {
		const app = express();
		app.disable('x-powered-by');

		app.get('/api/health', (req, res) => {
				res.json({ status: 'ok' });
		});
		const sessions = createSessionManager(db, now);
		app.use('/api/auth', (req, res, next) => {
				res.set('Cache-Control', 'no-store');
				next();
		});
		app.use('/api/auth', createRegistrationRouter(db));
		app.use('/api/auth', createAuthenticationRouter(db, sessions));

		// Expose this bundle only, not the rest of node_modules.
		app.get('/vendor/argon2-bundled.min.js', (req, res) => {
				res.sendFile(require.resolve('argon2-browser/dist/argon2-bundled.min.js'));
		});
		app.use(express.static(path.join(__dirname, '../public')));

		app.use((error, req, res, next) => {
				if (res.headersSent) return next(error);
				if (error.type === 'entity.too.large') {
						return res.status(413).json({ error: 'Request body is too large.' });
				}
				if (error.type === 'entity.parse.failed') {
						return res.status(400).json({ error: 'Invalid JSON.' });
				}
				// Do not log request bodies, secrets, or database error details.
				console.error('Request failed.');
				res.status(500).json({ error: 'Unable to process the request.' });
		});

		return app;
}

module.exports = { createApp };
