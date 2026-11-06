function decodeBase64(value, length) {
		if (typeof value !== 'string') throw new TypeError('Invalid binary field.');
		const bytes = Buffer.from(value, 'base64');
		if (bytes.length !== length || bytes.toString('base64') !== value) {
				bytes.fill(0);
				throw new TypeError('Invalid binary field.');
		}
		return bytes;
}

function normalizeEmail(value) {
		if (typeof value !== 'string') throw new TypeError('Invalid email.');
		const email = value.trim().toLowerCase();
		if (email.length > 254 || !/^[\x21-\x7e]+$/.test(email) || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
				throw new TypeError('Invalid email.');
		}
		return email;
}

function sameOriginJson(req, res, next) {
		if (req.get('origin') !== `${req.protocol}://${req.get('host')}`) {
				return res.status(403).json({ error: 'Same-origin requests are required.' });
		}
		if (!req.is('application/json')) {
				return res.status(415).json({ error: 'Send application/json.' });
		}
		next();
}

module.exports = { decodeBase64, normalizeEmail, sameOriginJson };
