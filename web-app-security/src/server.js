const express = require('express');
const path = require('node:path');
const fs = require('node:fs');
const https = require('node:https');
const { openDatabase } = require('./db');

const app = express();
const host = '127.0.0.1';
const port = 3000;

app.get('/api/health', (req, res) => {
		res.json({ status: 'ok' });
});

// Resolve from this file so static files do not depend on the working directory.
app.use(express.static(path.join(__dirname, '../public')));

// Publicly shared development credentials; keep outside the static web folder.
const certDirectory = path.join(__dirname, '../certs/dev');
let server;

try {
		server = https.createServer({
				key: fs.readFileSync(path.join(certDirectory, 'localhost-key.pem')),
				cert: fs.readFileSync(path.join(certDirectory, 'localhost.pem')),
				minVersion: 'TLSv1.2',
		}, app);
} catch (error) {
		console.error(`Unable to load HTTPS certificates: ${error.message}`);
		console.error('Restore the bundled files in certs/dev/ or see README.MD to regenerate them.');
		process.exit(1);
}

// Initialize storage before accepting requests.
let db;
try {
		db = openDatabase();
} catch (error) {
		console.error(`Unable to initialize database: ${error.message}`);
		process.exit(1);
}

server.on('close', () => db.close());

server.listen(port, host, () => {
		console.log(`Server running at https://${host}:${port}`);
});

server.on('error', (error) => {
		db.close();
		console.error(`Unable to start server: ${error.message}`);
		process.exit(1);
});
