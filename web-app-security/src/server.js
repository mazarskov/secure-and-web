const path = require('node:path');
const fs = require('node:fs');
const https = require('node:https');
const { openDatabase } = require('./db');
const { createApp } = require('./app');

const host = '127.0.0.1';
const port = 3000;

// Initialize storage before creating routes and accepting requests.
let db;
let app;
try {
		db = openDatabase();
		app = createApp(db);
} catch (error) {
		if (db?.open) db.close();
		console.error(`Unable to initialize application: ${error.message}`);
		process.exit(1);
}

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
		db.close();
		console.error(`Unable to load HTTPS certificates: ${error.message}`);
		console.error('Restore the bundled files in certs/dev/ or see README.MD to regenerate them.');
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
