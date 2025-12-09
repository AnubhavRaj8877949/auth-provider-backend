import Database from 'better-sqlite3';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dbPath = path.join(__dirname, 'oauth.db');

const db = new Database(dbPath);

const clientId = 'client_' + crypto.randomBytes(16).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const clientSecret = crypto.randomBytes(32).toString('hex');
const name = 'React Demo App';
const redirectUri = 'http://localhost:4001/callback'; // IMPORTANT: This matches our React app
const userId = 1; // Assuming admin user exists

try {
    const stmt = db.prepare('INSERT INTO clients (id, name, client_secret, redirect_uris, user_id) VALUES (?, ?, ?, ?, ?)');
    stmt.run(clientId, name, clientSecret, redirectUri, userId);

    console.log('✅ Client Created Successfully!');
    console.log('----------------------------------------');
    console.log(`Client ID:     ${clientId}`);
    console.log(`Client Secret: ${clientSecret}`);
    console.log(`Redirect URI:  ${redirectUri}`);
    console.log('----------------------------------------');
} catch (err) {
    console.error('Error creating client:', err);
}

db.close();
