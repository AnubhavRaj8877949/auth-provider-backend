import Database from 'better-sqlite3';
import crypto from 'crypto';
import { nanoid } from 'nanoid';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dbPath = path.join(__dirname, 'oauth.db');

const db = new Database(dbPath);

// Client details
const clientId = `client_${nanoid(22)}`;
const clientSecret = crypto.randomBytes(32).toString('hex');
const name = 'Demo App';
const description = 'OAuth Demo Application with Popup Login';
const redirectUris = JSON.stringify(['http://localhost:4001/callback']);
const userId = 1; // Your user ID

console.log('🔧 Creating new OAuth client...\n');

try {
    const stmt = db.prepare(`
    INSERT INTO clients (id, name, description, client_secret, redirect_uris, user_id)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

    stmt.run(clientId, name, description, clientSecret, redirectUris, userId);

    console.log('✅ OAuth Client Created Successfully!\n');
    console.log('📋 Client Details:');
    console.log('━'.repeat(60));
    console.log(`Client ID:     ${clientId}`);
    console.log(`Client Secret: ${clientSecret}`);
    console.log(`Name:          ${name}`);
    console.log(`Redirect URI:  http://localhost:4001/callback`);
    console.log('━'.repeat(60));

    // Update .env file
    const envContent = `OAUTH_CLIENT_ID=${clientId}
OAUTH_CLIENT_SECRET=${clientSecret}
OAUTH_AUTHORIZATION_URL=http://localhost:5173/oauth/authorize
OAUTH_TOKEN_URL=http://localhost:3000/api/oauth/token
OAUTH_USER_PROFILE_URL=http://localhost:3000/api/user/profile
OAUTH_REDIRECT_URI=http://localhost:4001/callback
PORT=4000
SESSION_SECRET=demo-app-secret-key-change-in-production-2024
NODE_ENV=development
FRONTEND_URL=http://localhost:4001`;

    const fs = await import('fs');
    const envPath = path.join(__dirname, '../demo-client-app/backend/.env');
    fs.writeFileSync(envPath, envContent);

    console.log('\n✅ Updated demo-client-app/backend/.env');
    console.log('\n🚀 Ready to test! Run: ./start.sh');

} catch (err) {
    console.error('❌ Error creating client:', err);
}

db.close();
