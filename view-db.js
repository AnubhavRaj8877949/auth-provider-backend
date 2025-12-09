import Database from 'better-sqlite3';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const db = new Database(join(__dirname, 'oauth.db'));

console.log('=== OAUTH DATABASE CONTENTS ===\n');

// Users
console.log('📊 USERS:');
const users = db.prepare('SELECT id, email, name, created_at FROM users').all();
console.table(users);

// Clients
console.log('\n📱 OAUTH CLIENTS:');
const clients = db.prepare('SELECT id, name, redirect_uris, user_id, created_at FROM clients').all();
const clientsFormatted = clients.map(c => ({
    ...c,
    redirect_uris: JSON.parse(c.redirect_uris).join(', ')
}));
console.table(clientsFormatted);

// Authorization Codes
console.log('\n🔑 AUTHORIZATION CODES:');
const codes = db.prepare('SELECT code, client_id, user_id, expires_at FROM authorization_codes').all();
console.table(codes.length > 0 ? codes : [{ message: 'No active codes' }]);

// Access Tokens
console.log('\n🎫 ACCESS TOKENS:');
const tokens = db.prepare('SELECT token, client_id, user_id, scope, expires_at FROM access_tokens').all();
console.table(tokens.length > 0 ? tokens : [{ message: 'No active tokens' }]);

// Refresh Tokens
console.log('\n🔄 REFRESH TOKENS:');
const refreshTokens = db.prepare('SELECT token, client_id, user_id, expires_at FROM refresh_tokens').all();
console.table(refreshTokens.length > 0 ? refreshTokens : [{ message: 'No active refresh tokens' }]);

// User Authorizations
console.log('\n✅ USER AUTHORIZATIONS:');
const auths = db.prepare(`
  SELECT ua.user_id, ua.client_id, c.name as client_name, ua.scope, ua.created_at
  FROM user_authorizations ua
  JOIN clients c ON ua.client_id = c.id
`).all();
console.table(auths.length > 0 ? auths : [{ message: 'No authorizations' }]);

db.close();
console.log('\n✅ Database query complete!');
