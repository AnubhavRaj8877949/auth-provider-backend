import Database from 'better-sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dbPath = path.join(__dirname, 'oauth.db');

const db = new Database(dbPath);

console.log('🗑️  Clearing OAuth database...\n');

try {
    // Clear all OAuth-related data
    const deleteduser = db.prepare('DELETE FROM users').run();
    console.log(`✅ Deleted ${deleteduser.changes} users`);

    const deletedTokens = db.prepare('DELETE FROM access_tokens').run();
    console.log(`✅ Deleted ${deletedTokens.changes} access tokens`);

    const deletedRefresh = db.prepare('DELETE FROM refresh_tokens').run();
    console.log(`✅ Deleted ${deletedRefresh.changes} refresh tokens`);

    const deletedCodes = db.prepare('DELETE FROM authorization_codes').run();
    console.log(`✅ Deleted ${deletedCodes.changes} authorization codes`);

    const deletedAuths = db.prepare('DELETE FROM user_authorizations').run();
    console.log(`✅ Deleted ${deletedAuths.changes} user authorizations`);

    const deletedClients = db.prepare('DELETE FROM clients').run();
    console.log(`✅ Deleted ${deletedClients.changes} OAuth clients`);

    console.log('\n✅ Database cleared successfully!');
    console.log('ℹ️  User accounts were preserved.');
} catch (err) {
    console.error('❌ Error clearing database:', err);
}

db.close();
