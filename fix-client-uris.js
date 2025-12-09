import Database from 'better-sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dbPath = path.join(__dirname, 'oauth.db');

const db = new Database(dbPath);

const clientId = 'client_bQnDIiPmByhNOzN13_vaKg'; // The ID we created earlier
const redirectUri = 'http://localhost:4001/callback';

try {
    // Update to be a JSON array
    const jsonUris = JSON.stringify([redirectUri]);

    const stmt = db.prepare('UPDATE clients SET redirect_uris = ? WHERE id = ?');
    const info = stmt.run(jsonUris, clientId);

    if (info.changes > 0) {
        console.log('✅ Client Redirect URIs fixed successfully!');
        console.log(`Updated to: ${jsonUris}`);
    } else {
        console.log('⚠️ Client not found or no changes made.');
    }
} catch (err) {
    console.error('Error updating client:', err);
}

db.close();
