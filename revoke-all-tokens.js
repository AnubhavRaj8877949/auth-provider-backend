import db from './database.js';

console.log('🗑️  Revoking all access tokens...');

try {
    const result = db.prepare('DELETE FROM access_tokens').run();
    console.log(`✅ Successfully revoked ${result.changes} access tokens.`);
    console.log('   The Demo Client should still be logged in if session independence is working!');
} catch (error) {
    console.error('❌ Error revoking tokens:', error);
}
