import express from 'express';
import db from '../database.js';
import { authenticateOAuthToken } from '../middleware/auth.middleware.js';

const router = express.Router();

// Get user profile (for third-party apps using OAuth token)
router.get('/profile', authenticateOAuthToken, (req, res) => {
    try {
        // Check if scope includes 'profile'
        const scopes = req.tokenScope ? req.tokenScope.split(' ') : [];

        if (!scopes.includes('profile')) {
            return res.status(403).json({ error: 'Insufficient scope. Required: profile' });
        }

        const userProfile = {
            id: req.user.id,
            name: req.user.name,
            avatar_url: req.user.avatar_url
        };

        // Include email if scope includes 'email'
        if (scopes.includes('email')) {
            userProfile.email = req.user.email;
        }

        res.json(userProfile);
    } catch (error) {
        console.error('Get profile error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get user's authorized applications
router.get('/authorizations', authenticateOAuthToken, (req, res) => {
    try {
        const authorizations = db.prepare(`
      SELECT 
        ua.client_id,
        ua.scope,
        ua.created_at,
        ua.updated_at,
        c.name,
        c.description,
        c.logo_url
      FROM user_authorizations ua
      JOIN clients c ON ua.client_id = c.id
      WHERE ua.user_id = ?
      ORDER BY ua.updated_at DESC
    `).all(req.user.id);

        res.json({ authorizations });
    } catch (error) {
        console.error('Get authorizations error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Revoke application access
router.delete('/authorizations/:clientId', authenticateOAuthToken, (req, res) => {
    try {
        const { clientId } = req.params;

        // Delete authorization
        const result = db.prepare(`
      DELETE FROM user_authorizations
      WHERE user_id = ? AND client_id = ?
    `).run(req.user.id, clientId);

        if (result.changes === 0) {
            return res.status(404).json({ error: 'Authorization not found' });
        }

        // Also revoke all active tokens for this client
        db.prepare('DELETE FROM access_tokens WHERE user_id = ? AND client_id = ?').run(req.user.id, clientId);
        db.prepare('DELETE FROM refresh_tokens WHERE user_id = ? AND client_id = ?').run(req.user.id, clientId);

        res.json({ message: 'Application access revoked successfully' });
    } catch (error) {
        console.error('Revoke authorization error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

export default router;
