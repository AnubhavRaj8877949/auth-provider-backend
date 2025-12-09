import express from 'express';
import { nanoid } from 'nanoid';
import crypto from 'crypto';
import db from '../database.js';
import { authenticateToken } from '../middleware/auth.middleware.js';
import { validateClientRegistration } from '../middleware/validation.middleware.js';

const router = express.Router();

// Register new OAuth client
router.post('/', authenticateToken, validateClientRegistration, (req, res) => {
    try {
        const { name, description, logo_url, redirect_uris } = req.body;
        const userId = req.user.id;

        // Generate client ID and secret
        const clientId = `client_${nanoid(24)}`;
        const clientSecret = crypto.randomBytes(32).toString('hex');

        // Store redirect URIs as JSON string
        const redirectUrisJson = JSON.stringify(redirect_uris);

        const result = db.prepare(`
      INSERT INTO clients (id, client_secret, name, description, logo_url, redirect_uris, user_id)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(clientId, clientSecret, name, description || null, logo_url || null, redirectUrisJson, userId);

        const client = db.prepare(`
      SELECT id, name, description, logo_url, redirect_uris, created_at
      FROM clients WHERE id = ?
    `).get(clientId);

        res.status(201).json({
            message: 'OAuth client registered successfully',
            client: {
                ...client,
                redirect_uris: JSON.parse(client.redirect_uris),
                client_secret: clientSecret // Only shown once!
            }
        });
    } catch (error) {
        console.error('Client registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get all clients for current user
router.get('/', authenticateToken, (req, res) => {
    try {
        const clients = db.prepare(`
      SELECT id, name, description, logo_url, redirect_uris, created_at, updated_at
      FROM clients
      WHERE user_id = ?
      ORDER BY created_at DESC
    `).all(req.user.id);

        const clientsWithParsedUris = clients.map(client => ({
            ...client,
            redirect_uris: JSON.parse(client.redirect_uris)
        }));

        res.json({ clients: clientsWithParsedUris });
    } catch (error) {
        console.error('Get clients error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get specific client
router.get('/:id', authenticateToken, (req, res) => {
    try {
        const client = db.prepare(`
      SELECT id, name, description, logo_url, redirect_uris, created_at, updated_at
      FROM clients
      WHERE id = ? AND user_id = ?
    `).get(req.params.id, req.user.id);

        if (!client) {
            return res.status(404).json({ error: 'Client not found' });
        }

        res.json({
            client: {
                ...client,
                redirect_uris: JSON.parse(client.redirect_uris)
            }
        });
    } catch (error) {
        console.error('Get client error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Update client
router.put('/:id', authenticateToken, (req, res) => {
    try {
        const { name, description, logo_url, redirect_uris } = req.body;

        // Verify client belongs to user
        const client = db.prepare('SELECT id FROM clients WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
        if (!client) {
            return res.status(404).json({ error: 'Client not found' });
        }

        const updates = [];
        const values = [];

        if (name) {
            updates.push('name = ?');
            values.push(name);
        }

        if (description !== undefined) {
            updates.push('description = ?');
            values.push(description);
        }

        if (logo_url !== undefined) {
            updates.push('logo_url = ?');
            values.push(logo_url);
        }

        if (redirect_uris && Array.isArray(redirect_uris)) {
            updates.push('redirect_uris = ?');
            values.push(JSON.stringify(redirect_uris));
        }

        if (updates.length === 0) {
            return res.status(400).json({ error: 'No valid fields to update' });
        }

        updates.push('updated_at = CURRENT_TIMESTAMP');
        values.push(req.params.id);

        db.prepare(`
      UPDATE clients
      SET ${updates.join(', ')}
      WHERE id = ?
    `).run(...values);

        const updatedClient = db.prepare(`
      SELECT id, name, description, logo_url, redirect_uris, created_at, updated_at
      FROM clients WHERE id = ?
    `).get(req.params.id);

        res.json({
            message: 'Client updated successfully',
            client: {
                ...updatedClient,
                redirect_uris: JSON.parse(updatedClient.redirect_uris)
            }
        });
    } catch (error) {
        console.error('Update client error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Delete client
router.delete('/:id', authenticateToken, (req, res) => {
    try {
        const result = db.prepare('DELETE FROM clients WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);

        if (result.changes === 0) {
            return res.status(404).json({ error: 'Client not found' });
        }

        res.json({ message: 'Client deleted successfully' });
    } catch (error) {
        console.error('Delete client error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

export default router;
