import jwt from 'jsonwebtoken';
import db from '../database.js';

export function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    let token = authHeader && authHeader.split(' ')[1];
    console.log(" i have header ", req.headers);
    console.log("token============================================", token);
    if (!token && req.cookies) {
        token = req.cookies.access_token;
    }

    console.log("Headers:", req.headers);
    console.log("Token found:", token);
    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        console.log("decoded", decoded);
        // Check if user still exists
        const user = db.prepare('SELECT id, email, name, avatar_url FROM users WHERE id = ?').get(decoded.userId);

        if (!user) {
            return res.status(401).json({ error: 'User not found' });
        }

        req.user = user;
        next();
    } catch (error) {
        console.log("error", error);
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token expired' });
        }
        return res.status(403).json({ error: 'Invalid token' });
    }
}

export function authenticateOAuthToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    try {
        // Check if token exists in database and is not expired
        const tokenRecord = db.prepare(`
      SELECT at.*, u.id as user_id, u.email, u.name, u.avatar_url
      FROM access_tokens at
      JOIN users u ON at.user_id = u.id
      WHERE at.token = ? AND at.expires_at > datetime('now')
    `).get(token);

        if (!tokenRecord) {
            return res.status(401).json({ error: 'Invalid or expired token' });
        }

        req.user = {
            id: tokenRecord.user_id,
            email: tokenRecord.email,
            name: tokenRecord.name,
            avatar_url: tokenRecord.avatar_url
        };
        req.tokenScope = tokenRecord.scope;
        req.clientId = tokenRecord.client_id;

        next();
    } catch (error) {
        return res.status(403).json({ error: 'Invalid token' });
    }
}
