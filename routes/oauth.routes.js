import express from 'express';
import crypto from 'crypto';
import { nanoid } from 'nanoid';
import db from '../database.js';
import jwt from 'jsonwebtoken';
import { authenticateToken } from '../middleware/auth.middleware.js';
import { validateAuthorizationRequest, validateTokenRequest } from '../middleware/validation.middleware.js';

const router = express.Router();

// Authorization endpoint - GET (display consent screen)
router.get('/authorize', authenticateToken, validateAuthorizationRequest, (req, res) => {
    try {
        console.log("iama here")
        const { client_id, redirect_uri, scope, state, code_challenge, code_challenge_method } = req.query;

        // Verify client exists
        const client = db.prepare('SELECT * FROM clients WHERE id = ?').get(client_id);
        if (!client) {
            return res.status(400).json({ error: 'Invalid client_id' });
        }
        console.log("iam here client", client)

        // Verify redirect_uri matches registered URIs
        const registeredUris = JSON.parse(client.redirect_uris);
        if (!registeredUris.includes(redirect_uri)) {
            return res.status(400).json({ error: 'Invalid redirect_uri' });
        }
        console.log("iam here redirect_uri", redirect_uri)

        // Check if user has already authorized this client
        const existingAuth = db.prepare(`
      SELECT * FROM user_authorizations
      WHERE user_id = ? AND client_id = ?
    `).get(req.user.id, client_id);
        console.log("iam here existingAuth", existingAuth)
        // Return client info for consent screen
        res.json({
            client: {
                id: client.id,
                name: client.name,
                description: client.description,
                logo_url: client.logo_url
            },
            user: req.user,
            scope: scope || 'profile email',
            state,
            redirect_uri,
            code_challenge,
            code_challenge_method,
            already_authorized: !!existingAuth
        });
    } catch (error) {
        console.error('Authorization error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Authorization endpoint - POST (user consent)
router.post('/authorize', authenticateToken, (req, res) => {
    try {
        const { client_id, redirect_uri, scope, state, code_challenge, code_challenge_method, approved } = req.body;

        console.log("iam here=========================", req.body)
        if (!approved) {
            // User denied authorization
            const errorUrl = new URL(redirect_uri);
            errorUrl.searchParams.set('error', 'access_denied');
            errorUrl.searchParams.set('state', state);
            return res.json({ redirect_url: errorUrl.toString() });
        }


        // Verify client exists
        const client = db.prepare('SELECT * FROM clients WHERE id = ?').get(client_id);
        console.log("DB Client:", client);
        if (!client) {
            return res.status(400).json({ error: 'Invalid client_id' });
        }


        // Verify redirect_uri
        const registeredUris = JSON.parse(client.redirect_uris);
        console.log("Registered URIs:", registeredUris);
        if (!registeredUris.includes(redirect_uri)) {
            return res.status(400).json({ error: 'Invalid redirect_uri' });
        }

        // Generate authorization code
        const code = `code_${nanoid(32)}`;
        const expiresAt = new Date(Date.now() + parseInt(process.env.AUTHORIZATION_CODE_EXPIRY) * 1000).toISOString();

        // Store authorization code
        db.prepare(`
      INSERT INTO authorization_codes (code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(code, client_id, req.user.id, redirect_uri, scope || 'profile email', code_challenge || null, code_challenge_method || null, expiresAt);

        // Store or update user authorization
        db.prepare(`
      INSERT INTO user_authorizations (user_id, client_id, scope, updated_at)
      VALUES (?, ?, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(user_id, client_id) DO UPDATE SET
        scope = excluded.scope,
        updated_at = CURRENT_TIMESTAMP
    `).run(req.user.id, client_id, scope || 'profile email');

        // Redirect back to client with authorization code

        const redirectUrl = new URL(redirect_uri);
        redirectUrl.searchParams.set('code', code);
        redirectUrl.searchParams.set('state', state);

        res.json({ redirect_url: redirectUrl.toString() });
        console.log("iam done", redirectUrl.toString());

    } catch (error) {
        console.error('Authorization consent error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Token endpoint
router.post('/token', validateTokenRequest, async (req, res) => {
    try {
        const { grant_type, code, redirect_uri, client_id, client_secret, code_verifier, refresh_token } = req.body;
        console.log("iam here token========================= ", req.body)

        // Verify client credentials
        const client = db.prepare('SELECT * FROM clients WHERE id = ? AND client_secret = ?').get(client_id, client_secret);
        if (!client) {
            return res.status(401).json({ error: 'Invalid client credentials' });
        }

        console.log("iam here client 1", client)
        if (grant_type === 'authorization_code') {
            console.log("iam here client2", client)

            const allCodes = db.prepare('SELECT * FROM authorization_codes').all();
            console.log("All authorization codes:", allCodes);
            console.log("iam here code ", code)

            // Verify authorization code
            const authCode = db.prepare(`SELECT * FROM authorization_codes WHERE code = ? AND client_id = ? AND expires_at > datetime('now')`).get(code, client_id);
            console.log("iam here authCode", authCode)

            if (!authCode) {
                return res.status(400).json({ error: 'Invalid or expired authorization code' });
            }
            // Verify PKCE if code_challenge was provided
            if (authCode.code_challenge) {
                if (!code_verifier) {
                    return res.status(400).json({ error: 'code_verifier required for PKCE' });
                }

                const hash = crypto.createHash('sha256').update(code_verifier).digest('base64url');
                if (hash !== authCode.code_challenge) {
                    return res.status(400).json({ error: 'Invalid code_verifier' });
                }
            }
            console.log("iam here token ", authCode)

            const user = db.prepare('SELECT * FROM users WHERE id = ?').get(authCode.user_id);
            console.log("iam here user", user)

            const accessToken = jwt.sign(
                {
                    userId: authCode.user_id,   // OAuth Standards
                    client_id,
                    email: user.email,
                    scope: authCode.scope,

                },
                "dev-secret-key-please-change-in-production-12345",
                { expiresIn: "1d" } // 15 minutes expiry
            );

            // JWT internally stores expiry — but DB column also required
            const accessTokenExpiresAt = new Date(Date.now() + 1 * 24 * 60 * 60 * 1000).toISOString();

            const refreshTokenValue = jwt.sign(
                {
                    userId: authCode.user_id,   // OAuth Standards
                    client_id,
                    email: user.email,
                    scope: authCode.scope
                },
                "dev-secret-key-please-change-in-production-12345",
                { expiresIn: "7d" } // 15 minutes expiry
            );
            const refreshTokenExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();


            console.log("iam here access token", accessToken)
            console.log("iam here refresh token", refreshTokenValue)
            // Store tokens
            db.prepare(`
        INSERT INTO access_tokens (token, client_id, user_id, scope, expires_at)
        VALUES (?, ?, ?, ?, ?)
      `).run(accessToken, client_id, authCode.user_id, authCode.scope, accessTokenExpiresAt);

            db.prepare(`
        INSERT INTO refresh_tokens (token, client_id, user_id, access_token, scope, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(refreshTokenValue, client_id, authCode.user_id, accessToken, authCode.scope, refreshTokenExpiresAt);

            // Delete used authorization code
            db.prepare('DELETE FROM authorization_codes WHERE code = ?').run(code);
            console.log("iam here", accessToken, refreshTokenValue, authCode.scope)

            res.json({
                access_token: accessToken,
                token_type: 'Bearer',
                expires_in: 900, // 15 minutes in seconds
                refresh_token: refreshTokenValue,
                scope: authCode.scope
            });
        } else if (grant_type === 'refresh_token') {
            // Verify refresh token
            const refreshTokenRecord = db.prepare(`
        SELECT * FROM refresh_tokens
        WHERE token = ? AND client_id = ? AND expires_at > datetime('now')
      `).get(refresh_token, client_id);

            if (!refreshTokenRecord) {
                return res.status(400).json({ error: 'Invalid or expired refresh token' });
            }

            // Delete old access token
            db.prepare('DELETE FROM access_tokens WHERE token = ?').run(refreshTokenRecord.access_token);

            // Generate new access token
            const newAccessToken = `access_${nanoid(48)}`;
            const accessTokenExpiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

            // Generate new refresh token (refresh token rotation)
            const newRefreshToken = `refresh_${nanoid(48)}`;
            const refreshTokenExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

            // Store new tokens
            db.prepare(`
        INSERT INTO access_tokens (token, client_id, user_id, scope, expires_at)
        VALUES (?, ?, ?, ?, ?)
      `).run(newAccessToken, client_id, refreshTokenRecord.user_id, refreshTokenRecord.scope, accessTokenExpiresAt);

            db.prepare(`
        INSERT INTO refresh_tokens (token, client_id, user_id, access_token, scope, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(newRefreshToken, client_id, refreshTokenRecord.user_id, newAccessToken, refreshTokenRecord.scope, refreshTokenExpiresAt);

            // Delete old refresh token
            db.prepare('DELETE FROM refresh_tokens WHERE token = ?').run(refresh_token);
            console.log("iam here", newAccessToken, newRefreshToken, refreshTokenRecord.scope)
            res.json({
                access_token: newAccessToken,
                token_type: 'Bearer',
                expires_in: 900,
                refresh_token: newRefreshToken,
                scope: refreshTokenRecord.scope
            });
        }
    } catch (error) {
        console.error('Token error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Token revocation endpoint
router.post('/revoke', (req, res) => {
    try {
        const { token, token_type_hint } = req.body;

        if (!token) {
            return res.status(400).json({ error: 'token is required' });
        }

        // Try to revoke as access token or refresh token
        if (token_type_hint === 'access_token' || !token_type_hint) {
            db.prepare('DELETE FROM access_tokens WHERE token = ?').run(token);
        }

        if (token_type_hint === 'refresh_token' || !token_type_hint) {
            db.prepare('DELETE FROM refresh_tokens WHERE token = ?').run(token);
        }

        res.json({ message: 'Token revoked successfully' });
    } catch (error) {
        console.error('Revocation error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

export default router;
