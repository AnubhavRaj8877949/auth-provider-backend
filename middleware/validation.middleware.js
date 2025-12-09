export function validateRegistration(req, res, next) {
    const { email, password, name } = req.body;

    const errors = [];

    if (!email || !email.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)) {
        errors.push('Valid email is required');
    }

    if (!password || password.length < 8) {
        errors.push('Password must be at least 8 characters');
    }

    if (!name || name.trim().length < 2) {
        errors.push('Name must be at least 2 characters');
    }

    if (errors.length > 0) {
        return res.status(400).json({ errors });
    }

    next();
}

export function validateLogin(req, res, next) {
    const { email, password } = req.body;

    const errors = [];

    if (!email) {
        errors.push('Email is required');
    }

    if (!password) {
        errors.push('Password is required');
    }

    if (errors.length > 0) {
        return res.status(400).json({ errors });
    }

    next();
}

export function validateClientRegistration(req, res, next) {
    const { name, redirect_uris } = req.body;

    const errors = [];

    if (!name || name.trim().length < 3) {
        errors.push('Client name must be at least 3 characters');
    }

    if (!redirect_uris || !Array.isArray(redirect_uris) || redirect_uris.length === 0) {
        errors.push('At least one redirect URI is required');
    } else {
        // Validate each redirect URI
        for (const uri of redirect_uris) {
            try {
                new URL(uri);
            } catch {
                errors.push(`Invalid redirect URI: ${uri}`);
            }
        }
    }

    if (errors.length > 0) {
        return res.status(400).json({ errors });
    }

    next();
}

export function validateAuthorizationRequest(req, res, next) {
    const { response_type, client_id, redirect_uri, state } = req.query;

    const errors = [];

    if (response_type !== 'code') {
        errors.push('Invalid response_type. Only "code" is supported');
    }

    if (!client_id) {
        errors.push('client_id is required');
    }

    if (!redirect_uri) {
        errors.push('redirect_uri is required');
    }

    if (!state) {
        errors.push('state parameter is required for security');
    }

    if (errors.length > 0) {
        return res.status(400).json({ errors });
    }

    next();
}

export function validateTokenRequest(req, res, next) {
    const { grant_type, code, redirect_uri, client_id, client_secret, code_verifier } = req.body;

    const errors = [];

    if (grant_type !== 'authorization_code' && grant_type !== 'refresh_token') {
        errors.push('Invalid grant_type. Only "authorization_code" and "refresh_token" are supported');
    }

    if (grant_type === 'authorization_code') {
        if (!code) {
            errors.push('code is required for authorization_code grant');
        }

        if (!redirect_uri) {
            errors.push('redirect_uri is required');
        }

        if (!client_id) {
            errors.push('client_id is required');
        }

        if (!client_secret) {
            errors.push('client_secret is required');
        }
    }

    if (grant_type === 'refresh_token') {
        if (!req.body.refresh_token) {
            errors.push('refresh_token is required for refresh_token grant');
        }

        if (!client_id) {
            errors.push('client_id is required');
        }

        if (!client_secret) {
            errors.push('client_secret is required');
        }
    }

    if (errors.length > 0) {
        return res.status(400).json({ errors });
    }

    next();
}
