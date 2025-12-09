import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';
import { initializeDatabase } from './database.js';

// Import routes
import authRoutes from './routes/auth.routes.js';
import clientRoutes from './routes/client.routes.js';
import oauthRoutes from './routes/oauth.routes.js';
import userRoutes from './routes/user.routes.js';

const app = express();
const PORT = process.env.PORT || 3000;
// require("dotenv").config();

// Initialize database
initializeDatabase();

// Security middleware
app.use(helmet());

// CORS configuration
app.use(cors({
    origin: [
        process.env.FRONTEND_URL,
        'http://localhost:5173',
        'http://localhost:8080',
        'http://127.0.0.1:8080',
        'http://localhost:5174',
        'http://172.16.14.145:5173',
        'http://172.16.14.145:5174'
    ],
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization"]

}));
console.log("process.env.JWT_SECRET", process.env.JWT_SECRET)

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.'
});

app.use('/api/', limiter);
app.use('/oauth/', limiter);

// Body parser
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Cookie parser
app.use(cookieParser());

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'ok', message: 'OAuth Provider is running' });
});

// Mount routes
app.use('/api/auth', authRoutes);
app.use('/api/clients', clientRoutes);
app.use('/api/oauth', oauthRoutes);
app.use('/api/user', userRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(err.status || 500).json({
        error: err.message || 'Internal server error'
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Not found' });
});

app.listen(PORT, () => {
    console.log(`🚀 OAuth Provider server running on http://localhost:${PORT}`);
    console.log(`📝 Environment: ${process.env.NODE_ENV}`);
    console.log(`🔗 Frontend URL: ${process.env.FRONTEND_URL}`);
});
