import dotenv from 'dotenv';

dotenv.config();

const config = {
    port: process.env.PORT || 3000,
    db: {
        host: process.env.DB_HOST || 'localhost',
        port: process.env.DB_PORT || 5432,
        user: process.env.DB_USER || 'user',
        password: process.env.DB_PASSWORD || 'password',
        database: process.env.DB_NAME || 'database',
    },
    jwt: {
        secret: process.env.JWT_SECRET || 'your_jwt_secret',
        expiresIn: process.env.JWT_EXPIRES_IN || '1h',
    },
    oauth: {
        clientID: process.env.OAUTH_CLIENT_ID || 'your_client_id',
        clientSecret: process.env.OAUTH_CLIENT_SECRET || 'your_client_secret',
        callbackURL: process.env.OAUTH_CALLBACK_URL || 'http://localhost:3000/auth/callback',
    },
};

export default config;