import { OAuth2Client } from 'google-auth-library';
import jwt from 'jsonwebtoken';
import { User } from '../types';

const oauthClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

export const googleLogin = async (token: string): Promise<User | null> => {
    const ticket = await oauthClient.verifyIdToken({
        idToken: token,
        audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    if (payload) {
        const user: User = {
            id: payload.sub,
            name: payload.name,
            email: payload.email,
        };
        return user;
    }
    return null;
};

export const jwtLogin = (user: User): string => {
    return jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, {
        expiresIn: '1h',
    });
};

export const verifyJwt = (token: string): User | null => {
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET) as User;
        return decoded;
    } catch (error) {
        return null;
    }
};