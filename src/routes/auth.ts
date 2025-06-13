import { Router } from 'express';
import { login, register } from '../auth/providers';
import { validateLogin, validateRegistration } from '../auth/middleware';

const router = Router();

router.post('/login', validateLogin, async (req, res) => {
    try {
        const user = await login(req.body);
        res.status(200).json(user);
    } catch (error) {
        res.status(401).json({ message: error.message });
    }
});

router.post('/register', validateRegistration, async (req, res) => {
    try {
        const newUser = await register(req.body);
        res.status(201).json(newUser);
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
});

export default router;