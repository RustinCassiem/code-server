import { Request, Response } from 'express';
import { User } from '../types';

// Dummy in-memory user store for demonstration
const users: User[] = [];

export const getUsers = (req: Request, res: Response) => {
  res.json(users);
};

export const getUserById = (req: Request, res: Response) => {
  const user = users.find(u => u.id === req.params.id);
  if (user) {
    res.json(user);
  } else {
    res.status(404).json({ message: 'User not found' });
  }
};

export const createUser = (req: Request, res: Response) => {
  const newUser: User = { ...req.body, id: String(Date.now()), createdAt: new Date(), isActive: true };
  users.push(newUser);
  res.status(201).json(newUser);
};

export const updateUser = (req: Request, res: Response) => {
  const idx = users.findIndex(u => u.id === req.params.id);
  if (idx !== -1) {
    users[idx] = { ...users[idx], ...req.body };
    res.json(users[idx]);
  } else {
    res.status(404).json({ message: 'User not found' });
  }
};

export const deleteUser = (req: Request, res: Response) => {
  const idx = users.findIndex(u => u.id === req.params.id);
  if (idx !== -1) {
    users.splice(idx, 1);
    res.status(204).send();
  } else {
    res.status(404).json({ message: 'User not found' });
  }
};
