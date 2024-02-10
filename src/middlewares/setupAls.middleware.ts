import { Request, Response, NextFunction } from 'express';
// import { authService } from '../api/auth/auth.service'
import { asyncLocalStorage, Storage } from '../services/als.service.js'
import { User } from '../models/user.model.js';
import { validateToken } from '../services/validation.service.js';

export async function setupAsyncLocalStorage(req: Request, res: Response, next: NextFunction): Promise<void> {
    const storage: Storage = {}
    asyncLocalStorage.run(storage, () => {
        if (!req.cookies?.loginToken) return next()

        const loggedinUser = validateToken(req.cookies.loginToken)
    
        if (loggedinUser) {
            // const alsStore = asyncLocalStorage.getStore() as typeof storage;
            storage.loggedinUser = loggedinUser;
        }
        next()
    })
}


