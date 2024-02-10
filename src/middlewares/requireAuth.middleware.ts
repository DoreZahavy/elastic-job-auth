import { Request, Response, NextFunction } from 'express';
import { logger } from '../services/logger.service.js';
import { asyncLocalStorage } from '../services/als.service.js';


export function requireAuth(req: Request, res: Response, next: NextFunction): void {
    const { loggedinUser} = asyncLocalStorage.getStore() || { loggedinUser: null };
    // req.loggedinUser = loggedinUser;
    
    console.log('user auth', loggedinUser);

    if (!loggedinUser) res.status(401).send('Not Authenticated');
    next();
}

// export function requireAdmin(req: Request, res: Response, next: NextFunction): void {
//     const { loggedinUser } = asyncLocalStorage.getStore() || { loggedinUser: null };
//     if (!loggedinUser) return res.status(401).send('Not Authenticated');
//     if (!loggedinUser.isAdmin) {
//         logger.warn(loggedinUser.fullname + ' attempted to perform admin action');
//         res.status(403).end('Not Authorized');
//         return;
//     }
//     next();
// }
