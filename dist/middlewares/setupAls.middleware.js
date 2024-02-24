// import { authService } from '../api/auth/auth.service'
import { asyncLocalStorage } from '../services/als.service.js';
import { validateToken } from '../services/validation.service.js';
export async function setupAsyncLocalStorage(req, res, next) {
    const storage = {};
    asyncLocalStorage.run(storage, () => {
        if (!req.cookies?.loginToken)
            return next();
        const loggedinUser = validateToken(req.cookies.loginToken);
        if (loggedinUser) {
            // const alsStore = asyncLocalStorage.getStore() as typeof storage;
            storage.loggedinUser = loggedinUser;
        }
        next();
    });
}
