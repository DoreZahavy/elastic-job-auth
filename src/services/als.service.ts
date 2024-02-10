
import { AsyncLocalStorage } from 'async_hooks'
import { User } from '../models/user.model.js'
// The AsyncLocalStorage singleton

export interface Storage {
    loggedinUser?:User
}

export const asyncLocalStorage = new AsyncLocalStorage<Storage>()


