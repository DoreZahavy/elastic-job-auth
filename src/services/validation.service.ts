import Cryptr from 'cryptr'
import { User } from '../models/user.model.js'
import {config} from '../config/index.js'

const cryptr = new Cryptr(config.tokenKey || 'secret-key')

export function validateToken(loginToken : string) : User | null {
    try {
        const json = cryptr.decrypt(loginToken)
        const loggedinUser = JSON.parse(json)
        return loggedinUser

    } catch(err) {
        console.log('Invalid login token')
    }
    return null
}