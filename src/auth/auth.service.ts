import Cryptr from 'cryptr'
import bcrypt from 'bcrypt'

// import {userService} from '../user/user.service.js'
import {logger} from '../services/logger.service.js'
import axios from 'axios'
import { User } from '../models/user.model.js'

const USER_URL = ''

const cryptr = new Cryptr(process.env.SECRET || 'board-land')

export const authService = {
    signup,
    login,
    getLoginToken,
    validateToken
}

async function login(email, password) {
    logger.debug(`auth.service - login with email: ${email}`)

    const user = await checkExistingEmail(email)
    if (!user) return Promise.reject('Invalid email or password')
    // TODO: un-comment for real login
    const match = await bcrypt.compare(password, user.password)
    if (!match) return Promise.reject('Invalid email or password')

    delete user.password
    user._id = user._id.toString()
    return user
}

async function signup({email, password, fullname, imgUrl}) {
    const saltRounds = 10

    logger.debug(`auth.service - signup with email: ${email}, fullname: ${fullname}`)
    if (!email || !password || !fullname) return Promise.reject('Missing required signup information')

    const isUserExist = await checkExistingEmail(email)
    if (isUserExist) return Promise.reject('Email already taken')

    const hash = await bcrypt.hash(password, saltRounds)
    return await axios.post(USER_URL,{ email, password: hash, fullname, imgUrl })
    // return userService.add({ email, password: hash, fullname, imgUrl })
}

function getLoginToken(user :User) {
    const userInfo = {_id : user._id, fullname: user.fullname, isAdmin: user.isAdmin}
    return cryptr.encrypt(JSON.stringify(userInfo))    
}

function validateToken(loginToken :string) {
    try {
        const json = cryptr.decrypt(loginToken)
        const loggedinUser = JSON.parse(json)
        return loggedinUser

    } catch(err) {
        console.log('Invalid login token')
    }
    return null
}


async function checkExistingEmail(email: string): Promise<boolean> {
    try {
        // Send a request to the user server to check if the email exists
        const response = await axios.get<boolean>(`http://user-server-url/users/check-email?email=${encodeURIComponent(email)}`);
        
        // If the request is successful and the email exists, return true
        return response.data;
    } catch (error) {
        // Handle errors (e.g., network errors, server errors)
        console.error('Error checking existing email:', error);
        throw new Error('Error checking existing email');
    }
}

// ;(async ()=>{
//     await signup('bubu', '123', 'Bubu Bi')
//     await signup('mumu', '123', 'Mumu Maha')
// })()