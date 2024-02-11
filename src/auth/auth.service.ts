import Cryptr from 'cryptr'
import bcrypt from "bcrypt";

// import {userService} from '../user/user.service.js'
import {logger} from '../services/logger.service.js'
import axios from 'axios'
import { User } from '../models/user.model.js'

const USER_URL = 'http://127.0.0.1:3031/user'

const cryptr = new Cryptr(process.env.SECRET || 'board-land')

export const authService = {
    signup,
    login,
    getLoginToken,
    validateToken
}

async function login(email:string, password:string) {
    logger.debug(`auth.service - login with email: ${email}`)
    if (!email || !password ) return Promise.reject('Missing required login information')
    const user = await _getUserByEmail(email)
    if (!user) return Promise.reject('Invalid email or password')
    const match = await bcrypt.compare(password, user.password || '')
    if (!match) return Promise.reject('Invalid email or password')

    delete user.password
    // user._id = user._id.toString()
    return user
}

async function signup(credentials: Omit<User, "_id">): Promise<User> {
    const {imgUrl,fullName,experience,loc,email,userName,gender,skills,password=''} = credentials
    const saltRounds = 10

    logger.debug(`auth.service - signup with email: ${email}, fullname: ${fullName}`)
    if (!email || !password || !fullName) return Promise.reject('Missing required signup information')

    const isUserExist = await _checkExistingEmail(email)
    if (isUserExist) return Promise.reject('Email already taken')

    const hash = await bcrypt.hash(password, saltRounds)
    credentials.password = hash

    const response = await axios.post(USER_URL,credentials)
    const {data : user} = response
    delete user.password
    return user
    // return userService.add({ email, password: hash, fullname, imgUrl })
}

function getLoginToken(user :User) {
    const userInfo = {...user}
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


async function _checkExistingEmail(email: string): Promise<boolean> {
    try {
        // Send a request to the user server to check if the email exists
        const response = await axios.get<boolean>(`${USER_URL}/check-email/${encodeURIComponent(email)}`);
        
        // If the request is successful and the email exists, return true
        return response.data;
    } catch (error) {
        // Handle errors (e.g., network errors, server errors)
        console.error('Error checking existing email:', error);
        throw new Error('Error checking existing email');
    }
}
async function _getUserByEmail(email: string): Promise<User> {
    try {
        // Send a request to the user server to check if the email exists
        const response = await axios.get<User>(`${USER_URL}/email/${encodeURIComponent(email)}`);
        
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