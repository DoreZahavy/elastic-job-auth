import axios from "axios";
import { Request, Response } from "express";
import { logger } from "../services/logger.service.js";
import { authService } from "./auth.service.js";
import { User } from "../models/user.model.js";

const AUTH_URL = ''


export async function login(req: Request, res: Response) {
    const { email, password } = req.body
    try {
        const user = await authService.login(email, password)
        const loginToken = authService.getLoginToken(user)
        logger.info('User login: ', user)
        res.cookie('loginToken', loginToken, {sameSite: 'none', secure: true})
        res.json(user)
    } catch (err) {
        logger.error('Failed to Login ' + err)
        res.status(401).send({ err: 'Failed to Login' })
    }
}

export async function signup(req: Request, res: Response) {
    try {
        
        const credentials : Omit<User, "_id"> = req.body
        // Never log passwords
        // logger.debug(credentials)
        const user = await authService.signup(credentials) // account
        console.log("🚀 ~ signup ~ user:", user)
        logger.debug(`auth.route - new account created: ` + JSON.stringify(user))
        // const user = await authService.login(credentials.email, credentials.password)
        logger.info('User signup:', user)
        const loginToken = authService.getLoginToken(user)
        res.cookie('loginToken', loginToken, {sameSite: 'none', secure: true})
        res.json(user)
    } catch (err) {
        logger.error('Failed to signup ' + err)
        res.status(400).send({ err: 'Failed to signup' })
    }
}

export async function logout(req: Request, res: Response) {
    try {
        res.clearCookie('loginToken')
        res.send({ msg: 'Logged out successfully' })
    } catch (err) {
        res.status(400).send({ err: 'Failed to logout' })
    }
}