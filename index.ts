import passport from 'passport';
import { Strategy as JwtStrategy, ExtractJwt } from 'passport-jwt';
import * as jwt from 'jsonwebtoken';
import * as dotenv from 'dotenv';
import { NextFunction, Request, Response } from 'express';
import { isValidObjectId } from 'mongoose';
dotenv.config();

interface Payload {
    id: string;
    username: string;
    email: string;
    isAdmin: boolean;
    iat: number;
}

interface UserData {
    _id?: string;
    userName?: string;
    FullName?: string;
    Email?: string;
    Password?: string;
    isAdmin?: boolean;
    isBlocked?: boolean;
}

const secretKey = process.env.SECRET_KEY || 'secretKey';
const refreshTokenSecret = process.env.REFRESH_TOKEN_SECRET || 'refreshTokenSecret';

interface JwtStrategyOptions {
    jwtFromRequest: any;
    secretOrKey: string;
}

const jwtOptions: JwtStrategyOptions = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: secretKey
};


passport.use("user", new JwtStrategy(jwtOptions, async (payload: Payload, done: any) => {
    try {
        if (isValidObjectId(payload.id)) {
            return done(null, payload);
        } else {
            return done(null, false);
        }
    } catch (error) {
        console.log(error, "this is the error");
        return done(error, false);
    }
}));


passport.use("admin", new JwtStrategy(jwtOptions, async (payload: Payload, done: any) => {
    try {
        if (isValidObjectId(payload.id) && payload.isAdmin) {
            return done(null, payload);
        } else {
            return done(null, false);
        }
    } catch (error) {
        console.log(error);
        return done(error, false);
    }
}));


const passportUserAuthenticate = passport.authenticate('user', { session: false })
const passportAdminAuthenticate = passport.authenticate('admin', { session: false })


export const isAuthenticated = async (req: Request, res: Response, next: NextFunction) => {
    const token: string = getTokenFromRequest(req) || ""
    if (await checkTokenValidity(token, false)) {
        res.status(200).json({ status: false, message: "access token expired",admin: false })
    } else {
        passportUserAuthenticate(req, res, next)
    }
}

export const isAdminAuthenticated = async (req: Request, res: Response, next: NextFunction) => {
    const token: string = getTokenFromRequest(req) || ""
    if (await checkTokenValidity(token, false)) {
        res.status(200).json({ status: false, message: "access token expired", admin: true })
    } else {
        passportAdminAuthenticate(req, res, next)
    }
}


export const generateToken = (user: UserData) => {
    return jwt.sign({
        id: user._id,
        username: user.userName,
        isAdmin: user.isAdmin,
        email: user.Email
    }, secretKey, { expiresIn: '2d' });
}

export const generateRefreshToken = (user: UserData) => {
    return jwt.sign({
        id: user._id,
        isAdmin: user.isAdmin,
        email: user.Email
    }, refreshTokenSecret, { expiresIn: '10d' });
}



//helper functions 

export const getDataFromToken = (token: string | undefined) => {
    try {
        return token ? jwt.decode(token) : null;
    } catch (error) {
        return error;
    }
};


export const getTokenFromRequest = (req: Request): string | null => {
    try {
        const authHeader = (req.headers as { authorization?: string }).authorization;
        if (authHeader && typeof authHeader === 'string') {
            const parts = authHeader.split(' ');
            if (parts.length === 2 && parts[0].toLowerCase() === 'bearer') {
                return parts[1]
            }
        }
        return null;
    } catch (error) {
        return null;
    }
}



export const checkTokenValidity = (token: string, refresh: boolean) => {
    return new Promise((resolve) => {
        jwt.verify(token, refresh ? secretKey : refreshTokenSecret, (err: any) => {
            if (err) {
                if (err.name === 'TokenExpiredError') {
                    resolve(true);
                } else {
                    resolve(false);
                }
            } else {
                resolve(false);
            }
        });
    });
};

