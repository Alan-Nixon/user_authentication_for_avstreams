"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.checkTokenValidity = exports.getTokenFromRequest = exports.getDataFromToken = exports.generateRefreshToken = exports.generateToken = exports.isAdminAuthenticated = exports.isAuthenticated = void 0;
const passport_1 = __importDefault(require("passport"));
const passport_jwt_1 = require("passport-jwt");
const jwt = __importStar(require("jsonwebtoken"));
const dotenv = __importStar(require("dotenv"));
const mongoose_1 = require("mongoose");
dotenv.config();
const secretKey = process.env.SECRET_KEY || 'secretKey';
const refreshTokenSecret = process.env.REFRESH_TOKEN_SECRET || 'refreshTokenSecret';
const jwtOptions = {
    jwtFromRequest: passport_jwt_1.ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: secretKey
};
passport_1.default.use("user", new passport_jwt_1.Strategy(jwtOptions, async (payload, done) => {
    try {
        if ((0, mongoose_1.isValidObjectId)(payload.id)) {
            return done(null, payload);
        }
        else {
            return done(null, false);
        }
    }
    catch (error) {
        console.log(error, "this is the error");
        return done(error, false);
    }
}));
passport_1.default.use("admin", new passport_jwt_1.Strategy(jwtOptions, async (payload, done) => {
    try {
        if ((0, mongoose_1.isValidObjectId)(payload.id) && payload.isAdmin) {
            return done(null, payload);
        }
        else {
            return done(null, false);
        }
    }
    catch (error) {
        console.log(error);
        return done(error, false);
    }
}));
const passportUserAuthenticate = passport_1.default.authenticate('user', { session: false });
const passportAdminAuthenticate = passport_1.default.authenticate('admin', { session: false });
const isAuthenticated = async (req, res, next) => {
    const token = (0, exports.getTokenFromRequest)(req) || "";
    if (await (0, exports.checkTokenValidity)(token, false)) {
        res.status(200).json({ status: false, message: "access token expired", admin: false });
    }
    else {
        passportUserAuthenticate(req, res, next);
    }
};
exports.isAuthenticated = isAuthenticated;
const isAdminAuthenticated = async (req, res, next) => {
    const token = (0, exports.getTokenFromRequest)(req) || "";
    if (await (0, exports.checkTokenValidity)(token, false)) {
        res.status(200).json({ status: false, message: "access token expired", admin: true });
    }
    else {
        passportAdminAuthenticate(req, res, next);
    }
};
exports.isAdminAuthenticated = isAdminAuthenticated;
const generateToken = (user) => {
    return jwt.sign({
        id: user._id,
        username: user.userName,
        isAdmin: user.isAdmin,
        email: user.Email
    }, secretKey, { expiresIn: '2d' });
};
exports.generateToken = generateToken;
const generateRefreshToken = (user) => {
    return jwt.sign({
        id: user._id,
        isAdmin: user.isAdmin,
        email: user.Email
    }, refreshTokenSecret, { expiresIn: '10d' });
};
exports.generateRefreshToken = generateRefreshToken;
//helper functions 
const getDataFromToken = (token) => {
    try {
        return token ? jwt.decode(token) : null;
    }
    catch (error) {
        return error;
    }
};
exports.getDataFromToken = getDataFromToken;
const getTokenFromRequest = (req) => {
    try {
        const authHeader = req.headers.authorization;
        if (authHeader && typeof authHeader === 'string') {
            const parts = authHeader.split(' ');
            if (parts.length === 2 && parts[0].toLowerCase() === 'bearer') {
                return parts[1];
            }
        }
        return null;
    }
    catch (error) {
        return null;
    }
};
exports.getTokenFromRequest = getTokenFromRequest;
const checkTokenValidity = (token, refresh) => {
    return new Promise((resolve) => {
        jwt.verify(token, refresh ? secretKey : refreshTokenSecret, (err) => {
            if (err) {
                if (err.name === 'TokenExpiredError') {
                    resolve(true);
                }
                else {
                    resolve(false);
                }
            }
            else {
                resolve(false);
            }
        });
    });
};
exports.checkTokenValidity = checkTokenValidity;
