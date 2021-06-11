const fs = require('fs');
const express = require('express');
const jsonServer = require('json-server');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');

const server = jsonServer.create();
const dbPath = './db.json';
const router = jsonServer.router(dbPath);
const userdb = JSON.parse(fs.readFileSync('./users.json', 'UTF-8'));

server.use(express.urlencoded({extended: true}));
server.use(express.json());
server.use(jsonServer.defaults());

const SECRET_KEY = '123456789';

// Create a token from a payload 
function createToken(payload){
    const expiresIn = '1h';
  return jwt.sign(payload, SECRET_KEY, { expiresIn });
}

// Verify the token 
function verifyToken(token){
  return  jwt.verify(token, SECRET_KEY, (err, decode) => decode !== undefined ?  decode : err);
}

// Check if the user exists in database
function isAuthenticated({ email, password }) {
    return userdb.users.find((user) => user.email === email && user.password === password) !== undefined;
}

// Login to one of the users from ./users.json
server.post('/auth/login', (req, res) => {
    let status, message;
    if (isAuthenticated(req.body)) {
        status = 200;
        message = createToken(req.body);
    } else {
        status = 401;
        message = 'Incorrect email or password';
    }
    res.status(status).json({ status, message });
});

server.use(/^(?!\/auth).*$/, (req, res, next) => {
    if (req.headers.authorization === undefined || req.headers.authorization.split(' ')[0] !== 'Bearer') {
        const status = 401;
        const message = 'Error in authorization format';
        res.status(status).json({ status, message });
        return;
    }
    try {
        let verifyTokenResult;
        verifyTokenResult = verifyToken(req.headers.authorization.split(' ')[1]);

        if (verifyTokenResult instanceof Error) {
            const status = 401;
            const message = 'Access token not provided';
            res.status(status).json({ status, message });
            return;
        }
        next();
    } catch (err) {
        const status = 401;
        const message = 'Error access_token is revoked';
        res.status(status).json({ status, message });
    }
})

server.post('/people',
    body('age').isNumeric(),
    body('name').isLength({ min: 3 }),
    body('gender').isIn(['Male', 'Female']),
    body('company').optional().isLength({ min: 1 }),
    body('email').isEmail(),
    body('phone').matches(/\d{3}-\d{3}-\d{3}/),
    body('address').isLength({ min: 10 }),
    body('credits').isArray(),
    (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            const status = 400;
            const invalidParams = errors.array().map(error => error.param);
            const message = `Missing param or invalid value: ${invalidParams.join(', ')}`
            return res.status(status).json({ status, message });
        } else if (JSON.parse(fs.readFileSync(dbPath)).people.some(p => p.name === req.body.name)) {
            const status = 409;
            return res.status(status).json({ status, message: 'Person already exists' });
        }
        next();
    });

server.use(router);

server.listen(8001, () => {
  console.log('Run Auth API Server');
});
