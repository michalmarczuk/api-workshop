const fs = require('fs');
const express = require('express');
const jsonServer = require('json-server');
const jwt = require('jsonwebtoken');
const { body, validationResult, matchedData } = require('express-validator');

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

server.use(/.*/, (req, res, next) => {
    console.log('*********** Request ***********');
    console.log(`[${req.method}] ${req.baseUrl}`);
    console.log(req.body);
    next();
})

const customerRequiredParamsValidation = [
    body('age').isNumeric(),
    body('name').isString().isLength({ min: 3 }),
    body('gender').isString().isIn(['Male', 'Female']),
    body('company').isString().optional().isLength({ min: 1 }),
    body('email').isEmail(),
    body('phone').isString().matches(/\d{3}-\d{3}-\d{3}/),
    body('address').isString().isLength({ min: 10 }),
    body('credits').isArray(),
]

const customerOptionalParamsValidation = [
    body('age').optional().isNumeric(),
    body('name').optional().isLength({ min: 3 }),
    body('gender').optional().isIn(['Male', 'Female']),
    body('company').optional().optional().isLength({ min: 1 }),
    body('email').optional().isEmail(),
    body('phone').optional().matches(/\d{3}-\d{3}-\d{3}/),
    body('address').optional().isLength({ min: 10 }),
    body('credits').optional().isArray(),
]

const validateCustomerRequest = (req) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        const invalidParams = [...new Set(errors.array().map(error => error.param))];
        return { status: 400, message: `Missing param or invalid value: ${invalidParams.join(', ')}` };
    } else if (JSON.parse(fs.readFileSync(dbPath)).customer.some(p => p.name === req.body.name)) {
        return { status: 409, message: 'Customer already exists' };
    }

    return { status: 200, message: 'OK' }
}

server.post('/customer', customerRequiredParamsValidation, (req, res, next) => {
    const validateCustomerRequestResult = validateCustomerRequest(req);
    if (validateCustomerRequestResult.status !== 200) {
        return res.status(validateCustomerRequestResult.status).json(validateCustomerRequestResult);
    }

    req.body = matchedData(req, { includeOptionals: false });
    next();
});

server.put(/\/customer\/.*/, customerRequiredParamsValidation, (req, res, next) => {
    const validateCustomerRequestResult = validateCustomerRequest(req);
    if (validateCustomerRequestResult.status !== 200) {
        return res.status(validateCustomerRequestResult.status).json(validateCustomerRequestResult);
    }

    req.body = matchedData(req, { includeOptionals: false });
    next();
});

server.patch(/\/customer\/.*/, customerOptionalParamsValidation, (req, res, next) => {
    const validateCustomerRequestResult = validateCustomerRequest(req);
    if (validateCustomerRequestResult.status !== 200) {
        return res.status(validateCustomerRequestResult.status).json(validateCustomerRequestResult);
    }

    req.body = matchedData(req, { includeOptionals: false });
    next();
});

server.use(router);

server.listen(8001, () => {
  console.log('Run Auth API Server');
});
