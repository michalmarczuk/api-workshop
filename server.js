const fs = require('fs');
const bodyParser = require('body-parser');
const jsonServer = require('json-server');
const jwt = require('jsonwebtoken');

const server = jsonServer.create();
const router = jsonServer.router('./db.json');
const userdb = JSON.parse(fs.readFileSync('./users.json', 'UTF-8'));

server.use(bodyParser.urlencoded({extended: true}));
server.use(bodyParser.json());
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

server.use(router);

server.listen(8000, () => {
  console.log('Run Auth API Server');
});