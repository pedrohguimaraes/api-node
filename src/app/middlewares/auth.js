const jwt = require('jsonwebtoken');
const authConfig = require('../../config/auth.json');

module.exports = (req, res, next) => {

    const authHeader = req.headers.authorization;

    if(!authHeader)
        return res.status(401).send({error: 'No token provided'});

    // Divide o token em duas partes
    const parts = authHeader.split(' ');

    // Verifica se o token está dividido em duas partes
    if(!parts.length === 2)
        return res.status(401).send({error: 'Token error' });

    const [scheme, token] = parts;

    // Verifica se exite o Bearer no token
    if (!/^Bearer$/i.test(scheme))
        return res.status(401).send({error: 'Token malformatted' });

    // Valida o token
    jwt.verify(token, authConfig.secret, (err, decoded) =>{
        if(err) return res.status(401).send({error: 'Token invalid'});

        req.userId = decoded.id;
        return next();
    });
};  