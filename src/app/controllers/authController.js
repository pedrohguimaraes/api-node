const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/user');
const authConfig = require('../../config/auth');
const router = express.Router();
const crypto = require('crypto');
const mailer = require('../../modules/mailer');

function generateToken(params = {}){
    return jwt.sign(params, authConfig.secret,{
        expiresIn: 86400
    });
}

// Cadastro
router.post('/store', async (req, res) => {

    const {email} = req.body;

    try{
        // Se já existir um email cadastrado
        if(await User.findOne({email}))
            return res.status(400).send({error: 'User already exists'})

        const user = await User.create(req.body);
        
        // Apagado do objeto assim que o usuário for criado
        user.password = undefined;

        return res.send({ 
            user,
            token:  generateToken({ id:user.id })
         });
    }catch(err){
        console.log(err);
        return res.status(400).send({ error:'Registration failed' });
    }
});

// Login
router.post('/authenticate', async(req, res) => {
    const {email, password} = req.body;

    const user = await User.findOne({email}).select('+password');

    if(!user)
        res.status(400).send({error: "User not found"});

    if(!await bcrypt.compare(password, user.password))
        res.status(400).send({error: "Invalid password"});

    user.password = undefined;
    res.send({ 
        user, 
        token: generateToken({ id:user.id }) 
    });
});

// Recuperação de senha
router.post('/forgot_password', async(req, res) =>{
    const {email} = req.body;

    try{
        const user = await User.findOne({ email });

        if(!user)
            return res.status(400).send({error: "User not found"});

        // token para mudança de senha
        const token = crypto.randomBytes(20).toString('hex');
        
        // Tempo de expiração do token
        const now = new Date();
        now.setHours(now.getHours() +1);

        // Update
        await User.findByIdAndUpdate(user.id, {
            '$set': {
                passwordResetToken: token,
                passwordResetExpires: now
            } 
        });

        // Envio de email
        mailer.sendMail({
            to: email,
            from: 'pedroguimaraes@email.com.br',
            template: 'auth/forgot_password',
            context: { token }
        }, (err) => {
            if(err)
                return res.status(400).send({error: 'Cannot send forgot password email'});
            
            return res.send();
        });

    }catch(err){
        res.status(400).send({error: 'Error on forgot password, try again'});
    }
});

// Redefinição de senha
router.post('/reset_password', async (req, res) => {
    const {email, token, password} = req.body;

    try{
        const user = await User.findOne({ email })
            .select('+passwordResetToken passwordResetExpires');

        if(!user)
            return res.status(400).send({error: "User not found"});
            
        if(token !== user.passwordResetToken)
            return res.status(400).send({error: "Token invalid"});

        const now = new Date();

        if(now > user.passwordResetExpires)
            return res.status(400).send({error: "Token expired, generate a new one"});
         
        user.password = password;
        
        await user.save();
        res.send();
        
    }catch(err){
        
        res.status(400).send({ error: 'Cannot reset password, try again'});
    }
});

// recebe o app passado na index
module.exports = app => app.use('/auth', router);