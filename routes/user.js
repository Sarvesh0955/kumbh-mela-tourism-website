const express = require('express');
const router = express.Router();
const {validate,transporter} = require('../middleware');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { promisify } = require("util");
require('dotenv').config();
const User = require('../models/user');

router.get('/', (req, res) => {
    res.render('./user/home', {
        username: req.session.name,
        isLogin: req.session.isLogin || false,
    });
});

router.get('/login', (req, res) => {
    res.render('./user/login');
});

router.get('/signup', (req, res) => {
    res.render('./user/signup');
});

router.get('/profile', validate, (req, res) => {
    res.render('./user/profile', {
        user_id: req.session.user_id,
        name: req.session.name,
        email: req.session.email,
    });
});

router.get('/profile/:id', validate, (req, res) => {
    res.render('./user/edit_profile', {
        user_id: req.params.id,
        name: req.session.name,
    });
});

router.get('/forgot-password', (req, res) => {
    res.render('./user/forgot-password');
});

router.get('/reset-password/:token', async (req, res) => {
    try {
        const user = await User.findOne({
            resetPasswordToken: req.params.token,
            resetPasswordExpires: { $gt: Date.now() },
        });
        if (!user) {
            return res.send("Password reset token is invalid or has expired.");
        }
        res.render('/user/reset-password', {token : req.params.token});
    } catch (e) {
        console.log("Error in reset password : ",e);
        res.status(500).send('Error in reset password.');
    }
});

router.post('/login', async (req, res) => {
    try {
        const user = await User.findOne({ email: req.body.email });
        if (!user || !(await bcrypt.compare(req.body.password, user.password))) {
            return res.send("Wrong credentials");
        }
        req.session.name = user.name;
        req.session.email = user.email;
        req.session.user_id = user._id;
        req.session.isLogin = true;
        res.redirect('/');
    } catch (e) {
        console.log('Error in login:', e);
        res.status(500).send('Error logging in.');
    }
});

router.post('/signup', async (req, res) => {
    try {
        if (await User.findOne({ email: req.body.email })) {
            return res.send("User already registered");
        }
        req.body.password = await bcrypt.hash(req.body.password, 12);
        const user = new User(req.body);
        await user.save();
        req.session.name = user.name;
        req.session.email = user.email;
        req.session.user_id = user._id;
        req.session.isLogin = true;
        res.redirect('/');
    } catch (e) {
        console.log('Error in signup:', e);
        res.status(500).send('Error signing up.');
    }
});

router.post('/profile/:id', validate, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) {
            return res.send("No such user present");
        }
        req.body.password = req.body.password
            ? await bcrypt.hash(req.body.password, 12)
            : user.password;
        await User.findByIdAndUpdate(req.params.id, {
            name: req.body.name || user.name,
            password: req.body.password,
        }, { new: true });
        req.session.name = req.body.name || user.name;
        res.redirect('/profile');
    } catch (e) {
        console.log('Error in update:', e);
        res.status(500).send('Error updating profile.');
    }
});

router.delete('/profile/:id', validate, async (req, res) => {
    try {
        const user = await User.findByIdAndDelete(req.params.id);
        if (!user) {
            return res.send("No such user present");
        }
        req.session.destroy();
        res.redirect('/');
    } catch (e) {
        console.log('Error in delete:', e);
        res.status(500).send('Error deleting account.');
    }
});

router.post('/logout', validate, (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).send("Error logging out.");
        }
        res.redirect('/');
    });
});


router.post('/forgot-password', async (req, res) => {
    try {
        const user = await User.findOne({ email: req.body.email });
        if (!user) {
            return res.send("User not found");
        }
        const token = (await promisify(crypto.randomBytes)(20)).toString('hex');
        const expiration = Date.now() + 3600000;
        await User.updateOne(
            { email: req.body.email },
            { $set: { resetPasswordToken: token, resetPasswordExpires: expiration } }
        );
        const resetLink = `http://localhost:8080/reset-password/${token}`;
        await transporter.sendMail({
            to: user.email,
            subject: "Password Reset",
            text: `You are receiving this because you (or someone else) have requested to reset the password for your account.\n\n
            Please click on the following link, or paste it into your browser to complete the process:\n\n
            ${resetLink}\n\n
            If you did not request this, please ignore this email and your password will remain unchanged.\n`
        });
        res.send("Reset link sent to your email.");
    } catch (e) {
        console.log("Error in forgot password : ",e);
        res.status(500).send('Error in forgot password.');
    }
});

router.post('/reset-password/:token', async (req, res) => {
    try {
        const user = await User.findOne({
            resetPasswordToken: req.params.token,
            resetPasswordExpires: { $gt: Date.now() },
        });
        if (!user) {
            return res.send("Password reset token is invalid or has expired.");
        }
        const newPassword = await bcrypt.hash(req.body.password,12);
        await User.updateOne(
            { _id: user._id },
            {
                $set: { password: newPassword },
                $unset: { resetPasswordToken: "", resetPasswordExpires: "" }
            }
        );
        res.send("Password has been successfully reset.");
    } catch (e) {
        console.log(e);
        res.send("An error occurred while resetting the password.");
    }
});

module.exports = router;
