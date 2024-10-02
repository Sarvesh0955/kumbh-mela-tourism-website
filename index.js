const express = require('express');
const app = express();
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const methodOverride = require('method-override');
const session = require('express-session');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const { promisify } = require("util");
require('dotenv').config();

const PORT = process.env.PORT || 8080;

// Setting up paths and middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '/views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(methodOverride('_method'));

// Set up email transporter for nodemailer
const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
        user: `${process.env.TRANSPORTER_EMAIL}`,
        pass: `${process.env.TRANSPORTER_KEY}`
    }
});

// Secure session setup
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, httpOnly: true, maxAge: 1000 * 60 * 60 * 24 } 
}));

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('MongoDB connected'))
    .catch(e => console.error('Error connecting to MongoDB'));

// Importing models
const User = require('./models/user');

// Middleware to validate login
function validate(req, res, next) {
    if (!req.session.isLogin) {
        return res.redirect('/login');
    }
    next();
}

// Routes
app.get('/', (req, res) => {
    res.render('home', {
        username: req.session.name,
        isLogin: req.session.isLogin || false,
    });
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.get('/signup', (req, res) => {
    res.render('signup');
});

app.get('/profile', validate, (req, res) => {
    res.render('profile', {
        user_id: req.session.user_id,
        name: req.session.name,
        email: req.session.email,
    });
});

app.get('/profile/:id', validate, (req, res) => {
    res.render('edit_profile', {
        user_id: req.params.id,
        name: req.session.name,
    });
});

app.get('/forgot-password', (req, res) => {
    res.render('forgot-password');
});

app.get('/reset-password/:token', async (req, res) => {
    try {
        const user = await User.findOne({
            resetPasswordToken: req.params.token,
            resetPasswordExpires: { $gt: Date.now() },
        });
        if (!user) {
            return res.send("Password reset token is invalid or has expired.");
        }
        res.render('reset-password', {token : req.params.token});
    } catch (e) {
        console.log("Error in reset password : ",e);
        res.status(500).send('Error in reset password.');
    }
});

app.post('/login', async (req, res) => {
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

app.post('/signup', async (req, res) => {
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

app.post('/profile/:id', validate, async (req, res) => {
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

app.delete('/profile/:id', validate, async (req, res) => {
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

app.post('/logout', validate, (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.post('/forgot-password', async (req, res) => {
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

app.post('/reset-password/:token', async (req, res) => {
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

app.listen(PORT, () => {
    console.log(`Website running at: http://localhost:${PORT}/`);
});
