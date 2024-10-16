const path = require('path');
const nodemailer = require('nodemailer');
const multer = require('multer');
require('dotenv').config();

// Middleware to check if the user is logged in
function validate(req, res, next) {
    if (!req.session.isLogin) {
        return res.redirect('/login');
    }
    next();
}

// Set up email transporter for nodemailer
const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
        user: `${process.env.TRANSPORTER_EMAIL}`,
        pass: `${process.env.TRANSPORTER_KEY}`
    }
});

transporter.verify((error, success) => {
    if (error) {
        console.error('Error connecting to mail server:', error);
    } else {
        console.log('Connected to mail server successfully');
    }
});

// Set up storage engine for multer
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'public/uploads'); 
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

// Initialize multer with the storage settings
const upload = multer({
    storage: storage,
    limits: { fileSize: 10000000 }, //10mb 
    fileFilter: (req, file, cb) => {
        const filetypes = /jpeg|jpg|png|gif/;
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = filetypes.test(file.mimetype);

        if (extname && mimetype) {
            return cb(null, true);
        } else {
            cb('Error: Images Only!');
        }
    }
});

module.exports = { validate,upload,transporter };
