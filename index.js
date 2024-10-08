const express = require('express');
const app = express();
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const methodOverride = require('method-override');
const session = require('express-session');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const multer = require('multer');
const { promisify } = require("util");
require('dotenv').config();
const User = require('./models/user');
const {Comment, Blog} = require('./models/blog');

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


// MongoDB connection
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('MongoDB connected'))
    .catch(e => console.error('Error connecting to MongoDB'));

    
    
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
    req.session.destroy(err => {
        if (err) {
            return res.status(500).send("Error logging out.");
        }
        res.redirect('/');
    });
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

// Get all blogs or search by title
app.get('/blog', async (req, res) => {
    try {
        const q = req.query.q;
        let posts;
        if (q) {
            posts = await Blog.find({ title: { $regex: q, $options: 'i' } });
        } else {
            posts = await Blog.find({});
        }
        res.render('blog', { posts });
    } catch (error) {
        res.status(500).send("Server error while fetching blog posts.");
    }
});

// Blog creation page
app.get('/blog/create',validate, (req, res) => {
    res.render('create_blog');
});

// View single blog post with comments
app.get('/blog/:id', async (req, res) => {
    try {
        const post = await Blog.findById(req.params.id).populate('comments').populate('author','name');
        if (!post) {
            return res.status(404).send("Blog post not found.");
        }
        res.render('post', { post });
    } catch (error) {
        res.status(500).send("Server error while fetching the blog post.");
    }
});

app.get('/blog/edit/:id',validate, async (req, res) => {
    try {
        const post = await Blog.findById(req.params.id);
        if (!post) {
            return res.status(404).send("Blog post not found.");
        }
        if (post.author.toString() !== req.session.user_id) {
            return res.status(403).send("You are not authorized to edit this post.");
        }
        res.render('edit_blog', { post });
    } catch (error) {
        res.status(500).send("Server error while fetching the blog post.");
    }
});


// Create a blog post with image upload
app.post('/blog/create', upload.single('image'), async (req, res) => {
    try {
        const data = req.body;
        const post = new Blog({
            title: data.title,
            body: data.body,
            image: req.file ? `/uploads/${req.file.filename}` : `/uploads/default.png`,
            author: req.session.user_id,
        });
        await post.save();

        const user = await User.findById(req.session.user_id);
        user.blogs.push(post);
        await user.save();

        res.redirect('/blog');
    } catch (error) {
        console.error(error);
        res.status(500).send("Server error while creating the blog post.");
    }
});


app.post('/blog/edit/:id',upload.single('image'), async (req, res) => {
    try {
        const post = await Blog.findById(req.params.id);
        if (!post) {
            return res.status(404).send("Blog post not found.");
        }
        if (post.author.toString() !== req.session.user_id) {
            return res.status(403).send("You are not authorized to edit this post.");
        }

        const updatedData = req.body;
        post.title = updatedData.title || post.title;
        post.body = updatedData.body || post.body;
        if (req.file) {
            post.image = `/uploads/${req.file.filename}`;
        }
        await post.save();
        res.redirect(`/blog/${post._id}`);
    } catch (error) {
        res.status(500).send("Server error while updating the blog post.");
    }
});

// Delete a blog post
app.delete('/blog/:id',validate, async (req, res) => {
    try {
        const post = await Blog.findById(req.params.id);
        if (!post) {
            return res.status(404).send("Blog post not found.");
        }
        if (post.author.toString() !== req.session.user_id) {
            return res.status(403).send("You are not authorized to delete this post.");
        }
        await post.remove();
        res.redirect('/blog');
    } catch (error) {
        res.status(500).send("Server error while deleting the blog post.");
    }
});

// Post a comment on a blog post
app.post('/blog/:id/comment', validate, async (req, res) => {
    try {
        const data = {
            body: req.body.comment,
            username: req.session.name,
            user_id: req.session.user_id
        };
        const comment = new Comment(data);
        const post = await Blog.findById(req.params.id);
        if (!post) {
            return res.status(404).send("Blog post not found.");
        }
        post.comments.push(comment);
        await comment.save();
        await post.save();
        res.redirect(`/blog/${req.params.id}`);
    } catch (error) {
        res.status(500).send("Server error while posting the comment.");
    }
});

// Delete a comment
app.delete('/blog/:id/comment/:c_id',validate, async (req, res) => {
    try {
        const post = await Blog.findById(req.params.id);
        if (!post) {
            return res.status(404).send("Blog post not found.");
        }
        const comment = await Comment.findById(req.params.c_id);
        if (!comment) {
            return res.status(404).send("Comment not found.");
        }
        if (comment.user_id.toString() !== req.session.user_id) {
            return res.status(403).send("You are not authorized to delete this comment.");
        }
        post.comments = post.comments.filter(c => c.toString() !== req.params.c_id);
        await Comment.findByIdAndDelete(req.params.c_id)
        await post.save();
        res.redirect(`/blog/${req.params.id}`);
    } catch (error) {
        res.status(500).send("Server error while deleting the comment.");
    }
});

app.post('/blog/:id/like',validate,async (req,res) => {
    try {
        const blog = await Blog.findById(req.params.id);
        if (blog.likedBy.includes(req.session.user_id)) {
            return res.status(400).send("You have already liked this blog post.");
        }
        blog.likes += 1;
        blog.likedBy.push(req.session.user_id);
        await blog.save();
        res.redirect(req.get('referer'))
    } catch (e) {
        res.status(500).send("Server error while liking the blog: ",e);
    }
});

app.post('/blog/:id/unlike', validate, async (req, res) => {
    try {
        const blog = await Blog.findById(req.params.id);
        const userId = req.session.user_id;
        const userIndex = blog.likedBy.indexOf(userId);
        if (userIndex === -1) {
            return res.status(400).send("You have not liked this blog post.");
        }
        blog.likes -= 1;
        blog.likedBy.splice(userIndex, 1);
        await blog.save();
        res.redirect(req.get('referer'))
    } catch (e) {
        res.status(500).send("Server error while unliking the blog: ",e);
    }
});

app.post('/blog/comment/:c_id/like', validate, async (req, res) => {
    try {
        const comment = await Comment.findById(req.params.c_id);
        if (!comment) {
            return res.status(404).send("Comment not found.");
        }
        if (comment.likedBy.includes(req.session.user_id)) {
            return res.status(400).send("You have already liked this comment.");
        }
        comment.likes += 1;
        comment.likedBy.push(req.session.user_id);
        await comment.save();
        res.redirect(req.get('referer'));
    } catch (e) {
        res.status(500).send("Server error while liking the comment: ",e);
    }
});

app.post('/blog/comment/:c_id/unlike', validate, async (req, res) => {
    try {
        const comment = await Comment.findById(req.params.c_id);
        if (!comment) {
            return res.status(404).send("Comment not found.");
        }
        const userId = req.session.user_id;
        const userIndex = comment.likedBy.indexOf(userId);
        if (userIndex === -1) {
            return res.status(400).send("You have not liked this comment.");
        }
        comment.likes -= 1;
        comment.likedBy.splice(userIndex, 1);
        await comment.save();
        res.redirect(req.get('referer'));
    } catch (e) {
        res.status(500).send("Server error while unliking the comment: ",e);
    }
});

app.listen(PORT, () => {
    console.log(`Website running at: http://localhost:${PORT}/`);
});
