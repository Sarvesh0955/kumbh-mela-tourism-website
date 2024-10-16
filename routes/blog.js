const express = require('express');
const router = express.Router();
require('dotenv').config();
const User = require('../models/user');
const {Comment, Blog} = require('../models/blog');
const {validate,upload} = require('../middleware');

// Get all blogs or search by title
router.get('/', async (req, res) => {
    try {
        const q = req.query.q;
        let posts;
        if (q) {
            posts = await Blog.find({ title: { $regex: q, $options: 'i' } }).populate('author', 'name');
        } else {
            posts = await Blog.find({}).populate('author', 'name');
        }
        res.render('./blog/blog', { posts });
    } catch (error) {
        res.status(500).send("Server error while fetching blog posts.");
    }
});

// Blog creation page
router.get('/create',validate, (req, res) => {
    res.render('./blog/create_blog');
});

// View single blog post with comments
router.get('/:id', async (req, res) => {
    try {
        const post = await Blog.findById(req.params.id).populate('comments').populate('author','name');
        if (!post) {
            return res.status(404).send("Blog post not found.");
        }
        res.render('./blog/post', { post });
    } catch (error) {
        res.status(500).send("Server error while fetching the blog post.");
    }
});

router.get('/edit/:id',validate, async (req, res) => {
    try {
        const post = await Blog.findById(req.params.id);
        if (!post) {
            return res.status(404).send("Blog post not found.");
        }
        if (post.author.toString() !== req.session.user_id) {
            return res.status(403).send("You are not authorized to edit this post.");
        }
        res.render('./blog/edit_blog', { post });
    } catch (error) {
        res.status(500).send("Server error while fetching the blog post.");
    }
});


// Create a blog post with image upload
router.post('/create',validate,upload.single('image'), async (req, res) => {
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


router.post('/edit/:id',upload.single('image'), async (req, res) => {
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
router.delete('/:id',validate, async (req, res) => {
    try {
        const post = await Blog.findById(req.params.id);
        const user = await User.findById(req.session.user_id);
        if (!post) {
            return res.status(404).send("Blog post not found.");
        }
        if (post.author.toString() !== req.session.user_id) {
            return res.status(403).send("You are not authorized to delete this post.");
        }
        user.blogs = user.blogs.filter(c => c.toString() !== req.params.id);
        await Blog.findByIdAndDelete(req.params.id);
        await user.save();
        res.redirect('/blog');
    } catch (error) {
        res.status(500).send("Server error while deleting the blog post.");
    }
});

// Post a comment on a blog post
router.post('/:id/comment', validate, async (req, res) => {
    try {
        const data = {
            body: req.body.comment,
            username: req.session.name,
            user_id: req.session.user_id
        };
        const comment = new Comment(data);
        const post = await Blog.findById(req.params.id);
        const user = await User.findById(req.session.user_id);
        if (!post) {
            return res.status(404).send("Blog post not found.");
        }
        post.comments.push(comment);
        user.comments.push(comment);
        await comment.save();
        await post.save();
        await user.save();
        res.redirect(`/blog/${req.params.id}`);
    } catch (error) {
        res.status(500).send("Server error while posting the comment.");
    }
});

// Delete a comment
router.delete('/:id/comment/:c_id',validate, async (req, res) => {
    try {
        const post = await Blog.findById(req.params.id);
        const user = await User.findById(req.session.user_id);
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
        user.comments = user.comments.filter(c => c.toString() !== req.params.c_id);
        await Comment.findByIdAndDelete(req.params.c_id)
        await post.save();
        await user.save();
        res.redirect(`/blog/${req.params.id}`);
    } catch (error) {
        res.status(500).send("Server error while deleting the comment.");
    }
});

router.post('/:id/like',validate,async (req,res) => {
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

router.post('/:id/dislike', validate, async (req, res) => {
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

router.post('/comment/:c_id/like', validate, async (req, res) => {
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

router.post('/comment/:c_id/dislike', validate, async (req, res) => {
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

module.exports = router;