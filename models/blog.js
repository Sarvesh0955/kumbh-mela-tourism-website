const mongoose = require("mongoose"); 

const commentSchema = new mongoose.Schema({
    body: {
        type: String,
        required: true
    },
    likes: {
        type: Number,
        default: 0
    },
    username: {
        type: String,
        required: true
    },
    likedBy: [ 
        {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        }
    ],
    user_id: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    }
});

const Comment = mongoose.model('Comment', commentSchema);

const blogSchema = new mongoose.Schema({
    title: {
        type: String,
        required: true
    },
    body: {
        type: String,
        required: true
    },
    likes: {
        type: Number,
        default: 0
    },
    comments: [
        {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'Comment' 
        }
    ],
    likedBy: [ 
        {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        }
    ],
    author: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    image: {
        type: String,
        required: false,
    }
});

const Blog = mongoose.model('Blog', blogSchema);

module.exports = {Comment, Blog};

