const mongoose = require("mongoose"); 

const userSchema = new mongoose.Schema({
    name: {
        type : String,
        required : true,
    },
    email: {
        type : String,
        required : true,
    },
    password: {
        type : String,
        required : true,
    },
    isAdmin: {
        type : Boolean,
        default : false,
    },
    resetPasswordToken : String,
    resetPasswordExpires : Date,
    blogs: [
        {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'Blog' 
        }
    ],
    comments: [
        {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'Comment' 
        }
    ],
});

const User = mongoose.model('User', userSchema);

//middleware to delete all blogs and post of user
userSchema.post('findByIdAndDelete', async function (doc) {
    if (doc) {
        await Blog.deleteMany({
            _id: {
                $in: doc.blogs
            }
        })
        await Comment.deleteMany({
            _id: {
                $in: doc.comments
            }
        })
    }
})

module.exports = User;

