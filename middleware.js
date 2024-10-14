// Middleware to check if the user is logged in
function validate(req, res, next) {
    if (!req.session.isLogin) {
        return res.redirect('/login');
    }
    next();
}

module.exports = { validate };
