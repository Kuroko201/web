const jwt = require('jsonwebtoken');

function login_authentication(req, res, next) {
    const token = req.cookies.accessToken;

    if (!token) {
        return res.status(403).redirect('/login');
    }

    try {
        const user = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
        req.user = user;
        next();
    } catch (err) {
        console.log('Invalid token:', err.message);
        res.clearCookie('accessToken');
        res.clearCookie('refreshToken');
        return res.status(403).redirect('/login');
    }
}


module.exports = { login_authentication };
