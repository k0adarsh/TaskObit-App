const jwt = require('jsonwebtoken');

// Sign JWT Token Payload : userId.
const signToken = (userId) => {
    return jwt.sign({ id: userId }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN
    });
}

// Creates & Send JWT in Cookie.
exports.createSendToken = (user, statusCode, res) => {
    const token = signToken(user._id);
    res.cookie('jwt', token, { maxAge: 900000, httpOnly: true });

    res.status(statusCode).json({
        user: {
            id: user._id,
            displayName: user.displayName,
        },
    });
}

// Verifies User is Authenticated
exports.auth = (req, res, next) => {
    try {
        const token = req.cookies.jwt;
        if (!token)
            return res.status(401).json({ msg: "No authentication token, access denied" });

        const verified = jwt.verify(token, process.env.JWT_SECRET);
        if (!verified)
            return res.status(401).json({ msg: "Token verification failed, authorization denied" });

        // User Id added to request as user so it can be user further in the middleware calls.
        req.user = verified.id;
        next();
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
}



