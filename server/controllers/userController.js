const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const User = require('../models/userModel')
const authControllers = require('../middleware/authControllers');
const sendEmail = require('./../utils/emailCon');


// Login an Existing User
exports.loginUser = async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({
                status: 'Failed',
                message: 'Please Provide Email & Password'
            })
        }
        const user = await User.findOne({ email: email }).select('+password');
        if (!user)
            return res
                .status(400)
                .json({ msg: "No account with this email has been registered." });

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) return res.status(400).json({ msg: "Invalid credentials." });

        authControllers.createSendToken(user, 200, res);

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
}

// Logout a Logged In User
exports.logoutUser = async (req, res) => {
    try {
        const token = req.cookies.jwt;
        if (!token)
            return res.status(400).json({ msg: "No Logged In User" });

        let userId = jwt.verify(token, process.env.JWT_SECRET);

        const user = await User.findOne({ _id: userId.id });
        if (!user)
            return res.status(400).json({ msg: "Logout Error" });
        res.clearCookie('jwToken');
        res.status(200).json({
            status: 'Success',
            data: {
                email: user.email
            }
        })
    } catch (err) {
        res.status(400).json({
            status: 'Failed Logging Out',
            message: err
        })
    }
}

// Create a New User.
exports.createUser = async (req, res) => {
    try {
        let { email, password, passwordCheck, displayName } = req.body;

        if (!email || !password || !passwordCheck || !displayName)
            return res.status(400).json({ msg: "Not all fields entered" });
        if (password.length < 5)
            return res
                .status(400)
                .json({ msg: "The password needs to be at least 5 characters long." });
        if (password !== passwordCheck)
            return res
                .status(400)
                .json({ msg: "Enter the same password twice for verification." });

        const existingUser = await User.findOne({ email: email });
        if (existingUser)
            return res
                .status(400)
                .json({ msg: "An account with this email already exists." });

        const salt = await bcrypt.genSalt();
        const passwordHash = await bcrypt.hash(password, salt);

        const newUser = new User({
            email,
            password: passwordHash,
            displayName,
            userCreatedAt: Date.now()
        });
        const savedUser = await newUser.save();

        const message = `Welcome ${savedUser.displayName} !. Hope you enjoy your journey with us!!`;
        await sendEmail({
            email: savedUser.email,
            subject: 'Welcome Email',
            message
        });
        authControllers.createSendToken(savedUser, 201, res);

    } catch (err) {
        res.status(400).json({
            status: 'Failed User Creation',
            message: err
        })
    }
}

// Update an Existing User.
// Protected Route.
exports.updateUser = async (req, res) => {
    try {
        const user = await User.findByIdAndUpdate(req.user.id, req.body, {
            new: true,
            runValidators: true
        });
        res.status(200).json({
            status: 'Update Successful',
            data: {
                user
            }
        })
    }
    catch (err) {
        res.status(404).json({
            status: 'Failed',
            message: err
        })
    }
}

// Get All Users. 
// Protected route.
exports.getAllUsers = async (req, res) => {
    try {
        const users = await User.find();
        res.status(200).json({
            status: 'Success',
            results: users.length,
            data: {
                users
            }
        })
    }
    catch (err) {
        res.status(400).json({
            status: 'Fail',
            message: err
        })
    }
}

// Get a Single User
// Protected Route
exports.getUser = async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        res.status(200).json({
            status: 'Success',
            data: {
                user
            }
        })
    }
    catch (err) {
        res.status(404).json({
            status: 'Failed',
            message: err
        })
    }
}

// Delete Existing User
// Should Be Protected to Admin
exports.deleteUser = async (req, res) => {
    try {
        await User.findByIdAndDelete(req.params.id);
        res.status(204).json({
            status: 'Success',
            data: null
        })
    }
    catch (err) {
        res.status(400).json({
            status: 'Failed',
            message: err
        })
    }
}
exports.forgotPassword = async (req, res, next) => {
    // 1) Get user from provided email
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
        return res.status(404).json({ msg: "No registered user with this email" })
    }

    // 2) Generate the random reset token
    const resetToken = user.createPasswordResetToken();
    await user.save({ validateBeforeSave: false });

    // 3) Send it to user's email
    const resetURL = `${req.protocol}://${req.get(
        'host'
    )}/api/v1/users/resetPassword/${resetToken}`;

    const message = `Forgot your password? Submit a PATCH request with your new password and passwordConfirm to: ${resetURL}.Token valid for 10 Mins. \nIf you didn't forget your password, please ignore this email!`;

    try {
        await sendEmail({
            email: user.email,
            subject: 'Your password reset token',
            message
        });

        res.status(200).json({
            status: 'success',
            message: 'Token sent to email!'
        });
    } catch (err) {
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        await user.save({ validateBeforeSave: false });

        return res.status(404).json({ msg: "Error Sending Token Mail" });
    }
}

exports.resetPassword = async (req, res, next) => {
    // 1) Get user based on the token
    const hashedToken = crypto
        .createHash('sha256')
        .update(req.params.token)
        .digest('hex');

    const user = await User.findOne({
        passwordResetToken: hashedToken,
        passwordResetExpires: { $gt: Date.now() }
    });

    // 2) If token has not expired, and there is user, set the new password
    if (!user) {
        return res.status(404).json({ msg: "Invalid password reset token" })
    }

    if (req.body.password != req.body.passwordConfirm)
        return res.status(404).json({ msg: "Password Don't Match" })

    const salt = await bcrypt.genSalt();
    const passwordHash = await bcrypt.hash(req.body.password, salt);

    user.password = passwordHash;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    // 3) Update changedPasswordAt property for the user
    // 4) Log the user in, send JWT
    authControllers.createSendToken(user, 200, res);
};
