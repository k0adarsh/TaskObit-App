const express = require('express');
const userController = require('./../controllers/userController');
const authControllers = require('../middleware/authControllers');

const router = express.Router();

router
    .route('/')
    .get(authControllers.auth, userController.getAllUsers)
    .post(userController.createUser);

router
    .route('/logout')
    .get(userController.logoutUser)

router
    .route('/login')
    .post(userController.loginUser)

router
    .route('/forgotPassword')
    .post(userController.forgotPassword);

router
    .route('/resetPassword/:token')
    .post(userController.resetPassword);

router
    .route('/:id')
    .get(userController.getUser)
    .patch(authControllers.auth, userController.updateUser)

module.exports = router;
