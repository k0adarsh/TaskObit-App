const express = require('express');
var cors = require('cors')
const app = express();
const morgan = require('morgan');
const userRouter = require('./routes/userRoutes');
const cookieParser = require('cookie-parser');

app.use(cors())
app.use(cookieParser());
app.use(express.urlencoded());

app.use(express.json());
app.use(morgan('dev'));

app.use('/api/users', userRouter);

module.exports = app;

