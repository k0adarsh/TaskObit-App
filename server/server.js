const mongoose = require('mongoose');
const dotenv = require('dotenv');
const app = require('./app');
//const bodyParser = require('body-parser');

dotenv.config({ path: './config.env' });

const DB = process.env.DATABASE;
mongoose.connect(DB, {
    useNewUrlParser: true,
    useCreateIndex: true,
    useFindAndModify: false,
    useUnifiedTopology: true
}).then((con) => {
    console.log('Database Connection Successful');
})
const port = 8000;
app.listen(port, () => {
    console.log(`Listening to port ${port}`);
})
