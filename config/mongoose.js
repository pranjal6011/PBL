const mongoose = require('mongoose');
const env = require('./environment');// Assuming env.db contains your database name
// require('dotenv').config();
mongoose.connect(env.MONGO_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
    .then(() => {
        console.log('Connected to Database :: MongoDB Atlas');
    })
    .catch((error) => {
        console.error('Error connecting to MongoDB Atlas:', error);
    });
const db = mongoose.connection;

// db.on('error', console.error.bind(console, "Error connecting to MongoDB"));

// db.once('open', function () {
//     console.log('Connected to Database :: MongoDB');
// });
module.exports = db;