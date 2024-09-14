const express = require("express");
const app = express();
const port = 8000;   //Port number at which server is running.
const expressLayouts = require('express-ejs-layouts'); // For using layouts
const db = require('./config/mongoose'); // Connecting to database
const cookieParser = require('cookie-parser');
const cors = require('cors')
const flash = require('connect-flash');
const flashMware = require('./config/middleware');
const env = require('./config/environment');
const path = require('path');
app.use(cors());

// Used for session cookie
const session = require('express-session'); // requiring session
const passport = require('passport');  // passport library
const passportLocal = require('./config/passport-local-strategy');
const MongoStore = require('connect-mongo');


// enable the parsing of URL-encoded data sent from a web form or as query parameters in the URL
app.use(express.urlencoded({ extended: true }));

app.use(cookieParser());

// Using aseets static file
app.use(express.static(env.asset_path));
// extract styles and scripts from sub pages into layout
app.set('layout extractStyles', true);
app.set('layout extractScripts', true);



// Here we are using Layouts
app.use(expressLayouts);


// Setting up our view Engine
app.set('view engine', 'ejs');
app.set('views', './views');


// setting up the cookie session
app.use(session({
    name: 'petcare',
    secret: env.session_cookie_key,
    saveUninitialized: false,
    resave: false,
    cookie: {
        maxAge: (1000 * 60 * 100)
    },
    store: new MongoStore({
        mongoUrl: env.MONGO_URL,
        autoRemove: 'disabled'
    }, function (err) {
        console.log(err || 'connect-mongodb setup ok');
    })
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(passport.setAuthenticatedUser);
app.use(flash());
app.use(flashMware.setFlash);

// Here basically we are using routes index file after coming in this file
app.use('/', require('./routes/index'));


// This is to run the server
app.listen(process.env.Port || port, function (err) {
    if (err) {
        console.log(`Error in running the server: ${err}`);
        return;
    }
    console.log(`Server is running on the port: ${port}`);
});