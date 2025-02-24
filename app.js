const express = require('express');
const app = express();
require('dotenv').config();
const path = require('path');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { createApi } = require('unsplash-js');
const fetch = require('node-fetch');
const mongoose = require('mongoose');
const userModel = require('./models/user');

// Middleware setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieParser());

// Environment variables
const JWT_SECRET = process.env.JWT_SECRET || 'some-secret-string';
const MONGODB_URL = process.env.MONGODB_URL;

// MongoDB Connection
mongoose.connect(MONGODB_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));

// Unsplash Setup
const unsplash = createApi({
    accessKey: process.env.ACCESS_KEY,
    fetch: fetch
});

// Middleware Functions
async function fetchUnsplash(req, res, next) {
    try {
        const response = await unsplash.photos.list({ page: 1, perPage: 50 });
        req.unsplashObjArray = response.response.results;
        console.log('Images fetched successfully');
        next();
    } catch (error) {
        console.error('Unsplash fetch error:', error.message);
        next(error);
    }
}

function jwtAuthentication(req, res, next) {
    try {
        const token = req.cookies.JWTcookie;
        
        if (!token) {
            return next();
        }

        jwt.verify(token, JWT_SECRET, async (err, decoded) => {
            if (err) {
                return res.redirect('/');
            }

            const userobj = await userModel.findOne({ email: decoded.email });
            if (!userobj) {
                return res.redirect('/pinterest-guest');
            }

            req.user = userobj;
            res.render('profile', { userObj: userobj });
        });
    } catch (error) {
        console.error('Auth error:', error);
        res.redirect('/');
    }
}

// Routes
app.get('/', (req, res) => {
    res.render('login');
});

app.get('/sign-up', (req, res) => {
    res.render('sign-up');
});

app.get('/profile', jwtAuthentication, (req, res) => {
    res.render('login');
});

app.post('/pinterest', fetchUnsplash, async (req, res) => {
    try {
        if (!req.body.firstName) {
            // Login flow
            const userObject = await userModel.findOne({ email: req.body.email });
            
            if (userObject && bcrypt.compareSync(req.body.password, userObject.password)) {
                const token = jwt.sign({ email: req.body.email }, JWT_SECRET);
                res.cookie('JWTcookie', token);

                return res.render('pinterest', {
                    obj: req.unsplashObjArray,
                    userDetail: {
                        firstName: userObject.firstName,
                        lastName: userObject.lastName
                    }
                });
            }
            return res.status(401).send('Invalid credentials');
        } else {
            // Signup flow
            const existingUser = await userModel.findOne({ email: req.body.email });
            
            if (existingUser) {
                return res.status(409).send('User already exists');
            }

            const { firstName, lastName, email, password } = req.body;
            const salt = await bcrypt.genSalt(10);
            const hash = await bcrypt.hash(password, salt);

            await userModel.create({
                firstName,
                lastName,
                email,
                password: hash
            });

            const token = jwt.sign({ email }, JWT_SECRET);
            res.cookie('JWTcookie', token);

            res.render('pinterest', {
                obj: req.unsplashObjArray,
                userDetail: { firstName, lastName }
            });
        }
    } catch (error) {
        console.error('Pinterest route error:', error);
        res.status(500).send('Internal server error');
    }
});

app.get('/home', jwtAuthentication, (req, res) => {
    res.render('home', { userDetail: null });
});

app.get('/pinterest-guest', fetchUnsplash, (req, res) => {
    res.render('pinterest', { obj: req.unsplashObjArray, userDetail: null });
});

app.get('/log-out', (req, res) => {
    res.clearCookie('JWTcookie');
    res.redirect('/');
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

// Server setup
if (process.env.NODE_ENV !== 'production') {
    const port = process.env.PORT || 3001;
    app.listen(port, () => {
        console.log(`Development server running on port ${port}`);
    });
}

module.exports = app;