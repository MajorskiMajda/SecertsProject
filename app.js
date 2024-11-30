require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const GitHubStrategy = require('passport-github').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const flash = require('connect-flash');
require('dotenv').config();



const app = express();

app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(flash());

app.use(session({
    secret: "Secretcode",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

const url = process.env.MONGO_URI

mongoose.connect(url)
    .then(() => console.log("Connected to MongoDB Atlas"))
    .catch((err) => console.log("Error connecting to MongoDB Atlas:", err));

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    googleId: String,
    facebookId: String,
    githubId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy())

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) {
        done(err);
    }
});

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "https://secertswebapp.onrender.com/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "https://secertswebapp.onrender.com/auth/facebook/secrets"
},
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ facebookId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));

passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: "https://secertswebapp.onrender.com/auth/github/secrets"
},
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ githubId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));

app.get("/", (req, res) => {
    res.render("home");
});
app.get("/auth/google", (req, res) => {
    passport.authenticate("google", { scope: ['profile'] })(req, res);
});
app.get("/auth/google/secrets",
    passport.authenticate("google", { failureRedirect: '/' }),
    (req, res) => {
        res.redirect('/secrets');
    }
);
app.get('/auth/facebook', (req, res) => {
    passport.authenticate("facebook", { scope: ['public_profile', 'email'] })(req, res);
});
app.get("/auth/facebook/secrets",
    passport.authenticate("facebook", { failureRedirect: '/' }),
    (req, res) => {
        res.redirect('/secrets');
    }
);
app.get('/auth/github', (req, res) => {
    passport.authenticate("github", { scope: ['email'] })(req, res);
});

app.get('/auth/github/secrets',
    passport.authenticate('github', { failureRedirect: '/login' }),
    function (req, res) {
        res.redirect('/secrets');
    });

app.get("/login", (req, res) => {
    res.render("login", {
        error: req.flash('error')
    });
});
app.get("/register", (req, res) => {
    res.render("register", {
        error: req.flash('error')
    });
});

app.get("/secrets", (req, res) => {
    User.find({ "secret": { $ne: null } })
        .then(foundUsers => {
            res.render("secrets", {
                usersWithSecrets: foundUsers, user: req.user,
                isAuthenticated: req.isAuthenticated()
            });
        })
        .catch(err => {
            console.log(err);
            res.status(500).send("Internal Server Error");
        });
});

app.get("/submit", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});


app.post("/submit", (req, res) => {
    const submittedSecret = req.body.secret;

    User.findById(req.user.id)
        .then(foundUser => {
            if (foundUser) {
                foundUser.secret = submittedSecret;
                return foundUser.save();
            } else {
                res.redirect("/");
            }
        })
        .then(() => {
            res.redirect("/secrets");
        })
        .catch(err => {
            console.log(err);
            res.status(500).send("Internal Server Error");
        });
});

app.post("/register", (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        req.flash('error', 'Please enter both your email and password.');
        return res.redirect("/register");
    }

    User.register({ username }, password, (err, user) => {
        if (err) {
            req.flash('error', 'An error occurred while registering. Please try again.');
            console.log(err);
            return res.redirect("/register");
        }

        req.logIn(user, (err) => {
            if (err) {
                req.flash('error', 'An error occurred while logging you in. Please try again.');
                console.log(err);
                return res.redirect("/register");
            }


            return res.redirect("/secrets");
        });
    });
});


app.post("/login", (req, res, next) => {
    const { username, password } = req.body;

    if (!username || !password) {
        req.flash('error', 'Please enter both your email and password.');
        return res.redirect("/login");
    }

    passport.authenticate('local', {
        successRedirect: "/secrets",
        failureRedirect: "/login",
        failureFlash: true
    })(req, res, next);
});

app.get("/logout", (req, res) => {
    req.logout((err) => {
        if (err) {
            return res.status(500).send("Error logging out");
        }
        res.redirect("/");
    });
});


app.listen(process.env.PORT || 3000, () => {
    console.log("Server running on port 3000.")
})
