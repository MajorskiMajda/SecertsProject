require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
// var encrypt = require('mongoose-encryption');
// const md5 = require("md5");
const bcrypt = require("bcrypt");
const saltRounds = 10;

const app = express();

app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({
    email: String,
    password: String
});

// userSchema.plugin(encrypt, { secret: process.env.SECRET , encryptedFields: ['password'] });


const User = new mongoose.model("User", userSchema);

app.get("/", (req, res) => {
    res.render("home");
});
app.get("/login", (req, res) => {
    res.render("login");
});
app.get("/register", (req, res) => {
    res.render("register");
});

app.post("/register", (req, res) => {

    bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
        const newUser = new User({
            email: req.body.email,
            password: hash
        });
        newUser.save()
            .then(() => {
                res.render("secrets");
            })
            .catch(err => {
                console.error(err);
                res.status(500).send("Error registering user. Please try again.");
            });
    });
});

app.post("/login", (req, res) => {
    const email = req.body.email;
    const password = req.body.password;


    User.findOne({ email: email }).then((foundUser) => {
        if (foundUser) {
            bcrypt.compare(password, foundUser.password, function(err, result) {
                if (result === true)
                {
                    res.render("secrets");  
                }
                else {
                    console.log("User doesn't exist" + err)
                    res.status(500).send("User doesn't exist. Please try again.");
                }
            });
        } 
    })
})

app.listen(3000, () => {
    console.log("Server running on port 3000.")
})