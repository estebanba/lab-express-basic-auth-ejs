const { Router } = require("express");
const router = new Router();

const bcryptjs = require("bcryptjs");
const saltRounds = 10
const salt = bcryptjs.genSaltSync(saltRounds)

const User = require("../models/User.model");

// SIGNUP //

router.get("/signup", (req, res) => {
    res.render("auth/signup")
} )

router.post("/signup", async (req, res) => {
    try {
        const { username, password } = req.body;

        const salt = await bcryptjs.genSalt(saltRounds);
        const hashedPassword = await bcryptjs.hash(password, salt);
        
        await User.create({ username, password: hashedPassword });
        res.render("user/profile", {username});
    } catch (error) {
        console.log("error", error)
    }        
})

// LOGIN //

router.get("/login", (req, res) => res.render("auth/login"))

router.post("/login", async (req, res, next) => {
    console.log('SESSION =====> ', req.session);
    
    const { username, password } = req.body;

    if (username === "" || password === "") {

        res.render("auth/login", {
            errorMessage: "Please enther both username and password to login."
        });
        return;
    }

    const userFromDB = await User.findOne({ username });
    if (!userFromDB) {
        
        return;
    }

    if (bcryptjs.compareSync(password, userFromDB.password)) {
        // console.log(userFromDB);
        req.session.currentUser = userFromDB;
        res.render("user/profile", { userInSession: req.session.currentUser });
    } else {
        res.render("auth/login", {
            errorMessage: "Wrong password!"
        });
    }
})

// PROFILE //

router.get("/profile", (req, res) => res.render("user/profile", { userInSession: req.session.currentUser }))

// LOGOUT //

router.post('/logout', (req, res, next) => {
    req.session.destroy(err => {
      if (err) next(err);
      res.redirect('/');
    });
  });



router.get("/main", (req, res) => res.render("user/profile", { userInSession: req.session.currentUser }))



module.exports = router

