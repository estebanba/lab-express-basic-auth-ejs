const { Router } = require("express");
const router = new Router();

const bcryptjs = require("bcryptjs");
const saltRounds = 10
const salt = bcryptjs.genSaltSync(saltRounds)

const User = require("../models/User.model");

router.get("/signup", (req, res) => {
    res.render("auth/signup")
} )

router.post("/signup", async (req, res) => {
    try {
        const { username, password } = req.body;
        const salt = await bcryptjs.genSalt(saltRounds);
        const hashedPassword = await bcryptjs.hash(password, salt);
        await User.create({ username, password: hashedPassword });
        res.render("auth/userProfile", {username});
    } catch (error) {
        console.log("error", error)
    }        
})

///LOGIN////
router.get("/login", (req, res) => res.render("auth/login"))

router.post("/login", async (req, res, next) => {
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
        console.log(userFromDB);
        res.render("auth/userProfile", userFromDB);
    } else {
        res.render("auth/login", {
            errorMessage: "Wrong password, biatch!"
        });
    }
})

module.exports = router

