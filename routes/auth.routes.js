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
        res.redirect("/userProfile");
    } catch (error) {
        console.log("error", error)
    }        
})

router.get("/userProfile", (req, res) => res.render("auth/userProfile"))


module.exports = router