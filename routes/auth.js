const express = require("express");
const jwt = require("jsonwebtoken");


const { SECRET_KEY } = require("../config");
const ExpressError = require("../expressError")
const User = require("../models/user")

const router = new express.Router();


/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/

router.post("/login", async function(req, res, next) {
    const {username, password} = req.body;
    if (await User.authenticate(username, password)) {
        const token = jwt.sign({username}, SECRET_KEY);
        return res.json({token})
    }
    else {
        const err = new ExpressError("Invalid username/password", 400);
        return next(err);
    }
})


/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */

router.post("/register", async function(req, res, next) {
    try {
        const {username, password, first_name, last_name, phone} = req.body;
        let newUser = await User.register({username, password, first_name, last_name, phone});
        newUser = await User.updateLoginTimestamp(username);
        const token = jwt.sign({username}, SECRET_KEY);
        return res.json({token})
    } catch (e) {
        return next(e)
    }
})

module.exports = router;