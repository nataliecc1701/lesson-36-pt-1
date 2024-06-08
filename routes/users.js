const express = require("express");
const jwt = require("jsonwebtoken");


const { SECRET_KEY } = require("../config");
const ExpressError = require("../expressError")
const User = require("../models/user")

const router = new express.Router();

/** GET / - get list of users.
 *
 * => {users: [{username, first_name, last_name, phone}, ...]}
 *
 **/

router.get("/", async function(req, res, next) {
    try {
        const results = await User.all();
        return res.json(results);
    } catch(err) {
        return next(err);
    }
})


/** GET /:username - get detail of users.
 *
 * => {user: {username, first_name, last_name, phone, join_at, last_login_at}}
 *
 **/

router.get("/:username", async function(req, res, next) {
    try {
        const user = await User.get(req.params.username);
        return res.json({user});
    } catch(err) {
        return next(err);
    }
})


/** GET /:username/to - get messages to user
 *
 * => {messages: [{id,
 *                 body,
 *                 sent_at,
 *                 read_at,
 *                 from_user: {username, first_name, last_name, phone}}, ...]}
 *
 **/

router.get("/:username/to", async function(req, res, next) {
    try {
        const results = await User.messagesTo(req.params.username);
        return res.json({messages : results});
    } catch(err) {
        return next(err);
    }
})

/** GET /:username/from - get messages from user
 *
 * => {messages: [{id,
 *                 body,
 *                 sent_at,
 *                 read_at,
 *                 to_user: {username, first_name, last_name, phone}}, ...]}
 *
 **/

router.get("/:username/from", async function(req, res, next) {
    try {
        const results = await User.messagesFrom(req.params.username);
        return res.json({messages : results});
    } catch(err) {
        return next(err);
    }
})

module.exports = router;