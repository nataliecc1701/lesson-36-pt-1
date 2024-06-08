const express = require("express");
const jwt = require("jsonwebtoken");


const { SECRET_KEY } = require("../config");
const ExpressError = require("../expressError")
const Message = require("../models/message");
const { ensureCorrectUser, ensureLoggedIn } = require("../middleware/auth");

const router = new express.Router();

/** GET /:id - get detail of message.
 *
 * => {message: {id,
 *               body,
 *               sent_at,
 *               read_at,
 *               from_user: {username, first_name, last_name, phone},
 *               to_user: {username, first_name, last_name, phone}}
 *
 * Make sure that the currently-logged-in users is either the to or from user.
 *
 **/

router.get("/:id", ensureLoggedIn, async function(req, res, next) {
    try {
        const msg = await Message.get(req.params.id);
        if (req.user.username !== msg.from_user.username &&
            req.user.username !== msg.to_user.username) {
                return next(new ExpressError("Unauthorized", 401))
        }
        else {
            return res.json({message: msg})
        }
    } catch (err) {
        return next(err)
    }
})

/** POST / - post message.
 *
 * {to_username, body} =>
 *   {message: {id, from_username, to_username, body, sent_at}}
 *
 **/

router.post("/", ensureLoggedIn, async function(req, res, next) {
    try {
        const {to_username, body} = req.body;
        if (!to_username || !body) {
            return next(new ExpressError("Message needs to_username and body", 400))
        }
        const from_username = req.user.username;
        const message = await Message.create({from_username, to_username, body});
        return res.json({message})
    } catch (err) {
        return next(err)
    }
})

/** POST/:id/read - mark message as read:
 *
 *  => {message: {id, read_at}}
 *
 * Make sure that the only the intended recipient can mark as read.
 *
 **/

router.post("/:id/read", ensureLoggedIn, async function(req, res, next) {
    try {
        let message = await Message.get(req.params.id);
        if (req.user.username !== message.to_user.username) {
            return next(new ExpressError("Only recipient can mark messages read!", 401))
        }
        else {
            message = await Message.markRead(req.params.id)
            return res.json({message})
        }
    } catch (err) {
        return next(err)
    }
})

module.exports = router;