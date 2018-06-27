/*
This is back-end authorization; it can be used to protect individual routes
from being hit either directly or through the front end. We'd want to
check the user's login status on the front end, too, possibly to hide
parts of the interface from unauthenticated users.

perryd@bu.edu @perrydBUCS
 */
const jwt = require('jsonwebtoken')
const jwtConfig = require('../Config/jwtConfig')
const User = require('../models/UserWithCrypto')


const checkAuthorization = function (req, res, next) {

    //See if there is a token on the request...if not, reject immediately
    //
    const userJWT = req.cookies.twitterAccessJwt
    if (!userJWT) {
        res.send(401, 'Invalid or missing authorization token')
    }
    //There's a token; see if it is a valid one and retrieve the payload
    //
    else {
        const userJWTPayload = jwt.verify(userJWT, jwtConfig.jwtSecret)
        if (!userJWTPayload) {
            //Kill the token since it is invalid
            //
            res.clearCookie('twitterAccessJwt')
            res.send(401, 'Invalid or missing authorization token')
        }
        else {
            //There's a valid token...see if it is one we have in the db as a logged-in user
            //
            User.findOne({'twitterAccessToken': userJWTPayload.twitterAccessToken})
                .then(function (user) {
                    if (!user) {
                        res.send(401, 'User not currently logged in')
                    }
                    else {
                        req.user = user
                        console.log('Valid user:', user.name)
                        next()
                    }

                })
        }
    }
}

module.exports = checkAuthorization