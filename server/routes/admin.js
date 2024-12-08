const express = require('express')
const db = require('../db')
const utils = require('../utils')
const crypto = require('crypto-js')
const jwt = require('jsonwebtoken')
const config = require('../config')
const mailer = require('../mailer')

const router = express.Router()

router.post('/login', (request, response) => {
  const { email, password } = request.body

  const statement = `
      SELECT id, firstName, lastName
      FROM Admin
      WHERE email = ? AND password = ?
    `

  // encrypt the password
  const encryptedPassword = String(crypto.MD5(password))

  db.pool.query(statement, [email, encryptedPassword], (error, users) => {
    // if error exists
    if (error) {
      response.send(utils.createError(error))
    } else {
      // query got successfully executed

      // check if user exists
      if (users.length == 0) {
        // user does not exist
        response.send(utils.createError('admin does not exist'))
      } else {
        // at least one user exists
        // send the users data to the client

        const { id, firstName, lastName } = users[0]

        // create a payload
        const payload = { id, firstName, lastName, email }

        // create a token
        const token = jwt.sign(payload, config.secrete)

        response.send(
          utils.createSuccess({
            token,
            firstName,
            lastName,
          })
        )
      }
    }
  })
})

module.exports = router
