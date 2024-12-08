const express = require('express')
const db = require('../db')
const utils = require('../utils')
const crypto = require('crypto-js')
const jwt = require('jsonwebtoken')
const config = require('../config')
const mailer = require('../mailer')

const router = express.Router()

router.post('/register', (request, response) => {
  const { firstName, email, phone, password, lastName } = request.body

  // generate a random number for OTP
  const otp = Math.floor(Math.random() * 1000000)

  const statement = `
    INSERT INTO User (
        firstName, lastName, email, password, phone, verificationOTP
    ) VALUES (?, ?, ?, ?, ?, ?)
  `

  // encrypt the password
  const encryptedPassword = String(crypto.MD5(password))

  db.pool.execute(
    statement,
    [firstName, lastName, email, encryptedPassword, phone, otp],
    (error, result) => {
      if (!error) {
        response.send(utils.createResult(error, result))
      } else {
        response.send(utils.createError(error))
      }
    }
  )
})

router.post('/login', (request, response) => {
  const { email, password } = request.body

  const statement = `
    SELECT id, firstName, lastName, phone, isActive 
    FROM User
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
        response.send(utils.createError('user does not exist'))
      } else {
        // at least one user exists
        // send the users data to the client

        const { id, firstName, lastName, phone, isActive } = users[0]

        // check if the user is active
        if (isActive) {
          // create a payload
          const payload = { id, firstName, lastName, email }

          // create a token
          const token = jwt.sign(payload, config.secrete)

          response.send(
            utils.createSuccess({
              token,
              firstName,
              lastName,
              phone,
            })
          )
        } else {
          // user is not active
          response.send(
            utils.createError(
              'You can not login as your account is not active. Please contact administrator.'
            )
          )
        }
      }
    }
  })
})

router.patch('/verify', (request, response) => {
  const { email, otp } = request.body

  // check if users otp is matching with the DB record
  const statement = `
    SELECT id
    FROM User
    WHERE email = ? AND verificationOTP = ?
  `
  db.pool.query(statement, [email, otp], (error, users) => {
    if (error) {
      response.send(utils.createError(error))
    } else {
      // check if user exists
      if (users.length == 0) {
        // user with email and otp does not exist
        response.send(utils.createError('Invalid OTP or email'))
      } else {
        // get the users id
        const { id } = users[0]

        // user found with email and right OTP
        const statement2 = `
          UPDATE User
          SET isActive = 1
          WHERE id = ?
        `
        db.pool.execute(statement2, [id], (error, result) => {
          response.send(utils.createResult(error, result))
        })
      }
    }
  })
})

router.put('/profile', (request, response) => {
  const { firstName, lastName, phone } = request.body
  const statement = `
    UPDATE User
    SET firstName = ?, lastName = ?, phone = ?
    WHERE id = ?
  `
  db.pool.execute(
    statement,
    [firstName, lastName, phone, request.user['id']],
    (error, result) => {
      response.send(utils.createResult(error, result))
    }
  )
})

router.put('/update-password', (request, response) => {
  const { password } = request.body

  // encrypt the password
  const encryptedPassword = String(crypto.MD5(password))

  const statement = `
    UPDATE User
    SET password = ?
    WHERE id = ?
  `
  db.pool.execute(
    statement,
    [encryptedPassword, request.user['id']],
    (error, result) => {
      response.send(utils.createResult(error, result))
    }
  )
})

router.get('/profile', (request, response) => {
  const statement = `
    SELECT firstName, lastName, email, phone
    FROM User
    WHERE id = ?
  `
  db.pool.query(statement, [request.user['id']], (error, users) => {
    if (error) {
      response.send(utils.createError(error))
    } else {
      if (users.length == 0) {
        response.send(utils.createError('user does not exist'))
      } else {
        response.send(utils.createSuccess(users[0]))
      }
    }
  })
})

router.get('/all-users', (request, response) => {
  const statement = `
    SELECT id, firstName, lastName, email, phone, isActive
    FROM User
  `
  db.pool.query(statement, (error, users) => {
    response.send(utils.createResult(error, users))
  })
})

router.patch('/make-active/:id', (request, response) => {
  const { id } = request.params

  const statement = `
    UPDATE User
    SET isActive = 1
    WHERE id = ?
  `
  db.pool.query(statement, [id], (error, items) => {
    response.send(utils.createResult(error, items))
  })
})

router.patch('/make-inactive/:id', (request, response) => {
  const { id } = request.params

  const statement = `
    UPDATE User
    SET isActive = 0
    WHERE id = ?
  `
  db.pool.query(statement, [id], (error, items) => {
    response.send(utils.createResult(error, items))
  })
})

module.exports = router
