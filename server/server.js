const express = require('express')
const jwt = require('jsonwebtoken')
const config = require('./config')
const utils = require('./utils')
const cors = require('cors')

const app = express()

// enable the CORS so that other applications can call the APIs
app.use(cors())

app.use(express.json())

// middleware to implement JWT authorization
app.use((request, response, next) => {
  if (
    request.url == '/user/register' ||
    request.url == '/user/login' ||
    request.url == '/admin/login' ||
    request.url == '/user/verify'
  ) {
    // skip checking the token
    next()
  } else {
    // read the token
    const token = request.headers['token']

    // check if token is available
    if (!token) {
      response.send(utils.createError('missing token'))
    } else {
      try {
        // validate the token
        const payload = jwt.verify(token, config.secrete)

        // add the payload in the request
        // since the same request will be forwarded to the
        // next function, every function/route in the application
        // can access the payload using request.user key
        request.user = payload

        // call the next function
        next()
      } catch (ex) {
        response.send(utils.createError('invalid token'))
      }
    }
  }
})

// add the routes
const userRouter = require('./routes/user')
const todoRouter = require('./routes/todo')
const adminRouter = require('./routes/admin')

app.use('/user', userRouter)
app.use('/todo', todoRouter)
app.use('/admin', adminRouter)

app.listen(4000, '0.0.0.0', () => {
  console.log(`server started on port 4000`)
})
