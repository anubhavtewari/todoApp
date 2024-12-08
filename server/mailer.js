const nodemailer = require('nodemailer')
const config = require('./config')

// create a transporter for sending email
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: config.email.user,
    pass: config.email.password,
  },
})

async function sendEmail(email, subject, body, callback) {
  // send email
  const result = await transporter.sendMail({
    to: email,
    subject,
    html: body,
  })
  console.log(result)

  // call the callback
  callback()
}

module.exports = {
  sendEmail,
}
