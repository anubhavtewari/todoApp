const express = require('express')
const db = require('../db')
const utils = require('../utils')

const router = express.Router()

router.get('/my', (request, response) => {
  const statement = `
    SELECT id, title, details, createdTimestamp, isPublic
    FROM TodoItem
    WHERE userId = ?
  `
  db.pool.query(statement, [request.user['id']], (error, items) => {
    response.send(utils.createResult(error, items))
  })
})

router.get('/search/:text', (request, response) => {
  const { text } = request.params

  const statement = `
    SELECT id, title, details, createdTimestamp
    FROM TodoItem
    WHERE isPublic = 1 AND (title LIKE '%${text}%' OR details LIKE '%${text}%')
  `
  db.pool.query(statement, (error, items) => {
    response.send(utils.createResult(error, items))
  })
})

router.post('/', (request, response) => {
  const { title, details } = request.body

  const statement = `
        INSERT INTO TodoItem (
            title, details, userId
        ) VALUES (?, ?, ?)
      `
  db.pool.execute(
    statement,
    [title, details, request.user['id']],
    (error, result) => {
      response.send(utils.createResult(error, result))
    }
  )
})

router.delete('/:itemId', (request, response) => {
  const { itemId } = request.params

  const statement = `
    DELETE FROM TodoItem
    WHERE userId = ? AND id = ?
  `
  db.pool.execute(statement, [request.user['id'], itemId], (error, result) => {
    response.send(utils.createResult(error, result))
  })
})

router.get('/public', (request, response) => {
  const statement = `
    SELECT id, title, details, createdTimestamp 
    FROM TodoItem
    WHERE isPublic = 1
  `
  db.pool.query(statement, [request.user['id']], (error, items) => {
    response.send(utils.createResult(error, items))
  })
})

router.patch('/make-public/:id', (request, response) => {
  const { id } = request.params

  const statement = `
    UPDATE TodoItem
    SET isPublic = 1
    WHERE id = ? AND userId = ?
  `
  db.pool.query(statement, [id, request.user['id']], (error, items) => {
    response.send(utils.createResult(error, items))
  })
})

router.patch('/make-private/:id', (request, response) => {
  const { id } = request.params

  const statement = `
    UPDATE TodoItem
    SET isPublic = 0
    WHERE id = ? AND userId = ?
  `
  db.pool.query(statement, [id, request.user['id']], (error, items) => {
    response.send(utils.createResult(error, items))
  })
})

module.exports = router
