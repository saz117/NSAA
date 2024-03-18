const express = require('express')
const logger = require('morgan')

const app = express()
const port = 3000

app.use(logger('dev'))

app.get('/', (req, res) => {
  res.send('hello world')
})

app.get('/user', (req, res) => {
  const user = {
    name: 'walrus',
    description: 'it is what it is'
  }
  res.json(user)
})

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`)
})
