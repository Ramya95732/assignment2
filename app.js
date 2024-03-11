const express = require('express')
const path = require('path')
const {open} = require('sqlite')
const sqlite3 = require('sqlite3')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')

const app = express()
app.use(express.json())
const dbPath = path.join(__dirname, 'twitterClone.db')
let db = null
const initialiserTheServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    })
    app.listen(3000, () => {
      console.log('Server Running at http://localhost:3000/')
    })
  } catch (e) {
    console.log(`DB Error: ${e.message}`)
  }
}
initialiserTheServer()

const gettingUserFollowingIds = async username => {
  const getFollowingPeoplebyUser = `
    SELECT following_user_id
    FROM follower INNER JOIN user ON user.user_id=follower.follower_user_id
    WHERE user.username='${username}'
  `
  const followingPeople = await db.all(getFollowingPeoplebyUser)
  const arrayOfIds = followingPeople.map(eachUser => eachUser.following_user_id)
  return arrayOfIds
}

const authenticationToken = (request, response, next) => {
  let jwtToken
  const authHeader = request.headers['authorization']
  if (authHeader !== undefined) {
    jwtToken = authHeader.split(' ')[1]
  }
  if (jwtToken) {
    jwt.verify(jwtToken, 'MY_SECRET_TOKEN', async (error, payload) => {
      if (error) {
        response.status(401)
        response.send('Invalid JWT Token')
      } else {
        request.username=payload.username
        request.userID=payload.userID
        next()
      }
    })
  } else {
        response.status(401)
        response.send('Invalid JWT Token')
  }
}

//API1
app.post('/register/', async (request, response) => {
  const {username, password, name, gender} = request.body

  const selectUserQuery = `SELECT * FROM user WHERE username='${username}'`
  const dbUser = await db.get(selectUserQuery)
  if (dbUser !== undefined) {
    response.status(400)
    response.send('User already exists')
  } else {
    if (password.length < 6) {
      response.status(400)
      response.send('Password is too short')
    } else {
      const hashedPassword = await bcrypt.hash(password, 10)
      const createUserQuery = `
            INSERT INTO user (username, password, name, gender)
            VALUES
            (
                '${username}',
                '${hashedPassword}',
                '${name}',
                '${gender}'
            )
        `
      await db.run(createUserQuery)
      response.send('User created successfully')
    }
  }
})

//API2
app.post('/login/', async (request, response) => {
  const {username, password} = request.body
  const selectUserQuery = `SELECT * FROM user WHERE username='${username}'`
  const dbUser = await db.get(selectUserQuery)

  if (dbUser === undefined) {
    response.status(400)
    response.send('Invalid user')
  } else {
    const comparedPswd = await bcrypt.compare(password, dbUser.password)
    if (comparedPswd === true) {
      const payload = {username: username}
      const jwtToken = jwt.sign(payload, 'MY_SECRET_TOKEN')
      response.send({jwtToken})
    } else {
      response.status(400)
      response.send('Invalid password')
    }
  }
})

//API3
app.get(
  '/user/tweets/feed/',
  authenticationToken,
  async (request, response) => {
    const {username} = request
    const followingPeopleIds = await gettingUserFollowingIds(username)
    const getTweetsQuery = `
        SELECT username, tweet, date_time as dateTime
        FROM user INNER JOIN tweet ON user.user_id=tweet.user_id
        WHERE user.user_id IN (${followingPeopleIds})
        ORDER BY date_time DESC
        LIMIT 4
  `
    const tweets = await db.all(getTweetsQuery)
    response.send(tweets)
  },
)

module.exports = app
