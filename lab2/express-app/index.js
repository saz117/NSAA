const express = require('express')
const logger = require('morgan')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')
const JwtStrategy = require('passport-jwt').Strategy

const sqlite3 = require('better-sqlite3');

const jwtSecret = require('crypto').randomBytes(16) // 16*8=256 random bits 

//----------------------
// encryption config
const scryptPbkdf = require('scrypt-pbkdf')
const scryptCODEC = require('base64-arraybuffer')

const global_salt = scryptPbkdf.salt(32)
const scryptParams = {
  N: 2097152, //2097152  //16384
  r: 8,
  p: 2
}
const derivedKeyLength = 32

//----------------------

const app = express()
const port = 3000

let sql;

app.use(logger('dev'))


//connect to DB
const db = new sqlite3("./test.db", {"fileMustExist": true})
/*
//create table :
sql = `CREATE TABLE users (id INTEGER PRIMARY KEY, username, password)`;
db.run(sql);
*/

// //drop table :
// db.run("DROP TABLE users");

//insert data into table :

async function key_func(pass, salt){
	const password = pass
	const key_array_buffer = await scryptPbkdf.scrypt(password, salt, derivedKeyLength, scryptParams)
	const key = scryptCODEC.encode(key_array_buffer)
	return key
}

async function change_salt(salt, flag){
	let new_salt = null;
	if (flag){
		new_salt = scryptCODEC.decode(salt);
	}
	else{
		new_salt = scryptCODEC.encode(salt);
	}
	return new_salt
}

async function getIDfromuser(db, username) {
        sql = `SELECT * FROM users WHERE username=?`;
        return db.prepare(sql).all(username)
}

async function get_info_from_user(db, userID) {
        sql = `SELECT * FROM users WHERE id=?`;
        return db.prepare(sql).all(userID)
}

async function func(username) {
	await new Promise(r => setTimeout(r, 1000))
	console.log("-----------")
	user = await getIDfromuser(db, username)
	user_info = await get_info_from_user(db, user[0].id)
	//console.log(user[0].id)
	//console.log(user_info[0].password)
	return user_info
}


/*
Configure the local strategy for using it in Passport.
The local strategy requires a `verify` function which receives the credentials
(`username` and `password`) submitted by the user.  The function must verify
that the username and password are correct and then invoke `done` with a user
object, which will be set at `req.user` in route handlers after authentication.
*/
passport.use('username-password', new LocalStrategy(
  {
    usernameField: 'username',  // it MUST match the name of the input field for the username in the login HTML formulary
    passwordField: 'password',  // it MUST match the name of the input field for the password in the login HTML formulary
    session: false // we will store a JWT in the cookie with all the required session data. Our server does not need to keep a session, it's going to be stateless
  },
  async function (username, password, done) {
    info = await func(username)
    old_salt = await change_salt(info[0].salt, true)
    key_result = await key_func(password, old_salt) //old_salt
    //new_salt = await change_salt(global_salt, false)
    console.log(info)
    console.log(key_result)
    //old_salt = await change_salt(info[0].salt, false)
    //console.log(old_salt)
    
    if (username === info[0].username && key_result === info[0].password) {
      const user = { 
        username: username,
        description: 'the only user that deserves to get to this server'
      }
      return done(null, user) // the first argument for done is the error, if any. In our case there is no error, and so we pass null. The object user will be added by the passport middleware to req.user and thus will be available there for the next middleware and/or the route handler 
    }
    return done(null, false)  // in passport returning false as the user object means that the authentication process failed. 
  }
))

passport.use('register-user', new LocalStrategy(

  async function (username, password, done) {
  	key_result = await key_func(password)
  	db.prepare('INSERT INTO USERS (username, password) VALUES(?, ?)').run('walrus',key_result.toString())
   	return done(null, true)
  } 
))

app.use(express.urlencoded({ extended: true })) // needed to retrieve html form fields (it's a requirement of the local strategy)

app.use(passport.initialize())  // we load the passport auth middleware to our express application. It should be loaded before any route.

app.use(cookieParser())

passport.use('jwtCookie', new JwtStrategy(
  {
    jwtFromRequest: (req) => {
      if (req && req.cookies) { return req.cookies.jwt }
      return null
    },
    secretOrKey: jwtSecret
  },
  function (jwtPayload, done) {
    if (jwtPayload.sub) {
      const user = { 
        username: jwtPayload.sub,
        description: 'one of the users that deserve to get to this server',
        role: jwtPayload.role ?? 'user'
      }
      return done(null, user)
    }
    return done(null, false)
  }
))


app.get('/',
  passport.authenticate(
    'jwtCookie',
    { session: false, failureRedirect: '/login' }
  ),
  (req, res) => {
    res.send(`Welcome to your private page, ${req.user.username}!`) // we can get the username from the req.user object provided by the jwtCookie strategy
  }
)

app.get('/login',
  (req, res) => {
    res.sendFile('login.html', { root: __dirname })  // we created this file before, which defines an HTML form for POSTing the user's credentials to POST /login
  }
)

app.get('/register', passport.authenticate('register-user', { failureRedirect: '/', session: false }))

app.post('/login', 
  passport.authenticate('username-password', { failureRedirect: '/login', session: false }), // we indicate that this endpoint must pass through our 'username-password' passport strategy, which we defined before
  (req, res) => { 
    // This is what ends up in our JWT
    const jwtClaims = {
      sub: req.user.username,
      iss: 'localhost:3000',
      aud: 'localhost:3000',
      exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
      role: 'user' // just to show a private JWT field
    }

    // generate a signed json web token. By default the signing algorithm is HS256 (HMAC-SHA256), i.e. we will 'sign' with a symmetric secret
    const token = jwt.sign(jwtClaims, jwtSecret)

    // From now, just send the JWT directly to the browser. Later, you should send the token inside a cookie.
    res.cookie('jwt', token, { httpOnly: true, secure: true }) // Write the token to a cookie with name 'jwt' and enable the flags httpOnly and secure.
    res.redirect('/')
    
    // And let us log a link to the jwt.io debugger for easy checking/verifying:
    console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
    console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
  }
)

app.get('/logout', function (req, res) {
  res.clearCookie('jwt');
  res.redirect('/');
});

app.use(function (err, req, res, next) {
  console.error(err.stack)
  res.status(500).send('Something broke!')
})

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`)
})
