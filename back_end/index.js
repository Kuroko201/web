const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const User_data = require('./db_table.js');
const { name } = require('ejs');
const bcrypt = require('bcrypt');
const rateLimit = require("express-rate-limit");
const jwt = require('jsonwebtoken')
const { login_authentication } = require('./middle_ware/login_authentication.js')
const cookieParser = require('cookie-parser'); 

require('dotenv').config()

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(express.static('public')) // middleware, user can read the file for example: css, js, pdf
app.use(express.static(path.join(__dirname, '../public')))
app.use(express.urlencoded({ extended: true })); // middleware, to catch the data send by the user

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '../views'));

const PORT = process.env.PORT
const DB_URL = process.env.DB_URL

mongoose.connect(DB_URL).catch(()=>{
       console.log("connection fail!")
});

const db = mongoose.connection;
db.once('open',()=>{
       console.log("successfully connect to mongoose database")
       console.log('Database: ' + db.name)
})


const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, 
    message: {
        error: "Too many login attempts from this IP, please try again after 15 minutes"
    },
    statusCode: 429,
    skipSuccessfulRequests: true, 
});

/*
app.use((req,res,next)=>{
       console.log(`new visiters from : ${req.hostname}`);
       console.log(`going to path : ${req.path}`);
       next();
})
*/

app.get('/register', function (req, res) {
       res.render('register');
})

app.post('/register', async (req, res)=>{ // <form action="/login" method="POST"></form>
       const username = req.body.username;
       const password = req.body.password;
       if (username === "" && password === "" ){      
              res.status(400).render('register', { 
                     Null_name_Error: 'username cannot be null',
                     Null_password_Error: 'password cannot be null' 
              });
       }
       else if(username === ""){
              res.status(400).render('register', { 
                     Null_name_Error: 'username cannot be null' 
              });
       }
       else if(password === ""){
              res.status(400).render('register', { 
                     Null_password_Error: 'password cannot be null' 
              });
       }else{
              const find_username = await User_data.findOne({name : username});
              if(find_username){
              res.status(400).render( 'register', { duplicate_name_Error: "This name has already be registered by other's user"} );
              }
              else{
              console.log(username,password);
              res.send('Account registered successfully');
              const salt = await bcrypt.genSalt(13);
              const hashedPassword = await bcrypt.hash(password,salt);

              const user_data = new User_data({
                     name: username,
                     password: hashedPassword,
              });
              user_data.save();
              }
       }
})


app.get('/login', async(req,res)=>{
       res.render('login');
});

app.post('/login', loginLimiter, async(req,res)=>{
       const username = req.body.username;
       const password = req.body.password;
       const user = await User_data.findOne({name : username});
       
       if(!user){
              res.status(401).render('login', { 
                     usernameError: 'Invalid username' 
              });
       }
       else{
              const match = await bcrypt.compare(password, user.password);
              if (!match){
                     res.status(401).render('login', { 
                            passwordError: 'Invalid password' 
                     });
              }
              else{
                     const accessToken = jwt.sign( {username: username, role: "Guest"}, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '30m' })
                     const refreshToken = jwt.sign( {username: username, role: "Guest"}, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '7d' })
                     
                     res.cookie("accessToken", accessToken, {httpOnly: true} )
                     res.cookie("refreshToken", refreshToken, {httpOnly: true} )
                     res.status(200).redirect('/home_page')
              }
       }

})

app.get('/home_page', login_authentication, (req,res)=>{
       console.log(req.user)

       res.render('home_page', req.user);
})

app.get('/logout',(req,res)=>{
       res.redirect('login');
})

app.post('/logout',(req,res)=>{
       res.clearCookie('accessToken');
       res.clearCookie('refreshToken');
       res.status(200).send('Logout successfully')
})

app.get('/test', function (req, res) {
       res.render('test');
}) 

app.listen(PORT,()=>{
    console.log(`Listening server port: ${PORT}`);
})