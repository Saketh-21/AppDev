const router = require('express').Router();
const User = require('../model/User');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const {registerValidation,loginValidation} = require('../validation');
const { serializeUser } = require('passport');


router.post('/register', async (req, res) => {

//LET'S VALIDATE THE DATA BEFORE WE Add USER
     //const {error} = schema.validate(req.body);
     const {error} = registerValidation(req.body);
    if(error){return res.status(400).send(error.details[0].message)};

     //Check if user already exists in database
       const emailExist = await User.findOne({email: req.body.email});
       if(emailExist) return res.status(400).send('Email already exists');

      //HASH THE PASSWORD
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(req.body.password, salt);



 //Create a new user
     const user = new User({
        name: req.body.name,
        email: req.body.email,
        password: hashedPassword
       
     });

     try{
          const savedUser = await user.save();
          res.send({ user:user._id});
     }catch(err){
          res.status(400).send(err);
     }
});



//LOGIN
router.post('/login',async (req,res) => {
     //VALIDATE DATA OF USER
     const {error} = loginValidation(req.body);
     if(error){return res.status(400).send(error.details[0].message)};

     //Check if email already exists in database
     const user = await User.findOne({email: req.body.email});
     if(!user) return res.status(400).send('Email or passwird is wrong');

     //PASSWORD IS CORRECT
      const validPass = await bcrypt.compare(req.body.password, user.password);
      if(!validPass) return res.status(400).send('Invalid password');



      //Create and assign a token
      const token = jwt.sign({_id: serializeUser._id},process.env.TOKEN_SECRET);
      res.header('auth-token', token).send(token);

      res.send('Logged in!');
});



module.exports = router;