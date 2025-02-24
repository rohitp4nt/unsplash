const express=require('express');
const app =express();
require('dotenv').config();


const userModel=require('./models/user');

app.set('view engine', 'ejs');

app.use(express.json());
app.use(express.urlencoded({extended: true}));


const path= require('path');
app.use(express.static(path.join(__dirname,'public')));

const cookieParser=require('cookie-parser');
app.use(cookieParser());
 




app.get('/',(req, res) =>{
    
    res.render('login');
})

app.get('/sign-up',(req,res) => {
    res.render('sign-up');
})
 
app.get('/profile',jwtAuthentication,(req,res)=>{
    
    res.render('login');
})


const bcrypt=require('bcrypt');
const jwt=require('jsonwebtoken');

app.post('/pinterest',fetchUnsplash ,async (req,res)=> {
    
    try {
        if(!req.body.firstName){
            console.log(!req.body.firstName);
            
            console.log("username & password");
            
            const userObject = await userModel.findOne({email: `${req.body.email}`});
             
            try {
                
                if(userObject != null && bcrypt.compareSync(`${req.body.password}`, userObject.password)){
                    var token = jwt.sign({ email :  `${req.body.email}` }, 'some-secret-string');
                
                    res.cookie('JWTcookie', token);
                    console.log('b');

                    res.render('pinterest' ,{obj : req.unsplashObjArray ,userDetail: { firstName: `${userObject.firstName}`,
                    lastName: `${userObject.lastName}`} });
                }else{
                
                    res.send('user is not available');
                } 
            } catch (error) {
                console.log("error 1");
                
            }

        }else{
           
            try {
                    console.log("create user");
                    
                const userObj= await userModel.findOne({email: `${req.body.email}`})
    
                if(userObj == null){
                    

                    let {firstName, lastName, email, password}= req.body;
                
                    bcrypt.genSalt( 10, function(err, salt) {
                        bcrypt.hash(password, salt,async function(err, hash){
                            const userDetail=await userModel.create({
                                firstName,
                                lastName,
                                email,
                                password: hash
                            }) 
                            var token = jwt.sign({ email :  `${req.body.email}` }, 'some-secret-string');
                
                            res.cookie('JWTcookie', token);

                            res.render('pinterest',{ obj : req.unsplashObjArray,
                                userDetail: { firstName: firstName,
                                               lastName: lastName}
                                            } );
                                        
                                        
                        });
                    });
                }else{
                    console.log(userObj);
                
                    res.send('user already exist');
                }

            } catch (error) {
                console.log('error 2');
                
            }
    
            
        }
    } catch (error) {
        console.log("error 3");
        
    }
    

})

app.get('/home', jwtAuthentication ,(req,res) =>{

    res.render('home',{userDetail: null});
})
  


function jwtAuthentication(req,res,next){
    try {
        
        const token=req.cookies.JWTcookie;
        
        if(!token){
            next();
        }else{
            
            jwt.verify(token, 'some-secret-string',async function(err, decoded) {
            
                const userobj = await userModel.findOne({email: decoded.email});

                if( !userobj ){
                    res.redirect('/pineterest-guest')
                }else{ 
                    console.log('user is authrosize');
                    
                    // this is important req.k="kk", means we are adding a k variable to the req and we can access this k variable by using req.k here jwtAuthentication function and also in the req of where this this function jwtAuthentication is called ; means in our case in req of '/home' route . 
                    req.userObj;
                    res.render('profile', {userObj: userobj});
                }


            
            });
        
        }

    } catch (error) {
        console.log('error 4');
        
    }
    
}

app.get('/pinterest-guest',fetchUnsplash,(req,res) =>{
    res.render('pinterest' , {obj : req.unsplashObjArray ,userDetail : null} );
})


const { createApi } = require('unsplash-js');
const fetch = require('node-fetch'); // Required for environments that don't have a built-in fetch

const unsplash = createApi({
    // accessKey: [process.env.ACCESS_KEY]
    // OR
    accessKey:process.env.ACCESS_KEY 
});

async function fetchUnsplash(req,res,next) {
    try {
        const response = await unsplash.photos.list({ page: 1, perPage: 50 });

        req.unsplashObjArray=response.response.results;
        console.log('images are fetched');
        
        next();
        
    } catch (error) {
        console.error('Error fetching data from Unsplash:', error.message);
    }
}

 


app.get('/log-out',(req,res)=> {
    
    res.clearCookie('JWTcookie');
    res.send('log-out');
})



const mongoose = require('mongoose'); 
const { log } = require('console');
async function dropAllCollections() {
    try {
        // Connect to the MongoDB database
        await mongoose.connect(`${process.env.MONGODB_URL/unsplashUser}`, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
        });
        console.log('Connected to MongoDB');

        // Get all collections in the database
        const collections = await mongoose.connection.db.collections();

        // Drop each collection
        for (let collection of collections) {
            try {
                await collection.drop();
                console.log(`Dropped collection: ${collection.collectionName}`);
            } catch (error) {
                // Ignore errors for collections that have already been dropped
                if (error.message === 'ns not found') continue;
                console.error(`Error dropping collection ${collection.collectionName}:`, error);
            }
        }

        console.log('All collections dropped');
        next();
    } catch (error) {
        console.error('Error connecting to MongoDB:', error);
    } finally {
        // Close the database connection
        await mongoose.connection.close();
        console.log('Connection closed');
    }
}


 
app.get('/delete', async (req, res) => {
     
    // Run the function to drop all collections
    dropAllCollections();

});
 
 //demo

app.get('/text',print,(req,res) => {
    
}) 
function print(req,res,next){
    
    return res.send(`${req.n}`)
}

if (!process.env.VERCEL) {
    // This means we’re NOT running on Vercel
    const port = process.env.PORT || 3001;
    app.listen(port, () => {
      console.log(`Local server is listening on port ${port}`);
    });
}

