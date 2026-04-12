import exp from "express";
import {config} from "dotenv";
import {connect} from 'mongoose'
import {userApp} from "./apis/userapi.js"
import {adminApp} from "./apis/adminapi.js" 
import {authorApp} from "./apis/authorapi.js"
import {commonApp} from "./apis/commonapi.js"
import cookieParser from "cookie-parser"
import dotenv from "dotenv";
import cors from 'cors'
dotenv.config();

config();
const app=exp()
app.use(
  cors({
    origin: ["http://localhost:5173"],
    credentials:true  //enables to send the token back to clients
  })
);
app.use(cookieParser()) 
app.use(exp.json())
app.use("/user-api",userApp)
app.use("/admin-api",adminApp)
app.use("/author-api",authorApp)
app.use("/common-api",commonApp)
const port=process.env.PORT||5000
const connectdb=async()=>{
    try{
        await connect(process.env.DB_URL)
        console.log("DB connected")
        
        app.listen(port,()=>console.log("listening to port...."))

    }
    catch(err){
        console.log("err in db connection",err)
    }
}
connectdb()
app.use((req,res,next)=>{
    console.log(req.url)
    return res.status(404).json({message:`path ${req.url} is invalid`})
})
app.use((err,req,res,next)=>{   
   console.log(err.name)

   //validation error
   if(err.name==="ValidationError"){
      return res.status(400).json({message:"Error Occured",error:err.message})
   }
 //casterror
 if(err.name==="CastError"){
      return res.status(400).json({message:"Error Occured",error:err.message})
   }
   //send server side error 
   res.status(500).json({message:"error occured",error:err.message})
})