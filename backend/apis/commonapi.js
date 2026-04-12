import exp from "express";
import { UserModel } from "../models/usermodel.js";
import {hash,compare} from 'bcryptjs' //IF ANY FUNCTION NAME ENDS WITH SYNC ITS SYNCHRONUS METHOD
import jwt from 'jsonwebtoken'
import {config} from 'dotenv'
import { verifytoken } from "../middleware/verifytoken.js";
export const commonApp=exp.Router()
const {sign}=jwt
//route for regiter(USER,AUTHOR)
commonApp.post("/common",async(req,res)=>{
   let allowedRoles=["USER","AUTHOR"]
    const newUser=req.body
    //check role 
    // we can search using includes method ex:[1,2,3,4].includes(3) -> true
    if(!allowedRoles.includes(newUser.role)){
      return res.status(400).json({message:"invalid role"})
    }
      //hash password
      newUser.password=await hash(newUser.password,12)
    // create user 
    const newUserDoc=new UserModel(newUser)
  //save document
  await newUserDoc.save()
  res.status(201).json({message:"user created"})
})
//route for login(USER,AUTHOR,ADMIN) login == creating token
commonApp.post("/login",async(req,res)=>{
  console.log(req.body)
  //get user cred from req body
  const {email, password} = req.body;
  let user = await UserModel.findOne({email:email})
  if(!user){
    return res.status(400).json({message:"user not found"})
  }
  let result = await compare(password,user.password)
   if(!result){
       return res.status(400).json({message:"password invalid "})
    }
    let signedtoken=sign({id:user._id,email:user.email,role:user.role},process.env.SECRET_KEY,{expiresIn:"2w"})
    res.cookie("token",signedtoken,{                //if normal cookie client side server can read it
      httpOnly:true,
      sameSite:"lax",
      secure:false
})//remove password from user doc
let userObj=user.toObject()
delete userObj.password
res.status(200).json({message:"login successful",payload:userObj})
})
//route for logout == removing token
commonApp.get("/logout",async(req,res)=>{
  res.clearCookie("token",{
     httpOnly:true,
      sameSite:"lax",
      secure:false
  })
  res.status(200).json({message:"logout successful"})
})
//Page refresh
commonApp.get("/check-auth",verifytoken("USER","AUTHOR","ADMIN"),(req,res)=>{
  res.status(200).json({
    message:"authenticated",
    payload:req.user,
  })
})
//to change the password 
commonApp.put("/password",verifytoken("USER","AUTHOR","ADMIN"),async(req,res)=>{
  let {newpassword,email} = req.body
  const user=req.user
  if(user.email!==email){
    return res.status(400).json({message:"email mismatch"})
  }
  //get user from DB
  const userDB = await UserModel.findOne({email})
  //check new password same as old
  let result = await compare(newpassword,userDB.password)
  if(result){
    return res.status(400).json({message:"current password and new password cannot be same"})
  }
  //hash new password
  newpassword = await hash(newpassword,12)
  await UserModel.findOneAndUpdate( {email:email}, {password:newpassword})
  res.status(200).json({message:"password updated successfully"})
})