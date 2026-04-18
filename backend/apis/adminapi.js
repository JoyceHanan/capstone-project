import exp from 'express'
import { verifytoken } from '../middleware/verifytoken.js'
import { ArticleModel } from '../models/articlemodel.js'
import { UserModel } from '../models/usermodel.js'
export const adminApp=exp.Router()
//login completed in common api 
//view all articles
adminApp.get("/articles",verifytoken("ADMIN"),async(req,res)=>{
    const articles=await ArticleModel.find()
    res.status(200).json({message:"all articles are as follows",payload:articles})
})
//view all users
adminApp.get("/users",verifytoken("ADMIN"),async(req,res)=>{
    const users=await UserModel.find()
    res.status(200).json({message:"all users are as follows",payload:users})
})
//block and activate user
adminApp.patch("/user/:id",verifytoken("ADMIN"),async(req,res)=>{
    const {_id,isActive}=req.body
    const user=await UserModel.findById(_id)
    if(!user){
        return res.status(404).json({message:"user not found"})
    }
    if(user.isActive===isActive){
        return res.status(200).json({message:"user already in same state"})
    }
    user.isActive=isActive
    await user.save()
    res.status(200).json({message:"user status updated",payload:user})
})
