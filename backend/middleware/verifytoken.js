import jwt from "jsonwebtoken"
import dotenv from "dotenv";
const {verify} = jwt;
dotenv.config();
export const verifytoken=(...allowedrole)=>{
   return (req,res,next)=>{
    //get token from cookie
    try{
    const token = req.cookies?.token;
    console.log(token)
    //check token exists or not 
    if(!token){
        return res.status(401).json({message:"please login first"})
    }
    //validate  token
    let decoded = verify(token,process.env.SECRET_KEY);
    //check the role is same as role in decoded token
    if(!allowedrole.includes(decoded.role)){
        return res.status(403).json({message:"you are unauthorized"})
    }
    //add decoded token 
    req.user=decoded;
    next()
    }
   catch (err) {
        return res.status(401).json({ message: "Invalid or expired token" });
    }
   }
}

