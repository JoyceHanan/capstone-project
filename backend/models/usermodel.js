import { Schema,model } from "mongoose";
const userSchema=new Schema({
    firstName:{
        type:String,
        required:[true,"First Name is required"]
    },
    lastName:{
        type:String
    },
    email:{
      type:String,
      required:[true,"email required"],
      unique:[true,"Email Already Registered"]
    },
    password:{
        type:String,
        required:[true,"password is required"]
    },
    role:{
        type:String,
        enum:["USER","AUTHOR","ADMIN"],
        required:[true,"{Value} invalid"]
    },
    profileImageUrl:{
        type:String
    },
    isUserActive:{
        type:Boolean,
        default:true
    }
},{
    timestamps:true,
    versionKey:false,
    strict:"throw"
});

export const UserModel=model("user",userSchema)