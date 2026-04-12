import { Schema,model,Types } from "mongoose";
const commentSchema=new Schema({
    //comment:" ",user:" "
    user:{
        type:Types.ObjectId,
        ref:"user",
        required:[true,"User ID required"]
    },
    comment:{
        type:String,
        required:[true,"Enter Comments"]      
    }
})
 const articleSchema=new Schema({
     author:{
        type:Types.ObjectId,
        ref:"user",
        required: [true,"Author is required"]
     },
     title:{
        type:String,
        required:[true,"Title required"]
     },
     category:{
        type:String,
        required:[true,"Category required"],
     },
      content:{
        type:String,
        required:[true,"content required"],
     },
     comments: [{ type:commentSchema, default: [] }],
     isArticleActive:{
        type:Boolean,
        default:true
     }
 },{
    timestamps:true,
    versionKey:false,
    strict:"throw"
 })
 export const ArticleModel=model("article",articleSchema)