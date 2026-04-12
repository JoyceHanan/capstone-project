1. create json package
2. create .env file 
3. create express app 
4. CONNECT TO DB
5. Define schema and create models
 - UserTypeSchema
     firstname
     lastname
     email(unique)
     password
     role
     profileImageURL
     isUserActive [soft delete (hiding the data , it can be restored )]
 
 - ArticleSchema 
     author
     title
     category
     content
     comments 
     isArticleActive
6. implement APIs
7. create common apis 