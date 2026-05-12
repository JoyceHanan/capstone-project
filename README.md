# 📝 Capstone Project — Blog & Article Publishing Platform

A full-stack blog and article publishing platform with **role-based access control**, built as a capstone project for the Advanced Training Program. Users can register, publish articles, leave comments, and manage content based on their assigned roles (Admin, Author, User).

🔗 **Live Demo:** [capstone-project-2vlt.vercel.app]((https://capstone-project-2vlt.vercel.app/))

---

## ✨ Features

- **Role-Based Access Control** — Three distinct roles with different permissions:
  - 🛡️ **Admin** — Full control over users and articles, including soft-delete management
  - ✍️ **Author** — Create, edit, and manage their own articles
  - 👤 **User** — Browse articles and leave comments
- **User Management** — Registration, login, profile images, and soft-delete (deactivation without data loss)
- **Article System** — Full CRUD operations with categories, comments, and active/inactive status
- **RESTful API** — Clean, modular Express.js backend with dedicated route files per role
- **Modern Frontend** — React + Vite SPA with state management and component-based architecture

---

## 📁 Project Structure

```
capstone-project/
├── backend/                    # Express.js REST API server
│   ├── apis/                   # Route handlers organized by role
│   │   ├── adminapi.js         # Admin endpoints (user & article management)
│   │   ├── authorapi.js        # Author endpoints (article CRUD)
│   │   ├── commonapi.js        # Shared endpoints (login, register)
│   │   └── userapi.js          # User endpoints (browse, comment)
│   ├── config/                 # Database connection configuration
│   ├── middleware/              # Authentication & authorization middleware
│   ├── models/                 # Mongoose data models
│   │   ├── articlemodel.js     # Article schema (title, category, content, comments)
│   │   └── usermodel.js        # User schema (name, email, role, profile image)
│   ├── server.js               # Express app entry point
│   ├── req.http                # API testing requests (REST Client)
│   ├── package.json
│   └── .env                    # Environment variables (DB URI, secrets)
│
└── frontend/                   # React + Vite SPA
    ├── public/                 # Static assets
    ├── src/
    │   ├── assets/             # Images and media files
    │   ├── components/         # Reusable React components
    │   ├── store/              # State management (Redux/Context)
    │   ├── styles/             # CSS stylesheets
    │   ├── App.jsx             # Root application component
    │   ├── App.css             # App-level styles
    │   ├── main.jsx            # React DOM entry point
    │   └── index.css           # Global styles
    ├── index.html              # HTML template
    ├── vite.config.js          # Vite build configuration
    ├── eslint.config.js        # ESLint rules
    └── package.json
```

---

## 🗃️ Data Models

### User Schema

| Field | Type | Description |
|-------|------|-------------|
| `firstname` | String | User's first name |
| `lastname` | String | User's last name |
| `email` | String (unique) | Login email address |
| `password` | String | Hashed password |
| `role` | String | User role — `admin`, `author`, or `user` |
| `profileImageURL` | String | URL to profile picture |
| `isUserActive` | Boolean | Soft-delete flag (deactivate without losing data) |

### Article Schema

| Field | Type | Description |
|-------|------|-------------|
| `author` | ObjectId | Reference to the author (User) |
| `title` | String | Article title |
| `category` | String | Article category |
| `content` | String | Article body content |
| `comments` | Array | User comments on the article |
| `isArticleActive` | Boolean | Soft-delete flag for articles |

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| **Frontend** | React, Vite, JavaScript (ES6+) |
| **Backend** | Node.js, Express.js |
| **Database** | MongoDB (Mongoose ODM) |
| **State Management** | Redux / Context API |
| **Deployment** | Vercel (Frontend) |
| **Auth** | JWT / Session-based authentication |

---

## 🚀 Getting Started

### Prerequisites

- [Node.js](https://nodejs.org/) (v16+)
- [MongoDB](https://www.mongodb.com/) (local or Atlas cloud instance)

### 1. Clone the Repository

```bash
git clone https://github.com/JoyceHanan/capstone-project.git
cd capstone-project
```

### 2. Setup Backend

```bash
cd backend
npm install
```

Create a `.env` file in the `backend/` directory with:

```env
DBURL=your_mongodb_connection_string
SECRET_KEY=your_jwt_secret_key
```

Start the backend server:

```bash
node server.js
```

### 3. Setup Frontend

```bash
cd frontend
npm install
npm run dev
```

The frontend will be available at `http://localhost:5173`.

---

## 📡 API Endpoints Overview

| Route File | Base Path | Description |
|------------|-----------|-------------|
| `commonapi.js` | `/common` | User registration, login, public article listing |
| `userapi.js` | `/user` | Browse articles, post comments |
| `authorapi.js` | `/author` | Create, update, delete own articles |
| `adminapi.js` | `/admin` | Manage all users and articles, activate/deactivate accounts |

---

## 👤 Author

**JoyceHanan**

---

## 📄 License

This project is for educational purposes as part of the Advanced Training Program capstone.
