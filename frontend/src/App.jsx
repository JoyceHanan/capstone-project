import { createBrowserRouter, RouterProvider } from "react-router";
import RootLayout from "./components/RootLayout";
import Home from "./components/Home";
import Register from "./components/Register";
import Login from "./components/Login";
import UserProfile from "./components/UserProfile";
import AuthorProfile from "./components/AuthorProfile";
import AuthorArticles from "./components/AuthorArticles";
import EditArticle from './components/EditArticle'
import WriteArticles from "./components/WriteArticles";
import ArticleByID from "./components/ArticleByID";
import AdminProfile from "./components/AdminProfile";
import './App.css'
function App() {
  const routerObj = createBrowserRouter([
    {
      path: "/",
      element: <RootLayout />,
      children: [
        {
          path: "",
          element: <Home />,
        },
        {
          path: "register",
          element: <Register />,
        },
        {
          path: "login",
          element: <Login />,
        },
        {
          path: "user-profile",
          element: <UserProfile />,
        },
        {
          path: "author-profile",
          element: <AuthorProfile />,

          children: [
            {
              index: true,
              element: <AuthorArticles />,
            },
            {
              path: "articles",
              element: <AuthorArticles />,
            },
            {
              path: "write-article",
              element: <WriteArticles />,
            },
          ],
        },
        {
          path: "article/:id",
          element: <ArticleByID />,
        },
        {
          path: "edit-article",
          element: <EditArticle />,
        },
        {
  path: "admin-profile",
  element: <AdminProfile />,
  children: [
    {
      index: true,
      element: <AuthorArticles />
    },
    {
      path: "articles",
      element: <AuthorArticles />
    },
    {
      path: "write-article",
      element: <WriteArticles />
    }
  ]
}
      ],
    },
  ]);

  return <RouterProvider router={routerObj} />;
}

export default App;