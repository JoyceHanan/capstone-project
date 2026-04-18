import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'
import axios from 'axios'

// set base URL globally
axios.defaults.baseURL = "https://capstone-project-ycw3.onrender.com"
axios.defaults.withCredentials = true  // ← applies to ALL requests too
createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
