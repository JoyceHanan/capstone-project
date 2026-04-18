import { useAuth } from "../store/authStore";
import { Navigate } from "react-router";
import { toast } from "react-hot-toast";
import { useEffect } from "react";

function ProtectedRoute({ children, allowedRoles }) {
  //get user login status from store
  const { loading, currentUser, isAuthenticated } = useAuth();
  const showRedirectToast = !loading && !isAuthenticated;
  const showUnauthorizedToast = !loading && isAuthenticated && allowedRoles && !allowedRoles.includes(currentUser?.role);

  useEffect(() => {
    if (showRedirectToast) {
      toast.error("Redirecting to Login");
    }
  }, [showRedirectToast]);

  useEffect(() => {
    if (showUnauthorizedToast) {
      toast.error("Unauthorized access");
    }
  }, [showUnauthorizedToast]);

  if (loading) {
    return <p>Loading...</p>;
  }

  //if user not loggedin
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  //check roles
  if (allowedRoles && !allowedRoles.includes(currentUser?.role)) {
    return <Navigate to="/unauthorized" replace state={{ redirectTo: "/" }} />;
  }

  return children;
}

export default ProtectedRoute;