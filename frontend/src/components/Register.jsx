
import {
  divider,
  errorClass,
  formCard,
  formGroup,
  formTitle,
  inputClass,
  labelClass,
  pageBackground,
  submitBtn,
  mutedText,
} from "../styles/common";
import { useForm } from "react-hook-form";
import { NavLink, useNavigate } from "react-router";
import { useState } from "react";
import axios from "axios";

function Register() {
  const navigate = useNavigate();
  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm();

  const [loading, setLoading] = useState(false);
  const [apiError, setApiError] = useState(null);

  // When user registration submitted
  const onUserRegister = async (userObj) => {
    console.log(userObj);
    try {
      setLoading(true);

      // ✅ FIXED URL (same backend as login)
      let res = await axios.post(
        "http://localhost:5000/common-api/common",
        userObj
      );

      if (res.status === 201) {
        navigate("/login");
      }
    } catch (err) {
      console.log("err in registration", err);
      setApiError(
        err.response?.data?.err ||
        err.response?.data?.error ||
        err.response?.data?.message ||
        err.message ||
        "Registration Failed"
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className={`${pageBackground} flex items-center justify-center py-16 px-4`}>
      <div className={formCard}>
        <h2 className={formTitle}>Create an Account</h2>

        {/* API Error */}
        {apiError && <p className={errorClass}>{apiError}</p>}

        {/* Loading */}
        {loading && <p className="loadingClass">Registering...</p>}

        <form onSubmit={handleSubmit(onUserRegister)}>
          {/* ROLE */}
          <div className="mb-5">
            <p className={labelClass}>Register as</p>

            <div className="flex gap-6 mt-1">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="radio"
                  value="USER"
                  {...register("role", {
                    required: "Please select a role",
                  })}
                  className="accent-blue-600 w-4 h-4"
                />
                <span className="text-sm">User</span>
              </label>

              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="radio"
                  value="AUTHOR"
                  {...register("role", {
                    required: "Please select a role",
                  })}
                  className="accent-blue-600 w-4 h-4"
                />
                <span className="text-sm">Author</span>
              </label>
            </div>

            {errors.role && <p className={errorClass}>{errors.role.message}</p>}
          </div>

          <div className={divider} />

          {/* NAME */}
          <div className="sm:flex gap-4 mb-4">
            <div className="flex-1">
              <label className={labelClass}>First Name</label>
              <input
                type="text"
                className={inputClass}
                placeholder="First name"
                {...register("firstName", {
                  required: "First name is required",
                  minLength: {
                    value: 2,
                    message: "At least 2 characters required",
                  },
                  maxLength: {
                    value: 30,
                    message: "Max 30 characters allowed",
                  },
                  validate: (v) =>
                    v.trim().length > 0 || "Cannot be empty",
                })}
              />
              {errors.firstName && (
                <p className={errorClass}>{errors.firstName.message}</p>
              )}
            </div>

            <div className="flex-1">
              <label className={labelClass}>Last Name</label>
              <input
                type="text"
                className={inputClass}
                placeholder="Last name"
                {...register("lastName", {
                  maxLength: {
                    value: 30,
                    message: "Max 30 characters allowed",
                  },
                })}
              />
              {errors.lastName && (
                <p className={errorClass}>{errors.lastName.message}</p>
              )}
            </div>
          </div>

          {/* EMAIL */}
          <div className={formGroup}>
            <label className={labelClass}>Email</label>
            <input
              type="email"
              className={inputClass}
              placeholder="you@example.com"
              {...register("email", {
                required: "Email is required",
              })}
            />
            {errors.email && (
              <p className={errorClass}>{errors.email.message}</p>
            )}
          </div>

          {/* PASSWORD */}
          <div className={formGroup}>
            <label className={labelClass}>Password</label>
            <input
              type="password"
              className={inputClass}
              placeholder="Min. 8 characters"
              {...register("password", {
                required: "Password is required",
              })}
            />
            {errors.password && (
              <p className={errorClass}>{errors.password.message}</p>
            )}
          </div>

          {/* PROFILE IMAGE */}
          <div className={formGroup}>
            <label className={labelClass}>Profile Image</label>

            {/* ✅ FIXED FIELD NAME */}
            <input
              type="text"
              {...register("profileImageUrl")}
            />

            {errors.profileImageUrl && (
              <p className={errorClass}>
                {errors.profileImageUrl.message}
              </p>
            )}
          </div>

          {/* SUBMIT */}
          <button type="submit" className={submitBtn}>
            Create Account
          </button>
        </form>

        {/* FOOTER */}
        <p className={`${mutedText} text-center mt-5`}>
          Already have an account?{" "}
          <NavLink to="/login" className="text-[#0066cc] font-medium">
            Sign in
          </NavLink>
        </p>
      </div>
    </div>
  );
}

export default Register;
