import jwt from "jsonwebtoken";
import ApiError from "../utils/ApiError.js";
import asyncHandler from "../utils/asyncHandler.js";
import User from "../users/models/user.model.js";

export const verifyJWT = asyncHandler(async (req, res, next) => {
  try {
    const accessToken = req.cookies?.access_token;
    const refreshToken = req.cookies?.refresh_token;

    if (!accessToken && !refreshToken) {
      throw new ApiError(401, "Unauthorized request - No tokens provided");
    }

    let decodedToken;

    // Step 1: Try to verify access token first
    if (accessToken) {
      try {
        decodedToken = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);
      } catch (error) {
        if (error.name === "TokenExpiredError") {
          console.log("Access token expired, trying refresh token...");
        } else {
          throw new ApiError(401, "Invalid Access Token");
        }
      }
    }

    // Step 2: If access token is expired, try using the refresh token
    if (!decodedToken && refreshToken) {
      try {
        decodedToken = jwt.verify(
          refreshToken,
          process.env.REFRESH_TOKEN_SECRET
        );

        // Generate a new access token
        const newAccessToken = jwt.sign(
          { id: decodedToken.id },
          process.env.ACCESS_TOKEN_SECRET,
          { expiresIn: process.env.ACCESS_TOKEN_EXPIRY } // Set your access token expiry
        );

        res.cookie("access_token", newAccessToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
          maxAge: 10 * 60 * 1000, // 10 minutes
        });
      } catch (error) {
        throw new ApiError(401, "Invalid or Expired Refresh Token");
      }
    }

    if (!decodedToken) {
      throw new ApiError(
        401,
        "Unauthorized request - Token verification failed"
      );
    }

    // Step 3: Find the user
    const user = await User.findOne({ id: decodedToken.id }).select(
      "-password -refreshToken"
    );
    if (!user) {
      throw new ApiError(401, "User not found or unauthorized");
    }

    req.user = user;
    next();
  } catch (error) {
    next(new ApiError(401, error.message || "Unauthorized request"));
  }
});

export const authenticateUser = async (req, res, next) => {
  const access_token = req.cookies?.access_token;
  const tId = req.headers['tid'] || ''
  const ssId = req.headers['ssid'] || ''


  if (!access_token) {
    req.user = null; // No user, treat as guest
    req.tid = tId;
    req.ssid = ssId;
    return next();
  }

  try {
    const decodedToken = jwt.verify(access_token, process.env.ACCESS_TOKEN_SECRET);
    const user = await User.findOne({ id: decodedToken.id }).select("id name");
    req.user = user; // Attach user to request
    req.tid = tId;
    req.ssid = ssId

    const options = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", // Make sure it's secure in production
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 30 * 24 * 60 * 60 * 1000, // Set to match JWT expiry (10 minutes)
    };

    const userLoggedInOption = {...options};
    delete userLoggedInOption.maxAge
    res.cookie("_is_user_logged_in", "true", userLoggedInOption); 
  } catch (error) {
    req.user = null;
    res.clearCookie("_is_user_logged_in"); // Clear logged-in cookie if invalid token
  }

  next();
};
