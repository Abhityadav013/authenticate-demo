import jwt from "jsonwebtoken";
import ApiError from "../utils/ApiError.js";
import asyncHandler from "../utils/asyncHandler.js";
import User from "../users/models/user.model.js";

export const verifyJWT = asyncHandler(async (req, _, next) => {
  try {
    const token =
      req.cookies?.access_token ||
      req.header("Authorization")?.replace("Bearer ", "");

      if (!token) {
      throw new ApiError(401, "Unauthorized request");
    }

    const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

    const user = await User.findOne({ id: decodedToken.id }).select(
      "-password -refreshToken"
    );

    if (!user) {
      throw new ApiError(401, "Invalid Access Token");
    }

    req.user = user;
    next();
  } catch (error) {
    throw new ApiError(401, error?.message || "Invalid access token");
  }
});


const authenticateUser = async (req, res, next) => {
  const access_token = req.cookies.access_token;
  
  if (!access_token) {
      return res.status(401).json({ error: "Unauthorized" });
  }

  try {
      const ticket = await client.verifyIdToken({ idToken: access_token, audience: process.env.GOOGLE_CLIENT_ID });
      req.user = ticket.getPayload();
      next();
  } catch (error) {
      res.status(401).json({ error: "Invalid or expired token" });
  }
};