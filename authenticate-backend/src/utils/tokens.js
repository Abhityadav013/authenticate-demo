import User from "../users/models/user.model.js";
import ApiError from "./ApiError.js";
import jwt from "jsonwebtoken";
import bcrypt from 'bcryptjs'

const generateAccessAndRefereshTokens = async (userId) => {
  try {
    const user = await User.findOne({ id: userId });

    if (!user) {
      throw new ApiError(404, "User not found");
    }

    const access_token_payload = {
      id: user.id,
      name: user.name,
      email: user.email,
    };

    const refresh_token_payload = {
      id: user.id,
    };

    const access_token = generateAccessToken(access_token_payload);
    const refresh_token = generateRefreshToken(refresh_token_payload);

    const hashedRefreshToken = await bcrypt.hash(refresh_token, 10);

    user.refreshToken = hashedRefreshToken;
    await user.save(); // Save user with new refresh token

    return { access_token, refresh_token };
  } catch (error) {
    throw new ApiError(
      500,
      error.message ||
        "Something went wrong while generating refresh and access token"
    );
  }
};

const generateAccessToken = (token_payload) => {
  const access_token = jwt.sign(
    token_payload,
    process.env.ACCESS_TOKEN_SECRET,
    {
      expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
    }
  );

  return access_token;
};

const generateRefreshToken = (token_payload) => {
  const refresh_token = jwt.sign(
    token_payload,
    process.env.REFRESH_TOKEN_SECRET,
    {
      expiresIn: process.env.REFRESH_TOKEN_EXPIRY,
    }
  );

  return refresh_token;
};

export default generateAccessAndRefereshTokens;
