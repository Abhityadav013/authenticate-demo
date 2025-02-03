import { Router } from "express";
import {
  login,
  logout,
  refreshToken,
  register,
  sendVerifyOtp,
  verifyEmail,
  verifyGoogleToken,
} from "../controller/user.command.controller.js";
import User from "../models/user.model.js";
import { verifyJWT } from "../../middleware/authenticate.js";
import ApiResponse from "../../utils/ApiResponse.js";
import passport from 'passport';
const GoogleStrategy = (await import("passport-google-oauth20")).Strategy
const authRouter = Router();

/**
 * @swagger
 * /api/v1/register:
 *   post:
 *     tags:
 *       - User
 *     summary: Register a new user
 *     description: User registration
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *                 example: John Doe
 *               email:
 *                 type: string
 *                 example: johndoe@example.com
 *               password:
 *                 type: string
 *                 example: securepassword123
 *     responses:
 *       201:
 *         description: User registered successfully
 *       400:
 *         description: Missing fields or invalid data
 *       409:
 *         description: User with this email already exists
 */
authRouter.post("/register", register);

/**
 * @swagger
 * /api/v1/login:
 *   post:
 *     tags:
 *       - User
 *     summary: Login an existing user
 *     description: User login
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 example: johndoe@example.com
 *               password:
 *                 type: string
 *                 example: securepassword123
 *     responses:
 *       200:
 *         description: User logged in successfully
 *       400:
 *         description: Missing fields or invalid data
 *       401:
 *         description: Invalid email or password
 */
authRouter.post("/login", login);

/**
 * @swagger
 * /api/v1/logout:
 *   post:
 *     tags:
 *       - User
 *     summary: Logout the existing user
 *     description: User logout (clear access token cookie)
 *     responses:
 *       200:
 *         description: User logged out successfully
 */
authRouter.post("/logout", logout);

authRouter.get("/profile", verifyJWT, async (req, res) => {
  try {
    const user = await User.findOne({ id: req.user.id }).select(
      "-password -verifyOtp -verifyOtpExpireAt -isAccountVerified -resetOtp -resetOtpExpireAt -refreshToken -_id"
    ); // Get user data without password

    if (!user) {
      return res.status(404).json(new ApiResponse(404, {}, "User not found"));
    }
    return res
      .status(200)
      .json(
        new ApiResponse(
          200,
          { userDetails: user },
          "User logged In Successfully"
        )
      );
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

authRouter.post("/refresh-token", refreshToken);

authRouter.post("/send-verify-otp", verifyJWT, sendVerifyOtp);

authRouter.post("/verify-account", verifyJWT, verifyEmail);

authRouter.post("/auth/google",verifyGoogleToken);


export default authRouter;
