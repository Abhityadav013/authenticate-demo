import { Router } from "express";
import {
  googleLogin,
  login,
  logout,
  refreshToken,
  register,
  sendVerifyOtp,
  verifyEmail,
  verifyGoogleToken,
} from "../controller/user.command.controller.js";
import User from "../models/user.model.js";
import { authenticateUser, verifyJWT } from "../../middleware/authenticate.js";
import ApiResponse from "../../utils/ApiResponse.js";
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
authRouter.post("/logout",authenticateUser, logout);

authRouter.get("/profile", verifyJWT, async (req, res) => {
  try {
    let deviceId = req.cookies?._device_id;
    const user = await User.findOne({ id: req.user.id }).select(
      "name isAccountVerified -_id" // Include required fields, exclude _id
    );

    if (!user) {
      return res.status(404).json(new ApiResponse(404, {}, "User not found"));
    }

    
    const options = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", // Make sure it's secure in production
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 30 * 24 * 60 * 60 * 1000, // Set to match JWT expiry (10 minutes)
    };
    const userLoggedInOption = { ...options };
    delete userLoggedInOption.maxAge;
    return res
      .status(200)
      .cookie("_device_id", deviceId, options)
      .cookie("_guest_id", "", options)
      .cookie("_is_user_logged_in", true, userLoggedInOption)
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

authRouter.post("/auth/google",googleLogin);


export default authRouter;
