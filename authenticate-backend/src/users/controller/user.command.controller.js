import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import User from "../models/user.model.js";
import validator from "validator"; // Optional: for email validation
import ApiResponse from "../../utils/ApiResponse.js";
import generateAccessAndRefereshTokens from "../../utils/tokens.js";
import transporter from "../../config/nodemailer.js";
import moment from "moment/moment.js";
import { OAuth2Client } from "google-auth-library";
import { verifyAccountEmail } from "../../utils/emails/accountVerification.js";
import UserSession from "../../session/models/session.model.js";
import Cart from "../../cart/models/cart.models.js";
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
import { v4 as uuidv4 } from "uuid";

export const register = async (req, res) => {
  const { name, email, password, phoneNumber, confirmPassword } = req.body;
  const errors = [];

  if (!name || !email || !password || !phoneNumber || !confirmPassword) {
    return res
      .status(400)
      .json(new ApiResponse(400, {}, "All fields are required."));
  }

  if (email && !validator.isEmail(email)) {
    errors.push({ key: "email", message: "Invalid email format." });
  }

  if (phoneNumber && !validator.isMobilePhone(phoneNumber, "de-DE")) {
    errors.push({ key: "phoneNumber", message: "Invalid phone number." });
  }

  if (
    password &&
    (password.length < 6 ||
      !/[A-Z]/.test(password) ||
      !/[0-9]/.test(password) ||
      !/[!@#$%^&*]/.test(password))
  ) {
    errors.push({
      key: "password",
      message:
        "Password must be at least 6 characters long and include an uppercase letter, a number, and a special character.",
    });
  }

  if (password && confirmPassword && password !== confirmPassword) {
    errors.push({ key: "confirmPassword", message: "Passwords do not match." });
  }
  if (errors.length > 0) {
    return res
      .status(400)
      .json(new ApiResponse(400, errors, "Validation failed."));
  }
  try {
    const isExistingUser = await User.findOne({ email });
    if (isExistingUser) {
      return res
        .status(409)
        .json(new ApiResponse(409, {}, "User with this email already exists"));
    }

    const salt = await bcrypt.genSalt(12); // Generate salt
    const hashedPassword = await bcrypt.hash(password, salt);

    const otp = String(Math.floor(100000 + Math.random() * 900000));

    const otpHash = await bcrypt.hash(otp, 10);

    const user = new User({
      name,
      email,
      password: hashedPassword,
      phoneNumber, // ✅ Add phone number
      verifyOtp: otpHash,
      verifyOtpExpireAt: Date.now() + 2 * 60 * 1000,
    });

    await user.save();

    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: user.email,
      subject: "Account Verification OTP",
      text: `Your OTP is ${otp}. Verify your account using this OTP.`,
      html: verifyAccountEmail(otp),
    };

    await transporter.sendMail(mailOptions);

    const { access_token, refresh_token } =
      await generateAccessAndRefereshTokens(user.id);

    const options = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", // Make sure it's secure in production
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 10 * 60 * 1000, // Set to match JWT expiry (10 minutes)
    };

    const refreshTokenOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", // Make sure it's secure in production
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 5 * 24 * 60 * 60 * 1000, // Set to match JWT expiry (10 minutes)
    };

    const userLoggedInOption = { ...options };
    delete userLoggedInOption.maxAge;
    delete userLoggedInOption.httpOnly;

    return res
      .status(201)
      .cookie("access_token", access_token, options)
      .cookie("refresh_token", refresh_token, refreshTokenOptions)
      .cookie("_guest_id", "", options)
      .cookie("_is_user_logged_in", "true", userLoggedInOption)
      .json(new ApiResponse(201, {}, "User Registered Successfully"));
  } catch (err) {
    res.status(500).json(new ApiResponse(500, {}, err.message));
  }
};

export const login = async (req, res) => {
  const { email, password } = req.body;
  const deviceId = req.cookies?._device_id;

  const errors = [];

  if (!email || !password) {
    const err = [
      {
        key: "email",
        message: "Please provide email to login",
      },
      {
        key: "password",
        message: "Please provide password to login",
      },
    ];
    errors = [...errors, ...err];
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      errors.push({
        key: "email",
        message: "User with this email doesn't exits.",
      });
    }
    if (user) {
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        errors.push({
          key: "password",
          message: "Password is invalid. please provide correct password.",
        });
      }
    }

    if (errors.length > 0) {
      return res
        .status(400)
        .json(new ApiResponse(400, errors, "Validation failed."));
    }

    const { access_token, refresh_token } =
      await generateAccessAndRefereshTokens(user.id);

    const options = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", // Make sure it's secure in production
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 10 * 60 * 1000, // Set to match JWT expiry (10 minutes)
    };

    const refreshTokenOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", // Make sure it's secure in production
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 5 * 24 * 60 * 60 * 1000, // Set to match JWT expiry (10 minutes)
    };

    const userLoggedInOption = { ...options };
    delete userLoggedInOption.maxAge;
    delete userLoggedInOption.httpOnly;

    const cart = await Cart.findOne({ deviceId: deviceId });
    if (cart) {
      cart.userId = user.id;
      await cart.save();
    }

    return res
      .status(200)
      .cookie("access_token", access_token, options)
      .cookie("refresh_token", refresh_token, refreshTokenOptions)
      .cookie("_guest_id", "", options)
      .cookie("_is_user_logged_in", "true", userLoggedInOption)
      .cookie("_user_id_", user.id, options)
      .json(new ApiResponse(200, {}, "User logged In Successfully"));
  } catch (err) {
    return res.status(500).json(new ApiResponse(500, {}, err.message));
  }
};

export const logout = async (req, res) => {
  try {
    const deviceId = req.cookies?._device_id;
    const userId = req.cookies?._user_id_;
    const options = {
      httpOnly: process.env.NODE_ENV === "production", // true in production
      secure: process.env.NODE_ENV === "production", // true in production
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax", // 'none' for cross-origin requests
    };
    await Cart.deleteOne({ userId });
    const session = await UserSession.findOne({ id: deviceId });
    const guestId = uuidv4();
    session.guestId = guestId;
    await session.save()

    return res
      .status(200)
      .clearCookie("access_token", options)
      .clearCookie("refresh_token", options)
      .cookie("_device_id", session?.id, {
        ...options,
        maxAge: 30 * 24 * 60 * 60 * 1000, //
      })
      .cookie("_guest_id", session?.guestId, {
        ...options,
        maxAge: 2 * 24 * 60 * 60 * 1000,
      })
      .cookie("_is_user_logged_in", "false", options)
      .json(
        new ApiResponse(
          200,
          {
            deviceId: session.id,
            tid: session.guestId,
            statusMessage: `Session logout`,
          },
          "Logged out successfully"
        )
      );
  } catch (err) {
    return res.status(500).json(new ApiResponse(500, {}, err.message));
  }
};

export const refreshToken = async (req, res) => {
  const refresToken =
    req.cookies?.refresh_token ||
    req.header("Authorization")?.replace("Bearer ", "");
  // const { refresToken } = req.body;

  if (!refresToken) {
    return res
      .status(401)
      .json(new ApiResponse(401, {}, "No refresh token provided"));
  }

  try {
    const decoded = jwt.verify(refresToken, process.env.REFRESH_TOKEN_SECRET);
    const user = await User.findOne({ id: decoded.id });

    if (!user) {
      return res.status(403).json(new ApiResponse(403, {}, "User not found"));
    }

    const isMatch = await bcrypt.compare(refresToken, user.refreshToken);
    if (!isMatch) {
      return res
        .status(403)
        .json(new ApiResponse(403, {}, "Invalid refresh token"));
    }

    // Rename the destructured variable here
    const { access_token } = await generateAccessAndRefereshTokens(decoded.id);

    const options = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", // Make sure it's secure in production
      sameSite: process.env.NODE_ENV === "production" ? "None" : "Strict",
      maxAge: 10 * 60 * 1000, // Set to match JWT expiry (10 minutes)
    };

    return res
      .status(200)
      .cookie("access_token", access_token, options)
      .json(new ApiResponse(200, {}, "Access token refreshed successfully"));
  } catch (err) {
    return res
      .status(403)
      .json(new ApiResponse(403, {}, "Invalid or expired refresh token"));
  }
};

export const sendVerifyOtp = async (req, res) => {
  try {
    const { id: userId } = req.user;
    const user = await User.findOne({ id: userId });
    if (user.isAccountVerified) {
      return res
        .status(200)
        .json(new ApiResponse(200, {}, "Account Already Verified"));
    }

    const otp = String(Math.floor(100000 + Math.random() * 900000));

    const otpHash = await bcrypt.hash(otp, 10); // hashing the OTP before saving
    user.verifyOtp = otpHash;
    user.verifyOtpExpireAt = Date.now() + 2 * 60 * 1000;

    await user.save();

    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: user.email,
      subject: "Account Verification OTP",
      text: `Your OTP is ${otp}. Verify your account using this OTP.`,
      html: verifyAccountEmail(otp),
    };

    await transporter.sendMail(mailOptions);

    return res
      .status(200)
      .json(
        new ApiResponse(
          200,
          { otpExpiresAt: user.verifyOtpExpireAt },
          "Verification OTP sent successfully"
        )
      );
  } catch (err) {
    return res.status(404).json(new ApiResponse(404, {}, err.message));
  }
};

export const verifyEmail = async (req, res) => {
  const { otp } = req.body;
  const token = req.cookies?.access_token;
  const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

  if (!decoded.id || !otp) {
    return res.status(404).json(new ApiResponse(404, {}, "Missing Details"));
  }

  try {
    const user = await User.findOne({ id: decoded.id });
    if (!user) {
      return res.status(404).json(new ApiResponse(404, {}, "User not found"));
    }

    if (!user.verifyOtp || !(await bcrypt.compare(otp, user.verifyOtp))) {
      return res.status(404).json(new ApiResponse(404, {}, "Invalid OTP"));
    }

    if (moment().isAfter(user.verifyOtpExpireAt)) {
      return res.status(404).json(new ApiResponse(404, {}, "OTP expired"));
    }

    user.isAccountVerified = true;
    user.verifyOtp = "";
    user.verifyOtpExpireAt = 0;

    await user.save();

    return res
      .status(200)
      .json(
        new ApiResponse(
          200,
          { isAccountVerified: user.isAccountVerified },
          "Email Verified Succesfully"
        )
      );
  } catch (err) {
    return res.status(404).json(new ApiResponse(404, {}, err.message));
  }
};

export const verifyGoogleToken = async (req, res) => {
  try {
    const { code } = req.body;
    const userData = await verifyToken(code);

    let user = await User.findOne({ email: userData.email });

    if (!user) {
      // If the user doesn't exist, create a new one
      const hashedPassword = await bcrypt.hash(userData.sub, 12);
      user = new User({
        name: userData.name,
        email: userData.email,
        isAccountVerified: true, // You can set this based on your requirements
        password: hashedPassword, // No password needed for Google login
        refreshToken: "", // Set the refreshToken to an empty string if not needed
      });

      await user.save(); // Save the new user to the database
    }

    const { access_token, refresh_token } =
      await generateAccessAndRefereshTokens(user.id);
    const options = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
      maxAge: 10 * 60 * 1000, // Set to match JWT expiry (10 minutes)
    };

    return res
      .status(200)
      .cookie("access_token", access_token, options)
      .cookie("refresh_token", refresh_token, options)
      .json(
        new ApiResponse(200, { user: userData }, "User logged In Successfully")
      );
  } catch (error) {
    res.status(400).json({ success: false, message: "Invalid token" });
  }
};

async function verifyToken(token) {
  const ticket = await client.verifyIdToken({
    idToken: token,
    audience: process.env.GOOGLE_CLIENT_ID,
  });

  const payload = ticket.getPayload();
  return payload; // Contains user info like email, name, picture, etc.
}

export const googleLogin = async (req, res) => {
  try {
    const deviceId = req.cookies?._device_id;
    const { credential } = req.body;
    const ticket = await client.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID, // Replace with your Google client ID
    });

    const payload = ticket.getPayload();
    const userId = payload["sub"]; // Google user ID
    const email = payload["email"];
    const avatarUrl = payload["picture"]; // Optional avatar URL
    const name = payload["name"] || "Google User"; // Fallback name if not available

    // Check if user already exists
    const existingUser = await User.findOne({ googleId: userId });

    // If user exists, log in or link Google account
    if (existingUser) {
      // If Google ID is already linked, log the user in
      if (existingUser.googleId) {
        const cart = await Cart.findOne({ deviceId: deviceId });
        if (cart) {
          cart.userId = existingUser.id;
          await cart.save();
        }
        const { access_token, refresh_token } =
          await generateAccessAndRefereshTokens(existingUser.id);
        const options = createCookieOptions(10 * 60 * 1000); // 10 min access token
        const refreshTokenOptions = createCookieOptions(
          5 * 24 * 60 * 60 * 1000
        ); // 5 days refresh token

        return res
          .status(200)
          .cookie("access_token", access_token, options)
          .cookie("refresh_token", refresh_token, refreshTokenOptions)
          .cookie("_guest_id", "", options)
          .cookie("_is_user_logged_in", "true", {
            ...options,
            maxAge: undefined,
            httpOnly: undefined,
          })
          .json(new ApiResponse(200, {}, "User logged in successfully."));
      }
    }

    // User does not exist, register them
    const otp = String(Math.floor(100000 + Math.random() * 900000));
    const otpHash = await bcrypt.hash(otp, 10);

    const newUser = new User({
      name,
      email,
      googleId: userId,
      avatarUrl: avatarUrl || "",
      verifyOtp: otpHash,
      verifyOtpExpireAt: Date.now() + 2 * 60 * 1000,
    });

    await newUser.save();

    const cart = await Cart.findOne({ deviceId: deviceId });
    if (cart) {
      cart.userId = newUser.id;
      await cart.save();
    }

    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: newUser.email,
      subject: "Account Verification OTP",
      text: `Your OTP is ${otp}. Verify your account using this OTP.`,
      html: verifyAccountEmail(otp), // Replace with actual verification email template
    };

    await transporter.sendMail(mailOptions);

    const { access_token, refresh_token } =
      await generateAccessAndRefereshTokens(newUser.id);
    const options = createCookieOptions(10 * 60 * 1000); // 10 min access token
    const refreshTokenOptions = createCookieOptions(5 * 24 * 60 * 60 * 1000); // 5 days refresh token

    return res
      .status(201)
      .cookie("access_token", access_token, options)
      .cookie("refresh_token", refresh_token, refreshTokenOptions)
      .cookie("_guest_id", "", options)
      .cookie("_is_user_logged_in", "true", {
        ...options,
        maxAge: undefined,
        httpOnly: undefined,
      })
      .cookie("_user_id_", newUser.id, options)
      .json(
        new ApiResponse(201, {}, "User registered successfully with Google.")
      );
  } catch (err) {
    res.status(500).json(new ApiResponse(500, {}, err.message));
  }
};

// Utility function to generate cookie options
const createCookieOptions = (maxAge) => ({
  httpOnly: true,
  secure: process.env.NODE_ENV === "production", // Ensure it's secure in production
  sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
  maxAge,
});
