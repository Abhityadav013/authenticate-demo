import ApiResponse from "../../utils/ApiResponse.js";
import UserSession from "../models/session.model.js";
import { v4 as uuidv4 } from "uuid";

export const sessionRegister = async (req, res) => {
  const { lat, lng } = req.query;

  try {
    let deviceId = req.cookies?._device_id;
    let isUserLoggedIn = req.cookies?._is_user_logged_in === "true";

    let session = new UserSession({
      latitude: lat || null,
      longitude: lng || null,
    });
   
    if (!deviceId || deviceId ==='undefined') {
      // If no deviceId in cookies, create a new guest session
      const guestId = uuidv4();
      session.guestId = guestId; // Set the guest ID
      await session.save(); // Save session to the database
    } else {
      // If deviceId exists, maybe fetch the session from the DB or use existing session
      session = (await UserSession.findOne({ id: deviceId })) || session;
    }

    const options = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", // Make sure it's secure in production
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 30 * 24 * 60 * 60 * 1000, // Set to match JWT expiry (10 minutes)
    };
    const guestOptions = {
      ...options,
      maxAge: 2 * 24 * 60 * 60 * 1000, // Set to match JWT expiry (10 minutes)
    };

    const userLoggedInOption = { ...options };
    delete userLoggedInOption.maxAge;

    res
      .status(200)
      .cookie("_device_id", session.id, options)
      .cookie("_guest_id", session.guestId, guestOptions)
      .cookie("_is_user_logged_in", isUserLoggedIn, userLoggedInOption)
      .json(
        new ApiResponse(
          200,
          {
            deviceId: session.id,
            tid: session.guestId,
            statusMessage: `Session expired. Please login again.`,
          },
          "Session expired. Please login again."
        )
      );
  } catch (err) {
    res.status(500).json(new ApiResponse(500, {}, err.message));
  }
};
