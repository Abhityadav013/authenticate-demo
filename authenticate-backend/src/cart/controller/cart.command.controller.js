import UserSession from "../../session/models/session.model.js";
import ApiResponse from "../../utils/ApiResponse.js";
import Cart from "../models/cart.models.js";

export const addToCart = async (req, res) => {
  try {
    let deviceId = req.cookies?._device_id;
    let isUserLoggedIn = req.cookies?._is_user_logged_in === "true";
    const userId = req.user ? req.user.id : null;
    const guestId = req.tid ? req.tid : null;
    if (!isUserLoggedIn && guestId) {
      const session = await UserSession.findOne({ guestId });
      deviceId = session?.id;
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

    let cartFilter = { $or: [{ deviceId }] };
    if (userId) {
      cartFilter["$or"].push({ userId });
    }

    let cart = await Cart.findOne(cartFilter).select("-cartItems.addons");
    if (!req.body.cart) {
      return res
        .status(200)
        .cookie("_device_id", deviceId, options)
        .cookie("_guest_id", guestId, guestOptions)
        .cookie("_is_user_logged_in", isUserLoggedIn, userLoggedInOption)
        .json(
          new ApiResponse(
            200,
            { cart },
            cart ? "Cart retrieved successfully." : "Cart is empty."
          )
        );
    }

    const { cart: cartItems } = req.body;
    if (!cart) {
      cart = new Cart({
        deviceId,
        userId: userId || undefined,
        cartItems: cartItems.filter((item) => item.quantity > 0),
      });
    } else {
      const isItemCompletRemove =
        cart.cartItems.length !== cartItems.length &&
        cart.length > cartItems.length;
      const isNewItemAdd = cart.length < cartItems.length;
      if (isItemCompletRemove) {
        const updatItem = cart.cartItems.find(
          (item) => !cartItems.includes(item)
        );
        cart.cartItems.filter((item) => item.itemId !== updatItem.itemId);
      } else if (isNewItemAdd) {
        cart.cartItems.push({ itemId, itemName, quantity });
      } else {
        cart.cartItems = cartItems;
      }
    }
    await cart.save();
    console.log("cart<<<<<<<<<<<", cart);
    if (cart.cartItems.length === 0) {
      await cart.deleteOne({ deviceId });
    }
    return res
      .status(201)
      .cookie("_device_id", deviceId, options)
      .cookie("_guest_id", guestId, guestOptions)
      .cookie("_is_user_logged_in", isUserLoggedIn, userLoggedInOption)
      .json(new ApiResponse(201, { cart }, "Cart updated successfully."));
  } catch (error) {
    console.error("Error handling cart:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

export const cartAddons = async (req, res) => {
  try {
    const { description, itemId } = req.body.cartDescription;
    let deviceId = req.cookies?._device_id;
    let isUserLoggedIn = req.cookies?._is_user_logged_in === "true";
    const userId = req.user ? req.user.id : null;
    const guestId = req.tid ? req.tid : null;
    if (guestId) {
      const session = await UserSession.findOne({ guestId });
      deviceId = session.id;
    }

    let cartFilter = { $or: [{ deviceId }] };
    if (userId) {
      cartFilter["$or"].push({ userId });
    }
    await Cart.updateOne(
      { deviceId, "cartItems.itemId": itemId }, // Find document with matching deviceId & itemId
      {
        $push: {
          "cartItems.$[cart].addons": description, // Push addon to the correct cart item
        },
      },
      {
        arrayFilters: [{ "cart.itemId": itemId }], // Identify the correct cart item
      }
    );

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

    return res
      .status(201)
      .cookie("_device_id", deviceId, options)
      .cookie("_guest_id", guestId, guestOptions)
      .cookie("_is_user_logged_in", isUserLoggedIn, userLoggedInOption)
      .json(new ApiResponse(201, {}, "Cart updated successfully."));
  } catch (error) {
    console.error("Error handling cart:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

export const fetchCartAddons = async (req, res) => {
  try {
    let deviceId = req.cookies?._device_id;
    let isUserLoggedIn = req.cookies?._is_user_logged_in === "true";
    const userId = req.user ? req.user.id : null;
    const guestId = req.tid ? req.tid : null;
    if (guestId) {
      const session = await UserSession.findOne({ guestId });
      deviceId = session.id;
    }

    let cartFilter = { $or: [{ deviceId }] };
    if (userId) {
      cartFilter["$or"].push({ userId });
    }

    const cart = await Cart.findOne(cartFilter);
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

    const cartDescription = cart?.cartItems?.map((item) => ({
      itemId: item.itemId,
      description: item.addons[0],
    }));
    return res
      .status(201)
      .cookie("_device_id", deviceId, options)
      .cookie("_guest_id", guestId, guestOptions)
      .cookie("_is_user_logged_in", isUserLoggedIn, userLoggedInOption)
      .json(
        new ApiResponse(201, { cartDescription }, "Cart updated successfully.")
      );
  } catch (error) {
    console.error("Error handling cart:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};
