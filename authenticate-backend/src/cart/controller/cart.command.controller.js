import ApiResponse from "../../utils/ApiResponse.js";
import Cart from "../models/cart.models.js";

export const addToCart = async (req, res) => {
  try {
    let deviceId = req.cookies?._device_id;
    let isUserLoggedIn = req.cookies?._is_user_logged_in === "true";
    const userId = req.user ? req.user.id : null;

    let cartFilter = { $or: [{ deviceId }] };
    if (userId) {
      cartFilter["$or"].push({ userId });
    }

    let cart = await Cart.findOne(cartFilter).select("-cartItems.addons -_id");
    if (!req.body.cart) {
      return res
        .status(200)
        .json(
          new ApiResponse(
            200,
            { cart },
            cart ? "Cart retrieved successfully." : "Cart is empty."
          )
        );
    }

    const { cart: cartItems } = req.body;
    if (!Array.isArray(cartItems) || cartItems.length === 0) {
      return res
        .status(400)
        .json({ message: "Cart items should be a non-empty array" });
    }

    if (!cart) {
      await Cart.updateOne(
        { deviceId }, // Find document by deviceId
        {
          $set: {
            deviceId,
            userId: userId || undefined,
            cartItems: cartItems.filter((item) => item.quantity > 0),
          },
        },{
          upsert:true
        }
      );
    } else {
      cartItems.forEach(({ itemId, itemName, quantity }) => {
        const cartIndex = cart.cartItems.findIndex(
          (item) => item.itemId === itemId
        );
        if (cartIndex !== -1) {
          if (quantity > 0) {
            // ✅ Update existing item quantity
            cart.cartItems[cartIndex].quantity = quantity;
          } else {
            // ❌ Remove item if quantity is 0
            cart.cartItems.splice(cartIndex, 1);
          }
        } else {
          // Add a new item if quantity > 0
          cart.cartItems.push({
            itemId,
            itemName,
            quantity,
          });
        }
      });

      await Cart.updateOne(
        { deviceId }, // Find document by deviceId
        {
          $set: {
            cartItems: cart.cartItems.filter((item) => item.quantity > 0),
          },
        } // Remove items with quantity 0
      );
    }

    res.cookie("_is_user_logged_in", isUserLoggedIn ? "true" : "false", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
    });

    const filteredCartItems = cartItems.filter(
      (item) => item.quantity > 0
    );


    return res
      .status(201)
      .json(
        new ApiResponse(
          201,
          { cart: { ...cart, cartItems: filteredCartItems } },
          "Cart updated successfully."
        )
      );
  } catch (error) {
    console.error("Error handling cart:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};
