import ApiResponse from "../../utils/ApiResponse.js";
import Cart from "../models/cart.models.js";

export const addToCart = async (req, res) => {
  try {
    let deviceId = req.cookies?._device_id;
    let isUserLoggedIn = req.cookies?._is_user_logged_in === "true";
    const userId = req.user ? req.user.id : null; // Extract userId if logged in

    // Find cart based on userId or deviceId

    let cartFilter = { $or: [{ deviceId }] };
    if (userId) {
      cartFilter["$or"].push({ userId });
    }

    let cart = await Cart.findOne({
      ...cartFilter,
      "cartItems.quantity": { $gt: 0 },
    }).select("-_id")
    if (!req.body.cart) {

      return res.status(200).json(
        new ApiResponse(
          200,
          {
            ...cart || {}
          },
          cart ? "Cart retrieved successfully." : "Cart is empty."
        )
      );
    }

    // 👉 If body is provided, update the cart
    const { cart: cartItems } = req.body;

    if (!Array.isArray(cartItems) || cartItems.length === 0) {
      return res
        .status(400)
        .json({ message: "Cart items should be a non-empty array" });
    }

    if (!cart) {
      // Create a new cart if not found
      cart = new Cart({
        deviceId,
        userId: userId || undefined, // Store only if user is logged in
        cartItems: cartItems
          .filter(({ quantity }) => quantity > 0) // ✅ Only store items with quantity > 0
          .map(({ itemId, itemName, quantity, addons }) => ({
            itemId,
            itemName,
            quantity,
            addons: addons || [],
          })),
      });
    } else {
      // Update existing cart
      cartItems.forEach(({ itemId, itemName, quantity, addons }) => {
        const existingItem = cart.cartItems.find(
          (item) => item.itemId === itemId
        );

        if (existingItem) {
          if (quantity > 0) {
            existingItem.quantity = quantity; // Update quantity
            if (addons) {
              existingItem.addons = addons; // Update addons if provided
            }
          } else {
            // Remove item if quantity is 0 or less
            cart.cartItems = cart.cartItems.filter(
              (item) => item.itemId !== itemId
            );
          }
        } else if (quantity > 0) {
          // Add a new item if quantity > 0
          cart.cartItems.push({
            itemId,
            itemName,
            quantity,
            addons: addons || [],
          });
        }
      });
    }

    // Save updated cart
    await cart.save();

    const options = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
    };

    // Set the user logged-in status in cookies
    res.cookie(
      "_is_user_logged_in",
      isUserLoggedIn ? "true" : "false",
      options
    );

    // Return cart with only valid items
    const filteredCartItems = cart.cartItems.filter(
      (item) => item.quantity > 0
    );

    return res
      .status(201)
      .json(
        new ApiResponse(
          201,
          { cart: { ...cart.toObject(), cartItems: filteredCartItems } },
          "Cart updated successfully."
        )
      );
  } catch (error) {
    console.error("Error handling cart:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};
