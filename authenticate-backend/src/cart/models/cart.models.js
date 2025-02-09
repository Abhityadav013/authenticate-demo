import mongoose from "mongoose";
import { v4 as uuidv4 } from "uuid";

export const UserCartSchemaName = "Cart"; // Collection name

const UserCartSchema = new mongoose.Schema(
  {
    id: {
      type: String,
      required: true,
      default: uuidv4, // Generate UUID as default
    },
    cartItems: [
      {
        itemId: {
          type: String,
          required: true,
        },
        itemName: {
          type: String,
          required: true,
        },
        quantity: {
          type: Number,
          required: true,
          default: 0, // Default quantity is 1
        },
        addons: {
          type: [String], // Optional addons
          default: [],
        },
      },
      {
        _id: false,
      },
    ],
    deviceId: {
      type: String,
      required: true,
    },
    userId: {
      type: String,
      required: false, // Required only when logged in
    },
  },
  {
    versionKey: false,
    collection: UserCartSchemaName, // Correct reference
  }
);

const Cart = mongoose.model("Cart", UserCartSchema);
export default Cart;
