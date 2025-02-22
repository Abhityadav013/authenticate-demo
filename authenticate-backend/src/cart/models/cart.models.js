import mongoose from "mongoose";
import { v4 as uuidv4 } from "uuid";

export const UserCartSchemaName = "Cart"; // Collection name

const CartItemSchema = new mongoose.Schema(
  {
    itemId: { type: String, required: true },
    itemName: { type: String, required: true },
    quantity: { type: Number, required: true, default: 0 },
    addons: { type: [String], default: [] },
  },
  { _id: false } // ✅ This removes `_id` from cartItems
);

const UserCartSchema = new mongoose.Schema(
  {
    id: { type: String, required: true, default: uuidv4 }, // Unique identifier
    cartItems: [CartItemSchema], // ✅ Use a separate schema with _id disabled
    deviceId: { type: String, required: true },
    userId: { type: String, required: false },
  },
  { versionKey: false, collection: UserCartSchemaName }
);

const Cart = mongoose.model("Cart", UserCartSchema);
export default Cart;
