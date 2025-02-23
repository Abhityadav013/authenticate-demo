import mongoose from "mongoose";
import { v4 as uuidv4 } from "uuid";

export const UserSchemaName = "Users"; // Collection name

const UserSchema = new mongoose.Schema(
  {
    id: {
      type: String,
      required: true,
      default: uuidv4, // Generate a UUID as the default value for the id field
    },
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: function() { return !this.googleId; } },
    verifyOtp: { type: String, default: "" },
    verifyOtpExpireAt: { type: Number, default: 0 },
    isAccountVerified: { type: Boolean, default: false },
    resetOtp: { type: String, default: "" },
    resetOtpExpireAt: { type: Number, default: 0 },
    refreshToken: { type: String, default: "" },
    googleId: { type: String, default: "" },
    avatarUrl: { type: String, default: "" },
  },
  {
    versionKey: false,
    collection: UserSchemaName, // Correctly reference UserSchemaName here
  }
);

// Model name is 'User', but the collection will be 'Users'
const User = mongoose.model("User", UserSchema);

export default User;
