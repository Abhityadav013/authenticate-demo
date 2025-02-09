import mongoose from "mongoose";
import { v4 as uuidv4 } from "uuid";

export const UserSessionSchemaName = "Session"; // Collection name

const UserSessionSchema = new mongoose.Schema(
  {
    id: {
      type: String,
      required: true,
      default: uuidv4, // Generate a UUID as the default value for the id field
    },
    guestId: {
      type: String,
      required: true,
    },
    latitude: { type: String, required: false },
    longitude: { type: String, required: false },
  },
  {
    versionKey: false,
    collection: UserSessionSchemaName, // Correctly reference UserSchemaName here
  }
);

// Model name is 'User', but the collection will be 'Users'
const UserSession = mongoose.model("Session", UserSessionSchema);

export default UserSession;
