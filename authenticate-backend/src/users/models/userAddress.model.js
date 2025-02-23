import mongoose from "mongoose";
import { v4 as uuidv4 } from "uuid";

export const UserAddressSchemaName = "UserAddress"; // Collection name

const UserAddressSchema = new mongoose.Schema(
  {
    id: { type: String, required: true, default: uuidv4 },
    userId: { type: String, required: false },
    pincode: { type: String, required: true },
    buildingNumber: { type: String, required: true },
    flatNumber: { type: String, required: true },
    street: { type: String, required: true },
    displayAddress: { type: String, required: false },
    addressType:{type: String,required:true,default: 'home'}
  },
  { versionKey: false, collection: UserAddressSchemaName }
);

const UserAddress = mongoose.model("UserAddress", UserAddressSchema);
export default UserAddress;
