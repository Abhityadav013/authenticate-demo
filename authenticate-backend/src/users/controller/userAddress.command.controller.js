
import ApiResponse from "../../utils/ApiResponse.js";
import UserAddress from "../models/userAddress.model.js";


export const registerAddress = async(req,res) =>{
    try{
        let isUserLoggedIn = req.cookies?._is_user_logged_in === "true";
        const userId = req.user ? req.user.id : null;

        const {
            street,
            flatNumber,
            buildingNumber,
            postalCode,
          } = req.body;

        if(!isUserLoggedIn && !userId){
            return res
            .status(400)
            .json(new ApiResponse(400, {}, "Please logged in for adding address"));
        }

        if (!street && !flatNumber && !buildingNumber && !postalCode) {
            return res
            .status(400)
            .json(new ApiResponse(400, {}, "Please fill all the required filed for the address."));
          }
      
          const address = new UserAddress({
            street,
            flatNumber,
            buildingNumber,
            postalCode,
            userId
          });

          await address.save()
          return res
          .status(200)
          .cookie("_guest_id", "", options)
          .cookie("_is_user_logged_in", "true", userLoggedInOption)
          .json(new ApiResponse(200, {address}, "Address Saved In Successfully"));
      } catch (err) {
        return res.status(500).json(new ApiResponse(500, {}, err.message));
      }
}
