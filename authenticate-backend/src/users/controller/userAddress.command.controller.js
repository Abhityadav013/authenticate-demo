
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
            displayAddress,
            pincode,
            addressType
          } = req.body.address;

        if(!isUserLoggedIn && !userId){
            return res
            .status(400)
            .json(new ApiResponse(400, {}, "Please logged in for adding address"));
        }

        if (!street && !flatNumber && !buildingNumber && !pincode) {
            return res
            .status(400)
            .json(new ApiResponse(400, {}, "Please fill all the required filed for the address."));
          }
      
          const address = new UserAddress({
            street,
            flatNumber,
            buildingNumber,
            displayAddress,
            pincode,
            userId,addressType
          });

          await address.save()

          return res
          .status(200)
          .json(new ApiResponse(200, {address:address}, "Address Saved In Successfully"));
      } catch (err) {
        return res.status(500).json(new ApiResponse(500, {}, err.message));
      }
}

export const fetchAddress = async (req, res) => {
  try {
    const userId = req.user ? req.user.id : null;
    console.log('userId>>>>',userId)


    if (!userId) {
      return res
        .status(400)
        .json(new ApiResponse(400, {}, "Please log in to view addresses"));
    }

    const addresses = await UserAddress.find({ userId }).select('-userId -_id');
    return res
      .status(200)
      .json(new ApiResponse(200, { addresses }, "Fetched addresses successfully"));
  } catch (err) {
    console.error("Error fetching addresses:", err);
    return res.status(500).json(new ApiResponse(500, {}, err.message));
  }
};
