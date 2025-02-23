import { Router } from "express";
import { addToCart, cartAddons } from "../controller/cart.command.controller.js";
import { authenticateUser } from "../../middleware/authenticate.js";


const cartRouter = Router();

cartRouter.post("/cart",authenticateUser, addToCart);
cartRouter.put("/cart",authenticateUser, cartAddons);

export default cartRouter;
