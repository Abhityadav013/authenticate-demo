import { Router } from "express";
import { addToCart } from "../controller/cart.command.controller.js";
import { authenticateUser } from "../../middleware/authenticate.js";


const cartRouter = Router();

cartRouter.post("/cart",authenticateUser, addToCart);

export default cartRouter;
