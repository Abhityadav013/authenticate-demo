import { Router } from "express";
import { sessionRegister } from "../controller/session.command.controller.js";

const sessionRouter = Router();

sessionRouter.get("/", sessionRegister);

export default sessionRouter;
