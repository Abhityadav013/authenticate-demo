import { Router } from "express";
import { authenticateUser } from "../../middleware/authenticate.js";
import { registerAddress } from "../controller/userAddress.command.controller.js";

const userAddressRouter = Router();


/**
 * @swagger
 * /api/v1/address:
 *   post:
 *     tags:
 *       - Address
 *     summary: Register a new address
 *     description: Adds a new address for the logged-in user
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               street:
 *                 type: string
 *                 example: "Skujenes iela"
 *               flatNumber:
 *                 type: string
 *                 example: "A-12"
 *               buildingNumber:
 *                 type: string
 *                 example: "9"
 *               postalCode:
 *                 type: string
 *                 example: "LV-1055"
 *     responses:
 *       200:
 *         description: Address saved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 statusCode:
 *                   type: integer
 *                   example: 200
 *                 data:
 *                   type: object
 *                   properties:
 *                     address:
 *                       type: object
 *                       properties:
 *                         id:
 *                           type: string
 *                           example: "550e8400-e29b-41d4-a716-446655440000"
 *                         userId:
 *                           type: string
 *                           example: "650e8400-e29b-41d4-a716-446655440000"
 *                         street:
 *                           type: string
 *                           example: "Skujenes iela"
 *                         flatNumber:
 *                           type: string
 *                           example: "A-12"
 *                         buildingNumber:
 *                           type: string
 *                           example: "9"
 *                         postalCode:
 *                           type: string
 *                           example: "LV-1055"
 *                 message:
 *                   type: string
 *                   example: "Address Saved Successfully"
 *       400:
 *         description: Missing required fields or user not logged in
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 statusCode:
 *                   type: integer
 *                   example: 400
 *                 message:
 *                   type: string
 *                   example: "Please fill all the required fields for the address."
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 statusCode:
 *                   type: integer
 *                   example: 500
 *                 message:
 *                   type: string
 *                   example: "Internal Server Error"
 */
userAddressRouter.post("/address", authenticateUser, registerAddress);

export default userAddressRouter;
