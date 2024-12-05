import express from "express";
import { loginUser, logoutUser, refreshToken, registerUser } from "../controllers/users.controllers.js";

const router = express.Router();

//* Register User
router.post("/register", registerUser);
router.post("/login", loginUser);
router.post("/logout", logoutUser);
router.post("/refreshToken", refreshToken);


export default router;