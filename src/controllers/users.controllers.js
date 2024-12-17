import User from "../models/users.models.js";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

const generateAccessToken = (user) => {
    return jwt.sign({ email: user.email }, process.env.ACCESS_JWT_SECRET, {
        expiresIn: "6h",
    });
};

const generateRefreshToken = (user) => {
    return jwt.sign({ email: user.email }, process.env.REFRESH_JWT_SECRET, {
        expiresIn: "7d",
    });
};

// Todo Register user 
const registerUser = async (req, res) => {
    const { email, password } = req.body;

    if (!email) return res.status(400).json({ message: "Email is Required" });
    if (!password) return res.status(400).json({ message: "Password is Required" });

    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(401).json({ message: "User  already exists" });

    // Hash the password before saving
    const hashedPassword = await bcrypt.hash(password, 10);

    const createUser = await User.create({
        email,
        password: hashedPassword,
    });
    res.json({ message: 'User  registered successfully', data: createUser });
};

// Todo Login user 
const loginUser = async (req, res) => {
    const { email, password } = req.body;
    if (!email) return res.status(400).json({ message: 'Email is Required' });
    if (!password) return res.status(400).json({ message: 'Password is Required' });

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "No user found" });

    // Await the password comparison
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) return res.status(400).json({ message: "Incorrect password" });

    // Generate tokens
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    // Set the refresh token in cookies
    res.cookie("refreshToken", refreshToken, { httpOnly: true, secure: false });

    res.json({
        message: "User  logged in successfully",
        accessToken,
        refreshToken, // Include refresh token in the response if needed
        data: user,
    });
};

// Todo Logout User
const logoutUser = async (req, res) => {
    res.clearCookie("refreshToken");
    res.json({ message: "User  logged out successfully" });
};

// Todo Refresh Token
const refreshToken = async (req, res) => {
    const refreshToken = req.cookies.refreshToken || req.body.refreshToken;
    if (!refreshToken) return res.status(401).json({ message: "No refresh token found!" });

    try {
        const decodedToken = jwt.verify(refreshToken, process.env.REFRESH_JWT_SECRET);
        const user = await User.findOne({ email: decodedToken.email });

        if (!user) return res.status(404).json({ message: "Invalid token" });

        const newAccessToken = generateAccessToken(user);
        res.json({ message: "Access token generated", accessToken: newAccessToken });
    } catch (error) {
        return res.status(403).json({ message: "Invalid refresh token", error: error.message });
    }
};

// Todo authenticate user middleware

export { registerUser, loginUser, logoutUser, refreshToken };