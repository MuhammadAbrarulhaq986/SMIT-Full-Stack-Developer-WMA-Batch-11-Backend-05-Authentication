import User from "../models/users.models.js"
import jwt from "jsonwebtoken"
import bcrypt from "bcrypt"

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

    if (!email) return res.status(400).json({ message: "Email is Requried " });
    if (!password) return res.status(400).json({ message: "Password is Requried " });

    const user = await User.findOne({ email: email });
    if (user) return res.status(401).json({ message: "Usser already exist" })

    const createUser = await User.create({
        email,
        password,
    });
    res.json({ message: 'User registered successfully', data: createUser });
};


//Todo Login user 
const loginUser = async (req, res) => {
    const { email, password } = req.body;
    if (!email) return res.status(400).json({ message: 'Email is Required' })
    if (!password) return res.status(400).json({ message: 'Password is Required' })

    //* CHECK IF THE EMAIL IS PRESENT OR NOT
    const user = await User.findOne({ email })
    if (!user) return res.status(404).json({ message: "no user found" });

    //* COMPARE THE PASSWORD WITH THE BCRYPT ONE
    //! await IS NOT NOT WORKING HERE  
    // * const isValidPassword = await bcrypt.compare(password, user.password); 
    const isValidPassword = bcrypt.compare(password, user.password);
    if (!isValidPassword) return res.status(400).json({ message: "Incorrect password" })


    //* GENERATE TOKEN 
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user); //* WITHOUT refreshToken EXPORTED IT WILL CRACHES 


    //* ADDING COOKIES
    //* IN PRODUCTION WE CHANGE THIS TO ( true ) secure: false 
    //! res.cookie("refreshToken", refreshToken, { http: true, secure: false });
    res.cookie("refreshToken", refreshToken, { http: true, secure: false }); //* WITHOUT refreshToken EXPORTED IT WILL CRACHES
    //* { http: true, secure: false }: These are options for the cookie: 

    res.json({
        message: "User loggedIn successfully",
        accessToken,
        refreshToken, //* WITHOUT refreshToken EXPORTED IT WILL CRACHES
        data: user,
    })
}

// Todo  logout User
const logoutUser = async (req, res) => {
    res.clearCookie("refreshToken");
    res.json({ message: "User logout successfully" });
}

// Todo  refresh Token
const refreshToken = async (req, res) => {
    const refreshToken = req.cookies.refreshToken || req.body.refreshToken;
    if (!refreshToken) return res.status(401).json({ message: "No refresh token found!" });

    const decodedToken = jwt.verify(refreshToken, process.env.REFRESH_JWT_SECRET);
    const user = await User.findOne({ email: decodedToken.email });

    if (!user) return res.status(404).json({ message: "Invalid token" });

    const generateToken = generateAccessToken(user);
    res.json({ message: "Access token generated", accessToken: generateToken });

    res.json({ decodedToken })
}


// Todo  authenticate user middleware

export { registerUser, loginUser, logoutUser, refreshToken };