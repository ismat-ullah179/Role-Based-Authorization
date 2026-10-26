const jwt = require("jsonwebtoken");
const User = require("../models/User");

const authMiddleware = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization; // request ke headers se token leta hai.

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      // token bhejne ka standard format hai.
      return res.status(401).json({
        message: "Access Token is required",
      });
    }

    const token = authHeader.split(" ")[1]; // token bhejne ka standard format hai.

    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET); //decoded token ka data aglay handler ke liye save karta hai. Tumhare token mein userId hai

    // req.user = decoded;

    const user = await User.findById(decoded.userId).select(
      "_id name email role",
    );

    if (!user) {
      return res.status(401).json({
        message: "User not Found",
      });
    }
    req.user = {
      userId: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
    };

    next(); // token valid ho to request ko aglay function tak jaane deta hai.
  } catch (error) {
    res.status(401).json({
      message: "Invalid or Expired Access Token",
    });
  }
};

module.exports = authMiddleware;
