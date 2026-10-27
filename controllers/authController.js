const bcrypt = require("bcrypt");
const User = require("../models/User");
const RefreshToken = require("../models/RefreshToken");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const hashToken = (token) => {
  return crypto.createHash("sha256").update(token).digest("hex");
};

const register = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        message: "Enter into the fields first",
      });
    }
    //if user Already registered
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({
        message: "Email already Registered",
      });
    }

    //hashing the password
    const hashedPassword = await bcrypt.hash(password, 12);

    //creating data to user Model
    const user = await User.create({
      name,
      email,
      password: hashedPassword,
    });
    return res.status(201).json({
      message: "User Registered SuccessFully",
      user: user,
    });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({
        message: "Email already registered",
      });
    }

    console.error(error);
    return res.status(500).json({
      message: "Internal server error",
    });
  }
};

// login
const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({
        message: "Please Enter Email & Password",
      });
    }
    const user = await User.findOne({
      email: email.toLowerCase().trim(),
    });

    if (!user) {
      return res.status(404).json({
        message: "Invalid Email or Password",
      });
    }
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({
        message: "Invalid Email or Password",
      });
    }

    const accessToken = jwt.sign(
      { userId: user._id },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: "15m" },
    );
    const refreshToken = jwt.sign(
      { userId: user._id },
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: "7d" },
    );

    // ab refresh token ko db me store kraty hain
    await RefreshToken.create({
      userId: user._id,
      token: hashToken(refreshToken),
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    return res.status(200).json({
      message: "Login Successfully",
      accessToken,
      refreshToken,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    console.error("Login Error:", error);

    return res.status(500).json({
      message: "Internal Error",
      error: error.message,
    });
  }
};

// admin route
const admin = (req, res) => {
  return res.status(200).json({
    message: "Welcome to Admin Dashboard",
    user: req.user,
  });
};

// Users list
const getAllUsers = async (req, res) => {
  try {
    const users = await User.find().select("-password");
    return res.status(200).json({
      message: "Users Fetched Successfully",
      totalUsers: users.length,
      users,
    });
  } catch (error) {
    return res.status(500).json({
      message: "Internal Server Error",
    });
  }
};

// getUserById
const getUserById = async (req, res) => {
  try {
    const { id } = req.params;
    if (!id) {
      return res.status(404).json({
        message: "Please Find By ID",
      });
    }

    const user = await User.findById(id).select("-password"); // -pass meant exclude pass
    if (!user) {
      return res.status(404).json({
        message: "User Not Found",
      });
    }

    return res.status(200).json({
      message: "User Found",
      user,
    });
  } catch (error) {
    console.error("Get User By ID Error:", error);

    if (error.name === "CastError") {
      return res.status(400).json({
        message: "Invalid user ID",
      });
    }
    return res.status(500).json({
      message: "Internal Server Error",
    });
  }
};

// update user
const updateUser = async (req, res) => {
  try {
    const { id } = req.params;
    const { name, email } = req.body;
    if (!name && !email) {
      return res.status(404).json({
        message: "Please Provide Name or Email to Update",
      });
    }

    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({
        message: "User not Found",
      });
    }

    if (name !== undefined) {
      if (!name.trim()) {
        return res.status(404).json({
          message: "Name Can't be Empty",
        });
      }
      user.name = name.trim();
    }

    if (email !== undefined) {
      if (!email.trim()) {
        return res.status(404).json({
          message: "Email Can't be Empty",
        });
      }

      const normalizedEmail = email.trim().toLowerCase();

      const existingUser = await User.findOne({
        email: normalizedEmail,
        _id: { $ne: user._id },
      });

      if (existingUser) {
        return res.status(409).json({
          message: "Email Already Exists",
        });
      }

      user.email = normalizedEmail;
    }
    await user.save();

    return res.status(200).json({
      message: "User Updated Successfully",
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error("Update User Error:", error);

    if (error.name === "CastError") {
      return res.status(400).json({
        message: "Invalid user ID",
      });
    }

    if (error.code === 11000) {
      return res.status(409).json({
        message: "Email already in use",
      });
    }

    return res.status(500).json({
      message: "Internal Server Error",
    });
  }
};

// delete user
const deleteUser = async (req, res) => {
  try {
    const { id } = req.params;
    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({
        message: "User Not Found",
      });
    }
    await User.findByIdAndDelete(id);
    return res.status(200).json({
      message: "User Deleted Successfully",
    });
  } catch (error) {
    console.error("Delete User Error:", error);

    if (error.name === "CastError") {
      return res.status(400).json({
        message: "Invalid user ID",
      });
    }
    return res.status(500).json({
      message: "Internal Error",
    });
  }
};

// profile
const profile = (req, res) => {
  try {
    return res.status(200).json({
      message: "Protected Profile accessed",
      user: req.user,
    });
  } catch (error) {
    return res.status(401).json({
      message: "Invalid Route",
    });
  }
};

// refreshToken
const refreshAccessToken = async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      return res.status(401).json({
        message: "Refresh Token Required",
      });
    }
    // Verify refresh token signature and expiry
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);

    // Check whether token exists in database
    const storedToken = await RefreshToken.findOne({
      token: hashToken(refreshToken),
      userId: decoded.userId,
    });

    if (!storedToken || storedToken.expiresAt <= new Date()) {
      return res.status(401).json({
        message: "Refresh token revoked or expired",
      });
    }

    // Generate a new access token
    const accessToken = jwt.sign(
      { userId: decoded.userId },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: "15m" },
    );

    return res.status(200).json({
      message: "access Token Refreshed Successfully",
      accessToken,
    });
  } catch (error) {
    return res.status(401).json({
      message: "Refresh Token expired",
    });
  }
};

const logout = async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      return res.status(401).json({
        message: "Refresh Token Required",
      });
    }

    // const matchedToken = await RefreshToken.findOne({ token: refreshToken });
    // console.log("matchedToken", !!matchedToken);

    const deletedToken = await RefreshToken.findOneAndDelete({
      token: hashToken(refreshToken),
    });

    if (!deletedToken) {
      return res.status(200).json({
        message: "Already Logged out",
      });
    }

    return res.status(200).json({
      message: "Logged Out Successfully",
    });
  } catch (error) {
    return res.status(500).json({
      message: "Internal Error",
    });
  }
};

module.exports = {
  register,
  login,
  profile,
  refreshAccessToken,
  logout,
  getAllUsers,
  admin,
  deleteUser,
  updateUser,
  getUserById,
};
