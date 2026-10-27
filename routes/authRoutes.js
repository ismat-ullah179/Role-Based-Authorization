const express = require("express");
const authMiddleware = require("../middleware/authMiddleware");
const authorizeRole = require("../middleware/authorizeRole");

const {
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
} = require("../controllers/authController");
const User = require("../models/User");
const router = express.Router();

router.post("/register", register);
router.post("/login", login);
router.get("/profile", authMiddleware, profile);
router.post("/Refresh-Token", refreshAccessToken);
router.post("/logout", logout);
router.delete("/users/:id", authMiddleware, authorizeRole("admin"), deleteUser);
router.put("/users/:id", authMiddleware, authorizeRole("admin"), updateUser);
router.post("/users/:id", authMiddleware, authorizeRole("admin"), getUserById);

router.get("/users", authMiddleware, authorizeRole("admin"), getAllUsers);

router.get("/admin", authMiddleware, authorizeRole("admin"), admin);

module.exports = router;
