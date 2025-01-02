const express = require("express");
const jwt = require('jsonwebtoken');
const { loginUser, registerUser } = require("../controllers/authController");
const router = express.Router();

router.post("/login", loginUser);
router.post("/register", registerUser);

module.exports = router;