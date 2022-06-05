const User = require("../../models/User");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { JWT_EXP_MS, JWT_SECRET } = require("../../config/keys");

exports.signin = async (req, res, next) => {
  try {
    // const payload = {
    //   _id: req.user._id,
    //   username: req.user.username,
    //   exp: Date.now() + JWT_EXP_MS,
    // };
    // const token = jwt.sign(payload, JWT_SECRET);
    const token = generateToken(req.user);
    res.json({ token });
  } catch (err) {
    next(err);
  }
};

exports.signup = async (req, res) => {
  try {
    const { password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    req.body.password = hashedPassword;
    const newUser = await User.create(req.body);
    const token = generateToken(newUser);
    res.status(201).json({ token });
  } catch (err) {
    res.status(500).json("Server Error");
  }
};

exports.getUsers = async (req, res) => {
  try {
    const users = await User.find().populate("urls");
    res.status(201).json(users);
  } catch (err) {
    res.status(500).json("Server Error");
  }
};

const generateToken = (user) => {
  const payload = {
    _id: user._id,
    username: user.username,
    exp: Date.now() + JWT_EXP_MS,
  };
  const token = jwt.sign(payload, JWT_SECRET);
  return token;
};
