const UserModel = require("../models/userModel.js");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

exports.homeAuth = async (req, res) => {
  res.send("You have logged in");
};

exports.loginAuth = async (req, res) => {
  const user = await UserModel.findOne({ email: req.body.email });

  if (!user) {
    return res.status(401).send("No user found");
  }

  const userAllowed = await bcrypt.compare(req.body.password, user.password);

  if (userAllowed) {
    const accessToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: 604800,
    });

    res.status(200).send({ accessToken: accessToken, user });
  } else {
    res.send("No user found or invalid password");
  }
};

exports.signupAuth = async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const newUser = new UserModel({
      firstName: req.body.firstName,
      lastName: req.body.lastName,
      email: req.body.email,
      password: hashedPassword,
    });

    const data = await newUser.save();
    console.log("Saved Successfully...");
    res.status(201).send(data);
  } catch (err) {
    console.error(err);
    res.status(500).send({ error: err, msg: "Something went wrong!" });
  }
};

exports.forgotPasswordAuth = async (req, res) => {
  const { email } = req.body;
  await UserModel.findOne({ email: email })
    .then((data) => {
      res.send(data.id);
    })
    .catch((err) => {
      console.log(err);
      res.status(500).send({ error: err, msg: "Something went wrong!" });
    });
};

exports.resetPasswordAuth = async (req, res) => {
  const { id } = req.params;
  console.log("Reset password request received for user ID:", id);

  // Extract the new password from the request body
  const newPassword = req.body.newPassword;

  try {
    if (!newPassword) {
      console.log("New password is missing.");
      res.status(400).json({ msg: "New password is missing." });
      return;
    }

    console.log("New Password:", newPassword); // Log the new password

    // Hash the new password using bcrypt
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    console.log("Hashed Password:", hashedPassword); // Log the hashed password

    // Update the user's password in the database with the hashed password
    const updatedUser = await UserModel.findByIdAndUpdate(id, {
      password: hashedPassword,
    });

    if (!updatedUser) {
      console.log("User not found.");
      res.status(404).json({ msg: "User not found." });
      return;
    }

    console.log("Password reset successful for user with ID:", id);
    res.json({ message: "Password reset successful" });
  } catch (error) {
    console.log("Error occurred during password reset for user with ID:", id);
    console.error(error);
    res.status(500).json({ error: error, msg: "Password reset failed." });
  }
};
