const mongoose = require("mongoose");
const validator = require("validator");

const DonationSchema = new mongoose.Schema({
  phoneNumber: {
    type: String,
  },
  ewasteType: {
    type: String,
  },
  donationAmount: {
    type: String,
  },
  fullName: {
    type: String,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  updatedAt: {
    type: Date,
    default: Date.now,
  },
});

const UserSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: true,
  },
  lastName: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    validate: {
      validator: validator.isEmail,
      isAsync: false,
    },
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
  donations: {
    type: [DonationSchema], // This is the nested array for donations
    default: [], // Initialize donations as an empty array
  },
});

module.exports = mongoose.model("User", UserSchema);
