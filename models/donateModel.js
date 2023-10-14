// const mongoose = require("mongoose");

// const donateSchema = new mongoose.Schema({
//   user: {
//     type: mongoose.Schema.Types.ObjectId,
//     ref: "User",
//     required: true, // You can adjust this requirement based on your application's logic
//   },
//   phoneNumber: {
//     type: String,
//   },
//   ewasteType: {
//     type: String,
//   },
//   donationAmount: {
//     type: String, // Assuming donation amount can be a string, you can adjust this to match your data type
//   },
//   // Add any other fields you need for donation data

//   // Timestamps for when the donation was created and last updated
//   createdAt: {
//     type: Date,
//     default: Date.now,
//   },
//   updatedAt: {
//     type: Date,
//     default: Date.now,
//   },
// });

// const DonateModel = mongoose.model("Donation", donateSchema);

// module.exports = DonateModel;
