const UserModel = require("../models/userModel");

// Create a new donation
// Create a new donation
exports.createDonation = async (req, res) => {
  try {
    const { phoneNumber, ewasteType, donationAmount } = req.body;
    const userId = req.user._id; // Using user._id to identify the user

    console.log("Received userId:", userId); // Log the userId

    const user = await UserModel.findById(userId);

    if (!user) {
      console.log("User not found in the database");
      return res.status(404).json({ msg: "User not found" });
    }

    console.log("Found user in the database:", user); // Log the user

    const newDonation = {
      phoneNumber,
      ewasteType,
      donationAmount,
      fullName: user.firstName + " " + user.lastName,
    };

    user.donations.push(newDonation);
    await user.save();

    const donationData = user.donations[user.donations.length - 1];

    res.status(201).json(donationData);
  } catch (error) {
    console.error("Create Donation Error:", error);
    res
      .status(500)
      .json({ error: error.message, msg: "Something went wrong!" });
  }
};

// Get all donations for the logged-in user
exports.listDonations = async (req, res) => {
  try {
    const { userId } = req.user; // Use req.user to get the user ID

    if (!userId) {
      console.log("User not authenticated"); // Log when the user is not authenticated
      return res.status(401).json({ msg: "User not authenticated" });
    }

    const user = await UserModel.findById(userId);

    if (!user) {
      console.error("User not found in the database");
      return res.status(404).json({ msg: "User not found" });
    }

    const donations = user.donations;

    // Add a console log to indicate successful retrieval
    console.log("Donations retrieved successfully");

    res.status(200).json(donations);
  } catch (err) {
    console.error("List Donations Error:", err);
    res.status(500).json({ error: err, msg: "Something went wrong!" });
  }
};

// Get a single donation by ID
exports.getDonation = async (req, res) => {
  try {
    const { userId } = req.user; // Use req.user to get the user ID

    if (!userId) {
      console.log("User not authenticated"); // Log when the user is not authenticated
      return res.status(401).json({ msg: "User not authenticated" });
    }

    const user = await UserModel.findById(userId);

    if (!user) {
      console.error("User not found in the database");
      return res.status(404).json({ msg: "User not found" });
    }

    const donationId = req.params.id;

    console.log("Found user in the database:", user);
    console.log("Retrieving donation with ID:", donationId);

    const donation = user.donations.find(
      (d) => d._id.toString() === donationId
    );

    if (!donation) {
      console.error("Donation not found");
      return res.status(404).json({ msg: "Donation not found" });
    }

    // Add a console log to indicate successful retrieval
    console.log("Donation retrieved successfully");

    res.status(200).json(donation);
  } catch (err) {
    console.error("Get Donation Error:", err);
    res.status(500).json({ error: err, msg: "Something went wrong!" });
  }
};

// Update a donation by ID
exports.updateDonation = async (req, res) => {
  try {
    // Get the user ID from the token
    const userId = req.user._id;

    // Find the user
    const user = await UserModel.findById(userId);

    if (!user) {
      return res.status(404).json({ msg: "User not found" });
    }

    const donationIndex = user.donations.findIndex(
      (d) => d._id.toString() === req.params.id
    );

    if (donationIndex === -1) {
      return res.status(404).json({ msg: "Donation not found" });
    }

    // Update donation properties based on req.body data
    const updatedDonation = user.donations[donationIndex];
    updatedDonation.phoneNumber = req.body.phoneNumber;
    updatedDonation.ewasteType = req.body.ewasteType;
    updatedDonation.donationAmount = req.body.donationAmount;
    updatedDonation.fullName = `${user.firstName} ${user.lastName}`; // Update fullName

    user.donations[donationIndex] = updatedDonation;

    await user.save();

    res.status(200).json(updatedDonation);
  } catch (err) {
    console.error("Update Donation Error:", err);
    res.status(500).json({ error: err, msg: "Something went wrong!" });
  }
};

// Delete a donation by ID
exports.deleteDonation = async (req, res) => {
  try {
    // You can directly access the user information from req.user
    const user = req.user;

    if (!user) {
      return res.status(404).json({ msg: "User not found" });
    }

    const donationIndex = user.donations.findIndex(
      (d) => d._id.toString() === req.params.id
    );

    if (donationIndex === -1) {
      return res.status(404).json({ msg: "Donation not found" });
    }

    user.donations.splice(donationIndex, 1);

    await user.save();

    res.status(204).end();
  } catch (err) {
    console.error("Delete Donation Error:", err); // Log the error
    res.status(500).json({ error: err, msg: "Something went wrong!" });
  }
};
