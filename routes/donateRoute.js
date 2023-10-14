const { Router } = require("express");
const { validateToken } = require("../middlewares/authMiddleware");
const {
  createDonation,
  listDonations,
  getDonation,
  updateDonation,
  deleteDonation,
} = require("../controllers/donateController");

const donateRoute = Router();

donateRoute.post("/create", validateToken, createDonation);
donateRoute.get("/list", validateToken, listDonations);
donateRoute.get("/retrieve/:id", validateToken, getDonation);
donateRoute.put("/update/:id", validateToken, updateDonation);
donateRoute.delete("/delete/:id", validateToken, deleteDonation);

module.exports = donateRoute;
