const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const cors = require("cors");
const UsersRoutes = require("./routes/UsersRoutes");
const HttpError = require("./models/Http-Error");

const app = express();
require("dotenv").config();
app.use(cors());

//swagger

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Origin,X-Requested-With,Content-Type,Authorization, multipart/form-data"
  );
  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, PATCH, PUT, DELETE, OPTIONS"
  );
  next();
});

//admin route here

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use("/v1/users", UsersRoutes);

app.use(() => {
  throw new HttpError("couldn't find this route", 404);
});

app.use((error, req, res, next) => {
  if (req.file) {
    fs.unlink(req.file.path, (err) => {
      console.log(err);
    });
  }
  if (req.headerSent) {
    return next(error);
  }
  res.status(error.code || 500);
  res.json({ message: error.message || "An unknown error occured" });
});

mongoose
  .connect(process.env.DB_CONNECT)
  .then(() => {
    app.listen(process.env.PORT || 5000, () => {
      console.log("listining on server");
    });
  })
  .catch((e) => {
    console.log(e);
  });
