const HttpError = require("../models/Http-Error");
const jwt = require("jsonwebtoken");
const jwtSecret = process.env.JWT_SECRET;

module.exports = (req, res, next) => {
  try {
    const token = req.headers.authorization.split(" ")[1]; //Authorization "Bear Token"
    if (!token) throw new Error("Authentication failed");
    const decodedToken = jwt.verify(token, jwtSecret);
    req.userData = { userId: decodedToken.userId };
    next();
  } catch (error) {
    console.log(error);
    return next(new HttpError("Authentication failed", 401));
  }
};
