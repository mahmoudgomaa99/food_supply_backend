require("dotenv").config();
const HttpError = require("../models/Http-Error");
const User = require("../models/User");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const jwtSecret = process.env.JWT_SECRET;
const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const client = require("twilio")(accountSid, authToken);
const otpGenrator = require("../utils/otp_generating");

const createUser = async (req, res, next) => {
  const {
    phone_number,
    user_type,
    registeration_token,
    name,
    password,
    store_name,
    store_address,
    store_city,
    store_governorate,
  } = req.body;
  if (
    !phone_number ||
    !user_type ||
    !name ||
    !password ||
    !store_name ||
    !store_address ||
    !store_city ||
    !store_governorate
  ) {
    return next(
      new HttpError("invalid credintials, please check your data", 422)
    );
  }
  let existingUser;

  try {
    existingUser = await User.findOne({
      phone_number: phone_number,
    });
  } catch (error) {
    return next(new HttpError("signing up failed please try again", 500));
  }

  if (existingUser) {
    return res
      .status(201)
      .json({ message: "User exists already, please login instead." });
  }

  let hashedPassword;

  try {
    hashedPassword = await bcrypt.hash(password, 12);
  } catch (error) {
    return next(new HttpError("signing up failed please try again", 500));
  }

  const createdUser = new User({
    phone_number,
    user_type,
    registeration_token,
    name,
    password: hashedPassword,
    store_name,
    store_address,
    store_city,
    store_governorate,
  });

  try {
    await createdUser.save();
  } catch (error) {
    return next(new HttpError("signing up failed please try again", 500));
  }

  let token;
  try {
    token = jwt.sign(
      {
        userId: createdUser.id,
        phone_number: createdUser.phone_number,
      },
      jwtSecret,
      { expiresIn: "350d" }
    );
  } catch (error) {
    return next(new HttpError("signing up failed please try again", 500));
  }
  res.setHeader("token", token);
  res.status(201).json({ user: createdUser });
};

const login = async (req, res, next) => {
  const { phone_number, password, registeration_token } = req.body;
  if (!phone_number || !password) {
    return next(
      new HttpError("invalid credintials, please check your data", 422)
    );
  }
  let existingUser;
  try {
    existingUser = await User.findOne({ phone_number: phone_number });
  } catch (error) {
    return next(new HttpError("logging in failed please try again", 500));
  }
  if (!existingUser) {
    return next(
      new HttpError(
        "There is no user with the provided phone number, please sign up first",
        401
      )
    );
  }
  let isValidatePaassword = false;
  try {
    isValidatePaassword = await bcrypt.compare(password, existingUser.password);
  } catch (error) {
    return next(new HttpError("logging in failed please try again", 500));
  }
  if (!isValidatePaassword) {
    return next(
      new HttpError(
        "couldn't log you in, please check your phone number or paswword and try again",
        401
      )
    );
  }

  existingUser.registeration_token = registeration_token;
  try {
    await existingUser.save();
  } catch (error) {
    return next(new HttpError("logging in failed please try again", 500));
  }

  let token;
  try {
    token = jwt.sign(
      {
        userId: existingUser.id,
        phone_number: existingUser.phone_number,
      },
      jwtSecret,
      { expiresIn: "350d" }
    );
  } catch (error) {
    return next(new HttpError("logging in failed please try again", 500));
  }
  res.setHeader("token", token);
  res.status(201).json({ user: existingUser });
};

const updateUser = async (req, res, next) => {
  const { uid } = req.headers;
  const { name, store_name, store_address, store_city, store_governorate } =
    req.body;
  let currentUser;
  try {
    currentUser = await User.findById(uid);
  } catch (error) {
    return next(
      new HttpError("failed updating the user, please try again", 500)
    );
  }
  if (!currentUser) {
    return next(
      new HttpError("couldn't find a user with the provided id", 401)
    );
  }
  if (name) {
    currentUser.name = name;
  }
  if (store_name) {
    currentUser.store_name = store_name;
  }
  if (store_address) {
    currentUser.store_address = store_address;
  }
  if (store_city) {
    currentUser.store_city = store_city;
  }
  if (store_governorate) {
    currentUser.store_governorate = store_governorate;
  }

  try {
    await currentUser.save();
  } catch (error) {
    console.log(error);
    return next(
      new HttpError("failed updating the user, please try again", 500)
    );
  }
  res.status(201).json({ user: currentUser });
};

const sendOtp = async (req, res, next) => {
  const { phone_number } = req.body;
  if (!phone_number) {
    return next(
      new HttpError("invalid credintials, please check your data", 422)
    );
  }
  const otp = otpGenrator();
  try {
    await client.messages.create({
      to: phone_number,
      from: "+19302057185",
      body: `Your Food Supply App OTP is ${otp}`,
    });
  } catch (error) {
    console.log(error);
    return next(new HttpError("failed sending the otp, please try again", 500));
  }
  res.status(201).json({ otp });
};

const deleteUser = async (req, res, next) => {
  const { uid } = req.headers;
  if (!uid) {
    return next(new HttpError("invalid inputs, please check your data", 422));
  }
  let currentUser;
  try {
    currentUser = await User.findById(uid);
  } catch (error) {
    return next(
      new HttpError("couldn't delete the user, please try again", 500)
    );
  }
  if (!currentUser) {
    return next(
      new HttpError("couldn't find a user with the provided id", 401)
    );
  }
  try {
    await currentUser.delete();
  } catch (error) {
    new HttpError("couldn't delete the user, please try again", 500);
  }
  res.status(201).json({ message: "user deleted succssfully" });
};

const fetchUser = async (req, res, next) => {
  const { uid } = req.headers;
  if (!uid) {
    return next(new HttpError("invalid inputs, please check your data", 422));
  }
  let user;
  try {
    user = await User.findById(uid);
  } catch (error) {
    return next(new HttpError("couldn't get the user, please try again", 500));
  }
  if (!user) {
    return next(
      new HttpError("couldn't find a user with the provided id", 401)
    );
  }
  res.status(201).json({ user: user });
};

const fetchUserById = async (req, res, next) => {
  const { uid } = req.headers;
  const { id } = req.query;
  if (!id) {
    return next(new HttpError("invalid inputs, please check your data", 422));
  }
  let user;
  try {
    user = await User.findById(id);
  } catch (error) {
    return next(new HttpError("couldn't get the user, please try again", 500));
  }
  if (!user) {
    return next(
      new HttpError("couldn't find a user with the provided id", 401)
    );
  }
  res.status(201).json({ user: user });
};

const changePassword = async (req, res, next) => {
  const { uid } = req.headers;
  const { oldPassword, newPassword } = req.body;
  if ((!uid, !oldPassword, !newPassword)) {
    return next(
      new HttpError("invalid credintials, please check your data", 422)
    );
  }
  if (newPassword.length < 6) {
    return next(new HttpError("password must be at least 6 charachters", 420));
  }
  let currentUser;
  try {
    currentUser = await User.findById(uid);
  } catch (error) {
    return next(
      new HttpError("failed changing the password, please try again", 500)
    );
  }
  if (!currentUser) {
    return next(
      new HttpError("couldn't find a user with the provided id", 401)
    );
  }
  let isValidatePaassword = false;
  try {
    isValidatePaassword = await bcrypt.compare(
      oldPassword,
      currentUser.password
    );
  } catch (error) {
    return next(
      new HttpError("failed changing the password, please try again", 500)
    );
  }
  if (!isValidatePaassword) {
    return next(
      new HttpError(
        "the password you provided is not correct, please try again",
        421
      )
    );
  }
  let hashedPassword;
  try {
    hashedPassword = await bcrypt.hash(newPassword, 12);
  } catch (error) {
    return next(
      new HttpError("failed changing the password, please try again", 500)
    );
  }
  currentUser.password = hashedPassword;
  try {
    await currentUser.save();
  } catch (error) {
    return next(
      new HttpError("failed changing the password, please try again", 500)
    );
  }
  res.status(201).json({ message: "password changed successfully" });
};

const forgetPassword = async (req, res, next) => {
  const { phone_number } = req.body;
  if (!phone_number) {
    return next(
      new HttpError("invalid credintials, please check your data", 422)
    );
  }
  let existingUser;
  try {
    existingUser = await User.findOne({ phone_number: phone_number });
  } catch (error) {
    return next(
      new HttpError("failed changing the password, please try again", 500)
    );
  }
  if (!existingUser) {
    return next(
      new HttpError(
        "There is no user with the provided phone number, please sign up first",
        401
      )
    );
  }
  const randomPassword = Math.random().toString(36).slice(-8);
  try {
    await client.messages.create({
      to: phone_number,
      from: "+19302057185",
      body: `Your Food Supply App new password is ${randomPassword}`,
    });
  } catch (error) {
    return next(
      new HttpError("failed retrieving the password, please try again", 500)
    );
  }
  let hashedPassword;
  try {
    hashedPassword = await bcrypt.hash(randomPassword, 12);
  } catch (error) {
    return next(new HttpError("signing up failed please try again", 500));
  }
  existingUser.password = hashedPassword;
  try {
    await existingUser.save();
  } catch (error) {
    return next(
      new HttpError("failed retrieving the password, please try again", 500)
    );
  }
  res
    .status(201)
    .json({ message: "a new password is sent to your phone number(SMS)" });
};

exports.createUser = createUser;
exports.login = login;
exports.updateUser = updateUser;
exports.sendOtp = sendOtp;
exports.deleteUser = deleteUser;
exports.fetchUser = fetchUser;
exports.changePassword = changePassword;
exports.forgetPassword = forgetPassword;
exports.fetchUserById = fetchUserById;
