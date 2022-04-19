const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const mongoosePaginate = require("mongoose-paginate-v2");

const UserSchema = new Schema({
  name: { type: String, required: true },
  phone_number: { type: String, required: true, minlength: 6 },
  password: { type: String, minlength: 5, required: true },
  user_type: { type: String, required: true },
  registeration_token: { type: String },
  store_name: { type: String },
  store_address: { type: String },
  store_city: { type: String },
  store_governorate: { type: String },
});

UserSchema.plugin(mongoosePaginate);

module.exports = mongoose.model("User", UserSchema);
