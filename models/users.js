const mongoose = require("mongoose");
const validator = require("validator");
const { Schema, Types } = mongoose;
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const schema = new mongoose.Schema({
  isAdmin: {
    type: Boolean,
    default: false
  },
  isTeacher: {
    type: Boolean,
    default: false
  },
  firstName: {
    type: String,
    required: true,
    trim: true,
    validate(value) {
      let re = new RegExp("^[a-zA-ZàáâäãåąčćęèéêëėįìíîïłńòóôöõøùúûüųūÿýżźñçčšžÀÁÂÄÃÅĄĆČĖĘÈÉÊËÌÍÎÏĮŁŃÒÓÔÖÕØÙÚÛÜŲŪŸÝŻŹÑßÇŒÆČŠŽ∂ð ,.'-]+$");
      if (validator.isEmpty(value)) {
        throw new Error("First name cannot be empty");
      } else if (!re.test(value)) {
        throw new Error("First name contains certain characters that aren't allowed");
      }
    },
  },
  lastName: {
    type: String,
    required: true,
    trim: true,
    validate(value) {
      let re = new RegExp("^[a-zA-ZàáâäãåąčćęèéêëėįìíîïłńòóôöõøùúûüųūÿýżźñçčšžÀÁÂÄÃÅĄĆČĖĘÈÉÊËÌÍÎÏĮŁŃÒÓÔÖÕØÙÚÛÜŲŪŸÝŻŹÑßÇŒÆČŠŽ∂ð ,.'-]+$");

      if (validator.isEmpty(value)) {
        throw new Error("Last name cannot be empty");
      } else if (!re.test(value)) {
        throw new Error("Last name contains certain characters that aren't allowed");
      }
    },
  },
  email: {
    type: String,
    required: true,
    trim: true,
    validate(value) {
      if (!validator.isEmail(value)) {
        throw new Error("Please Enter valid email address");
      } else if (validator.isEmpty(value)) {
        throw new Error("Email cannot be empty");
      }
    },
  },
  password: {
    type: String,
    required: true,
    trim: true,
    validate(value) {
      if (validator.isEmpty(value)) {
        throw new Error("User Password cannot be empty");
      } else if (!validator.isStrongPassword(value, {
        minLength: 8, minLowercase: 1,
        minUppercase: 1, minNumbers: 1, minSymbols: 1
      })) {
        throw new Error('Please choose a more secure password. It should be longer than 8 characters, unique to you and difficult for others to guess.');
      }
    },
  },
  phoneNumber: {
    type: String,
    required: true,
    validate(value) {
      if (validator.isEmpty(value)) {
        throw new Error("Phone number cannot be empty");
      } else if (!validator.isLength(value, { min: 10, max: 10 })) {
        throw new Error("Phone number should be 10 digits only");
      }
    }
  },
  isVerified: {
    type: Boolean,
    required: true,
  },
  tokens: [
    {
      token: {
        type: String,
        required: true,
      },
    },
  ],
  userId: {
    type: Types.ObjectId,
    ref: "Users",
  },
  isEnabled:{
    type:Boolean,
    required:true,
    default:false
  },

},
  { timestamps: true });

schema.methods.toJSON = function () {
  const user = this;
  const userObject = user.toObject();
  delete userObject.password;
  delete userObject.tokens;
  return userObject;
};

schema.methods.generateAuthToken = async function () {
  const user = this;
  const token = jwt.sign({ _id: user._id.toString() }, "trackingsecret");

  user.tokens = user.tokens.concat({ token });
  await user.save();
  return token;
};

schema.statics.findByCredentials = async (email, password) => {
  const user = await User.findOne({ email });

  if (!user) {
    throw new Error("Unable to login, Please signup first!");
  }
  if (user.isVerified == false) {
    throw new Error("Unable to login, Please verify your email account!");
  }
  if (!user.isAdmin && !user.isEnabled){
    throw new Error("You are disabled, Please Contact the admin.")
  }

  const isMatch = await bcrypt.compare(password, user.password);

  if (!isMatch) {
    throw new Error("Unable to login, Please enter correct password");
  }

  return user;
};

schema.pre("save", async function (next) {
  const user = this;
  if (user.isModified("password")) {
    user.password = await bcrypt.hash(user.password, 8);
  }
  next();
});

const User = mongoose.model("Users", schema);

module.exports = User;
