const express = require("express");
const User = require("../models/users");
const auth = require("../middleware/auth");
const jwt = require("jsonwebtoken");
const app = express();
const { google } = require("googleapis");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
require('dotenv').config();

// These id's and secrets should come from .env file.
const CLIENT_ID =process.env.CLIENT_ID;
const CLEINT_SECRET =process.env.CLEINT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI;
const REFRESH_TOKEN = process.env.REFRESH_TOKEN;

const oAuth2Client = new google.auth.OAuth2(
  CLIENT_ID,
  CLEINT_SECRET,
  REDIRECT_URI
);

oAuth2Client.setCredentials({ refresh_token: REFRESH_TOKEN });

async function sendEmail({ to, subject, html }) {
  let result;
  try {

    const transporter = nodemailer.createTransport({
      service: "gmail",
      secureConnection: false, // TLS requires secureConnection to be false
      port: 587, // port for secure SMTP
      tls: {
        ciphers: 'SSLv3'
      },
      requireTLS: true,//this parameter solved problem for me
      auth: {
        user: process.env.USER,
        pass:process.env.PASS,
      },

    });

    await transporter.verify((err, success) => {
      err ? console.error("Error In Config: ", err) : console.log('Config is correct');
    });

    const mailOptions = {
      from: process.env.USER,
      to,
      subject,
      html,
    };

    result = await transporter.sendMail(mailOptions);

  } catch (err) {
    console.log("Error using the pass method: ", err);
    console.log("Using the OAuth2 method");
    const accessToken = await oAuth2Client.getAccessToken();

    const transport = await nodemailer.createTransport({
      host: "smtp.gmail.com",
      auth: {
        user: process.env.USER,
        pass:process.env.PASS,
        refreshToken: REFRESH_TOKEN,
        accessToken: accessToken,
      },
    });

    await transport.verify((err, success) => {
      err ? console.error("Error In Config: ", err) : console.log('Config is correct');
    });

    const mailOptions = {
      from: process.env.USER,
      to,
      subject,
      html,
    };

    result = await transport.sendMail(mailOptions);

  }
  return result;
}


app.post("/user/signup", async (req, res) => {
  // checks if password and confirm password matches
  console.log(req.body.password )
  console.log(req.body.confirmPassword )

  if (req.body.password != req.body.confirmPassword) {
    console.log(new Date().toLocaleString() + ` User ${req.body.email} sending response: Password does not match`);
    return res.status(400).json({ message: "Password does not match" });
  }
  // checks if user already exits
  const user = await User.findOne({ email: req.body.email });

  console.log(new Date().toLocaleString() + ` User ${req.body.email} details received`);

  if (user) {
    console.log(new Date().toLocaleString() + ` User ${req.body.email} sending response: Email already signed-up`);
    return res.status(400).json({ message: "Email already signed-up" });
  } else {
    // create user with isVerified false
    const user = new User({
      isAdmin: req.body.isAdmin,
      isTeacher: req.body.isTeacher,
      firstName: req.body.firstName,
      lastName: req.body.lastName,
      email: req.body.email,
      password: req.body.password,
      phoneNumber:req.body.phoneNumber,
      isVerified: false,
    });


    const token = jwt.sign({ _id: user._id.toString() }, "trackingsecret");
    user.tokens = user.tokens.concat({ token });

    console.log(new Date().toLocaleString() + ` User ${req.body.email}: token assigned`);
    try {
      await user.save();
      console.log(new Date().toLocaleString() + ` User ${req.body.email}: added to database`);
    } catch (err) {
      console.log(new Date().toLocaleString() + ` User ${req.body.email}: sending response: ${err.message}`);
      return res.status(400).json({ message: err.message });
    }

    console.log(new Date().toLocaleString() + ` User ${req.body.email}: sending verification email`);
    // send verification mail
    await sendEmail({
      to: user.email,
      subject: "Tracking: VERIFY YOUR EMAIL",
      html: `
        <html>
          <body>
            <p>Hi ${user.firstName},</p>
            <p>Welcome to Tracking Application!</p>
            <p>
              To verify your account click
              <a href="${process.env.BASE_URL}/verify-account?token=${user.tokens[user.tokens.length - 1].token
        }">HERE</a>
  
            </p>
          </body>
        
        </html>   
      `,
    }).then(async () => {
      console.log(new Date().toLocaleString() + ` User ${req.body.email} sending response: Please verify your email account`);
      return res.status(201).json({ message: "Please verify your email account", user });
    }).catch((err) => {
      console.log(new Date().toLocaleString() + ` User ${req.body.email} Error: ${err}`);
      console.log(new Date().toLocaleString() + ` User ${req.body.email} sending response: Error occurred while sending verification email`);
      return res.status(500).send({
        message: "Error occurred while sending verification email",
        errorMessage: err.message,
      });
    });
  }
});


app.post("/user/verify-account", auth, async (req, res) => {
  console.log(req.body)
  try {
    req.user.tokens = req.user.tokens.filter((token) => {
      return token.token !== req.token;
    });
    req.user.isVerified = true;
    await req.user.save();
    res.json({ message: "Account verified!" });
  } catch (err) {
    return res.status(500).json({
      message: "Error occure while verifing account",
      errorMessage: err.message,
    });
  }
});

app.patch("/user/enable/:id",auth, async (req, res) => {
  if(!req.user.isAdmin) {
    return res.status(401).send({ message: "Unauthorized, Only admin can enable users!" });
  }
  const updates = Object.keys(req.body);
  const allowedUpdates = [
    "isEnabled",
  ];
  const isValidOperation = updates.every((update) =>
    allowedUpdates.includes(update)
  );
  if (!isValidOperation) {
    return res.status(400).send({ message: "Invalid updates!" });
  }
  try {
    const user = await User.findByIdAndUpdate(req.params.id, {"isEnabled":true}, {
      new: true,
      runValidators: true,
    });

    if (!user) {
      return res.status(404).send({ message: "User not found" });
    }
    res.send({"message":"User is enabled successfully!"});
  } catch (e) {
    return res.status(400).send(e);
  }
});
app.post("/user/resend-verification-mail", async (req, res) => {
  console.log(process.env.BASE_URL)
  const user = await User.findOne({ email: req.body.email });
  console.log(user);

  if (!user) {
    return res.status(400).json({ message: "Please sign-in first" });
  } else if (user.isVerified == true) {
    return res.status(400).json({ message: "Your account is already verified" });
  } else {
    const token = jwt.sign({ _id: user._id.toString() }, "trackingsecret");
    user.tokens = user.tokens.concat({ token });

    console.log(new Date() + "User" + user);

    // send verification mail
    sendEmail({
      to: user.email,
      subject: "Tracking App: VERIFY YOUR EMAIL",
      html: `
          <html>
            <body>
              <p>Hi ${user.firstName},</p>
              <p>Welcome to Tracking App!</p>
              <p>
                To verify your account click
                <a href="${process.env.BASE_URL}/verify-account?token=${user.tokens[user.tokens.length - 1].token
        }">HERE</a>
              </p>
            </body>
          </html>   
        `,
    })
      .then(async () => {
        console.log("smtp success");
        try {
          await user.save();
          return res.status(201).json({
            message:
              "Verification email sent, please verify your email account",
            user,
          });
        } catch (err) {
          return res.status(400).json({ message: err.message });
        }
      })
      .catch((err) => {
        return res.status(500).send({
          message: "Error occure while sending verification email",
          errorMessage: err.message,
        });
      });
  }
});

app.post("/user/login", async (req, res) => {
  try {
    const user = await User.findByCredentials(
      req.body.email,
      req.body.password
    );
    const token = await user.generateAuthToken();
    res.json({ message: "Successfully Login", user, token });
  } catch (err) {
    res
      .status(400)
      .json({ message: "Login Failed", errorMessage: err.message });
  }
});

app.post("/user/logout", auth, async (req, res) => {
  try {
    req.user.tokens = req.user.tokens.filter((token) => {
      return token.token !== req.token;
    });
    await req.user.save();
    res.json({ message: "Successfully Logout" });
  } catch (err) {
    res
      .status(500)
      .json({ message: "Logout Failed", errorMessage: err.message });
  }
});

// FORGET PASSWORD API
app.post('/user/forget-password', async (req, res) => {

  let user = await User.findOne({ email: req.body.email });

  if (!user) {
    return res
      .status(409)
      .send({ message: "User with given email does not exist!" });
  }
  console.log(new Date().toLocaleString() + ` User ${req.body.email}: user found`);
  const token = jwt.sign({ _id: user._id.toString() }, "trackingsecret");

  user.tokens = user.tokens.concat({ token });
  console.log(new Date().toLocaleString() + ` User ${req.body.email}: token assigned`);

  try {

    await user.save();
    console.log(new Date().toLocaleString() + ` User ${req.body.email}: added to database`);

  } catch (err) {

    console.log(new Date().toLocaleString() + ` User ${req.body.email}: sending response: ${err.message}`);

    return res.status(400).json({ message: err.message });

  }

  console.log(new Date().toLocaleString() + ` User ${req.body.email}: sending reset password email`);

  // send reset password mail
  await sendEmail({
    to: user.email,
    subject: "Tracking App: RESET YOUR PASSWORD",
    html: `
          <html>
            <body>
              <p>Hi ${user.firstName},</p>
              <p>Welcome to Tracking Application!</p>
              <p>
                To reset your password click
                <a href="${process.env.BASE_URL}/auth/reset-password?token=${user.tokens[user.tokens.length - 1].token}">HERE</a>
              </p>
            </body>          
          </html>   
        `,
  }).then(async () => {

    console.log(new Date().toLocaleString() + ` User ${req.body.email} sending response: Password reset link sent to your email account`);

    return res
      .status(200)
      .send({ message: "Password reset link sent to your email account" });

  }).catch((err) => {

    console.log(new Date().toLocaleString() + ` User ${req.body.email} Error: ${err}`);
    console.log(new Date().toLocaleString() + ` User ${req.body.email} sending response: Error occurred while sending reset password email`);

    return res.status(500).send({
      message: "Error occurred while sending reset password email",
      errorMessage: err.message,
    });
  });

});

// RESET PASSWORD API
app.post('/user/reset-password', auth, async (req, res) => {
  try {
    req.user.password = req.body.password;

    if (req.body.password != req.body.confirmPassword) {
      console.log(new Date().toLocaleString() + ` User ${req.body.email} sending response: Password does not match`);
      return res.status(400).json({ message: "Password does not match" });
    }

    req.user.tokens = req.user.tokens.filter((token) => {
      return token.token !== req.token;
    });

    await req.user.save();

    return res.json({ message: "Your password has been resetted successfully!" });
  } catch (err) {
    return res.status(500).json({
      message: "Error occure while resetting password",
      errorMessage: err.message,
    });
  }
});

// app.delete("/user/:email", auth, async (req, res) => {

//   await User.findOneAndDelete({ email: req.body.email }, (error, result) => {
//     if (error) {
//       res.json({ message: "Deletion Failed", errorMessage: err.message });
//     }
//     return res.send("Deleted Successfully");
//   });
// });

app.delete("/user/:id", auth, async (req, res) => {
  try {
    await User.findOneAndDelete({
      _id: req.params.id,
    });
    res.json({ message: "Successfully Deleted" });
  } catch (e) {
    res.status(500).send({
      message: "Error occur while deleting the user",
      errorMessage: e.message,
    });
  }
});


app.get('/users', auth, async (req, res) => {
  try {
    const readUser = await User.find({ isAdmin: false });

    res.send(readUser);

  } catch (err) {
    res
      .status(500)
      .json({ message: "Error in finding all the user data!", errorMessage: err.message });
  }
});
app.post("/users/logoutAll", auth, async (req, res) => {
  try {
    req.user.tokens = [];
    await req.user.save();
    res.json({ message: "Successfully Logout All" });
  } catch (err) {
    res
      .status(500)
      .json({ message: "Logout All Failed", errorMessage: err.message });
  }
});

app.patch("/user/:id", auth, async (req, res) => {
  const updates = Object.keys(req.body);
  const allowedUpdates = [
    "firstName",
    "lastName",
    "email",
    "password",
    "isEnabled",
    "isAdmin",
    "isTeacher",
    "phoneNumber"
  ];
  const isValidOperation = updates.every((update) =>
    allowedUpdates.includes(update)
  );
  if (!isValidOperation) {
    return res.status(400).send({ message: "Invalid updates!" });
  }
  try {

    // encrypt (hash) update password
    if (req.body.password) {
      req.body.password = await bcrypt.hash(req.body.password, 8);
    }

    const user = await User.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true,
    });

    if (!user) {
      return res.status(404).send({ message: "User not found" });
    }
    res.send(user);
  } catch (e) {
    return res.status(400).send(e);
  }
});

module.exports = app;
