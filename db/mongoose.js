const dotenv = require("dotenv")
dotenv.config()

const mongoose = require("mongoose");
mongoose.set('strictQuery',false);
mongoose.connect(process.env.MONGO_URI || 'mongodb://0.0.0.0:27017/Tracking',{useNewUrlParser: true});